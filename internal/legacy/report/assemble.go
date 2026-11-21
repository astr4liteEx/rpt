package report

import (
	"cmp"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/astr4liteEx/rpt/sdk"
)

// SchemaVersion is the version of the record schemas rpt writes.
const SchemaVersion = 2

// FormatVersion is the report format this rpt reads: the format key in
// rpt.yaml.
const FormatVersion = 2

// Assemble builds the render-ready report record: findings sorted by the
// config's severity order then ID number, each target's scope ID replaced
// by its full row (a target that doesn't fit its row is left out),
// evidence and relative section links made absolute and listed as
// assets, and a count per severity level. It never refuses: anything it
// can't use is left out and reported in the returned warnings, using the
// validate rule that covers it. rpt validate is the gate. The error is for
// a report that can't be assembled at all, such as an unreadable config.
func (r *Report) Assemble() (sdk.Report, []sdk.Problem, error) {
	cfg, err := r.Config()
	if err != nil {
		return sdk.Report{}, nil, err
	}
	a := &assembly{r: r}
	rows, err := r.Scope()
	for i := range rows {
		rows[i].Rev = "" // a renderer has no use for revs
	}
	for _, e := range unjoin(err) {
		a.warnError(RuleScope, e)
	}
	byID := make(map[string]sdk.ScopeRow, len(rows))
	for _, row := range rows {
		byID[row.ID] = row
	}

	files, err := r.findingFiles()
	if err != nil {
		return sdk.Report{}, nil, err
	}
	summary := make(map[sdk.Severity]int, len(cfg.Severities))
	for _, l := range cfg.Severities {
		summary[l] = 0
	}
	findings := []sdk.ReportFinding{}
	for _, ff := range files {
		if ff.err != nil {
			a.warnError(RuleReadable, ff.err)
			continue
		}
		rf := a.finding(ff, byID)
		summary[rf.Severity]++
		findings = append(findings, rf)
	}

	rank := func(s sdk.Severity) int {
		if i := slices.Index(cfg.Severities, s); i >= 0 {
			return i
		}
		return len(cfg.Severities) // unknown levels last; validate reports them
	}
	slices.SortStableFunc(findings, func(x, y sdk.ReportFinding) int {
		return cmp.Or(cmp.Compare(rank(x.Severity), rank(y.Severity)), compareIDs(x.ID, y.ID))
	})

	pages, err := r.Pages()
	for _, e := range unjoin(err) {
		if e != nil {
			a.warnError(RuleReadable, e)
		}
	}
	pages = slices.DeleteFunc(pages, func(p sdk.Page) bool { return !ValidPageID(p.ID) }) // validate reports them
	order := PageOrder(cfg.Pages, pages)
	reportPages := []sdk.ReportPage{}
	for _, id := range order {
		if i := slices.IndexFunc(pages, func(p sdk.Page) bool { return p.ID == id }); i >= 0 {
			reportPages = append(reportPages, a.page(pages[i]))
		}
	}
	slices.SortStableFunc(a.warnings, func(x, y sdk.Problem) int {
		return cmp.Or(cmp.Compare(x.Path, y.Path), cmp.Compare(x.Line, y.Line), cmp.Compare(x.Rule, y.Rule), cmp.Compare(x.Message, y.Message))
	})

	return sdk.Report{
		Kind:          "report",
		SchemaVersion: SchemaVersion,
		Report: sdk.ReportMeta{
			Severities: cfg.Severities,
			Sections:   reportSections(cfg),
			Order:      order,
		},
		Summary:  summary,
		Scope:    nonNilRows(rows),
		Findings: findings,
		Pages:    reportPages,
	}, a.warnings, nil
}

type assembly struct {
	r        *Report
	warnings []sdk.Problem
}

func (a *assembly) warn(path string, line int, rule, format string, args ...any) {
	a.warnings = append(a.warnings, sdk.Problem{
		Kind: "problem", Path: path, Line: line, Rule: rule, Level: sdk.Warning, Message: fmt.Sprintf(format, args...),
	})
}

func (a *assembly) warnError(rule string, err error) {
	if fe, ok := errors.AsType[*FileError](err); ok {
		a.warn(fe.Path, fe.Line, rule, "%v; left out of the report", fe.Err)
		return
	}
	a.warn("", 0, rule, "%v", err)
}

// finding turns one finding file into its report form.
func (a *assembly) finding(ff findingSrc, byID map[string]sdk.ScopeRow) sdk.ReportFinding {
	f := ff.f
	rf := sdk.ReportFinding{
		ID:       f.ID,
		Path:     ff.rel,
		Title:    f.Title,
		Severity: f.Severity,
		Targets:  []sdk.ReportTarget{},
		Sections: map[string]string{},
		Assets:   a.r.assets(owner{id: f.ID, rel: ff.rel, evidence: f.Evidence, body: ff.body, first: ff.first, h: a.r.headings()}, true),
		Extra:    f.Extra,
	}
	line := ff.keyLines["targets"]
	for _, t := range f.Targets {
		if err := checkTarget(t); err != nil {
			a.warn(ff.rel, line, RuleTargets, "%v; target left out of the finding", err)
			continue
		}
		row, ok := byID[t.Scope]
		if !ok {
			a.warn(ff.rel, line, RuleScopeIDsExist, "%q is not in scope.csv; target left out of the finding", t.Scope)
			continue
		}
		if err := TargetFits(t, row); err != nil {
			a.warn(ff.rel, line, RuleTargets, "%v; target left out of the finding", err)
			continue
		}
		rf.Targets = append(rf.Targets, sdk.ReportTarget{Scope: row, Host: t.Host, Port: t.Port, Protocol: t.Protocol, Extra: t.Extra})
	}
	for _, p := range f.Evidence {
		if _, msg := a.r.checkEvidence(f, p); msg != "" {
			a.warn(ff.rel, ff.keyLines["evidence"], RuleEvidence, "%s; left out", msg)
		}
	}
	for _, l := range relLinks(ff.body) {
		if _, msg := a.r.checkEvidence(f, l.path); msg != "" {
			a.warn(ff.rel, ff.bodyLine(l.off), RuleEvidence, "%s; left out", msg)
		}
	}
	for key, text := range f.Sections {
		rf.Sections[key] = a.absoluteLinks(f, text)
	}
	return rf
}

// absoluteLinks points each link in md to a file in the report at its
// absolute path. A link that fails its evidence check stays as written.
func (a *assembly) absoluteLinks(f sdk.Finding, md string) string {
	return string(rewriteDests([]byte(md), func(l link) (string, bool) {
		if path.IsAbs(l.path) {
			return "", false
		}
		rel, msg := a.r.checkEvidence(f, l.path)
		if msg != "" {
			return "", false
		}
		return filepath.ToSlash(filepath.Join(a.r.abs, filepath.FromSlash(rel))), true
	}))
}

// page turns one page into its report form: body links made absolute and
// every listed or linked file given as an asset.
func (a *assembly) page(p sdk.Page) sdk.ReportPage {
	o := owner{id: p.ID, rel: p.Path, page: true, evidence: p.Evidence, body: []byte(p.Body), first: 1}
	rp := sdk.ReportPage{ID: p.ID, Path: p.Path, Title: p.Title, Assets: a.r.assets(o, true), Extra: p.Extra}
	f := o.stub()
	for _, e := range p.Evidence {
		if _, msg := a.r.checkEvidence(f, e); msg != "" {
			a.warn(p.Path, 0, RuleEvidence, "%s; left out", msg)
		}
	}
	for _, l := range relLinks([]byte(p.Body)) {
		if _, msg := a.r.checkEvidence(f, l.path); msg != "" {
			a.warn(p.Path, 0, RuleEvidence, "%s; left out", msg)
		}
	}
	rp.Body = a.absoluteLinks(f, p.Body)
	return rp
}

// compareIDs orders finding IDs by number, so F-999 comes before F-1000;
// malformed IDs sort after well-formed ones, by text.
func compareIDs(a, b string) int {
	na, errA := strconv.Atoi(strings.TrimPrefix(strings.TrimPrefix(a, "F-"), "P-"))
	nb, errB := strconv.Atoi(strings.TrimPrefix(strings.TrimPrefix(b, "F-"), "P-"))
	switch {
	case errA == nil && errB == nil:
		return cmp.Or(cmp.Compare(na, nb), cmp.Compare(a, b))
	case errA == nil:
		return -1
	case errB == nil:
		return 1
	}
	return cmp.Compare(a, b)
}

// reportSections is the config's sections as the report record gives
// them: each key with this report's heading.
func reportSections(cfg Config) []sdk.ReportSection {
	out := []sdk.ReportSection{}
	for _, k := range cfg.sectionKeys() {
		out = append(out, sdk.ReportSection{Key: k, Heading: cfg.Headings.heading(k)})
	}
	return out
}

func nonNilRows(rows []sdk.ScopeRow) []sdk.ScopeRow {
	if rows == nil {
		return []sdk.ScopeRow{}
	}
	return rows
}
