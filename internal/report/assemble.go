package report

import (
	"cmp"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/astr4liteEx/rpt/sdk"
)

// SchemaVersion is the version of the record schemas rpt writes.
const SchemaVersion = 1

// Assemble builds the render-ready report record: findings sorted by the
// config's severity order then ID number, scope IDs replaced by their full
// rows, evidence and relative section links made absolute and listed as
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
	slices.SortStableFunc(a.warnings, func(x, y sdk.Problem) int {
		return cmp.Or(cmp.Compare(x.Path, y.Path), cmp.Compare(x.Line, y.Line), cmp.Compare(x.Rule, y.Rule), cmp.Compare(x.Message, y.Message))
	})

	return sdk.Report{
		Kind:          "report",
		SchemaVersion: SchemaVersion,
		Report: sdk.ReportMeta{
			Name:       cfg.Name,
			Client:     cfg.Client,
			Period:     cfg.Period,
			Severities: cfg.Severities,
		},
		Summary:  summary,
		Scope:    nonNilRows(rows),
		Findings: findings,
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
		Title:    f.Title,
		Severity: f.Severity,
		Scope:    []sdk.ScopeRow{},
		Sections: map[string]string{},
		Assets:   []string{},
		Target:   f.Target,
		Extra:    f.Extra,
	}
	for _, id := range f.Scope {
		row, ok := byID[id]
		if !ok {
			a.warn(ff.rel, ff.keyLines["scope"], RuleScopeIDsExist, "%s is not in scope.csv; left out of the finding's scope", id)
			continue
		}
		rf.Scope = append(rf.Scope, row)
	}
	addAsset := func(rel string) string {
		abs := filepath.Join(a.r.abs, filepath.FromSlash(rel))
		if !slices.Contains(rf.Assets, abs) {
			rf.Assets = append(rf.Assets, abs)
		}
		return abs
	}
	for _, p := range f.Evidence {
		rel, msg := a.r.checkEvidence(f, p)
		if msg != "" {
			a.warn(ff.rel, ff.keyLines["evidence"], RuleEvidence, "%s; left out", msg)
			continue
		}
		addAsset(rel)
	}
	// Section links: problems are located in the file body, rewrites done
	// per section.
	for _, l := range relLinks(ff.body) {
		if _, msg := a.r.checkEvidence(f, l.path); msg != "" {
			a.warn(ff.rel, ff.bodyLine(l.off), RuleEvidence, "%s; left out", msg)
		}
	}
	for key, text := range f.Sections {
		for _, l := range relLinks([]byte(text)) {
			rel, msg := a.r.checkEvidence(f, l.path)
			if msg != "" {
				continue // warned above; the link stays as written
			}
			text = rewriteLink(text, l.dest, linkTarget(addAsset(rel)))
		}
		rf.Sections[key] = text
	}
	return rf
}

// rewriteLink points every inline link and reference definition with the
// target dest at target instead.
func rewriteLink(md, dest, target string) string {
	return strings.NewReplacer("]("+dest, "]("+target, "]: "+dest, "]: "+target).Replace(md)
}

// linkTarget writes an absolute path as a markdown link target, in angle
// brackets when it holds characters a bare target can't.
func linkTarget(abs string) string {
	p := filepath.ToSlash(abs)
	if strings.ContainsAny(p, " ()<>") {
		return "<" + p + ">"
	}
	return p
}

// compareIDs orders finding IDs by number, so F-999 comes before F-1000;
// malformed IDs sort after well-formed ones, by text.
func compareIDs(a, b string) int {
	na, errA := strconv.Atoi(strings.TrimPrefix(a, "F-"))
	nb, errB := strconv.Atoi(strings.TrimPrefix(b, "F-"))
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

func nonNilRows(rows []sdk.ScopeRow) []sdk.ScopeRow {
	if rows == nil {
		return []sdk.ScopeRow{}
	}
	return rows
}
