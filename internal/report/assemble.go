package report

import (
	"cmp"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/astr4liteEx/rpt/internal/doc"
	"github.com/astr4liteEx/rpt/sdk"
)

// Assemble builds the record renderers read: findings by severity, then
// ID; each target with its scope row; links to files in the report made
// absolute; pages in report order. It never refuses: what it can't use
// is left out, and each such thing is a warning, under the validate rule
// that covers it. rpt validate is the gate.
func (m *Model) Assemble() (sdk.Report, []Problem) {
	var warn []Problem
	leave := func(path string, line int, rule, format string, a ...any) {
		warn = append(warn, Problem{Path: path, Line: line, Rule: rule, Level: Warning, Message: fmt.Sprintf(format, a...) + "; left out"})
	}
	cfg := m.Config
	r := sdk.Report{
		Kind: "report", SchemaVersion: SchemaVersion,
		Summary: map[sdk.Severity]int{}, Scope: []sdk.ScopeRow{}, Findings: []sdk.ReportFinding{}, Pages: []sdk.ReportPage{},
	}
	var fe *FileError
	if errors.As(cfg.Err, &fe) {
		warn = append(warn, Problem{Path: fe.Path, Line: fe.Line, Rule: "readable", Level: Warning, Message: fmt.Sprintf("%v; the default config is used", fe.Err)})
		cfg = parseConfig([]byte(fmt.Sprintf("format: %d\n", FormatVersion)))
	}
	for _, s := range cfg.Severities {
		r.Report.Severities = append(r.Report.Severities, sdk.Severity(s))
		r.Summary[sdk.Severity(s)] = 0
	}
	for _, k := range FixedSections {
		r.Report.Sections = append(r.Report.Sections, sdk.ReportSection{Key: k, Heading: cfg.Heading(k)})
	}
	for _, h := range cfg.RequiredSections {
		if k := cfg.SectionKey(h); !slices.Contains(FixedSections, k) {
			r.Report.Sections = append(r.Report.Sections, sdk.ReportSection{Key: k, Heading: h})
		}
	}

	if errors.As(m.Scope.Err, &fe) {
		leave(fe.Path, fe.Line, "scope", "%v: every target", fe.Err)
	}
	for _, err := range m.Scope.RowErrs {
		if errors.As(err, &fe) {
			leave(fe.Path, fe.Line, "scope", "%v: the row", fe.Err)
		}
	}
	for _, row := range m.Scope.Rows {
		rec := m.ScopeRecord(row, false)
		rec.Rev = ""
		r.Scope = append(r.Scope, rec)
	}

	for _, d := range m.docs[FindingKind] {
		if !m.usable(d, leave) {
			continue
		}
		f := sdk.ReportFinding{
			ID: d.ID, Path: d.Path, Title: d.Title, Severity: sdk.Severity(d.Severity),
			Targets: []sdk.ReportTarget{}, Sections: map[string]string{}, Assets: m.Assets(d), Extra: extra(d.Extra),
		}
		for _, t := range d.Targets {
			row, err := m.Scope.Row(t.Scope)
			switch {
			case m.Scope.Err != nil:
				continue
			case err != nil:
				leave(d.Path, t.Line, "scopeIDsExist", "%s is not in %s: the target", t.Scope, ScopeFile)
				continue
			}
			if err := Fits(row, t); err != nil {
				leave(d.Path, t.Line, "targets", "%v: the target", err)
				continue
			}
			rec := m.ScopeRecord(row, false)
			rec.Rev = ""
			f.Targets = append(f.Targets, sdk.ReportTarget{Scope: rec, Host: t.Host, Port: t.Port, Protocol: t.Protocol, Extra: extra(t.Extra)})
		}
		for _, s := range sectionsOf(m.absolute(d), cfg) {
			if _, dup := f.Sections[s.Key]; !dup {
				f.Sections[s.Key] = s.Text
			}
		}
		r.Summary[f.Severity]++
		r.Findings = append(r.Findings, f)
	}
	rank := func(s sdk.Severity) int {
		if i := slices.Index(cfg.Severities, string(s)); i >= 0 {
			return i
		}
		return len(cfg.Severities)
	}
	slices.SortStableFunc(r.Findings, func(a, b sdk.ReportFinding) int {
		return cmp.Or(cmp.Compare(rank(a.Severity), rank(b.Severity)), CompareIDs(a.ID, b.ID))
	})

	pages := map[string]*Doc{}
	for _, d := range m.docs[PageKind] {
		if m.usable(d, leave) {
			pages[d.ID] = d
		}
	}
	r.Report.Order = m.PageOrder()
	for _, id := range r.Report.Order {
		d, ok := pages[id]
		if !ok {
			continue
		}
		r.Pages = append(r.Pages, sdk.ReportPage{
			ID: d.ID, Path: d.Path, Title: d.Title, Assets: m.Assets(d), Extra: extra(d.Extra),
			Body: strings.Trim(string(m.absolute(d).Body()), "\n"),
		})
	}
	SortProblems(warn)
	return r, warn
}

// usable reports whether a document goes into the assembled report: it
// reads, and its ID is well-formed and its own.
func (m *Model) usable(d *Doc, leave func(string, int, string, string, ...any)) bool {
	rule := map[*Kind]string{FindingKind: "findingID", PageKind: "pageID"}[d.Kind]
	switch {
	case d.Err != nil:
		line := 0
		var fe *FileError
		if errors.As(d.Err, &fe) {
			line = fe.Line
		}
		leave(d.Path, line, "readable", "%s doesn't read: the %s", d.Path, d.Kind.Name)
		return false
	case !d.Kind.Valid(d.ID):
		leave(d.Path, max(d.KeyLine("id"), 1), rule, "id %q is not of the form %sNNN: the %s", d.ID, d.Kind.Prefix, d.Kind.Name)
		return false
	}
	for _, o := range m.docs[d.Kind] {
		if o == d {
			return true
		}
		if o.Err == nil && o.ID == d.ID {
			leave(d.Path, max(d.KeyLine("id"), 1), rule, "%s is also the id of %s: the %s", d.ID, o.Path, d.Kind.Name)
			return false
		}
	}
	return true
}

// absolute is d's document with every link to a file in the report
// pointing at its absolute path. A link to a missing file stays as
// written.
func (m *Model) absolute(d *Doc) *doc.Doc {
	refs, _ := m.Refs(d)
	var spans []doc.Span
	seen := map[int]bool{}
	for _, r := range refs {
		if r.Link == nil || r.Path == "" || !m.exists(r.Path) || seen[r.Link.DestStart] {
			continue
		}
		seen[r.Link.DestStart] = true
		dest := filepath.ToSlash(m.abs(r.Path))
		switch {
		case r.Link.HTML:
			dest = strings.ReplaceAll(dest, `"`, "&quot;")
		case d.src.Body()[r.Link.DestStart-1] != '<':
			dest = markdownDest(dest)
		}
		spans = append(spans, doc.Span{Start: r.Link.DestStart, End: r.Link.DestEnd, Text: dest})
	}
	out, err := doc.Parse(d.src.Bytes())
	if err != nil || out.RewriteSpans(spans) != nil {
		return d.src
	}
	return out
}

// PageOrder is the order of the report's parts: the pages rpt.yaml lists
// that exist, with findings where its slot is (last when it isn't
// listed), then the other pages by ID.
func (m *Model) PageOrder() []string {
	exists := map[string]bool{}
	for _, d := range m.docs[PageKind] {
		if d.Err == nil && PageKind.Valid(d.ID) {
			exists[d.ID] = true
		}
	}
	var order []string
	for _, id := range m.Config.Pages {
		if (id == FindingsSlot || exists[id]) && !slices.Contains(order, id) {
			order = append(order, id)
		}
	}
	if !slices.Contains(order, FindingsSlot) {
		order = append(order, FindingsSlot)
	}
	var rest []string
	for id := range exists {
		if !slices.Contains(order, id) {
			rest = append(rest, id)
		}
	}
	slices.SortFunc(rest, CompareIDs)
	return append(order, rest...)
}
