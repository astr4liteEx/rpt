package report

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"

	"github.com/astr4liteEx/rpt/sdk"
)

// StreamPath is the path of problems in records read from a stream.
const StreamPath = "-"

// A Record is one record from a stream: its kind, its line, its JSON.
type Record struct {
	Kind string
	Line int
	Raw  jsontext.Value
}

// A claim says which record a file, or a scope row, came from.
type claim struct {
	line int
	id   string
	path string // the file the record wrote
}

// CheckRecords checks records as if they were written to the report: a
// finding, page or scope row with an ID the report has replaces it, one
// without is added, and a config record replaces rpt.yaml. They are
// checked together, so a finding may cite a scope row added in the same
// stream.
//
// Problems in what the records wrote are given at StreamPath and the
// record's line; problems they cause elsewhere keep their place; problems
// the report already had are left out. A record that can't be applied is
// a problem at its line. The model is left changed; don't save it.
func (m *Model) CheckRecords(recs []Record) []Problem {
	had := map[string]bool{}
	key := func(p Problem) string { return fmt.Sprint(p.Path, "\x00", p.Line, "\x00", p.Rule, "\x00", p.Message) }
	for _, p := range m.Check() {
		had[key(p)] = true
	}
	var out []Problem
	bad := func(r Record, rule, format string, a ...any) {
		out = append(out, Problem{Path: StreamPath, Line: r.Line, Rule: rule, Level: Error, Message: fmt.Sprintf(format, a...)})
	}
	claims := map[string]claim{}
	rowClaims := map[string]claim{}
	seen := map[string]int{}
	for _, r := range recs {
		var head struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(r.Raw, &head); err != nil {
			bad(r, "input", "%s: %v", r.Kind, err)
			continue
		}
		id := CanonicalID(head.ID)
		if id != "" || r.Kind == "config" {
			k := r.Kind + " " + strings.ToUpper(id)
			if first, ok := seen[k]; ok {
				bad(r, "duplicate", "%s %s is in the stream twice; the first is on line %d", r.Kind, id, first)
				continue
			}
			seen[k] = r.Line
		}
		c, row, err := m.apply(r, id)
		var ref *Refusal
		switch {
		case errors.As(err, &ref):
			bad(r, "write", "%s", ref.Msg)
		case errors.Is(err, errInput):
			bad(r, "input", "%s", strings.TrimPrefix(err.Error(), errInput.Error()+": "))
		case err != nil:
			bad(r, "write", "%v", err)
		case row != "":
			rowClaims[row] = c
		case c.path != "":
			claims[c.path] = c
		}
	}
	rowAt := map[int]claim{}
	for _, row := range m.Scope.Rows {
		if c, ok := rowClaims[row.ID]; ok {
			rowAt[row.Line] = c
		}
	}
	for _, p := range m.Check() {
		c, ok := claims[p.Path]
		if !ok && p.Path == ScopeFile {
			c, ok = rowAt[p.Line]
		}
		switch {
		case ok:
			if c.id != "" {
				p.Message = c.id + ": " + p.Message
			}
			p.Path, p.Line = StreamPath, c.line
		case had[key(p)]:
			continue
		}
		out = append(out, p)
	}
	SortProblems(out)
	return out
}

var errInput = errors.New("bad record")

// apply writes one record into the model. It returns the claim, with the
// file the record wrote, or the ID of the scope row it wrote.
func (m *Model) apply(r Record, id string) (claim, string, error) {
	decode := func(v any) error {
		if err := json.Unmarshal(r.Raw, v); err != nil {
			return fmt.Errorf("%w: %s: %v", errInput, r.Kind, err)
		}
		return nil
	}
	c := claim{line: r.Line, id: id}
	switch r.Kind {
	case "finding", "page":
		k := FindingKind
		var dr Draft
		var err error
		if r.Kind == "page" {
			k = PageKind
			var p sdk.Page
			if err := decode(&p); err != nil {
				return c, "", err
			}
			dr, err = PageDraft(p)
		} else {
			var f sdk.Finding
			if err := decode(&f); err != nil {
				return c, "", err
			}
			dr, err = FindingDraft(f)
		}
		if err != nil {
			return c, "", fmt.Errorf("%w: %v", errInput, err)
		}
		var d *Doc
		if _, gerr := m.Get(k, id); id != "" && gerr == nil {
			d, err = m.Replace(k, id, dr)
		} else {
			d, err = m.Add(k, dr)
		}
		if err != nil {
			return c, "", err
		}
		c.path = d.Path
		return c, "", nil
	case "scope":
		var s sdk.ScopeRow
		if err := decode(&s); err != nil {
			return c, "", err
		}
		row, err := ScopeDraft(s)
		if err != nil {
			return c, "", fmt.Errorf("%w: %v", errInput, err)
		}
		var got *Row
		if _, gerr := m.Scope.Row(row.ID); row.ID != "" && gerr == nil {
			got, err = m.ReplaceScope(row)
		} else {
			got, err = m.AddScope(row)
		}
		if err != nil {
			return c, "", err
		}
		c.id = s.ID
		return c, got.ID, nil
	case "config":
		var cfg sdk.Config
		if err := decode(&cfg); err != nil {
			return c, "", err
		}
		c.path = ConfigFile
		return c, "", m.ReplaceConfig(cfg)
	}
	return c, "", nil // other records pass by
}
