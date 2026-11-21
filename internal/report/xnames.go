package report

import (
	"encoding/json/jsontext"
	"slices"
)

// The versions this rpt reads and writes.
const (
	SchemaVersion = 3 // the record schemas
	FormatVersion = 2 // the report format
)

// An XName is one use of a plugin's name: an x- frontmatter key, scope
// column, config section or record kind, with its value and place.
type XName struct {
	Noun  string // finding, page, scope, config or kinds
	Name  string
	Path  string
	Line  int
	Value jsontext.Value
}

// XNames lists the x- names the report uses, in file order.
func (m *Model) XNames() []XName {
	var out []XName
	for _, k := range Kinds {
		for _, d := range m.docs[k] {
			for _, e := range d.Extra {
				if IsPluginKey(e.Key.Value) {
					out = append(out, XName{k.Name, e.Key.Value, d.Path, e.Key.Line + d.src.HeadLine() - 1, NodeJSON(e.Value)})
				}
			}
		}
	}
	for _, r := range m.Scope.Rows {
		for _, col := range m.Scope.Header {
			if v, ok := r.Extra[col]; ok && IsPluginKey(col) {
				q, _ := jsontext.AppendQuote(nil, v)
				out = append(out, XName{"scope", col, ScopeFile, r.Line, q})
			}
		}
	}
	if m.Config.Err == nil {
		for _, e := range m.Config.src.Entries() {
			if IsPluginKey(e.Key.Value) {
				out = append(out, XName{"config", e.Key.Value, ConfigFile, e.Key.Line, NodeJSON(e.Value)})
			}
		}
	}
	return out
}

// Leveled gives problems the levels the config's rules set, and sorts
// them.
func (m *Model) Leveled(ps []Problem) []Problem { return m.leveled(slices.Clone(ps)) }
