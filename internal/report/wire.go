package report

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/astr4liteEx/rpt/internal/doc"
	"github.com/astr4liteEx/rpt/sdk"
)

// This file is the one seam between the model and the records rpt reads
// and writes: every conversion between the two is here.

// RecordOpts say what to add to a finding or page record.
type RecordOpts struct {
	Lines  bool // where each part sits in the file
	Assets bool // every file it lists or links
}

func extra(es []doc.Entry) map[string]jsontext.Value {
	if len(es) == 0 {
		return nil
	}
	out := make(map[string]jsontext.Value, len(es))
	for _, e := range es {
		out[e.Key.Value] = NodeJSON(e.Value)
	}
	return out
}

// abs is a report path as an absolute OS path, symlinks kept.
func (m *Model) abs(rel string) string {
	dir, err := filepath.Abs(m.Dir)
	if err != nil {
		dir = m.Dir
	}
	return filepath.Join(dir, filepath.FromSlash(rel))
}

func (m *Model) keyPositions(d *doc.Doc) map[string]sdk.Position {
	out := map[string]sdk.Position{}
	for _, e := range d.Entries() {
		out[e.Key.Value] = sdk.Position{Line: e.Key.Line + d.HeadLine() - 1, Column: e.Key.Column}
	}
	return out
}

// FindingRecord is a finding as a record.
func (m *Model) FindingRecord(d *Doc, o RecordOpts) sdk.Finding {
	f := sdk.Finding{
		Kind: "finding", ID: d.ID, Title: d.Title, Severity: sdk.Severity(d.Severity),
		Path: d.Path, Rev: d.Rev, Evidence: d.Evidence, Extra: extra(d.Extra),
		Targets: []sdk.Target{},
	}
	for _, t := range d.Targets {
		f.Targets = append(f.Targets, sdk.Target{Scope: t.Scope, Host: t.Host, Port: t.Port, Protocol: t.Protocol, Extra: extra(t.Extra)})
	}
	if len(d.Sections) > 0 {
		f.Sections = map[string]string{}
		for _, s := range d.Sections {
			if _, dup := f.Sections[s.Key]; !dup {
				f.Sections[s.Key] = s.Text
			}
		}
	}
	if o.Lines {
		f.Lines = &sdk.Lines{File: m.abs(d.Path), Keys: m.keyPositions(d.src)}
		if len(d.Sections) > 0 {
			f.Lines.Sections = map[string]sdk.SectionLines{}
			for _, s := range d.Sections {
				f.Lines.Sections[s.Key] = sdk.SectionLines{Heading: s.Line, Text: s.TextLine}
			}
		}
	}
	if o.Assets {
		f.Assets = m.Assets(d)
	}
	return f
}

// PageRecord is a page as a record.
func (m *Model) PageRecord(d *Doc, o RecordOpts) sdk.Page {
	p := sdk.Page{
		Kind: "page", ID: d.ID, Title: d.Title, Path: d.Path, Rev: d.Rev,
		Body: strings.Trim(d.Body(), "\n"), Evidence: d.Evidence, Extra: extra(d.Extra),
	}
	if o.Lines {
		p.Lines = &sdk.Lines{File: m.abs(d.Path), Keys: m.keyPositions(d.src), Body: d.BodyLine()}
	}
	if o.Assets {
		p.Assets = m.Assets(d)
	}
	return p
}

// Assets are the files a document lists and links, each once, inside the
// report.
func (m *Model) Assets(d *Doc) []sdk.Asset {
	refs, _ := m.Refs(d)
	out := []sdk.Asset{}
	seen := map[string]bool{}
	for _, r := range refs {
		if r.Path == "" || seen[r.Source+"\x00"+r.Ref] {
			continue
		}
		seen[r.Source+"\x00"+r.Ref] = true
		a := sdk.Asset{Ref: r.Ref, Path: r.Path, File: m.abs(r.Path), Source: r.Source, MediaType: m.MediaType(r.Path)}
		if r.Link != nil {
			a.Text, a.Image = r.Link.Text, r.Link.Image
		}
		out = append(out, a)
	}
	return out
}

// EvidenceRecord is one reference as an evidence record.
func (m *Model) EvidenceRecord(r Ref) sdk.Evidence {
	e := sdk.Evidence{Kind: "evidence", Ref: r.Ref, Source: r.Source, Line: r.Line, Rev: r.Doc.Rev}
	if r.Doc.Kind == PageKind {
		e.Page = r.Doc.ID
	} else {
		e.Finding = r.Doc.ID
	}
	if r.Path != "" {
		e.Path, e.File, e.Exists = r.Path, m.abs(r.Path), m.exists(r.Path)
		if e.Exists {
			e.MediaType = m.MediaType(r.Path)
		}
	}
	if r.Link != nil {
		e.Text, e.Image = r.Link.Text, r.Link.Image
		if r.Doc.Kind.Sectioned {
			for _, s := range r.Doc.Sections {
				if s.Line <= r.Line {
					e.Section = s.Key
				}
			}
		}
	}
	return e
}

// OrphanRecord is an orphaned evidence file as a record.
func (m *Model) OrphanRecord(rel string) sdk.Evidence {
	return sdk.Evidence{Kind: "evidence", Path: rel, File: m.abs(rel), Exists: true, MediaType: m.MediaType(rel)}
}

// ScopeRecord is a scope row as a record.
func (m *Model) ScopeRecord(r *Row, lines bool) sdk.ScopeRow {
	s := sdk.ScopeRow{Kind: "scope", ID: r.ID, Host: r.Host, Port: r.Port, Protocol: r.Protocol, Rev: r.Rev}
	for _, col := range m.Scope.Header {
		if v, ok := r.Extra[col]; ok {
			if s.Extra == nil {
				s.Extra = map[string]jsontext.Value{}
			}
			s.Extra[col], _ = jsontext.AppendQuote(nil, v)
		}
	}
	if lines {
		s.Lines = &sdk.Lines{Row: r.Line, File: m.abs(ScopeFile)}
	}
	return s
}

// ConfigRecord is the config in effect as a record, plugin sections in
// Extra. It is the zero record when rpt.yaml doesn't parse.
func (m *Model) ConfigRecord(lines bool) sdk.Config {
	c := m.Config
	if c.Err != nil {
		return sdk.Config{Kind: "config"}
	}
	r := sdk.Config{
		Kind: "config", Format: c.Format, Sections: c.Headings,
		RequiredSections: c.RequiredSections, Pages: c.Pages, RequiredPages: c.RequiredPages,
		Rev: m.RevOf(ConfigFile),
	}
	if f, ok := m.files[ConfigFile]; ok {
		r.Rev = Rev(f.data)
	}
	for _, s := range c.Severities {
		r.Severities = append(r.Severities, sdk.Severity(s))
	}
	for k, v := range c.Rules {
		if r.Rules == nil {
			r.Rules = map[string]sdk.Level{}
		}
		r.Rules[k] = sdk.Level(v)
	}
	for _, e := range c.src.Entries() {
		if IsPluginKey(e.Key.Value) {
			if r.Extra == nil {
				r.Extra = map[string]jsontext.Value{}
			}
			r.Extra[e.Key.Value] = NodeJSON(e.Value)
		}
	}
	if lines {
		r.Lines = &sdk.Lines{File: m.abs(ConfigFile), Keys: m.keyPositions(c.src)}
	}
	return r
}

// ProblemRecord is a problem as a record.
func ProblemRecord(p Problem) sdk.Problem {
	return sdk.Problem{Kind: "problem", Path: p.Path, Line: p.Line, Rule: p.Rule, Level: sdk.Level(p.Level), Message: p.Message}
}

// sortedExtra turns a record's unknown members into frontmatter keys, by
// name, so a written file doesn't depend on map order.
func sortedExtra(m map[string]jsontext.Value) ([]KeyValue, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var out []KeyValue
	for _, k := range keys {
		n, err := JSONNode(m[k])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", k, err)
		}
		out = append(out, KeyValue{k, n})
	}
	return out, nil
}

// FindingDraft is the draft a finding record describes.
func FindingDraft(f sdk.Finding) (Draft, error) {
	dr := Draft{ID: f.ID, Title: f.Title, Severity: string(f.Severity), Evidence: f.Evidence}
	var err error
	if dr.Extra, err = sortedExtra(f.Extra); err != nil {
		return Draft{}, err
	}
	for _, t := range f.Targets {
		te, err := sortedExtra(t.Extra)
		if err != nil {
			return Draft{}, err
		}
		tt := Target{Scope: t.Scope, Host: t.Host, Port: t.Port, Protocol: t.Protocol}
		for _, kv := range te {
			tt.Extra = append(tt.Extra, doc.Entry{Key: &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: kv.Key}, Value: kv.Value})
		}
		dr.Targets = append(dr.Targets, tt)
	}
	for k, text := range f.Sections {
		dr.Sections = append(dr.Sections, Section{Key: k, Text: text})
	}
	return dr, nil
}

// PageDraft is the draft a page record describes.
func PageDraft(p sdk.Page) (Draft, error) {
	dr := Draft{ID: p.ID, Title: p.Title, Evidence: p.Evidence, Body: p.Body}
	var err error
	dr.Extra, err = sortedExtra(p.Extra)
	return dr, err
}

// ScopeDraft is the row a scope record describes. Its other columns must
// be text.
func ScopeDraft(s sdk.ScopeRow) (Row, error) {
	r := Row{ID: s.ID, Host: s.Host, Port: s.Port, Protocol: s.Protocol}
	for k, v := range s.Extra {
		var str string
		if err := json.Unmarshal(v, &str); err != nil {
			return Row{}, fmt.Errorf("column %s must be text", k)
		}
		if r.Extra == nil {
			r.Extra = map[string]string{}
		}
		r.Extra[k] = str
	}
	return r, nil
}

// ReplaceConfig writes c as rpt.yaml: its keys in the usual order, then
// its plugin sections by name. Findings keep their headings.
func (m *Model) ReplaceConfig(c sdk.Config) error {
	s, _ := doc.ParseYAML(nil)
	set := func(key string, v *yaml.Node) error { return s.Set(v, key) }
	if err := set("format", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: fmt.Sprint(c.Format)}); err != nil {
		return err
	}
	var sev []string
	for _, v := range c.Severities {
		sev = append(sev, string(v))
	}
	for _, l := range []struct {
		key  string
		list []string
	}{{"severities", sev}, {"required_sections", c.RequiredSections}, {"pages", c.Pages}, {"required_pages", c.RequiredPages}} {
		if l.list != nil {
			if err := set(l.key, listNode(l.list)); err != nil {
				return err
			}
		}
	}
	for _, mp := range []struct {
		key string
		m   map[string]string
	}{{"sections", c.Sections}, {"rules", levels(c.Rules)}} {
		if len(mp.m) == 0 {
			continue
		}
		keys := make([]string, 0, len(mp.m))
		for k := range mp.m {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			if err := s.Set(StringNode(mp.m[k]), mp.key, k); err != nil {
				return err
			}
		}
	}
	ex, err := sortedExtra(c.Extra)
	if err != nil {
		return refuse(ConfigFile, "%v", err)
	}
	for _, kv := range ex {
		if !IsPluginKey(kv.Key) {
			return refuse(ConfigFile, "%s isn't a config key; plugin sections are x-<plugin>", kv.Key)
		}
		if err := set(kv.Key, kv.Value); err != nil {
			return err
		}
	}
	out := s.Bytes()
	nc := parseConfig(out)
	if nc.Err != nil {
		return refuse(ConfigFile, "the config would be unreadable: %v", nc.Err)
	}
	if err := m.put(ConfigFile, out); err != nil {
		return err
	}
	m.Config = nc
	for _, d := range m.docs[FindingKind] {
		if d.Err == nil {
			d.Sections = sectionsOf(d.src, nc)
		}
	}
	return nil
}

func levels(m map[string]sdk.Level) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		out[k] = string(v)
	}
	return out
}
