package report

import (
	"errors"
	"fmt"
	"slices"
	"strconv"

	"go.yaml.in/yaml/v3"

	"github.com/astr4liteEx/rpt/internal/doc"
)

// A Doc is a finding or a page.
type Doc struct {
	Kind *Kind
	Path string // relative to the report root, slash-separated
	Rev  string
	// Err is why the file doesn't parse, a *FileError. Nothing below is
	// set then.
	Err error

	ID, Title string
	Evidence  []string // as written, relative to the file's folder
	// Extra are the frontmatter keys rpt doesn't define, in file order.
	Extra []doc.Entry

	// Findings only.
	Severity string
	Targets  []Target
	Sections []Section

	src *doc.Doc
}

// A Target is one place a finding was found on.
type Target struct {
	Scope, Host, Protocol string
	Port                  int
	Extra                 []doc.Entry
	Line                  int // file line
}

// A Section is a part of a finding's body under a ## heading.
type Section struct {
	Key     string // the fixed key (description, remediation, poc) or the heading
	Heading string
	Text    string
	Line    int // file line of the heading
	// TextLine is the file line of the text's first line; 0 when empty.
	TextLine int
}

// declared are the frontmatter keys each kind defines.
var declared = map[*Kind][]string{
	FindingKind: {"id", "title", "targets", "severity", "evidence"},
	PageKind:    {"id", "title", "evidence"},
}

// parseDoc reads a finding or page file.
func parseDoc(k *Kind, rel string, src []byte, cfg *Config) *Doc {
	d := &Doc{Kind: k, Path: rel, Rev: Rev(src)}
	fail := func(line int, err error) *Doc {
		return &Doc{Kind: k, Path: rel, Rev: d.Rev, Err: &FileError{Path: rel, Line: line, Err: err}}
	}
	s, err := doc.Parse(src)
	if err != nil {
		var e *doc.Error
		errors.As(err, &e)
		return fail(e.Line, errors.New(e.Msg))
	}
	d.src = s
	line := func(n *yaml.Node) int { return n.Line + s.HeadLine() - 1 }
	for _, e := range s.Entries() {
		key, val := e.Key.Value, e.Value
		if slices.Contains(k.Reserved, key) {
			return fail(line(e.Key), fmt.Errorf("the key %q is reserved: rpt sets it on %s records", key, k.Name))
		}
		var err error
		switch {
		case !slices.Contains(declared[k], key):
			d.Extra = append(d.Extra, e)
		case key == "id":
			d.ID, err = str(val)
			d.ID = CanonicalID(d.ID)
		case key == "title":
			d.Title, err = str(val)
		case key == "severity":
			d.Severity, err = str(val)
		case key == "evidence":
			d.Evidence, err = strs(val)
		case key == "targets":
			d.Targets, err = targets(val, line)
		}
		if err != nil {
			return fail(line(e.Key), fmt.Errorf("%s: %w", key, err))
		}
	}
	if k.Sectioned {
		d.Sections = sectionsOf(s, cfg)
	}
	return d
}

// Body is the markdown after the frontmatter.
func (d *Doc) Body() string { return string(d.src.Body()) }

// BodyLine is the file line the body starts on.
func (d *Doc) BodyLine() int { return d.src.BodyLine() }

// KeyLine is the file line of a top-level frontmatter key, or 0.
func (d *Doc) KeyLine(key string) int {
	for _, e := range d.src.Entries() {
		if e.Key.Value == key {
			return e.Key.Line + d.src.HeadLine() - 1
		}
	}
	return 0
}

// Keys are the frontmatter's top-level keys in file order.
func (d *Doc) Keys() []string {
	var out []string
	for _, e := range d.src.Entries() {
		out = append(out, e.Key.Value)
	}
	return out
}

// Section returns the section with the given key.
func (d *Doc) Section(key string) (Section, bool) {
	i := slices.IndexFunc(d.Sections, func(s Section) bool { return s.Key == key })
	if i < 0 {
		return Section{}, false
	}
	return d.Sections[i], true
}

// Lead is the text before a finding's first heading, trimmed.
func (d *Doc) Lead() string {
	_, lead := d.src.Sections()
	return string(lead)
}

func sectionsOf(s *doc.Doc, cfg *Config) []Section {
	secs, _ := s.Sections()
	out := make([]Section, len(secs))
	for i, sec := range secs {
		out[i] = Section{
			Key: cfg.SectionKey(sec.Heading), Heading: sec.Heading,
			Text: string(s.SectionText(sec)),
			Line: sec.Line + s.BodyLine() - 1,
		}
		if sec.Text > 0 {
			out[i].TextLine = sec.Text + s.BodyLine() - 1
		}
	}
	return out
}

// str reads a single value. Null is empty.
func str(n *yaml.Node) (string, error) {
	switch {
	case n.Kind == yaml.AliasNode:
		return str(n.Alias)
	case n.Kind != yaml.ScalarNode:
		return "", errors.New("must be a single value")
	case n.ShortTag() == "!!null":
		return "", nil
	}
	return n.Value, nil
}

// strs reads a list of single values.
func strs(n *yaml.Node) ([]string, error) {
	if n.ShortTag() == "!!null" {
		return nil, nil
	}
	if n.Kind != yaml.SequenceNode {
		return nil, errors.New("must be a list")
	}
	out := make([]string, 0, len(n.Content))
	for _, c := range n.Content {
		v, err := str(c)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func targets(n *yaml.Node, line func(*yaml.Node) int) ([]Target, error) {
	if n.ShortTag() == "!!null" {
		return nil, nil
	}
	if n.Kind != yaml.SequenceNode {
		return nil, errors.New("must be a list")
	}
	var out []Target
	for i, c := range n.Content {
		if c.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("target %d must be a mapping such as {scope: S-1}", i+1)
		}
		t := Target{Line: line(c)}
		for j := 0; j+1 < len(c.Content); j += 2 {
			key, val := c.Content[j].Value, c.Content[j+1]
			var err error
			switch key {
			case "scope":
				t.Scope, err = str(val)
			case "host":
				t.Host, err = str(val)
			case "protocol":
				t.Protocol, err = str(val)
			case "port":
				var p string
				if p, err = str(val); err == nil && p != "" {
					if t.Port, err = strconv.Atoi(p); err != nil || t.Port < 1 || t.Port > 65535 {
						err = fmt.Errorf("port %q is not a number from 1 to 65535", p)
					}
				}
			default:
				t.Extra = append(t.Extra, doc.Entry{Key: c.Content[j], Value: val})
			}
			if err != nil {
				return nil, fmt.Errorf("target %d: %s: %w", i+1, key, err)
			}
		}
		out = append(out, t)
	}
	return out, nil
}
