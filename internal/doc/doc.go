// Package doc reads and edits the files a report is made of: markdown
// with YAML frontmatter (findings and pages) and plain YAML (rpt.yaml).
//
// Edits keep every byte they don't change, and every edit is verified:
// the file is parsed again and must mean exactly what the edit intended,
// or the edit is refused and the Doc is left as it was.
package doc

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strconv"

	"go.yaml.in/yaml/v3"
)

// A Doc is one file: a YAML head and, for markdown, a body.
type Doc struct {
	crlf bool
	bare bool       // the whole file is YAML: no --- lines, no body
	head []byte     // the YAML, LF endings
	body []byte     // after the closing --- line, LF endings
	root *yaml.Node // the head's top-level mapping
}

// An Error is a file that doesn't parse, at a file line when known.
type Error struct {
	Line int // 1-based file line, 0 when unknown
	Msg  string
}

func (e *Error) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("line %d: %s", e.Line, e.Msg)
	}
	return e.Msg
}

// ErrUnsafe is an edit rpt can't make without changing something else in
// the file. The file needs editing by hand.
var ErrUnsafe = errors.New("can't make this edit without changing something else in the file; edit it by hand")

// Parse reads a markdown file that starts with YAML frontmatter.
func Parse(src []byte) (*Doc, error) {
	d := &Doc{crlf: bytes.Contains(src, []byte("\r\n"))}
	src = lf(src)
	rest, ok := bytes.CutPrefix(src, []byte("---\n"))
	if !ok {
		return nil, &Error{Line: 1, Msg: "no frontmatter: the file must start with a --- line"}
	}
	for off := 0; off <= len(rest); {
		line, _, _ := bytes.Cut(rest[off:], []byte("\n"))
		if string(line) == "---" {
			d.head = rest[:off:off]
			d.body = rest[min(off+len(line)+1, len(rest)):]
			return d, d.parseHead()
		}
		off += len(line) + 1
	}
	return nil, &Error{Line: 1, Msg: "unterminated frontmatter: no closing --- line"}
}

// ParseYAML reads a plain YAML file, such as rpt.yaml: a Doc with no body.
func ParseYAML(src []byte) (*Doc, error) {
	d := &Doc{crlf: bytes.Contains(src, []byte("\r\n")), bare: true, head: lf(src)}
	return d, d.parseHead()
}

func (d *Doc) parseHead() error {
	root, err := parseMapping(d.head)
	if err != nil {
		var e *Error
		if errors.As(err, &e) && e.Line > 0 {
			e.Line += d.HeadLine() - 1
		}
		return err
	}
	d.root = root
	return nil
}

var yamlLine = regexp.MustCompile(`^yaml: line (\d+): `)

// parseMapping parses YAML whose top level must be a mapping. Empty YAML
// is an empty mapping.
func parseMapping(src []byte) (*yaml.Node, error) {
	var n yaml.Node
	if err := yaml.Unmarshal(src, &n); err != nil {
		msg := err.Error()
		line := 0
		if m := yamlLine.FindStringSubmatch(msg); m != nil {
			line, _ = strconv.Atoi(m[1])
			msg = msg[len(m[0]):]
		}
		return nil, &Error{Line: line, Msg: msg}
	}
	if len(n.Content) == 0 {
		return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}, nil
	}
	root := n.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, &Error{Line: root.Line, Msg: "the YAML must be a mapping of keys to values"}
	}
	return root, nil
}

func lf(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")) }

// Bytes is the file as it now stands, in its own line endings.
func (d *Doc) Bytes() []byte {
	var b []byte
	if d.bare {
		b = bytes.Clone(d.head)
	} else {
		b = make([]byte, 0, len(d.head)+len(d.body)+8)
		b = append(b, "---\n"...)
		b = append(b, d.head...)
		b = append(b, "---\n"...)
		b = append(b, d.body...)
	}
	if d.crlf {
		b = bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n"))
	}
	return b
}

// Head is the YAML top-level mapping. Callers must not change it: edit
// with Set and Unset.
func (d *Doc) Head() *yaml.Node { return d.root }

// HeadLine is the file line the YAML starts on.
func (d *Doc) HeadLine() int {
	if d.bare {
		return 1
	}
	return 2
}

// Body is the markdown after the frontmatter, LF endings.
func (d *Doc) Body() []byte { return d.body }

// BodyLine is the file line the body starts on.
func (d *Doc) BodyLine() int { return d.HeadLine() + bytes.Count(d.head, []byte("\n")) + 1 }

// SetBody replaces the body.
func (d *Doc) SetBody(body []byte) { d.body = lf(body) }

// Entries lists the top-level keys and values in file order.
func (d *Doc) Entries() []Entry { return entries(d.root) }

// An Entry is one key of a mapping and its value.
type Entry struct{ Key, Value *yaml.Node }

func entries(m *yaml.Node) []Entry {
	out := make([]Entry, 0, len(m.Content)/2)
	for i := 0; i+1 < len(m.Content); i += 2 {
		out = append(out, Entry{m.Content[i], m.Content[i+1]})
	}
	return out
}

// Get returns the value at path, a key per mapping level, or nil.
func (d *Doc) Get(path ...string) *yaml.Node {
	n := d.root
	for _, k := range path {
		n = resolve(n)
		if n == nil || n.Kind != yaml.MappingNode {
			return nil
		}
		i := find(n, k)
		if i < 0 {
			return nil
		}
		n = n.Content[i+1]
	}
	return n
}

// find is the index in m.Content of key k, or -1.
func find(m *yaml.Node, k string) int {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == k {
			return i
		}
	}
	return -1
}

func resolve(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}
