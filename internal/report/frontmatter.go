package report

import (
	"bytes"
	"encoding/json/v2"
	"fmt"
	"reflect"
	"strings"

	"go.yaml.in/yaml/v3"
)

// findingFile is a finding file split for editing. Edits splice the lines
// they change and leave every other byte alone, so comments, key order,
// spacing and flow lists survive; re-encoding the whole frontmatter with
// yaml/v3 would rewrite lines nobody touched.
type findingFile struct {
	crlf bool   // the file used CRLF line endings, restored on write
	head []byte // frontmatter YAML, LF endings, ending in a newline
	body []byte // markdown after the closing --- line, LF endings
}

func splitFindingFile(src []byte) (findingFile, error) {
	crlf := bytes.Contains(src, []byte("\r\n"))
	head, body, err := splitFrontmatter(normaliseNewlines(src))
	if err != nil {
		return findingFile{}, err
	}
	return findingFile{crlf: crlf, head: head, body: body}, nil
}

func (f findingFile) bytes() []byte {
	var b bytes.Buffer
	b.WriteString("---\n")
	b.Write(f.head)
	b.WriteString("---\n")
	b.Write(f.body)
	if f.crlf {
		return bytes.ReplaceAll(b.Bytes(), []byte("\n"), []byte("\r\n"))
	}
	return b.Bytes()
}

// setEntry sets top-level key to val in the frontmatter. An existing entry
// is replaced in place, keeping the old value's quoting or flow style and
// its line comment with the spacing before it; a new entry is appended,
// lists and maps in flow style. Setting a value equal to the current one
// changes nothing.
func (f *findingFile) setEntry(key string, val *yaml.Node) error {
	var doc yaml.Node
	if err := yaml.Unmarshal(f.head, &doc); err != nil {
		return err
	}
	lines := strings.SplitAfter(string(f.head), "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	var m *yaml.Node
	if len(doc.Content) > 0 {
		if m = doc.Content[0]; m.Kind != yaml.MappingNode {
			return fmt.Errorf("frontmatter is not a mapping")
		}
	}
	i := -1
	if m != nil {
		for j := 0; j+1 < len(m.Content); j += 2 {
			if m.Content[j].Value == key {
				i = j
				break
			}
		}
	}
	val = clean(val)

	if i < 0 {
		if val.Kind == yaml.SequenceNode || val.Kind == yaml.MappingNode {
			val.Style |= yaml.FlowStyle
		}
		entry, err := renderEntry(key, val)
		if err != nil {
			return err
		}
		f.head = []byte(strings.Join(lines, "") + entry)
		return nil
	}

	keyNode, old := m.Content[i], m.Content[i+1]
	if equalValues(old, val) {
		return nil
	}
	matchStyle(old, val)

	start, end := keyNode.Line-1, len(lines)
	if i+2 < len(m.Content) {
		end = m.Content[i+2].Line - 1
	}
	// Leave blank and top-level comment lines before the next key: they
	// belong to it.
	for end > start+1 && isGap(lines[end-1]) {
		end--
	}

	entry, err := renderEntry(key, val)
	if err != nil {
		return err
	}
	comment := old.LineComment
	if comment == "" {
		comment = keyNode.LineComment
	}
	if comment != "" {
		orig := strings.TrimSuffix(lines[start], "\n")
		if at := strings.LastIndex(orig, comment); end == start+1 && at > 0 && strings.Count(entry, "\n") == 1 {
			gap := orig[len(strings.TrimRight(orig[:at], " \t")):at]
			entry = strings.TrimSuffix(entry, "\n") + gap + comment + "\n"
		} else {
			entry = strings.TrimSuffix(entry, "\n") + " " + comment + "\n"
		}
	}
	f.head = []byte(strings.Join(lines[:start], "") + entry + strings.Join(lines[end:], ""))
	return nil
}

// removeEntry deletes a top-level key and its value's lines, including
// the continuation lines of a block value. Comment and blank lines before
// the next key stay: they belong to it. A missing key is no change.
func (f *findingFile) removeEntry(key string) error {
	var doc yaml.Node
	if err := yaml.Unmarshal(f.head, &doc); err != nil {
		return err
	}
	if len(doc.Content) == 0 {
		return nil
	}
	m := doc.Content[0]
	if m.Kind != yaml.MappingNode {
		return fmt.Errorf("frontmatter is not a mapping")
	}
	lines := strings.SplitAfter(string(f.head), "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value != key {
			continue
		}
		start, end := m.Content[i].Line-1, len(lines)
		if i+2 < len(m.Content) {
			end = m.Content[i+2].Line - 1
		}
		for end > start+1 && isGap(lines[end-1]) {
			end--
		}
		f.head = []byte(strings.Join(lines[:start], "") + strings.Join(lines[end:], ""))
		return nil
	}
	return nil
}

// isGap reports whether a frontmatter line is blank or a top-level comment.
func isGap(line string) bool {
	return strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#")
}

// clean returns a copy of n with no comments or positions, ready to encode.
func clean(n *yaml.Node) *yaml.Node {
	c := *n
	c.HeadComment, c.LineComment, c.FootComment = "", "", ""
	c.Line, c.Column = 0, 0
	c.Content = make([]*yaml.Node, len(n.Content))
	for i, ch := range n.Content {
		c.Content[i] = clean(ch)
	}
	return &c
}

// matchStyle gives val the layout of the value it replaces: a quoted
// scalar stays quoted, a flow list stays flow, a block list stays block.
func matchStyle(old, val *yaml.Node) {
	switch {
	case old.Kind == yaml.ScalarNode && val.Kind == yaml.ScalarNode:
		if old.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle) != 0 && val.Style == 0 {
			val.Style, val.Tag = old.Style, "!!str"
		}
	case old.Kind == val.Kind && (old.Kind == yaml.SequenceNode || old.Kind == yaml.MappingNode):
		val.Style = val.Style&^yaml.FlowStyle | old.Style&yaml.FlowStyle
	}
}

// equalValues reports whether two YAML values decode to the same data.
func equalValues(a, b *yaml.Node) bool {
	var va, vb any
	if a.Decode(&va) != nil || b.Decode(&vb) != nil {
		return false
	}
	return reflect.DeepEqual(va, vb)
}

// renderEntry encodes one "key: value" entry as it appears at the top
// level of the frontmatter, ending in a newline.
func renderEntry(key string, val *yaml.Node) (string, error) {
	m := &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{
		{Kind: yaml.ScalarNode, Value: key},
		val,
	}}
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(m); err != nil {
		return "", fmt.Errorf("encode %s: %w", key, err)
	}
	if err := enc.Close(); err != nil {
		return "", fmt.Errorf("encode %s: %w", key, err)
	}
	return b.String(), nil
}

// parseValue reads a command-line value as YAML; an empty string is an
// empty string, not null.
func parseValue(s string) (*yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(s), &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) == 0 {
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: ""}, nil
	}
	return doc.Content[0], nil
}

// toNode converts a Go value to YAML by way of JSON, so struct fields use
// their JSON names and unknown members (jsontext.Value) come along.
func toNode(v any) (*yaml.Node, error) {
	b, err := json.Marshal(v, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	var data any
	if err := json.Unmarshal(b, &data); err != nil {
		return nil, err
	}
	var n yaml.Node
	if err := n.Encode(data); err != nil {
		return nil, err
	}
	return &n, nil
}
