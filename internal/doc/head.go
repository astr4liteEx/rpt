package doc

import (
	"bytes"
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Set sets the value at path, a key per mapping level, creating the key
// and any missing mappings on the way. Only the lines of the entry it
// changes are rewritten; a flow-style mapping on the way ({a: 1}) is
// rewritten in block style.
func (d *Doc) Set(val *yaml.Node, path ...string) error {
	if len(path) == 0 {
		return fmt.Errorf("set: no key")
	}
	want := clone(d.root)
	if err := setNode(want, path, clone(val)); err != nil {
		return err
	}
	return d.apply(want, func(e *editor) error { return e.set(d.root, path, val, nil) })
}

// Unset removes the key at path and reports whether it was there. A
// mapping it leaves empty stays, as {}.
func (d *Doc) Unset(path ...string) (bool, error) {
	if d.Get(path...) == nil {
		return false, nil
	}
	want := clone(d.root)
	unsetNode(want, path)
	return true, d.apply(want, func(e *editor) error { return e.unset(d.root, path, nil) })
}

// apply runs an edit on the head's lines and keeps the result only if it
// parses to want.
func (d *Doc) apply(want *yaml.Node, edit func(*editor) error) error {
	e := &editor{lines: splitLines(d.head), want: want}
	if err := edit(e); err != nil {
		return err
	}
	head := []byte(strings.Join(e.lines, ""))
	if e.whole {
		w := clone(want)
		blockStyle(w)
		head = render(w, 0)
	}
	got, err := parseMapping(head)
	if err != nil || canon(got) != canon(want) {
		return ErrUnsafe
	}
	d.head, d.root = head, got
	return nil
}

// An editor rewrites lines of the head. Each line keeps its "\n".
type editor struct {
	lines []string
	want  *yaml.Node // the whole head as the edit intends it
	whole bool       // give up splicing: render want in full
}

// A frame is a mapping on the way down and the index of the entry taken.
type frame struct {
	m *yaml.Node
	i int
}

// set sets path under the block mapping m, reached through up.
func (e *editor) set(m *yaml.Node, path []string, val *yaml.Node, up []frame) error {
	if !e.spliceable(m) {
		return e.rerender(up)
	}
	i := find(m, path[0])
	if i < 0 {
		v := val
		for k := len(path) - 1; k > 0; k-- {
			v = mapping(path[k], v)
		}
		return e.insert(m, path[0], v, up)
	}
	if len(path) == 1 {
		return e.replace(m, i, keepComment(m.Content[i+1], val), up)
	}
	child := resolve(m.Content[i+1])
	if child.Kind == yaml.MappingNode && child.Style&yaml.FlowStyle == 0 && len(child.Content) > 0 && m.Content[i+1].Kind != yaml.AliasNode {
		return e.set(child, path[1:], val, append(up, frame{m, i}))
	}
	if child.Kind != yaml.MappingNode && child.ShortTag() != "!!null" {
		return fmt.Errorf("%s is not a mapping", m.Content[i].Value)
	}
	return e.rerender(append(up, frame{m, i}))
}

// unset removes path under the block mapping m, reached through up.
func (e *editor) unset(m *yaml.Node, path []string, up []frame) error {
	if !e.spliceable(m) {
		return e.rerender(up)
	}
	i := find(m, path[0])
	if len(path) > 1 {
		child := resolve(m.Content[i+1])
		if child.Style&yaml.FlowStyle == 0 && m.Content[i+1].Kind != yaml.AliasNode {
			return e.unset(child, path[1:], append(up, frame{m, i}))
		}
		return e.rerender(append(up, frame{m, i}))
	}
	if len(m.Content) == 2 && len(up) > 0 {
		return e.rerender(up) // the mapping goes empty: {}
	}
	start, end := e.span(m, i, up)
	for start > 0 && isComment(e.lines[start-1]) && indent(e.lines[start-1]) == m.Content[i].Column-1 {
		start-- // the comment lines just above describe the key
	}
	e.lines = append(e.lines[:start], e.lines[end:]...)
	return nil
}

// spliceable reports whether m's entries each own their lines.
func (e *editor) spliceable(m *yaml.Node) bool {
	if m.Style&yaml.FlowStyle != 0 {
		return false
	}
	last := 0
	for i := 0; i < len(m.Content); i += 2 {
		if m.Content[i].Line <= last {
			return false
		}
		last = m.Content[i].Line
	}
	return true
}

// replace rewrites entry i of m with val.
func (e *editor) replace(m *yaml.Node, i int, val *yaml.Node, up []frame) error {
	start, end := e.span(m, i, up)
	out := render(mapping(m.Content[i].Value, val), m.Content[i].Column-1)
	e.lines = splice(e.lines, start, end, out)
	return nil
}

// insert adds key: val as the last entry of m.
func (e *editor) insert(m *yaml.Node, key string, val *yaml.Node, up []frame) error {
	if len(m.Content) == 0 {
		if len(up) == 0 { // an empty head
			e.lines = splice(e.lines, len(e.lines), len(e.lines), render(mapping(key, val), 0))
			return nil
		}
		return e.rerender(up)
	}
	_, end := e.span(m, len(m.Content)-2, up)
	out := render(mapping(key, val), m.Content[0].Column-1)
	e.lines = splice(e.lines, end, end, out)
	return nil
}

// rerender rewrites the innermost entry on the way down, up's last, from
// the head as the edit intends it. With no entry to rewrite, the whole
// head is rendered.
func (e *editor) rerender(up []frame) error {
	if len(up) == 0 {
		e.whole = true
		return nil
	}
	f := up[len(up)-1]
	key := f.m.Content[f.i]
	// Find the same entry in want by its key path.
	n := e.want
	for _, g := range up {
		n = resolve(n)
		n = n.Content[find(n, g.m.Content[g.i].Value)+1]
	}
	v := clone(n)
	blockStyle(v)
	start, end := e.span(f.m, f.i, up[:len(up)-1])
	e.lines = splice(e.lines, start, end, render(mapping(key.Value, v), key.Column-1))
	return nil
}

// span is the lines [start, end) entry i of m holds: from its key's line
// to the next key at its level or above, less trailing blank lines and
// comments that sit no deeper than the key.
func (e *editor) span(m *yaml.Node, i int, up []frame) (int, int) {
	key := m.Content[i]
	start := key.Line - 1
	end := len(e.lines)
	if i+2 < len(m.Content) {
		end = m.Content[i+2].Line - 1
	} else {
		for k := len(up) - 1; k >= 0; k-- {
			if f := up[k]; f.i+2 < len(f.m.Content) {
				end = f.m.Content[f.i+2].Line - 1
				break
			}
		}
	}
	for end > start+1 && (strings.TrimSpace(e.lines[end-1]) == "" || isComment(e.lines[end-1]) && indent(e.lines[end-1]) <= key.Column-1) {
		end--
	}
	return start, end
}

func splitLines(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	if b[len(b)-1] != '\n' {
		b = append(bytes.Clone(b), '\n')
	}
	parts := strings.SplitAfter(string(b), "\n")
	return parts[:len(parts)-1] // the last is empty: b ends in "\n"
}

func splice(lines []string, start, end int, with []byte) []string {
	add := splitLines(with)
	out := make([]string, 0, len(lines)-(end-start)+len(add))
	out = append(out, lines[:start]...)
	out = append(out, add...)
	return append(out, lines[end:]...)
}

func isComment(line string) bool { return strings.HasPrefix(strings.TrimSpace(line), "#") }

func indent(line string) int { return len(line) - len(strings.TrimLeft(line, " ")) }

// render encodes n as YAML with each line indented by ind spaces.
func render(n *yaml.Node, ind int) []byte {
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if n.Kind == yaml.MappingNode && len(n.Content) == 0 {
		return nil
	}
	if err := enc.Encode(n); err != nil {
		return nil // apply's check refuses the edit
	}
	enc.Close()
	if ind == 0 {
		return b.Bytes()
	}
	pad := strings.Repeat(" ", ind)
	var out []byte
	for _, line := range splitLines(b.Bytes()) {
		if line != "\n" {
			out = append(out, pad...)
		}
		out = append(out, line...)
	}
	return out
}

// keepComment gives val the old value's line comment, so setting a value
// doesn't drop "# why" after it.
func keepComment(old, val *yaml.Node) *yaml.Node {
	if old.LineComment == "" || val.LineComment != "" || val.Kind != yaml.ScalarNode {
		return val
	}
	v := *val
	v.LineComment = old.LineComment
	return &v
}

func mapping(key string, val *yaml.Node) *yaml.Node {
	return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, val,
	}}
}

// blockStyle turns flow mappings in n into block ones, leaving sequences
// and nested values as they are written.
func blockStyle(n *yaml.Node) {
	if n.Kind == yaml.MappingNode && len(n.Content) > 0 {
		n.Style &^= yaml.FlowStyle
	}
}

// setNode sets path in the mapping m, making missing mappings.
func setNode(m *yaml.Node, path []string, val *yaml.Node) error {
	for k, key := range path {
		m = resolve(m)
		if m.Kind != yaml.MappingNode {
			if m.ShortTag() != "!!null" {
				return fmt.Errorf("%s is not a mapping", strings.Join(path[:k], "."))
			}
			*m = yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		}
		i := find(m, key)
		if k == len(path)-1 {
			if i < 0 {
				m.Content = append(m.Content, mapping(key, val).Content...)
			} else {
				m.Content[i+1] = val
			}
			return nil
		}
		if i < 0 {
			m.Content = append(m.Content, mapping(key, &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}).Content...)
			i = len(m.Content) - 2
		}
		m = m.Content[i+1]
	}
	return nil
}

// unsetNode removes path from the mapping m, which has it.
func unsetNode(m *yaml.Node, path []string) {
	for _, key := range path[:len(path)-1] {
		m = resolve(m)
		m = m.Content[find(m, key)+1]
	}
	m = resolve(m)
	i := find(m, path[len(path)-1])
	m.Content = append(m.Content[:i], m.Content[i+2:]...)
	if len(m.Content) == 0 {
		m.Style |= yaml.FlowStyle
	}
}

// clone deep-copies a node tree, aliases resolved.
func clone(n *yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	n = resolve(n)
	c := *n
	c.Anchor = ""
	c.Content = make([]*yaml.Node, len(n.Content))
	for i, ch := range n.Content {
		c.Content[i] = clone(ch)
	}
	return &c
}

// canon is what n means, style and comments aside: two heads that canon
// the same hold the same keys, values and order.
func canon(n *yaml.Node) string {
	var b strings.Builder
	var walk func(*yaml.Node)
	walk = func(n *yaml.Node) {
		n = resolve(n)
		switch n.Kind {
		case yaml.MappingNode:
			b.WriteString("{")
			for i := 0; i+1 < len(n.Content); i += 2 {
				walk(n.Content[i])
				b.WriteString(":")
				walk(n.Content[i+1])
				b.WriteString(",")
			}
			b.WriteString("}")
		case yaml.SequenceNode:
			b.WriteString("[")
			for _, c := range n.Content {
				walk(c)
				b.WriteString(",")
			}
			b.WriteString("]")
		default:
			tag := n.ShortTag()
			if tag == "!!null" {
				b.WriteString("null")
				return
			}
			fmt.Fprintf(&b, "%s%q", tag, n.Value)
		}
	}
	walk(n)
	return b.String()
}
