package doc

import (
	"bytes"
	"fmt"
	"regexp"
	"slices"

	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/util"
)

// A Link is a link or image in the body, or a src or href attribute in
// its HTML, with the exact place of each part. Offsets are into the body.
type Link struct {
	Image bool
	HTML  bool   // an attribute in raw HTML; it has no text
	Dest  string // the destination as markdown reads it: escapes and entities resolved
	// Text is the link's text as written; TextStart:TextEnd is where. Both
	// are -1 for HTML.
	Text               string
	TextStart, TextEnd int
	// DestStart:DestEnd is where the destination is written: inside the
	// brackets of a <destination>, and in the definition for a reference
	// link. Label names that definition; other links using it share the
	// span.
	DestStart, DestEnd int
	Label              string
	// Start:End is the whole link, ![text](dest "title") or [text][label].
	Start, End int
	Line       int // body line of Start, 1-based
}

// An UnplacedError is a link markdown sees but rpt can't find exactly in
// the text, so it can't rewrite it.
type UnplacedError struct {
	Line int
	Dest string
}

func (e *UnplacedError) Error() string {
	return fmt.Sprintf("line %d: can't find the link to %s exactly; edit it by hand", e.Line, e.Dest)
}

// Links lists every link, image and HTML src or href in the body, in
// order. A link markdown sees but rpt can't place is an *UnplacedError,
// returned with the links it could place.
func (d *Doc) Links() ([]Link, []error) { return links(d.body) }

func links(body []byte) ([]Link, []error) {
	root := parseBody(body)
	defs := definitions(body, root)
	var out []Link
	var errs []error
	ast.Walk(root, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch n := n.(type) {
		case *ast.Link:
			l, err := place(body, n.Pos(), false, string(n.Destination), n.Reference, defs)
			add(&out, &errs, l, err)
		case *ast.Image:
			l, err := place(body, n.Pos(), true, string(n.Destination), n.Reference, defs)
			add(&out, &errs, l, err)
		case *ast.RawHTML:
			for i := range n.Segments.Len() {
				s := n.Segments.At(i)
				out = append(out, htmlLinks(body, s.Start, s.Stop)...)
			}
		case *ast.HTMLBlock:
			l := n.Lines()
			for i := range l.Len() {
				s := l.At(i)
				out = append(out, htmlLinks(body, s.Start, s.Stop)...)
			}
			if n.HasClosure() {
				out = append(out, htmlLinks(body, n.ClosureLine.Start, n.ClosureLine.Stop)...)
			}
		}
		return ast.WalkContinue, nil
	})
	for i := range out {
		out[i].Line = 1 + bytes.Count(body[:out[i].Start], []byte("\n"))
	}
	slices.SortStableFunc(out, func(a, b Link) int { return a.Start - b.Start })
	return out, errs
}

func add(out *[]Link, errs *[]error, l Link, err error) {
	if err != nil {
		*errs = append(*errs, err)
		return
	}
	*out = append(*out, l)
}

// place finds the link that starts at pos ([ or ![) in the source.
func place(body []byte, pos int, image bool, dest string, ref *ast.ReferenceLink, defs map[string]def) (Link, error) {
	unplaced := &UnplacedError{Line: 1 + bytes.Count(body[:min(pos, len(body))], []byte("\n")), Dest: dest}
	l := Link{Image: image, Dest: dest, Start: pos}
	open := pos
	if image {
		open++
	}
	if open >= len(body) || body[open] != '[' {
		return Link{}, unplaced
	}
	closeAt := closing(body, open)
	if closeAt < 0 {
		return Link{}, unplaced
	}
	l.TextStart, l.TextEnd, l.Text = open+1, closeAt, string(body[open+1:closeAt])
	i := closeAt + 1
	switch {
	case ref == nil && i < len(body) && body[i] == '(':
		ds, de, end, ok := inlineDest(body, i+1)
		if !ok {
			return Link{}, unplaced
		}
		l.DestStart, l.DestEnd, l.End = ds, de, end
	case ref != nil:
		label := l.Text
		l.End = i
		if ref.Type == ast.ReferenceLinkFull || ref.Type == ast.ReferenceLinkCollapsed {
			if i >= len(body) || body[i] != '[' {
				return Link{}, unplaced
			}
			c := closing(body, i)
			if c < 0 {
				return Link{}, unplaced
			}
			if ref.Type == ast.ReferenceLinkFull {
				label = string(body[i+1 : c])
			}
			l.End = c + 1
		}
		d, ok := defs[string(util.ToLinkReference([]byte(label)))]
		if !ok {
			return Link{}, unplaced
		}
		l.Label, l.DestStart, l.DestEnd = d.label, d.start, d.end
	default:
		return Link{}, unplaced
	}
	// goldmark keeps the destination as written; compare that, then read
	// it as markdown does.
	if written := body[l.DestStart:l.DestEnd]; string(written) != dest && decode(written) != decode([]byte(dest)) {
		return Link{}, unplaced
	}
	l.Dest = decode([]byte(dest))
	return l, nil
}

// closing is the ] that closes the [ at open, skipping escapes, code
// spans and nested brackets, or -1.
func closing(body []byte, open int) int {
	depth := 0
	for i := open; i < len(body); i++ {
		switch body[i] {
		case '\\':
			i++
		case '`':
			n := run(body, i, '`')
			if j := bytes.Index(body[i+n:], bytes.Repeat([]byte("`"), n)); j >= 0 {
				i += n + j + n - 1
			} else {
				i += n - 1
			}
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func run(b []byte, i int, c byte) int {
	n := 0
	for i+n < len(b) && b[i+n] == c {
		n++
	}
	return n
}

// inlineDest reads (dest "title") from just after the (. It returns the
// destination's span, inside <> when bracketed, and the offset past ).
func inlineDest(body []byte, i int) (start, end, after int, ok bool) {
	i = skipSpace(body, i)
	if i < len(body) && body[i] == '<' {
		start = i + 1
		for j := start; j < len(body) && body[j] != '\n'; j++ {
			switch body[j] {
			case '\\':
				j++
			case '>':
				end = j
				i = j + 1
				goto title
			case '<':
				return 0, 0, 0, false
			}
		}
		return 0, 0, 0, false
	}
	start = i
	for depth := 0; i < len(body); i++ {
		c := body[i]
		if c == '\\' && i+1 < len(body) {
			i++
			continue
		}
		if c <= ' ' {
			break
		}
		if c == '(' {
			depth++
		}
		if c == ')' {
			if depth == 0 {
				break
			}
			depth--
		}
	}
	end = i
title:
	i = skipSpace(body, i)
	if i < len(body) && (body[i] == '"' || body[i] == '\'' || body[i] == '(') {
		q := body[i]
		if q == '(' {
			q = ')'
		}
		for i++; i < len(body) && body[i] != q; i++ {
			if body[i] == '\\' {
				i++
			}
		}
		i = skipSpace(body, i+1)
	}
	if i >= len(body) || body[i] != ')' {
		return 0, 0, 0, false
	}
	return start, end, i + 1, true
}

func skipSpace(b []byte, i int) int {
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n') {
		i++
	}
	return i
}

// decode reads a destination as markdown does: escapes and entities.
func decode(raw []byte) string {
	return string(util.UnescapePunctuations(util.ResolveNumericReferences(util.ResolveEntityNames(raw))))
}

// A def is a link reference definition: [label]: destination.
type def struct {
	label      string
	start, end int
}

var defLine = regexp.MustCompile(`(?m)^((?:[ \t]*>)*[ \t]{0,3})\[((?:[^\]\\]|\\.)+)\]:[ \t]*\n?[ \t]*(<(?:[^>\\\n]|\\.)*>|\S+)`)

// definitions finds the reference definitions goldmark read, by label.
// A definition can only sit where a paragraph could start, so lines in
// code blocks are skipped.
func definitions(body []byte, root ast.Node) map[string]def {
	var code [][2]int
	ast.Walk(root, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		switch n.(type) {
		case *ast.FencedCodeBlock, *ast.CodeBlock, *ast.HTMLBlock:
			if entering && n.Lines().Len() > 0 {
				l := n.Lines()
				code = append(code, [2]int{l.At(0).Start, l.At(l.Len() - 1).Stop})
			}
		}
		return ast.WalkContinue, nil
	})
	out := map[string]def{}
	for _, m := range defLine.FindAllSubmatchIndex(body, -1) {
		if slices.ContainsFunc(code, func(c [2]int) bool { return m[0] >= c[0] && m[0] < c[1] }) {
			continue
		}
		key := string(util.ToLinkReference(body[m[4]:m[5]]))
		if _, dup := out[key]; dup {
			continue // the first definition wins
		}
		s, e := m[6], m[7]
		if body[s] == '<' {
			s, e = s+1, e-1
		}
		out[key] = def{label: string(body[m[4]:m[5]]), start: s, end: e}
	}
	return out
}

var htmlAttr = regexp.MustCompile(`(?i)\b(src|href)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>` + "`" + `]+))`)

// htmlLinks finds src and href attributes in body[start:stop].
func htmlLinks(body []byte, start, stop int) []Link {
	var out []Link
	for _, m := range htmlAttr.FindAllSubmatchIndex(body[start:stop], -1) {
		src := bytes.EqualFold(body[start+m[2]:start+m[3]], []byte("src"))
		for g := 4; g < len(m); g += 2 {
			if m[g] >= 0 {
				s, e := start+m[g], start+m[g+1]
				out = append(out, Link{HTML: true, Image: src, Dest: string(util.ResolveNumericReferences(util.ResolveEntityNames(body[s:e]))),
					Text: "", TextStart: -1, TextEnd: -1, DestStart: s, DestEnd: e, Start: start + m[0], End: start + m[1]})
			}
		}
	}
	return out
}

// RewriteSpans replaces each span of the body with its text, in one pass.
// Spans must not overlap.
func (d *Doc) RewriteSpans(spans []Span) error {
	slices.SortFunc(spans, func(a, b Span) int { return a.Start - b.Start })
	var b []byte
	at := 0
	for _, s := range spans {
		if s.Start < at {
			return fmt.Errorf("overlapping edits at %d", s.Start)
		}
		b = append(b, d.body[at:s.Start]...)
		b = append(b, s.Text...)
		at = s.End
	}
	b = append(b, d.body[at:]...)
	secs, _ := sections(d.body)
	return d.setBodyChecked(b, headings(secs), -1, nil)
}

// A Span is a part of the body to replace.
type Span struct {
	Start, End int
	Text       string
}
