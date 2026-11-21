package report

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/text"

	"github.com/astr4liteEx/rpt/sdk"
)

// link is a link or image target in markdown naming a local file, with
// the byte offset of its text for locating it.
type link struct {
	dest  string // as written, without angle brackets
	path  string // the file part, decoded
	off   int
	text  string // the link text, or an image's alt text
	image bool
	// defn marks a reference definition, [label]: dest, rather than a link.
	defn bool
	// start and end are the byte range of the whole inline link,
	// ![text](dest "title") or [text](dest), or of a definition;
	// textStart and textEnd that of its text, and destStart and destEnd
	// that of its destination as written, angle brackets and all. start is
	// -1 for a reference-style link: its definition holds the destination.
	start, end, textStart, textEnd, destStart, destEnd int
}

// inlineLink matches an inline link or image: its bang, text and
// destination.
var inlineLink = regexp.MustCompile(`(!?)\[((?:[^\[\]\\]|\\.)*)\]\(\s*(<[^>\n]*>|[^\s()]+)(?:\s+(?:"[^"]*"|'[^']*'|\([^)]*\)))?\s*\)`)

// linkDefinition matches a reference definition: its label and destination.
var linkDefinition = regexp.MustCompile(`(?m)^ {0,3}\[((?:[^\[\]\\]|\\.)+)\]:[ \t]*(<[^>\n]*>|\S+)`)

// relLinks finds the link and image targets in md that name a file
// relative to the finding: URLs, anchors and absolute paths are left out.
func relLinks(md []byte) []link {
	return slices.DeleteFunc(fileLinks(md), func(l link) bool { return l.defn || path.IsAbs(l.path) })
}

// fileLinks finds the links, images and reference definitions in md that
// name a local file, relative or absolute: URLs and anchors are left out,
// and so is anything in code. Links are placed in the source, so their
// destinations can be rewritten in place.
func fileLinks(md []byte) []link {
	var out []link
	var code [][2]int // byte ranges of code blocks and spans
	doc := goldmark.DefaultParser().Parse(text.NewReader(md))
	_ = ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		var dest []byte
		image := false
		switch n := n.(type) {
		case *ast.FencedCodeBlock, *ast.CodeBlock, *ast.HTMLBlock:
			if ls := n.Lines(); ls.Len() > 0 {
				code = append(code, [2]int{ls.At(0).Start, ls.At(ls.Len() - 1).Stop})
			}
			return ast.WalkSkipChildren, nil
		case *ast.CodeSpan:
			if c := n.FirstChild(); c != nil {
				if t, ok := c.(*ast.Text); ok {
					code = append(code, [2]int{t.Segment.Start, t.Segment.Stop})
				}
			}
			return ast.WalkSkipChildren, nil
		case *ast.Link:
			dest = n.Destination
		case *ast.Image:
			dest, image = n.Destination, true
		default:
			return ast.WalkContinue, nil
		}
		if p, ok := localPath(string(dest)); ok {
			out = append(out, link{dest: string(dest), path: p, off: textOffset(n), image: image, start: -1})
		}
		return ast.WalkContinue, nil
	})
	inCode := func(off int) bool {
		return slices.ContainsFunc(code, func(c [2]int) bool { return off >= c[0] && off < c[1] })
	}
	// Place each link in the source, so it can be rewritten in place.
	used := map[int]bool{}
	for _, m := range inlineLink.FindAllSubmatchIndex(md, -1) {
		if inCode(m[0]) {
			continue
		}
		dest := strings.TrimSuffix(strings.TrimPrefix(string(md[m[6]:m[7]]), "<"), ">")
		for i := range out {
			l := &out[i]
			if l.start >= 0 || used[m[0]] || l.dest != dest || l.image != (m[3] > m[2]) {
				continue
			}
			if m[5] > m[4] && !(l.off >= m[4] && l.off < m[5]) {
				continue // another link with the same target
			}
			l.start, l.end, l.textStart, l.textEnd, l.destStart, l.destEnd = m[0], m[1], m[4], m[5], m[6], m[7]
			l.text = string(md[m[4]:m[5]])
			used[m[0]] = true
		}
	}
	for _, m := range linkDefinition.FindAllSubmatchIndex(md, -1) {
		if inCode(m[0]) {
			continue
		}
		dest := strings.TrimSuffix(strings.TrimPrefix(string(md[m[4]:m[5]]), "<"), ">")
		p, ok := localPath(dest)
		if !ok {
			continue
		}
		out = append(out, link{dest: dest, path: p, off: m[2], defn: true,
			start: m[0], end: m[1], textStart: m[2], textEnd: m[3], destStart: m[4], destEnd: m[5]})
	}
	slices.SortStableFunc(out, func(a, b link) int { return cmp.Compare(a.place(), b.place()) })
	return out
}

// place is where a link sits in its source, for ordering.
func (l link) place() int {
	if l.start >= 0 {
		return l.start
	}
	return l.off
}

// rewriteDests replaces the destination of each placed link and
// definition in md for which to returns a new one, written as linkDest
// writes it. Reference-style links are reached through their definitions;
// nothing else in md changes.
func rewriteDests(md []byte, to func(l link) (string, bool)) []byte {
	ls := fileLinks(md)
	out := slices.Clone(md)
	for i := len(ls) - 1; i >= 0; i-- {
		l := ls[i]
		if l.start < 0 {
			continue
		}
		if d, ok := to(l); ok {
			out = slices.Concat(out[:l.destStart], []byte(linkDest(d)), out[l.destEnd:])
		}
	}
	return out
}

// lineCol is the 1-based line and byte column of offset off in md, md
// starting on line first.
func lineCol(md []byte, first, off int) (int, int) {
	line := first + bytes.Count(md[:off], []byte("\n"))
	return line, off - (bytes.LastIndexByte(md[:off], '\n') + 1) + 1
}

// localPath returns the file a link target names, when it is a local
// path, relative or absolute, rather than a URL or an anchor.
func localPath(dest string) (string, bool) {
	if dest == "" || strings.HasPrefix(dest, "#") || strings.HasPrefix(dest, "//") {
		return "", false
	}
	u, err := url.Parse(dest)
	if err != nil || u.Scheme != "" || u.Host != "" || u.Path == "" {
		return "", false
	}
	return u.Path, true
}

// textOffset is the offset of the first text inside n, or of the block
// holding it.
func textOffset(n ast.Node) int {
	for c := n.FirstChild(); c != nil; c = c.NextSibling() {
		if t, ok := c.(*ast.Text); ok {
			return t.Segment.Start
		}
	}
	for p := n.Parent(); p != nil; p = p.Parent() {
		if p.Type() == ast.TypeBlock && p.Lines().Len() > 0 {
			return p.Lines().At(0).Start
		}
	}
	return 0
}

// checkEvidence checks one evidence path of a finding and returns its path
// relative to the report root, or a message saying what is wrong with it.
func (r *Report) checkEvidence(f sdk.Finding, p string) (rel, problem string) {
	info, err := r.EvidenceInfo(f, p)
	switch {
	case errors.Is(err, ErrOutsideReport):
		return "", fmt.Sprintf("evidence %q leaves the report", p)
	case errors.Is(err, fs.ErrNotExist):
		return "", fmt.Sprintf("evidence %q does not exist", p)
	case err != nil:
		return "", fmt.Sprintf("evidence %q can't be read inside the report: %v", p, errors.Unwrap(err))
	case !info.Mode().IsRegular():
		return "", fmt.Sprintf("evidence %q is not a regular file", p)
	}
	rel, _ = evidencePath(f, p)
	return rel, ""
}
