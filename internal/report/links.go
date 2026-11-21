package report

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"regexp"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/text"

	"github.com/astr4liteEx/rpt/sdk"
)

// link is a relative link or image target in markdown, with the byte
// offset of its text for locating it.
type link struct {
	dest  string // as written
	path  string // the file part, decoded
	off   int
	text  string // the link text, or an image's alt text
	image bool
	// start and end are the byte range of the whole inline link,
	// ![text](dest "title") or [text](dest); textStart and textEnd that of
	// its text. start is -1 for a reference-style link, which rpt doesn't
	// rewrite in place.
	start, end, textStart, textEnd int
}

// inlineLink matches an inline link or image: its bang, text and
// destination.
var inlineLink = regexp.MustCompile(`(!?)\[((?:[^\[\]\\]|\\.)*)\]\(\s*(<[^>]*>|[^\s()]+)(?:\s+(?:"[^"]*"|'[^']*'|\([^)]*\)))?\s*\)`)

// relLinks finds the link and image targets in md that name a file
// relative to the finding: URLs, anchors and absolute paths are left out.
func relLinks(md []byte) []link {
	var out []link
	doc := goldmark.DefaultParser().Parse(text.NewReader(md))
	_ = ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		var dest []byte
		image := false
		switch n := n.(type) {
		case *ast.Link:
			dest = n.Destination
		case *ast.Image:
			dest, image = n.Destination, true
		default:
			return ast.WalkContinue, nil
		}
		if p, ok := relativePath(string(dest)); ok {
			out = append(out, link{dest: string(dest), path: p, off: textOffset(n), image: image, start: -1})
		}
		return ast.WalkContinue, nil
	})
	// Place each link in the source, so it can be rewritten in place.
	used := map[int]bool{}
	for _, m := range inlineLink.FindAllSubmatchIndex(md, -1) {
		dest := strings.TrimSuffix(strings.TrimPrefix(string(md[m[6]:m[7]]), "<"), ">")
		for i := range out {
			l := &out[i]
			if l.start >= 0 || used[m[0]] || l.dest != dest || l.image != (m[3] > m[2]) {
				continue
			}
			if m[5] > m[4] && l.off != m[4] && !(l.off >= m[4] && l.off < m[5]) {
				continue // another link with the same target
			}
			l.start, l.end, l.textStart, l.textEnd = m[0], m[1], m[4], m[5]
			l.text = string(md[m[4]:m[5]])
			used[m[0]] = true
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

// relativePath returns the file a link target names, when it is relative.
func relativePath(dest string) (string, bool) {
	if dest == "" || strings.HasPrefix(dest, "#") || strings.HasPrefix(dest, "/") {
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
