package report

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/text"

	"github.com/astr4liteEx/rpt/sdk"
)

// link is a relative link or image target in markdown, with the byte
// offset of its text for locating it.
type link struct {
	dest string // as written
	path string // the file part, decoded
	off  int
}

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
		switch n := n.(type) {
		case *ast.Link:
			dest = n.Destination
		case *ast.Image:
			dest = n.Destination
		default:
			return ast.WalkContinue, nil
		}
		if p, ok := relativePath(string(dest)); ok {
			out = append(out, link{dest: string(dest), path: p, off: textOffset(n)})
		}
		return ast.WalkContinue, nil
	})
	return out
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
