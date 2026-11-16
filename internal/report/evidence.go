package report

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"github.com/astr4liteEx/rpt/sdk"
)

// ErrOutsideReport means a path would leave the report folder. Evidence
// paths come from frontmatter and are untrusted.
var ErrOutsideReport = errors.New("path leaves the report folder")

// EvidenceInfo describes the evidence file p named by finding f. p is
// relative to the finding file's folder. A path that leaves the report,
// lexically or through a symlink, is refused; a missing file reports
// fs.ErrNotExist.
func (r *Report) EvidenceInfo(f sdk.Finding, p string) (fs.FileInfo, error) {
	rel, err := evidencePath(f, p)
	if err != nil {
		return nil, err
	}
	info, err := r.root.Stat(rel)
	if err != nil {
		return nil, fmt.Errorf("evidence %q of %s: %w", p, f.Path, err)
	}
	return info, nil
}

// evidencePath resolves p against the finding file's folder to a path
// relative to the report root, refusing anything that leaves the report.
// os.Root still guards the actual access, including symlinks.
func evidencePath(f sdk.Finding, p string) (string, error) {
	if p == "" || path.IsAbs(p) || strings.HasPrefix(p, `\`) || (len(p) > 1 && p[1] == ':') {
		return "", fmt.Errorf("evidence %q of %s: %w", p, f.Path, ErrOutsideReport)
	}
	rel := path.Join(path.Dir(f.Path), p)
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return "", fmt.Errorf("evidence %q of %s: %w", p, f.Path, ErrOutsideReport)
	}
	return rel, nil
}
