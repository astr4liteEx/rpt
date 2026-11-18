package report

import (
	"fmt"
	"path"

	"github.com/astr4liteEx/rpt/sdk"
)

// Delete removes the file of the finding with the given ID and returns the
// finding as it was stored. Evidence files stay: another finding may cite
// them. The ID is free again: rpt keeps no history, so the next new finding
// may take it if it was the highest.
func (r *Report) Delete(id string) (sdk.Finding, error) {
	rel, err := r.locate(id)
	if err != nil {
		return sdk.Finding{}, err
	}
	src, err := r.root.ReadFile(rel)
	if err != nil {
		return sdk.Finding{}, &FileError{Path: rel, Err: err}
	}
	f, err := parseFinding(rel, src, r.headings())
	if err != nil {
		return sdk.Finding{}, err
	}
	if err := r.root.Remove(rel); err != nil {
		return sdk.Finding{}, fmt.Errorf("delete %s: %w", rel, err)
	}
	return f, syncDir(r.root, path.Dir(rel))
}
