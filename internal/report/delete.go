package report

import (
	"fmt"

	"github.com/astr4liteEx/rpt/sdk"
)

// Delete removes the file of the finding with the given ID and returns the
// finding as it was stored. Evidence files stay: another finding may cite
// them. The ID is free again: rpt keeps no history, so the next new finding
// may take it if it was the highest.
func (r *Report) Delete(id string) (sdk.Finding, error) {
	return one(r, func(tx *Tx) (sdk.Finding, error) { return tx.Delete(id) })
}

// Delete is Report.Delete as part of the write tx.
func (tx *Tx) Delete(id string) (sdk.Finding, error) {
	rel, err := tx.r.locate(id)
	if err != nil {
		return sdk.Finding{}, err
	}
	src, exists, err := tx.read(rel)
	if err != nil {
		return sdk.Finding{}, err
	}
	if !exists {
		return sdk.Finding{}, fmt.Errorf("%w: %s in %s/", ErrNoFinding, id, FindingsDir) // removed earlier in this write
	}
	if err := tx.checkRev(id, rel, Rev(src)); err != nil {
		return sdk.Finding{}, err
	}
	f, err := parseFinding(rel, src, tx.r.headings())
	if err != nil {
		return sdk.Finding{}, err
	}
	return f, tx.del(rel, rankFinding)
}
