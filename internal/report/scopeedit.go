package report

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"slices"
	"strings"

	"github.com/astr4liteEx/rpt/sdk"
)

// Cited says what a scope write does to the targets citing a row it
// removes, or narrows past them (ADR 0008).
type Cited int

const (
	CitedRefuse  Cited = iota // refuse the write, naming the findings
	CitedForce                // leave the targets dangling or unfit
	CitedCleanup              // drop those targets from their findings
)

// ScopeChange is what one scope write did: the row (as stored, or as it
// was for a removal), the findings it rewrote, and the findings left
// citing a removed row or unfit for a narrowed one (--force).
type ScopeChange struct {
	Row      sdk.ScopeRow
	Findings []sdk.Finding
	Left     []string
}

// A citation is one finding as this write sees it.
type citation struct {
	rel string
	f   sdk.Finding
}

// citations reads every finding as this write sees it. Files that don't
// parse are skipped: validate reports them.
func (tx *Tx) citations() ([]citation, error) {
	list, err := tx.r.Findings()
	if err != nil && !onlyFileErrors(err) {
		return nil, err
	}
	var out []citation
	for _, f := range list {
		src, exists, err := tx.read(f.Path)
		if err != nil {
			return nil, err
		}
		if !exists {
			continue
		}
		g, err := parseFindingBytes(f.Path, src, tx.headings())
		if err != nil {
			continue
		}
		out = append(out, citation{rel: f.Path, f: g})
	}
	return out, nil
}

// retarget rewrites the targets citing scope ID id in every finding:
// change returns a target's replacement, or keep false to drop it.
// Findings it doesn't change are left alone. It returns the findings it
// changed.
func (tx *Tx) retarget(id string, change func(sdk.Target) (t sdk.Target, keep bool)) ([]sdk.Finding, error) {
	cites, err := tx.citations()
	if err != nil {
		return nil, err
	}
	var out []sdk.Finding
	for _, c := range cites {
		var ts []sdk.Target
		changed := false
		for _, t := range c.f.Targets {
			if t.Scope != id {
				ts = append(ts, t)
				continue
			}
			nt, keep := change(t)
			changed = changed || !keep || nt.Scope != t.Scope || nt.Host != t.Host || nt.Port != t.Port || nt.Protocol != t.Protocol
			if keep {
				ts = append(ts, nt)
			}
		}
		if !changed {
			continue
		}
		f, err := tx.edit(c.f.ID, c.rel, func(ff *findingFile) error {
			if len(ts) == 0 {
				ts = []sdk.Target{}
			}
			val, err := toNode(ts)
			if err != nil {
				return err
			}
			return ff.setEntry("targets", val)
		})
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// citing returns the IDs of the findings with a target on scope ID id
// that bad rejects (every one, when bad is nil).
func (tx *Tx) citing(id string, bad func(sdk.Target) bool) ([]string, error) {
	cites, err := tx.citations()
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, c := range cites {
		if slices.ContainsFunc(c.f.Targets, func(t sdk.Target) bool { return t.Scope == id && (bad == nil || bad(t)) }) {
			ids = append(ids, c.f.ID)
		}
	}
	return ids, nil
}

// handleCited applies mode to the targets on row id that unfit rejects
// (every one, when nil): refused, left, or dropped.
func (tx *Tx) handleCited(id, what string, mode Cited, unfit func(sdk.Target) bool, ch *ScopeChange) error {
	ids, err := tx.citing(id, unfit)
	if err != nil || len(ids) == 0 {
		return err
	}
	switch mode {
	case CitedForce:
		ch.Left = ids
	case CitedCleanup:
		fs, err := tx.retarget(id, func(t sdk.Target) (sdk.Target, bool) { return t, unfit != nil && !unfit(t) })
		if err != nil {
			return err
		}
		ch.Findings = append(ch.Findings, fs...)
	default:
		return fmt.Errorf("%w: %s %s %s; change their targets first, or pass --force (leave them) or --cleanup (drop them)", ErrCited, id, what, strings.Join(ids, ", "))
	}
	return nil
}

// RemoveScope removes the row with the given id from scope.csv. A row a
// finding cites is refused unless mode says otherwise. The other rows keep
// their bytes.
func (tx *Tx) RemoveScope(id string, mode Cited) (ScopeChange, error) {
	t, i, row, err := tx.scopeRowFor(id)
	if err != nil {
		return ScopeChange{}, err
	}
	ch := ScopeChange{Row: row}
	if err := tx.handleCited(row.ID, "is cited by", mode, nil, &ch); err != nil {
		return ScopeChange{}, err
	}
	sp := t.spans[i]
	out := slices.Concat(t.src[:sp[0]], t.src[sp[1]:])
	return ch, tx.put(ScopeFile, out, rankScope)
}

// scopeRowFor reads scope.csv and finds the row id, checking its rev.
func (tx *Tx) scopeRowFor(id string) (scopeTable, int, sdk.ScopeRow, error) {
	t, err := tx.scopeTable()
	if err != nil {
		return t, 0, sdk.ScopeRow{}, err
	}
	i := t.find(id)
	if i < 0 {
		return t, 0, sdk.ScopeRow{}, fmt.Errorf("%w: %s in %s", ErrNoScopeRow, id, ScopeFile)
	}
	row := t.rows[i]
	row.Rev = rowRev(trimEOL(t.src[:t.headerEnd]), t.src[t.spans[i][0]:t.spans[i][1]])
	if err := tx.checkRev(id, ScopeFile, row.Rev); err != nil {
		return t, 0, sdk.ScopeRow{}, err
	}
	return t, i, row, nil
}

// SetScope sets one column of the row id to value, which is the cell's
// text. Setting id renames the row and every target citing it. Setting
// host, port or protocol so that a citing target no longer fits is
// refused unless mode says otherwise. rpt never adds a column.
func (tx *Tx) SetScope(id, col, value string, mode Cited) (ScopeChange, error) {
	return tx.changeRow(id, col, value, mode)
}

// UnsetScope blanks columns of the row id. A row needs its id and host.
// Blanking port or protocol only widens the row, so it never unfits a
// target.
func (tx *Tx) UnsetScope(id string, cols ...string) (ScopeChange, error) {
	for _, c := range cols {
		if c == "id" || c == "host" {
			return ScopeChange{}, fmt.Errorf("%w: %s: a scope row needs it", ErrRefusedUnset, c)
		}
	}
	var ch ScopeChange
	for _, c := range cols {
		var err error
		if ch, err = tx.changeRow(id, c, "", CitedRefuse); err != nil {
			return ScopeChange{}, err
		}
	}
	return ch, nil
}

// changeRow sets one cell of row id and rewrites that row alone.
func (tx *Tx) changeRow(id, col, value string, mode Cited) (ScopeChange, error) {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s: %s", ErrBadValue, col, fmt.Sprintf(format, a...))
	}
	if col == "rev" {
		return ScopeChange{}, fmt.Errorf("%w: rev: rev is the row's revision; rpt sets it on records", ErrRefusedKey)
	}
	t, i, old, err := tx.scopeRowFor(id)
	if err != nil {
		return ScopeChange{}, err
	}
	at := slices.Index(t.header, col)
	if at < 0 {
		return ScopeChange{}, bad("scope.csv has no %q column; add it to the header by hand first", col)
	}
	cr := csv.NewReader(bytes.NewReader(t.src[t.spans[i][0]:t.spans[i][1]]))
	cr.FieldsPerRecord = len(t.header)
	rec, err := cr.Read()
	if err != nil {
		return ScopeChange{}, err
	}
	rec[at] = value
	row, err := scopeRow(t.header, rec)
	if err != nil {
		return ScopeChange{}, bad("%v", err)
	}
	switch {
	case row.ID == "" || row.Host == "":
		return ScopeChange{}, bad("must not be empty")
	case row.ID != old.ID:
		if j := t.find(row.ID); j >= 0 && j != i {
			return ScopeChange{}, bad("%s is already the ID of another row", row.ID)
		}
		if ids, err := tx.citing(row.ID, nil); err != nil {
			return ScopeChange{}, err
		} else if len(ids) > 0 {
			return ScopeChange{}, bad("%s is cited by %s, though no row has it; pick another ID", row.ID, strings.Join(ids, ", "))
		}
	}

	ch := ScopeChange{}
	if row.ID != old.ID {
		fs, err := tx.retarget(old.ID, func(t sdk.Target) (sdk.Target, bool) { t.Scope = row.ID; return t, true })
		if err != nil {
			return ScopeChange{}, err
		}
		ch.Findings = fs
	} else if err := tx.handleCited(old.ID, "no longer fits targets in", mode,
		func(t sdk.Target) bool { return TargetFits(t, row) != nil }, &ch); err != nil {
		return ScopeChange{}, err
	}

	var line bytes.Buffer
	w := csv.NewWriter(&line)
	w.UseCRLF = t.crlf
	if err := w.Write(rec); err != nil {
		return ScopeChange{}, err
	}
	w.Flush()
	text := line.Bytes()
	sp := t.spans[i]
	if !bytes.HasSuffix(t.src[sp[0]:sp[1]], []byte("\n")) {
		text = trimEOL(text) // the last row, with no line end
	}
	out := slices.Concat(t.src[:sp[0]], text, t.src[sp[1]:])
	if err := tx.put(ScopeFile, out, rankScope); err != nil {
		return ScopeChange{}, err
	}
	row.Rev = rowRev(trimEOL(t.src[:t.headerEnd]), text)
	ch.Row = row
	return ch, nil
}
