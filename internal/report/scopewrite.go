package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/astr4liteEx/rpt/sdk"
)

// Errors from changing scope.csv, both mistakes in the request.
var (
	ErrNoScopeRow = errors.New("no such scope row")
	ErrCited      = errors.New("scope row is cited")
)

// scopeTable is scope.csv read for editing: its bytes, its header, and the
// byte range of each row, so rows can be added and removed without
// re-encoding the others.
type scopeTable struct {
	src       []byte
	header    []string
	headerEnd int // where the header line ends, line end included
	rows      []sdk.ScopeRow
	spans     [][2]int // byte range of each row, in step with rows
	crlf      bool
}

// scopeTable reads scope.csv as this write sees it.
func (tx *Tx) scopeTable() (scopeTable, error) {
	src, exists, err := tx.read(ScopeFile)
	if err != nil {
		return scopeTable{}, err
	}
	if !exists {
		return scopeTable{}, fmt.Errorf("read scope: %s is missing", ScopeFile)
	}
	if _, err := parseScope(src, ""); err != nil {
		return scopeTable{}, err // never edit a table that doesn't read cleanly
	}
	t := scopeTable{src: src, crlf: bytes.Contains(src, []byte("\r\n"))}
	cr := csv.NewReader(bytes.NewReader(src))
	if t.header, err = cr.Read(); err != nil {
		return scopeTable{}, err
	}
	t.headerEnd = int(cr.InputOffset())
	for {
		start := cr.InputOffset()
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return scopeTable{}, err
		}
		row, err := scopeRow(t.header, rec)
		if err != nil {
			return scopeTable{}, err
		}
		t.rows = append(t.rows, row)
		t.spans = append(t.spans, [2]int{int(start), int(cr.InputOffset())})
	}
	return t, nil
}

// nextScopeID is S- and one more than the highest S-<number> in use, by a
// row or by a finding's target (an ID left dangling by --force is never
// reused), padded to three digits: S-012 and S-12 both count as 12.
func (tx *Tx) nextScopeID(t scopeTable) (string, error) {
	n := 0
	count := func(id string) {
		if d, ok := strings.CutPrefix(strings.ToUpper(id), "S-"); ok {
			if v, err := strconv.Atoi(d); err == nil && v > n {
				n = v
			}
		}
	}
	for _, row := range t.rows {
		count(row.ID)
	}
	cites, err := tx.citations()
	if err != nil {
		return "", err
	}
	for _, c := range cites {
		for _, t := range c.f.Targets {
			count(t.Scope)
		}
	}
	return fmt.Sprintf("S-%03d", n+1), nil
}

// find returns the index of the row with the given ID: exactly, or else
// the one row whose ID matches it in any case; -1 if none.
func (t scopeTable) find(id string) int {
	if i := slices.IndexFunc(t.rows, func(x sdk.ScopeRow) bool { return x.ID == id }); i >= 0 {
		return i
	}
	i := -1
	for j, x := range t.rows {
		if strings.EqualFold(x.ID, id) {
			if i >= 0 {
				return -1 // ambiguous: S-a and s-A
			}
			i = j
		}
	}
	return i
}

// AddScope appends row to scope.csv, taking its id or the next free S-N,
// and returns the row as stored. Every member must have a column in the
// header: rpt never adds a column, since that would rewrite every row.
// The other rows keep their bytes, and the new row takes the file's line
// ends.
func (r *Report) AddScope(row sdk.ScopeRow) (sdk.ScopeRow, error) {
	return one(r, func(tx *Tx) (sdk.ScopeRow, error) { return tx.AddScope(row) })
}

// AddScope is Report.AddScope as part of the write tx: several adds in one
// write append one after another.
func (tx *Tx) AddScope(row sdk.ScopeRow) (sdk.ScopeRow, error) {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrBadValue, fmt.Sprintf(format, a...))
	}
	t, err := tx.scopeTable()
	if err != nil {
		return sdk.ScopeRow{}, err
	}
	if row.ID == "" {
		if row.ID, err = tx.nextScopeID(t); err != nil {
			return sdk.ScopeRow{}, err
		}
	} else if slices.ContainsFunc(t.rows, func(x sdk.ScopeRow) bool { return x.ID == row.ID }) {
		return sdk.ScopeRow{}, bad("id: %s is already taken", row.ID)
	}
	if row.Host == "" {
		return sdk.ScopeRow{}, bad("host is required")
	}
	vals := map[string]string{"id": row.ID, "host": row.Host}
	if row.Port != 0 {
		vals["port"] = strconv.Itoa(row.Port)
	}
	if row.Protocol != "" {
		vals["protocol"] = row.Protocol
	}
	for _, k := range slices.Sorted(maps.Keys(row.Extra)) {
		var s string
		if err := json.Unmarshal(row.Extra[k], &s); err != nil {
			return sdk.ScopeRow{}, bad("%s: a scope column holds text, not %s", k, row.Extra[k])
		}
		vals[k] = s
	}
	for _, k := range slices.Sorted(maps.Keys(vals)) {
		if vals[k] != "" && !slices.Contains(t.header, k) {
			return sdk.ScopeRow{}, bad("%s: scope.csv has no %q column; add it to the header by hand first", k, k)
		}
	}
	rec := make([]string, len(t.header))
	for i, col := range t.header {
		rec[i] = vals[col]
	}
	stored, err := scopeRow(t.header, rec)
	if err != nil {
		return sdk.ScopeRow{}, bad("%v", err)
	}

	var line bytes.Buffer
	w := csv.NewWriter(&line)
	w.UseCRLF = t.crlf
	if err := w.Write(rec); err != nil {
		return sdk.ScopeRow{}, err
	}
	w.Flush()
	out := t.src
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, newline(t.crlf)...)
	}
	if err := tx.put(ScopeFile, append(out, line.Bytes()...), rankScope); err != nil {
		return sdk.ScopeRow{}, err
	}
	stored.Rev = rowRev(trimEOL(t.src[:t.headerEnd]), line.Bytes())
	return stored, nil
}

func newline(crlf bool) string {
	if crlf {
		return "\r\n"
	}
	return "\n"
}
