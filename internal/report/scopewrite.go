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
	src    []byte
	header []string
	rows   []sdk.ScopeRow
	spans  [][2]int // byte range of each row, in step with rows
	crlf   bool
}

func (r *Report) readScopeTable() (scopeTable, error) {
	src, err := r.root.ReadFile(ScopeFile)
	if err != nil {
		return scopeTable{}, fmt.Errorf("read scope: %w", err)
	}
	if _, err := r.Scope(); err != nil {
		return scopeTable{}, err // never edit a table that doesn't read cleanly
	}
	t := scopeTable{src: src, crlf: bytes.Contains(src, []byte("\r\n"))}
	cr := csv.NewReader(bytes.NewReader(src))
	if t.header, err = cr.Read(); err != nil {
		return scopeTable{}, err
	}
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

// nextScopeID is S- and one more than the highest S-<number> in use.
func (t scopeTable) nextScopeID() string {
	n := 0
	for _, row := range t.rows {
		if v, err := strconv.Atoi(strings.TrimPrefix(row.ID, "S-")); err == nil && strings.HasPrefix(row.ID, "S-") {
			n = max(n, v)
		}
	}
	return "S-" + strconv.Itoa(n+1)
}

// AddScope appends row to scope.csv, taking its id or the next free S-N,
// and returns the row as stored. Every member must have a column in the
// header: rpt never adds a column, since that would rewrite every row.
// The other rows keep their bytes, and the new row takes the file's line
// ends.
func (r *Report) AddScope(row sdk.ScopeRow) (sdk.ScopeRow, error) {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrBadValue, fmt.Sprintf(format, a...))
	}
	t, err := r.readScopeTable()
	if err != nil {
		return sdk.ScopeRow{}, err
	}
	if row.ID == "" {
		row.ID = t.nextScopeID()
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
	if err := writeAtomic(r.root, ScopeFile, append(out, line.Bytes()...)); err != nil {
		return sdk.ScopeRow{}, err
	}
	return stored, nil
}

func newline(crlf bool) string {
	if crlf {
		return "\r\n"
	}
	return "\n"
}

// DeleteScope removes the row with the given id from scope.csv and returns
// it. A row a finding cites is refused, naming the findings, unless force.
// The other rows keep their bytes.
func (r *Report) DeleteScope(id string, force bool) (sdk.ScopeRow, error) {
	t, err := r.readScopeTable()
	if err != nil {
		return sdk.ScopeRow{}, err
	}
	i := slices.IndexFunc(t.rows, func(x sdk.ScopeRow) bool { return x.ID == id })
	if i < 0 {
		return sdk.ScopeRow{}, fmt.Errorf("%w: %s in %s", ErrNoScopeRow, id, ScopeFile)
	}
	if !force {
		findings, err := r.Findings()
		if err != nil && !onlyFileErrors(err) {
			return sdk.ScopeRow{}, err
		}
		var citing []string
		for _, f := range findings {
			if slices.ContainsFunc(f.Targets, func(t sdk.Target) bool { return t.Scope == id }) {
				citing = append(citing, f.ID)
			}
		}
		if len(citing) > 0 {
			return sdk.ScopeRow{}, fmt.Errorf("%w: %s is cited by %s; change their targets first, or pass --force", ErrCited, id, strings.Join(citing, ", "))
		}
	}
	sp := t.spans[i]
	out := append(append([]byte{}, t.src[:sp[0]]...), t.src[sp[1]:]...)
	if err := writeAtomic(r.root, ScopeFile, out); err != nil {
		return sdk.ScopeRow{}, err
	}
	return t.rows[i], nil
}
