package report

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/astr4liteEx/rpt/internal/doc"
)

// A ScopeChange is what one scope write did: the row as stored, or as it
// was for a removal; the findings whose targets it rewrote; and, with
// Force, the findings left citing a removed row or unfit for a changed
// one.
type ScopeChange struct {
	Row     *Row
	Rewrote []*Doc
	Left    []*Doc
}

// editScope changes scope.csv's bytes through change. The result must
// read without a new row error, or nothing changes.
func (m *Model) editScope(change func(src []byte) ([]byte, error)) error {
	if !m.Scope.Exists {
		return refuse(ScopeFile, "the report has no %s", ScopeFile)
	}
	if m.Scope.Err != nil {
		return refuse(ScopeFile, "%s doesn't read; fix it first: %v", ScopeFile, m.Scope.Err)
	}
	out, err := change(m.Scope.src)
	if err != nil {
		return err
	}
	s := parseScope(out, true)
	if s.Err != nil || len(s.RowErrs) > len(m.Scope.RowErrs) {
		err := s.Err
		if err == nil {
			err = s.RowErrs[len(s.RowErrs)-1]
		}
		return refuse(ScopeFile, "the change would break %s: %v", ScopeFile, err)
	}
	if err := m.put(ScopeFile, out); err != nil {
		return err
	}
	m.Scope = s
	return nil
}

// cells is a row's values in header order.
func (s *Scope) cells(r *Row) []string {
	out := make([]string, len(s.Header))
	for i, col := range s.Header {
		switch col {
		case "id":
			out[i] = r.ID
		case "host":
			out[i] = r.Host
		case "port":
			if r.Port != 0 {
				out[i] = strconv.Itoa(r.Port)
			}
		case "protocol":
			out[i] = r.Protocol
		default:
			out[i] = r.Extra[col]
		}
	}
	return out
}

// line is a row as a CSV line, in the file's line endings.
func (s *Scope) line(cells []string) []byte {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	w.UseCRLF = bytes.Contains(s.src[:s.headerEnd], []byte("\r\n"))
	w.Write(cells)
	w.Flush()
	return b.Bytes()
}

// NextScopeID is S- and one more than the highest S- number among the
// rows and the findings' targets, three digits at least.
func (m *Model) NextScopeID() string {
	n := 0
	count := func(id string) {
		if d, ok := strings.CutPrefix(strings.ToUpper(id), "S-"); ok {
			if v, err := strconv.Atoi(d); err == nil {
				n = max(n, v)
			}
		}
	}
	for _, r := range m.Scope.Rows {
		count(r.ID)
	}
	for _, d := range m.docs[FindingKind] {
		for _, t := range d.Targets {
			count(t.Scope)
		}
	}
	return fmt.Sprintf("S-%03d", n+1)
}

// AddScope appends a row, with row's ID or the next free one. Its columns
// must be in the header: rpt never adds a column.
func (m *Model) AddScope(row Row) (*Row, error) {
	if row.ID == "" {
		row.ID = m.NextScopeID()
	}
	if err := m.checkColumns(row); err != nil {
		return nil, err
	}
	if r := m.Scope.find(row.ID); r != nil {
		return nil, refuse(ScopeFile, "%s is taken by the row on line %d", row.ID, r.Line)
	}
	err := m.editScope(func(src []byte) ([]byte, error) {
		out := bytes.Clone(src)
		if len(out) > 0 && out[len(out)-1] != '\n' {
			if bytes.Contains(src[:m.Scope.headerEnd], []byte("\r\n")) {
				out = append(out, '\r')
			}
			out = append(out, '\n')
		}
		return append(out, m.Scope.line(m.Scope.cells(&row))...), nil
	})
	if err != nil {
		return nil, err
	}
	r, _ := m.Scope.Row(row.ID)
	return r, nil
}

// checkColumns refuses a row with a value for a column the header lacks.
func (m *Model) checkColumns(row Row) error {
	if row.Port != 0 && !slices.Contains(m.Scope.Header, "port") {
		return refuse(ScopeFile, "%s has no port column", ScopeFile)
	}
	if row.Protocol != "" && !slices.Contains(m.Scope.Header, "protocol") {
		return refuse(ScopeFile, "%s has no protocol column", ScopeFile)
	}
	for col, v := range row.Extra {
		if v != "" && !slices.Contains(m.Scope.Header, col) {
			return refuse(ScopeFile, "%s has no %s column; rpt never adds one", ScopeFile, col)
		}
	}
	return nil
}

// replaceRow writes row in place of the row old, keeping its place.
func (m *Model) replaceRow(old *Row, row Row) (*Row, error) {
	if err := m.checkColumns(row); err != nil {
		return nil, err
	}
	err := m.editScope(func(src []byte) ([]byte, error) {
		line := m.Scope.line(m.Scope.cells(&row))
		if !bytes.HasSuffix(src[old.Start:old.End], []byte("\n")) {
			line = bytes.TrimRight(line, "\r\n")
		}
		return slices.Concat(src[:old.Start], line, src[old.End:]), nil
	})
	if err != nil {
		return nil, err
	}
	r, _ := m.Scope.Row(row.ID)
	return r, nil
}

// ReplaceScope puts row in place of the row with its ID, leaving findings
// as they are.
func (m *Model) ReplaceScope(row Row) (*Row, error) {
	old, err := m.Scope.Row(row.ID)
	if err != nil {
		return nil, err
	}
	return m.replaceRow(old, row)
}

// SetScope sets one column of the row id to value, the cell's text.
// Setting id renames the row and every target citing it. Changing host,
// port or protocol so that a citing target no longer fits is refused
// unless mode says otherwise.
func (m *Model) SetScope(id, col, value string, mode Cited) (ScopeChange, error) {
	old, err := m.Scope.Row(id)
	if err != nil {
		return ScopeChange{}, err
	}
	if !slices.Contains(m.Scope.Header, col) {
		return ScopeChange{}, refuse(ScopeFile, "%s has no %s column; rpt never adds one", ScopeFile, col)
	}
	row := *old
	row.Extra = maps(old.Extra)
	switch col {
	case "id":
		if value == "" {
			return ScopeChange{}, refuse(ScopeFile, "a row needs an id")
		}
		if r := m.Scope.find(value); r != nil && r != old {
			return ScopeChange{}, refuse(ScopeFile, "%s is taken by the row on line %d", value, r.Line)
		}
		row.ID = value
	case "host":
		if value == "" {
			return ScopeChange{}, refuse(ScopeFile, "a row needs a host")
		}
		row.Host = value
	case "port":
		row.Port = 0
		if value != "" {
			p, err := strconv.Atoi(value)
			if err != nil || p < 1 || p > 65535 {
				return ScopeChange{}, refuse(ScopeFile, "port %q is not a number from 1 to 65535", value)
			}
			row.Port = p
		}
	case "protocol":
		if value != "" && value != "tcp" && value != "udp" {
			return ScopeChange{}, refuse(ScopeFile, "protocol %q is not tcp or udp", value)
		}
		row.Protocol = value
	default:
		if row.Extra == nil {
			row.Extra = map[string]string{}
		}
		row.Extra[col] = value
	}
	var ch ScopeChange
	// The findings citing the row: renamed with it, or checked against
	// its new host, port and protocol.
	for _, d := range m.Citing(old.ID) {
		var unfit []Target
		ts := slices.Clone(d.Targets)
		for i, t := range ts {
			if !strings.EqualFold(t.Scope, old.ID) {
				continue
			}
			ts[i].Scope = row.ID
			if Fits(&row, t) != nil {
				unfit = append(unfit, t)
			}
		}
		switch {
		case len(unfit) > 0 && mode == Refuse:
			return ScopeChange{}, refuse(d.Path, "%s's target on %s wouldn't fit: %v; pass --force to keep it, or --cleanup to drop it", d.ID, old.ID, Fits(&row, unfit[0]))
		case len(unfit) > 0 && mode == Cleanup:
			ts = slices.DeleteFunc(ts, func(t Target) bool { return strings.EqualFold(t.Scope, row.ID) && Fits(&row, t) != nil })
		case len(unfit) > 0:
			ch.Left = append(ch.Left, d)
		}
		if col == "id" || len(unfit) > 0 && mode == Cleanup {
			nd, err := m.setTargetList(d, ts)
			if err != nil {
				return ScopeChange{}, err
			}
			ch.Rewrote = append(ch.Rewrote, nd)
		}
	}
	if ch.Row, err = m.replaceRow(old, row); err != nil {
		return ScopeChange{}, err
	}
	return ch, nil
}

func maps(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// setTargetList rewrites a finding's targets.
func (m *Model) setTargetList(d *Doc, ts []Target) (*Doc, error) {
	return m.edit(d, func(s *doc.Doc) error { return s.Set(targetsNode(ts), "targets") })
}

// UnsetScope blanks columns of the row id. A row needs its id and host;
// blanking port or protocol only widens the row, so no target stops
// fitting.
func (m *Model) UnsetScope(id string, cols ...string) (ScopeChange, error) {
	old, err := m.Scope.Row(id)
	if err != nil {
		return ScopeChange{}, err
	}
	row := *old
	row.Extra = maps(old.Extra)
	for _, col := range cols {
		switch col {
		case "id", "host":
			return ScopeChange{}, refuse(ScopeFile, "a row needs its %s", col)
		case "port":
			row.Port = 0
		case "protocol":
			row.Protocol = ""
		default:
			if !slices.Contains(m.Scope.Header, col) {
				return ScopeChange{}, refuse(ScopeFile, "%s has no %s column", ScopeFile, col)
			}
			delete(row.Extra, col)
		}
	}
	r, err := m.replaceRow(old, row)
	return ScopeChange{Row: r}, err
}

// RemoveScope removes the row id. A row findings cite is refused unless
// mode says otherwise: Force leaves their targets dangling, Cleanup drops
// them. The other rows keep their bytes.
func (m *Model) RemoveScope(id string, mode Cited) (ScopeChange, error) {
	old, err := m.Scope.Row(id)
	if err != nil {
		return ScopeChange{}, err
	}
	ch := ScopeChange{Row: old}
	citing := m.Citing(old.ID)
	switch {
	case len(citing) > 0 && mode == Refuse:
		var ids []string
		for _, d := range citing {
			ids = append(ids, d.ID)
		}
		return ScopeChange{}, refuse(ScopeFile, "%s is cited by %s: pass --force to leave the targets, or --cleanup to drop them", old.ID, strings.Join(ids, ", "))
	case mode == Cleanup:
		for _, d := range citing {
			ts := slices.DeleteFunc(slices.Clone(d.Targets), func(t Target) bool { return strings.EqualFold(t.Scope, old.ID) })
			nd, err := m.setTargetList(d, ts)
			if err != nil {
				return ScopeChange{}, err
			}
			ch.Rewrote = append(ch.Rewrote, nd)
		}
	default:
		ch.Left = citing
	}
	err = m.editScope(func(src []byte) ([]byte, error) {
		return slices.Concat(src[:old.Start], src[old.End:]), nil
	})
	return ch, err
}
