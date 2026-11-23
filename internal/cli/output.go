// Package cli holds the output conventions every rpt verb follows: terminal
// detection, the JSON Lines writer, tables and exit-code names. It never
// reads report files. There is no template output: JSON Lines is the data
// format, and jq is the query language.
package cli

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"slices"
	"strings"

	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
)

// Column is one column of a terminal table: its header and the record's
// JSON field it shows.
type Column struct {
	Header string
	Field  string
	// Value, when set, computes the cell from the record's JSON object
	// instead of reading Field.
	Value func(map[string]any) string
	// Severity colours the cell as the severity level it names.
	Severity bool
}

// Output writes a command's records: JSON Lines, or on a terminal a table
// per kind of record, printed by Flush in a fixed order. Records of a kind
// with no columns are left out of tables; a person reading a terminal
// isn't feeding another program.
type Output struct {
	w      io.Writer
	tables bool
	rows   map[string][][]string
	recs   map[string][]map[string]any
	others []string // Render's records of kinds with no columns
	// Severities, when set, orders the totals line under a findings table.
	Severities []string
}

// NewOutput writes JSON Lines when jsonFlag is set or w isn't a terminal,
// otherwise tables.
func NewOutput(w io.Writer, terminal, jsonFlag bool) *Output {
	return &Output{w: w, tables: terminal && !jsonFlag, rows: map[string][][]string{}, recs: map[string][]map[string]any{}}
}

// Write writes one record.
func (o *Output) Write(rec any) error {
	if o.tables {
		return o.writeRow(rec)
	}
	if err := json.MarshalWrite(o.w, rec, json.Deterministic(true)); err != nil {
		return fmt.Errorf("write record: %w", err)
	}
	_, err := io.WriteString(o.w, "\n")
	return err
}

// WriteRaw passes on a record exactly as it arrived; tables leave it out.
func (o *Output) WriteRaw(raw []byte) error {
	if o.tables {
		return nil
	}
	if _, err := o.w.Write(raw); err != nil {
		return fmt.Errorf("write record: %w", err)
	}
	_, err := io.WriteString(o.w, "\n")
	return err
}

// Render writes a record as it arrived: byte for byte in JSON Lines; in
// tables, a row of its kind's table, or for a kind with no columns its
// line after the tables, so nothing piped in to be shown is lost.
func (o *Output) Render(raw []byte) error {
	if !o.tables {
		return o.WriteRaw(raw)
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) == nil {
		kind, _ := m["kind"].(string)
		if slices.ContainsFunc(columns, func(c kindColumns) bool { return c.kind == kind }) {
			return o.writeRow(m)
		}
	}
	o.others = append(o.others, CleanLine(string(raw)))
	return nil
}

// Table reports whether o prints tables rather than JSON Lines.
func (o *Output) Table() bool { return o.tables }

// Flush prints the tables, rounded and grey-bordered, as wide as the
// terminal allows; a findings table has a totals line under it. Render's
// records of other kinds follow, one line each.
func (o *Output) Flush() error {
	if !o.tables {
		return nil
	}
	var out strings.Builder
	for _, c := range columns {
		rows := o.rows[c.kind]
		if len(rows) == 0 {
			continue
		}
		cols := c.cols
		headers := make([]string, len(cols))
		for i, col := range cols {
			headers[i] = col.Header
		}
		t := table.New().
			Border(lipgloss.RoundedBorder()).
			BorderStyle(lipgloss.NewStyle().Foreground(grey)).
			Headers(headers...).
			Rows(rows...).
			StyleFunc(func(row, col int) lipgloss.Style {
				s := lipgloss.NewStyle().Padding(0, 1)
				switch {
				case row == table.HeaderRow:
					return s.Bold(true)
				case cols[col].Severity:
					if c, ok := severityColors[rows[row][col]]; ok {
						return s.Foreground(c)
					}
				}
				return s
			})
		if w := Width(o.w); w > 0 && lipgloss.Width(t.Render()) > w {
			t = t.Width(w)
		}
		out.WriteString(t.Render() + "\n")
		if c.kind == "finding" {
			out.WriteString(SeverityTotals(o.Severities)(o.recs[c.kind]) + "\n")
		}
	}
	for _, l := range o.others {
		out.WriteString(l + "\n")
	}
	clear(o.rows)
	clear(o.recs)
	o.others = nil
	_, err := io.WriteString(Styled(o.w), out.String())
	return err
}

// writeRow adds a table row for the record's kind.
func (o *Output) writeRow(rec any) error {
	m, err := jsonMap(rec)
	if err != nil {
		return err
	}
	kind, _ := m["kind"].(string)
	i := slices.IndexFunc(columns, func(c kindColumns) bool { return c.kind == kind })
	if i < 0 {
		return nil
	}
	cells := make([]string, len(columns[i].cols))
	for j, c := range columns[i].cols {
		if c.Value != nil {
			cells[j] = cell(c.Value(m))
		} else {
			cells[j] = cell(m[c.Field])
		}
	}
	o.rows[kind] = append(o.rows[kind], cells)
	o.recs[kind] = append(o.recs[kind], m)
	return nil
}

// SeverityTotals is a findings table's totals line: how many, then each
// level in its colour with its count, in the order given, then any level
// not given.
func SeverityTotals(order []string) func([]map[string]any) string {
	return func(recs []map[string]any) string {
		count := map[string]int{}
		var extra []string
		for _, m := range recs {
			s, _ := m["severity"].(string)
			if count[s] == 0 && !slices.Contains(order, s) && !slices.Contains(extra, s) {
				extra = append(extra, s)
			}
			count[s]++
		}
		noun := "findings"
		if len(recs) == 1 {
			noun = "finding"
		}
		parts := []string{dim.Render(fmt.Sprintf("%d %s", len(recs), noun))}
		for _, s := range append(slices.Clone(order), extra...) {
			if count[s] > 0 {
				parts = append(parts, Severity(s)+dim.Render(fmt.Sprintf(" %d", count[s])))
			}
		}
		return strings.Join(parts, dim.Render(" · "))
	}
}

// cell renders one JSON value for a table, on one line and cleaned.
func cell(v any) string {
	var s string
	switch v := v.(type) {
	case nil:
	case string:
		s = v
	case []any:
		parts := make([]string, len(v))
		for i, p := range v {
			parts[i] = cell(p)
		}
		s = strings.Join(parts, ",")
	default:
		s = fmt.Sprint(v)
	}
	return CleanLine(s)
}

// jsonMap returns rec's JSON object form.
func jsonMap(rec any) (map[string]any, error) {
	b, err := json.Marshal(rec, json.Deterministic(true))
	if err != nil {
		return nil, fmt.Errorf("encode record: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("decode record: %w", err)
	}
	return m, nil
}
