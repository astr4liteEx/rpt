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

type mode int

const (
	modeJSONLines mode = iota
	modeTable
)

// Output writes records in the one mode chosen for this run.
type Output struct {
	w       io.Writer
	mode    mode
	columns []Column
	rows    [][]string       // a table's rows, rendered by Flush
	recs    []map[string]any // the records behind them, for Totals
	// Totals, when set, gives a line under a table, such as a count per
	// severity, from its records.
	Totals func([]map[string]any) string
}

// NewOutput picks the output mode once: JSON Lines when jsonFlag is set or
// w is not a terminal, otherwise a table of columns.
func NewOutput(w io.Writer, terminal, jsonFlag bool, columns []Column) (*Output, error) {
	o := &Output{w: w}
	switch {
	case jsonFlag || !terminal:
		o.mode = modeJSONLines
	default:
		o.mode, o.columns = modeTable, columns
	}
	return o, nil
}

// Write writes one record.
func (o *Output) Write(rec any) error {
	if o.mode == modeTable {
		return o.writeRow(rec)
	}
	if err := json.MarshalWrite(o.w, rec, json.Deterministic(true)); err != nil {
		return fmt.Errorf("write record: %w", err)
	}
	_, err := io.WriteString(o.w, "\n")
	return err
}

// WriteRaw passes through a record this verb doesn't own, as the exact
// bytes it arrived with. Only JSON Lines output carries it: a table shows
// the verb's own records, and a person reading a terminal isn't feeding
// another program.
func (o *Output) WriteRaw(raw []byte) error {
	if o.mode != modeJSONLines {
		return nil
	}
	if _, err := o.w.Write(raw); err != nil {
		return fmt.Errorf("write record: %w", err)
	}
	_, err := io.WriteString(o.w, "\n")
	return err
}

// WriteOwn writes one of the verb's own records that arrived as raw and
// may have been edited: JSON Lines output gets raw exactly, a table gets
// rec.
func (o *Output) WriteOwn(rec any, raw []byte) error {
	if o.mode == modeJSONLines {
		return o.WriteRaw(raw)
	}
	return o.Write(rec)
}

// Table reports whether o prints a table rather than JSON Lines.
func (o *Output) Table() bool { return o.mode == modeTable }

// Flush writes anything buffered: a table, with rounded grey borders, as
// wide as the terminal allows, and its totals line. A table with no rows
// prints nothing.
func (o *Output) Flush() error {
	if o.mode != modeTable || len(o.rows) == 0 {
		return nil
	}
	headers := make([]string, len(o.columns))
	for i, c := range o.columns {
		headers[i] = c.Header
	}
	rows := o.rows
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
			case o.columns[col].Severity:
				if c, ok := severityColors[rows[row][col]]; ok {
					return s.Foreground(c)
				}
			}
			return s
		})
	if w := Width(o.w); w > 0 && lipgloss.Width(t.Render()) > w {
		t = t.Width(w)
	}
	out := t.Render() + "\n"
	if o.Totals != nil {
		if line := o.Totals(o.recs); line != "" {
			out += line + "\n"
		}
	}
	_, err := io.WriteString(Styled(o.w), out)
	o.rows, o.recs = nil, nil
	return err
}

// writeRow adds one table row; lists are joined with commas.
func (o *Output) writeRow(rec any) error {
	m, err := jsonMap(rec)
	if err != nil {
		return err
	}
	cells := make([]string, len(o.columns))
	for i, c := range o.columns {
		if c.Value != nil {
			cells[i] = cell(c.Value(m))
		} else {
			cells[i] = cell(m[c.Field])
		}
	}
	o.rows = append(o.rows, cells)
	o.recs = append(o.recs, m)
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

// cell renders one JSON value for a table. Tabs and newlines would break
// the table's layout, so they become spaces.
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
	return strings.NewReplacer("\t", " ", "\n", " ").Replace(s)
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
