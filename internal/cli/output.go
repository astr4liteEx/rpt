// Package cli holds the output conventions every rpt verb follows: terminal
// detection, the JSON Lines writer, tables and exit-code names. It never
// reads report files. There is no template output: JSON Lines is the data
// format, and jq is the query language.
package cli

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// Column is one column of a terminal table: its header and the record's
// JSON field it shows.
type Column struct {
	Header string
	Field  string
	// Value, when set, computes the cell from the record's JSON object
	// instead of reading Field.
	Value func(map[string]any) string
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
	tw      *tabwriter.Writer
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
		o.tw = tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
		headers := make([]string, len(columns))
		for i, c := range columns {
			headers[i] = c.Header
		}
		if _, err := fmt.Fprintln(o.tw, strings.Join(headers, "\t")); err != nil {
			return nil, err
		}
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

// Flush writes anything buffered, such as a table.
func (o *Output) Flush() error {
	if o.tw != nil {
		return o.tw.Flush()
	}
	return nil
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
	_, err = fmt.Fprintln(o.tw, strings.Join(cells, "\t"))
	return err
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
