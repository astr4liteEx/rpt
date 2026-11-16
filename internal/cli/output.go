// Package cli holds the output conventions every rpt verb follows: terminal
// detection, the JSON Lines writer, --format templates, tables and exit-code
// names. It never reads report files.
package cli

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"text/template"
	"text/template/parse"
)

// Column is one column of a terminal table: its header and the record's
// JSON field it shows.
type Column struct {
	Header string
	Field  string
}

type mode int

const (
	modeJSONLines mode = iota
	modeTemplate
	modeTable
)

// Output writes records in the one mode chosen for this run.
type Output struct {
	w       io.Writer
	mode    mode
	tmpl    *template.Template
	columns []Column
	tw      *tabwriter.Writer
	fields  map[string]any // top-level fields the template names, with the empty value each defaults to
}

// unescape turns the two-character \t and \n a shell passes through into
// real tab and newline characters.
var unescape = strings.NewReplacer(`\t`, "\t", `\n`, "\n")

// NewOutput picks the output mode once: a template when format is set,
// JSON Lines when jsonFlag is set or w is not a terminal, otherwise a table
// of columns. Every error it returns is a usage error (exit 2).
func NewOutput(w io.Writer, terminal, jsonFlag bool, format string, columns []Column) (*Output, error) {
	o := &Output{w: w}
	if jsonFlag && format != "" {
		return nil, errors.New("--json and --format ask for different output; use one")
	}
	switch {
	case format != "":
		tmpl, err := template.New("format").Parse(unescape.Replace(format))
		if err != nil {
			return nil, fmt.Errorf("--format: %w", err)
		}
		o.mode, o.tmpl, o.fields = modeTemplate, tmpl, templateFields(tmpl.Tree.Root)
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
	switch o.mode {
	case modeTemplate:
		return o.writeTemplate(rec)
	case modeTable:
		return o.writeRow(rec)
	default:
		if err := json.MarshalWrite(o.w, rec, json.Deterministic(true)); err != nil {
			return fmt.Errorf("write record: %w", err)
		}
		_, err := io.WriteString(o.w, "\n")
		return err
	}
}

// WriteRaw passes through a record this verb doesn't own, as the exact
// bytes it arrived with. Only JSON Lines output carries it: a table or a
// --format template shows the verb's own records, and a person reading a
// terminal isn't feeding another program.
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
// may have been edited: JSON Lines output gets raw exactly, a table or
// template gets rec.
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
		cells[i] = cell(m[c.Field])
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

// writeTemplate runs the --format template against the record's JSON form,
// so names match the JSON field names and unknown fields are reachable.
func (o *Output) writeTemplate(rec any) error {
	m, err := jsonMap(rec)
	if err != nil {
		return err
	}
	// A field the record lacks prints as empty, not "<no value>".
	for f, empty := range o.fields {
		if _, ok := m[f]; !ok {
			m[f] = empty
		}
	}
	if err := o.tmpl.Execute(o.w, m); err != nil {
		return fmt.Errorf("--format: %w", err)
	}
	_, err = io.WriteString(o.w, "\n")
	return err
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

// templateFields maps the first identifier of every .field reference in a
// template to the empty value a missing field gets: an empty list where the
// field is ranged over, an empty string anywhere else. Both print nothing
// and are false in an if.
func templateFields(n parse.Node) map[string]any {
	out := map[string]any{}
	var walk func(n parse.Node, ranged bool)
	walk = func(n parse.Node, ranged bool) {
		switch n := n.(type) {
		case *parse.ListNode:
			if n == nil {
				return
			}
			for _, c := range n.Nodes {
				walk(c, false)
			}
		case *parse.ActionNode:
			walk(n.Pipe, false)
		case *parse.PipeNode:
			if n == nil {
				return
			}
			for _, c := range n.Cmds {
				walk(c, ranged)
			}
		case *parse.CommandNode:
			for _, a := range n.Args {
				walk(a, ranged && len(n.Args) == 1)
			}
		case *parse.FieldNode:
			if _, seen := out[n.Ident[0]]; !seen || ranged {
				if ranged {
					out[n.Ident[0]] = []any{}
				} else {
					out[n.Ident[0]] = ""
				}
			}
		case *parse.ChainNode:
			walk(n.Node, false)
		case *parse.IfNode:
			walk(n.Pipe, false)
			walk(n.List, false)
			walk(n.ElseList, false)
		case *parse.RangeNode:
			walk(n.Pipe, true)
			walk(n.List, false)
			walk(n.ElseList, false)
		case *parse.WithNode:
			walk(n.Pipe, false)
			walk(n.List, false)
			walk(n.ElseList, false)
		}
	}
	walk(n, false)
	return out
}
