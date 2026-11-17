package cli

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/astr4liteEx/rpt/sdk"
)

var findings = []sdk.Finding{
	{Kind: "finding", ID: "F-003", Title: "SQL injection in login", Scope: []string{"S-12", "S-14"}, Severity: "high"},
	{Kind: "finding", ID: "F-001", Title: "Reflected XSS", Scope: []string{"S-14"}, Severity: "medium"},
}

var findingColumns = []Column{
	{Header: "ID", Field: "id"}, {Header: "SEVERITY", Field: "severity"}, {Header: "TITLE", Field: "title"}, {Header: "SCOPE", Field: "scope"},
}

func render(t *testing.T, terminal, jsonFlag bool) string {
	t.Helper()
	var buf bytes.Buffer
	out, err := NewOutput(&buf, terminal, jsonFlag, findingColumns)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if err := out.Write(f); err != nil {
			t.Fatal(err)
		}
	}
	if err := out.Flush(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestOutputModes(t *testing.T) {
	jsonl := `{"kind":"finding","id":"F-003","title":"SQL injection in login","scope":["S-12","S-14"],"severity":"high"}` + "\n" +
		`{"kind":"finding","id":"F-001","title":"Reflected XSS","scope":["S-14"],"severity":"medium"}` + "\n"
	tests := []struct {
		name     string
		terminal bool
		json     bool
		want     string
	}{
		{name: "pipe gets JSON Lines", want: jsonl},
		{name: "--json forces JSON Lines on a terminal", terminal: true, json: true, want: jsonl},
		{name: "terminal gets a table, lists joined with commas", terminal: true, want: "" +
			"ID     SEVERITY  TITLE                   SCOPE\n" +
			"F-003  high      SQL injection in login  S-12,S-14\n" +
			"F-001  medium    Reflected XSS           S-14\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := render(t, tt.terminal, tt.json); got != tt.want {
				t.Errorf("output\n got: %q\nwant: %q", got, tt.want)
			}
		})
	}
}

func TestOutputComputedColumn(t *testing.T) {
	var buf bytes.Buffer
	cols := []Column{
		{Header: "ID", Field: "id"},
		{Header: "WHERE", Value: func(m map[string]any) string { return fmt.Sprint(m["scope"]) + "\t!" }},
	}
	out, err := NewOutput(&buf, true, false, cols)
	if err != nil {
		t.Fatal(err)
	}
	if err := out.Write(findings[1]); err != nil {
		t.Fatal(err)
	}
	if err := out.Flush(); err != nil {
		t.Fatal(err)
	}
	if want := "ID     WHERE\nF-001  [S-14] !\n"; buf.String() != want {
		t.Errorf("table\n got: %q\nwant: %q", buf.String(), want)
	}
}

func TestOutputPassThrough(t *testing.T) {
	raw := []byte(`{"kind":"scope",  "id":"S-1","b":1,"a":2}`) // odd spacing and key order must survive
	tests := []struct {
		name     string
		terminal bool
		json     bool
		want     string
	}{
		{name: "JSON Lines writes the original bytes", want: string(raw) + "\n"},
		{name: "--json on a terminal too", terminal: true, json: true, want: string(raw) + "\n"},
		{name: "a table leaves foreign records out", terminal: true, want: "ID  SEVERITY  TITLE  SCOPE\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			out, err := NewOutput(&buf, tt.terminal, tt.json, findingColumns)
			if err != nil {
				t.Fatal(err)
			}
			if err := out.WriteRaw(raw); err != nil {
				t.Fatal(err)
			}
			if err := out.Flush(); err != nil {
				t.Fatal(err)
			}
			if got := buf.String(); got != tt.want {
				t.Errorf("output\n got: %q\nwant: %q", got, tt.want)
			}
		})
	}
}

func TestOutputWriteOwn(t *testing.T) {
	raw := []byte(`{"kind":"finding", "id":"F-003","title":"SQL injection in login","scope":["S-12","S-14"],"severity":"high"}`)
	tests := []struct {
		name     string
		terminal bool
		want     string
	}{
		{name: "JSON Lines keeps the original bytes", want: string(raw) + "\n"},
		{name: "a table shows the decoded record", terminal: true, want: "" +
			"ID     SEVERITY  TITLE                   SCOPE\n" +
			"F-003  high      SQL injection in login  S-12,S-14\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			out, err := NewOutput(&buf, tt.terminal, false, findingColumns)
			if err != nil {
				t.Fatal(err)
			}
			if err := out.WriteOwn(findings[0], raw); err != nil {
				t.Fatal(err)
			}
			if err := out.Flush(); err != nil {
				t.Fatal(err)
			}
			if got := buf.String(); got != tt.want {
				t.Errorf("output\n got: %q\nwant: %q", got, tt.want)
			}
		})
	}
}
