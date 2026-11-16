package cli

import (
	"bytes"
	"testing"

	"github.com/astr4liteEx/rpt/sdk"
)

var findings = []sdk.Finding{
	{Kind: "finding", ID: "F-003", Title: "SQL injection in login", Scope: []string{"S-12", "S-14"}, Severity: "high"},
	{Kind: "finding", ID: "F-001", Title: "Reflected XSS", Scope: []string{"S-14"}, Severity: "medium"},
}

var findingColumns = []Column{{"ID", "id"}, {"SEVERITY", "severity"}, {"TITLE", "title"}, {"SCOPE", "scope"}}

func render(t *testing.T, terminal, jsonFlag bool, format string) string {
	t.Helper()
	var buf bytes.Buffer
	out, err := NewOutput(&buf, terminal, jsonFlag, format, findingColumns)
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
		format   string
		want     string
	}{
		{name: "pipe gets JSON Lines", want: jsonl},
		{name: "--json forces JSON Lines on a terminal", terminal: true, json: true, want: jsonl},
		{name: "--format with shell-escaped tab", format: `{{.id}}\t{{.severity}}`, want: "F-003\thigh\nF-001\tmedium\n"},
		{name: "--format wins over the terminal table", terminal: true, format: `{{.id}}`, want: "F-003\nF-001\n"},
		{name: "--format missing field prints empty", format: `{{.id}}|{{.cvss}}|`, want: "F-003||\nF-001||\n"},
		{name: "--format missing field inside if and range", format: `{{if .cvss}}x{{end}}{{range .refs}}r{{end}}{{.id}}`, want: "F-003\nF-001\n"},
		{name: "terminal gets a table, lists joined with commas", terminal: true, want: "" +
			"ID     SEVERITY  TITLE                   SCOPE\n" +
			"F-003  high      SQL injection in login  S-12,S-14\n" +
			"F-001  medium    Reflected XSS           S-14\n"},
		{name: "--format sees arrays as lists", format: `{{range .scope}}{{.}} {{end}}`, want: "S-12 S-14 \nS-14 \n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := render(t, tt.terminal, tt.json, tt.format); got != tt.want {
				t.Errorf("output\n got: %q\nwant: %q", got, tt.want)
			}
		})
	}
}

func TestNewOutputRejectsBadFlags(t *testing.T) {
	tests := []struct {
		name   string
		json   bool
		format string
	}{
		{"--json with --format", true, "{{.id}}"},
		{"unparsable template", false, "{{.id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if _, err := NewOutput(&buf, false, tt.json, tt.format, nil); err == nil {
				t.Error("NewOutput succeeded, want a usage error")
			}
		})
	}
}
