package cli

import (
	"bytes"
	"fmt"
	"github.com/charmbracelet/x/ansi"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// listRec is a record with a list member, to show how tables render lists.
type listRec struct {
	Kind     string   `json:"kind"`
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Scope    []string `json:"scope"`
	Severity string   `json:"severity"`
}

var findings = []listRec{
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
			"╭───────┬──────────┬────────────────────────┬───────────╮\n" +
			"│ ID    │ SEVERITY │ TITLE                  │ SCOPE     │\n" +
			"├───────┼──────────┼────────────────────────┼───────────┤\n" +
			"│ F-003 │ high     │ SQL injection in login │ S-12,S-14 │\n" +
			"│ F-001 │ medium   │ Reflected XSS          │ S-14      │\n" +
			"╰───────┴──────────┴────────────────────────┴───────────╯\n"},
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
	if want := "╭───────┬──────────╮\n│ ID    │ WHERE    │\n├───────┼──────────┤\n│ F-001 │ [S-14] ! │\n╰───────┴──────────╯\n"; buf.String() != want {
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
		{name: "a table leaves foreign records out", terminal: true, want: ""},
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
			"╭───────┬──────────┬────────────────────────┬───────────╮\n" +
			"│ ID    │ SEVERITY │ TITLE                  │ SCOPE     │\n" +
			"├───────┼──────────┼────────────────────────┼───────────┤\n" +
			"│ F-003 │ high     │ SQL injection in login │ S-12,S-14 │\n" +
			"╰───────┴──────────┴────────────────────────┴───────────╯\n"},
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

func TestEmptyTableIsSilent(t *testing.T) {
	var buf bytes.Buffer
	out, err := NewOutput(&buf, true, false, findingColumns)
	if err != nil {
		t.Fatal(err)
	}
	if err := out.Flush(); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Errorf("a table with no rows printed %q; want nothing, not a bare header", buf.String())
	}
}

func TestSeverityTotals(t *testing.T) {
	recs := []map[string]any{{"severity": "high"}, {"severity": "low"}, {"severity": "high"}, {"severity": "odd"}}
	if got := ansi.Strip(SeverityTotals([]string{"critical", "high", "low"})(recs)); got != "4 findings · high 2 · low 1 · odd 1" {
		t.Errorf("got %q", got)
	}
}

func TestMarkdownCopiesClean(t *testing.T) {
	md := "## Description\n\n" + strings.Repeat("word ", 30) + "\n\n```\n" + strings.Repeat("x", 100) + "\n```\n"
	got := Markdown(md)
	for _, l := range strings.Split(got, "\n") {
		if strings.HasSuffix(l, " ") {
			t.Errorf("trailing space: %q", l)
		}
		if len(l) > ReadingWidth && !strings.HasPrefix(l, "x") {
			t.Errorf("prose not wrapped: %q", l)
		}
	}
	if !strings.Contains(got, strings.Repeat("x", 100)) {
		t.Error("code was wrapped")
	}
}

func TestReadingViewSharesRules(t *testing.T) {
	var buf bytes.Buffer
	v := NewReadingView(&buf)
	_ = v.Record("F-001", "One", Facts("high", "S-1"), "Body one.")
	_ = v.Record("F-002", "Two", "", "")
	rule := strings.Repeat("─", ReadingWidth)
	want := rule + "\nF-001  One\nhigh  ·  S-1\n" + rule + "\n\nBody one.\n\n" + rule + "\nF-002  Two\n" + rule + "\n" + rule + "\n"
	if buf.String() != want {
		t.Errorf("got\n%s\nwant\n%s", buf.String(), want)
	}
}

func TestDiagnostics(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.md"), []byte("---\ntitle: [broken\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	d := NewDiagnostics(&buf)
	d.Root = dir
	d.Print(Diagnostic{Path: "f.md", Rule: "readable", Message: "bad yaml", Error: true, Line: 2, Column: 8, End: 14})
	d.Print(Diagnostic{Path: "g.md", Message: "missing section"})
	d.Totals()
	want := "error[readable] bad yaml\n  --> f.md:2:8\n   |\n 2 | title: [broken\n   |        ^^^^^^^\n\n" +
		"warning missing section\n  --> g.md\n\n1 error, 1 warning\n"
	if buf.String() != want {
		t.Errorf("got\n%s\nwant\n%s", buf.String(), want)
	}
}
