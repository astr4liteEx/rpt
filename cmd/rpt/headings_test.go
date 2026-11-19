package main

import (
	"encoding/json/v2"
	"maps"
	"os"
	"path/filepath"
	"testing"
)

// renamedReport is a new report whose config renames two fixed sections,
// holding one finding written with those headings.
func renamedReport(t *testing.T, config, finding string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "report")
	if code, _, errOut := runIn(t, "", "new", dir); code != 0 {
		t.Fatalf("new: exit %d, stderr %q", code, errOut)
	}
	if err := os.WriteFile(filepath.Join(dir, "rpt.yaml"), []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scope.csv"), []byte("id,host,port\nS-1,app.acme.com,\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if finding != "" {
		if err := os.WriteFile(filepath.Join(dir, "findings", "f.md"), []byte(finding), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const renamedConfig = "format: 2\nsections:\n  remediation: Recommendation\n  poc: Steps to reproduce\n"

func TestRenamedHeadingsRead(t *testing.T) {
	dir := renamedReport(t, renamedConfig, "---\nid: F-001\ntitle: XSS\ntargets: [{scope: S-1}]\nseverity: low\n---\n"+
		"\n## Description\n\nd\n\n## Recommendation\n\nr\n\n## Steps to reproduce\n\np\n\n## Remediation\n\nold\n")

	code, out, errOut := runIn(t, "", "findings", "--report", dir)
	if code != 0 || errOut != "" {
		t.Fatalf("findings: exit %d, stderr %q", code, errOut)
	}
	// The renamed headings fill the fixed keys; the old default heading is
	// now an ordinary custom section.
	want := map[string]string{"description": "d", "remediation": "r", "poc": "p", "Remediation": "old"}
	if got := sectionsOf(t, out); !maps.Equal(got, want) {
		t.Errorf("sections\n got: %v\nwant: %v", got, want)
	}

	if code, out, errOut := runIn(t, "", "validate", "--report", dir); code != 0 || out != "" {
		t.Errorf("validate: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

// sectionsOf returns the sections of the one finding record in jsonl.
func sectionsOf(t *testing.T, jsonl string) map[string]string {
	t.Helper()
	var rec struct {
		Sections map[string]string `json:"sections"`
	}
	if err := json.Unmarshal([]byte(jsonl), &rec); err != nil {
		t.Fatalf("not one finding record: %q: %v", jsonl, err)
	}
	return rec.Sections
}

func TestRenamedHeadingsAdd(t *testing.T) {
	dir := renamedReport(t, renamedConfig, "")
	in := `{"kind":"finding","title":"XSS","targets":[{"scope":"S-1"}],"severity":"low","sections":{"description":"d","remediation":"r","poc":"p","Impact":"i"}}` + "\n"
	if code, _, errOut := runIn(t, in, "findings", "add", "--report", dir); code != 0 {
		t.Fatalf("add: exit %d, stderr %q", code, errOut)
	}
	got, err := os.ReadFile(filepath.Join(dir, "findings", "F-001-xss.md"))
	if err != nil {
		t.Fatal(err)
	}
	want := "---\nid: F-001\ntitle: XSS\ntargets:\n  - {scope: S-1}\nseverity: low\n---\n" +
		"\n## Description\n\nd\n\n## Recommendation\n\nr\n\n## Steps to reproduce\n\np\n\n## Impact\n\ni\n"
	if string(got) != want {
		t.Errorf("finding file\n got: %q\nwant: %q", got, want)
	}
	if code, out, errOut := runIn(t, "", "validate", "--report", dir); code != 0 || out != "" {
		t.Errorf("validate: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

func TestFixedHeadingsIgnoreCase(t *testing.T) {
	dir := renamedReport(t, "format: 2\n", "---\nid: F-001\ntitle: XSS\ntargets: [{scope: S-1}]\nseverity: low\n---\n"+
		"## DESCRIPTION\n\nd\n\n## remediation\n\nr\n\n## Proof Of Concept\n\np\n")
	code, out, errOut := runIn(t, "", "findings", "--report", dir)
	if code != 0 || errOut != "" {
		t.Fatalf("findings: exit %d, stderr %q", code, errOut)
	}
	want := map[string]string{"description": "d", "remediation": "r", "poc": "p"}
	if got := sectionsOf(t, out); !maps.Equal(got, want) {
		t.Errorf("sections\n got: %v\nwant: %v", got, want)
	}
}

func TestSectionsConfigProblems(t *testing.T) {
	tests := []struct{ name, sections, want string }{
		{"a key that isn't a fixed section", "  impact: Impact\n",
			`sections renames "impact", which is not a fixed section; use one of description, remediation, poc`},
		{"an empty heading", "  poc: \"\"\n",
			`sections gives "poc" an empty heading`},
		{"two keys sharing a heading", "  remediation: description\n",
			`sections gives "description" and "remediation" the same heading "Description"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := renamedReport(t, "format: 2\nsections:\n"+tt.sections, "")
			code, out, _ := runIn(t, "", "validate", "--report", dir)
			want := "problem rpt.yaml 2 config error " + tt.want + "\n"
			if got := pick(t, out, "kind", "path", "line", "rule", "level", "message"); code != 1 || got != want {
				t.Errorf("exit %d\n got: %q\nwant: %q", code, got, want)
			}
		})
	}
}

func TestRequiredSectionByRenamedHeading(t *testing.T) {
	dir := renamedReport(t, renamedConfig+"required_sections: [Recommendation, steps to reproduce]\n",
		"---\nid: F-001\ntitle: XSS\ntargets: [{scope: S-1}]\nseverity: low\n---\n## Recommendation\n\nr\n\n## Steps to reproduce\n\np\n")
	if code, out, errOut := runIn(t, "", "validate", "--report", dir); code != 0 || out != "" {
		t.Errorf("validate: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}
