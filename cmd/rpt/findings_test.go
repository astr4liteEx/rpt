package main

import (
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/astr4liteEx/rpt/sdk"
)

// findingsOut decodes rpt findings output into records keyed by ID.
func findingsOut(t *testing.T, jsonl string) map[string]sdk.Finding {
	t.Helper()
	out := map[string]sdk.Finding{}
	for line := range strings.Lines(jsonl) {
		var f sdk.Finding
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			t.Fatalf("not a finding record: %q: %v", line, err)
		}
		out[f.ID] = f
	}
	return out
}

func TestFindingsLinesFlag(t *testing.T) {
	code, out, errOut := runIn(t, "", "findings", "--report", fixture, "--json", "--lines")
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	l := findingsOut(t, out)["F-003"].Lines
	if l == nil || l.Frontmatter["severity"] != 5 || l.Sections["poc"].Heading != 17 || l.Sections["poc"].Text != 19 {
		t.Errorf("F-003 lines = %+v, want severity on 5 and poc at 17/19", l)
	}

	code, out, _ = runIn(t, "", "findings", "--report", fixture, "--json")
	if code != 0 || strings.Contains(out, `"lines"`) {
		t.Errorf("without --lines: exit %d, output carries lines: %s", code, out)
	}
}

func TestAddNeverWritesLines(t *testing.T) {
	dir := reportCopy(t)
	in := `{"kind":"finding","title":"Copied","scope":[],"severity":"low","lines":{"frontmatter":{"id":2}},"sections":{"description":"d"}}` + "\n"
	code, out, errOut := runIn(t, in, "add", "--report", dir, "--json")
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if strings.Contains(out, `"lines"`) {
		t.Errorf("add printed lines: %s", out)
	}
	b, err := os.ReadFile(filepath.Join(dir, "findings/F-004-copied.md"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "lines") {
		t.Errorf("lines written into the file:\n%s", b)
	}
}

func TestSetRefusesLinesAndPrintsNone(t *testing.T) {
	dir := reportCopy(t)
	code, _, errOut := runIn(t, "", "set", "--report", dir, "F-003", "lines", "{}")
	if code != 2 || !strings.Contains(errOut, "key can't be set: lines") {
		t.Errorf("set lines: exit %d, stderr %q", code, errOut)
	}
	code, out, _ := runIn(t, "", "set", "--report", dir, "--json", "F-003", "severity", "low")
	if code != 0 || strings.Contains(out, `"lines"`) {
		t.Errorf("set: exit %d, output carries lines: %s", code, out)
	}
}
