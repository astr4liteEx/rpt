package main

import (
	"encoding/json/v2"
	"maps"
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
	code, out, errOut := runIn(t, in, "findings", "add", "--report", dir, "--json")
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
	code, _, errOut := runIn(t, "", "findings", "set", "--report", dir, "F-003", "lines", "{}")
	if code != 1 || !strings.Contains(errOut, "key can't be set: lines") {
		t.Errorf("set lines: exit %d, stderr %q", code, errOut)
	}
	code, out, _ := runIn(t, "", "findings", "set", "--report", dir, "--json", "F-003", "severity", "low")
	if code != 0 || strings.Contains(out, `"lines"`) {
		t.Errorf("set: exit %d, output carries lines: %s", code, out)
	}
}

// linesFiles runs rpt findings --json --lines in dir with args and returns
// each finding's lines.file.
func linesFiles(t *testing.T, dir string, args ...string) []string {
	t.Helper()
	t.Chdir(dir)
	code, out, errOut := runIn(t, "", append([]string{"findings", "--json", "--lines"}, args...)...)
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	var files []string
	for _, f := range findingsOut(t, out) {
		files = append(files, f.Lines.File)
	}
	return files
}

func TestLinesFileIsAbsolute(t *testing.T) {
	t.Setenv("RPT_REPORT_DIR", "")
	base := t.TempDir()
	report := filepath.Join(base, "acme")
	if err := os.CopyFS(report, os.DirFS(fixture)); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(base, "other")
	if err := os.CopyFS(other, os.DirFS(fixture)); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "via-link")
	if err := os.Symlink(report, link); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name, dir string
		args      []string
		wantIn    string // folder every file must sit in
	}{
		{"found from a report subfolder", filepath.Join(report, "findings", "evidence"), nil, filepath.Join(report, "findings")},
		{"relative --report", report, []string{"--report", "../other"}, filepath.Join(other, "findings")},
		{"symlinked report keeps the link", link, nil, filepath.Join(link, "findings")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := linesFiles(t, tt.dir, tt.args...)
			if len(files) != 3 {
				t.Fatalf("got %d files, want 3", len(files))
			}
			for _, f := range files {
				if filepath.Dir(f) != tt.wantIn {
					t.Errorf("file %q is not in %s", f, tt.wantIn)
				}
				if info, err := os.Stat(f); err != nil || !info.Mode().IsRegular() {
					t.Errorf("file %q: not a regular file (%v)", f, err)
				}
			}
		})
	}
}

func TestFindingsAddFromFlagsWritesABlankFinding(t *testing.T) {
	dir := reportCopy(t)
	code, out, errOut := runIn(t, `{"kind":"finding","title":"ignored","severity":"low"}`+"\n",
		"findings", "add", "--report", dir, "--title", "SQL injection", "--severity", "high", "--scope", "S-12,S-14")
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if got := pick(t, out, "id", "path"); got != "F-004 findings/F-004-sql-injection.md\n" {
		t.Errorf("stdout = %q, want one finding from the flags (stdin unread)", got)
	}
	b, err := os.ReadFile(filepath.Join(dir, "findings/F-004-sql-injection.md"))
	if err != nil {
		t.Fatal(err)
	}
	want := "---\nid: F-004\ntitle: SQL injection\nscope: [S-12, S-14]\nseverity: high\n---\n" +
		"## Description\n\n\n## Remediation\n\n\n## Proof of concept\n\n"
	if string(b) != want {
		t.Errorf("file\n%q\nwant\n%q", b, want)
	}
}

func TestFindingsAddFlagsNeedTitleAndSeverity(t *testing.T) {
	dir := reportCopy(t)
	for _, args := range [][]string{{"--title", "T"}, {"--severity", "high"}, {"--scope", "S-12"}} {
		code, _, errOut := runIn(t, "", append([]string{"findings", "add", "--report", dir}, args...)...)
		if code != 2 || !strings.Contains(errOut, "usage: rpt findings add") {
			t.Errorf("%v: exit %d, stderr %q; want 2 and usage", args, code, errOut)
		}
	}
	if code, _, errOut := runIn(t, "", "findings", "add", "--report", dir, "--title", "T", "--severity", "high", "--id", "F-010"); code != 0 {
		t.Errorf("--id: exit %d, stderr %q", code, errOut)
	} else if _, err := os.Stat(filepath.Join(dir, "findings/F-010-t.md")); err != nil {
		t.Error(err)
	}
}

func TestFindingsAddScaffold(t *testing.T) {
	dir := reportCopy(t)
	in := `{"kind":"finding","title":"Half done","scope":[],"severity":"low","sections":{"description":"Known so far."}}` + "\n"
	if code, _, errOut := runIn(t, in, "findings", "add", "--scaffold", "--report", dir); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "findings/F-004-half-done.md"))
	want := "---\nid: F-004\ntitle: Half done\nscope: []\nseverity: low\n---\n" +
		"## Description\n\nKnown so far.\n\n## Remediation\n\n\n## Proof of concept\n\n"
	if string(b) != want {
		t.Errorf("file\n%q\nwant\n%q", b, want)
	}
}

func TestFindingsUnset(t *testing.T) {
	dir := reportCopy(t)
	file := filepath.Join(dir, "findings/F-009-x.md")
	src := "---\r\nid: F-009\r\ntitle: X\r\nscope: [S-12]\r\n# scored by hand\r\ncvss: \"9.1\"   # v3.1\r\n" +
		"target:\r\n  host: 10.0.0.5\r\n  port: 443\r\nseverity: low\r\n---\r\n## Description\r\n\r\nd\r\n"
	if err := os.WriteFile(file, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runIn(t, "", "findings", "unset", "--report", dir, "F-009", "target", "cvss", "not-there")
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if strings.Contains(out, "cvss") || strings.Contains(out, "target") {
		t.Errorf("printed finding still has the keys: %s", out)
	}
	// The comment above cvss stays: it may describe what follows.
	want := "---\r\nid: F-009\r\ntitle: X\r\nscope: [S-12]\r\n# scored by hand\r\nseverity: low\r\n---\r\n## Description\r\n\r\nd\r\n"
	if b, _ := os.ReadFile(file); string(b) != want {
		t.Errorf("file\n%q\nwant\n%q", b, want)
	}
}

func TestFindingsUnsetRefuses(t *testing.T) {
	for _, key := range []string{"id", "title", "scope", "severity", "kind", "path", "sections", "lines"} {
		dir := reportCopy(t)
		before := folderState(t, dir)
		code, _, errOut := runIn(t, "", "findings", "unset", "--report", dir, "F-003", "cvss", key)
		if code != 1 || !strings.Contains(errOut, "key can't be unset: "+key) {
			t.Errorf("unset %s: exit %d, stderr %q; want 1", key, code, errOut)
		}
		if !maps.Equal(before, folderState(t, dir)) {
			t.Errorf("unset %s: folder changed; a refused key must stop every change", key)
		}
	}
	if code, _, _ := runIn(t, "", "findings", "unset", "--report", reportCopy(t), "F-404", "cvss"); code != 1 {
		t.Errorf("unknown ID: exit %d, want 1", code)
	}
}
