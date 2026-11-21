package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// problemFields are the members tests compare problem records by.
var problemFields = []string{"kind", "path", "line", "rule", "level", "command"}

func TestReadGivesProblemRecords(t *testing.T) {
	dir := brokenFixture(t)
	code, out, errOut := runIn(t, "", "finding", "get", "--report", dir)
	if code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	// The good findings, then the broken file as a problem record.
	want := "finding F-003    \nfinding F-002    \nfinding F-001    \nproblem  3 readable error finding get\n"
	if got := pick(t, out, "kind", "id", "line", "rule", "level", "command"); got != want {
		t.Errorf("stdout\n got: %q\nwant: %q", got, want)
	}
	if !strings.HasSuffix(pick(t, out, "path"), "findings/broken.md\n") {
		t.Errorf("the problem's path isn't findings/broken.md: %q", out)
	}
	if !strings.HasPrefix(errOut, "rpt: findings/broken.md:3: ") {
		t.Errorf("stderr %q: the problem also goes to stderr as text", errOut)
	}
}

func TestMissingIDIsAProblemRecord(t *testing.T) {
	code, out, errOut := runIn(t, "", "scope", "get", "--report", fixture, "S-20", "S-404")
	if code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	if got, want := pick(t, out, "kind", "id", "path", "rule", "level", "command"), "scope S-20    \nproblem  scope.csv exists error scope get\n"; got != want {
		t.Errorf("stdout\n got: %q\nwant: %q", got, want)
	}
	if !strings.Contains(errOut, "S-404") {
		t.Errorf("stderr %q lacks the ID", errOut)
	}
}

const (
	newFinding   = `{"kind":"finding","title":"New","severity":"low","targets":[{"scope":"S-12"}],"sections":{"description":"d"}}` + "\n"
	errorProblem = `{"kind":"problem","path":"x.xml","rule":"parse","level":"error","message":"bad","command":"parse-x"}` + "\n"
	warnProblem  = `{"kind":"problem","path":"x.xml","rule":"parse","level":"warning","message":"odd","command":"parse-x"}` + "\n"
)

// findingFiles lists the finding files in a report.
func findingFiles(t *testing.T, dir string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(dir, "findings", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestAnErrorOnStdinStopsAWrite(t *testing.T) {
	for _, tt := range []struct {
		name, in, wantOut, wantErr string
	}{
		{"an error problem passes on, silently", newFinding + errorProblem, errorProblem, ""},
		{"a line that isn't a record", newFinding + "{nope\n", "", "rpt: -:2: "},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := reportCopy(t)
			before := findingFiles(t, dir)
			code, out, errOut := runIn(t, tt.in, "finding", "add", "--report", dir)
			if code != 1 {
				t.Errorf("exit %d, want 1", code)
			}
			if tt.wantOut != "" && out != tt.wantOut {
				t.Errorf("stdout %q, want only the incoming problem %q", out, tt.wantOut)
			}
			if tt.wantOut == "" && pick(t, out, problemFields...) != "problem - 2 input error finding add\n" {
				t.Errorf("stdout %q, want one input problem", out)
			}
			if tt.wantErr == "" && errOut != "" || !strings.HasPrefix(errOut, tt.wantErr) {
				t.Errorf("stderr %q, want %q", errOut, tt.wantErr)
			}
			if after := findingFiles(t, dir); len(after) != len(before) {
				t.Errorf("wrote %d finding files", len(after)-len(before))
			}
		})
	}
}

func TestAWarningOnStdinPassesThrough(t *testing.T) {
	dir := reportCopy(t)
	code, out, errOut := runIn(t, warnProblem+newFinding, "finding", "add", "--report", dir)
	if code != 0 || !strings.HasPrefix(out, warnProblem) || !strings.Contains(out, `"title":"New"`) {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

func TestAnErrorOnStdinStopsAFilter(t *testing.T) {
	code, out, errOut := runIn(t, newFinding+errorProblem, "scope", "match", "--report", fixture)
	if code != 1 || out != errorProblem || errOut != "" {
		t.Errorf("exit %d, stdout %q, stderr %q; want 1 and only the problem", code, out, errOut)
	}
}

func TestAnErrorOnStdinStopsScopeAdd(t *testing.T) {
	dir := reportCopy(t)
	before, _ := os.ReadFile(filepath.Join(dir, "scope.csv"))
	code, out, _ := runIn(t, `{"kind":"scope","host":"new.example"}`+"\n"+errorProblem, "scope", "add", "--report", dir)
	after, _ := os.ReadFile(filepath.Join(dir, "scope.csv"))
	if code != 1 || out != errorProblem || string(after) != string(before) {
		t.Errorf("exit %d, stdout %q; scope.csv changed: %v", code, out, string(after) != string(before))
	}
}

func TestValidateProblemsNameTheCommand(t *testing.T) {
	code, out, errOut := runIn(t, "", "validate", "--report", fixture)
	if code != 1 || out == "" {
		t.Fatalf("exit %d, stdout %q", code, out)
	}
	for line := range strings.Lines(pick(t, out, "command")) {
		if line != "validate\n" {
			t.Errorf("a problem's command is %q, want validate", line)
		}
	}
	if strings.Count(errOut, "\n") != strings.Count(out, "\n") {
		t.Errorf("stderr has %d lines for %d problems:\n%s", strings.Count(errOut, "\n"), strings.Count(out, "\n"), errOut)
	}
}

func TestAssembleWarningsFollowTheReport(t *testing.T) {
	code, out, _ := runIn(t, "", "assemble", "--report", fixture)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	report, rest, _ := strings.Cut(out, "\n")
	if !strings.HasPrefix(report, `{"kind":"report"`) {
		t.Errorf("first line isn't the report: %.60q", report)
	}
	if got, want := pick(t, rest, problemFields...), "problem findings/tls-weak.md 5 scopeIDsExist warning assemble\n"; got != want {
		t.Errorf("after the report\n got: %q\nwant: %q", got, want)
	}
}
