package main

import (
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// reportCopy gives a test its own writable copy of the fixture report.
func reportCopy(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "report")
	if err := os.CopyFS(dir, os.DirFS(fixture)); err != nil {
		t.Fatal(err)
	}
	return dir
}

// folderState reads every file under dir with its mode and modification time.
func folderState(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		info, _ := d.Info()
		files[p] = info.Mode().String() + info.ModTime().String() + "\n" + string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// Done-when: rpt set changes exactly one value.
func TestSetChangesOneValue(t *testing.T) {
	dir := reportCopy(t)
	before, _ := os.ReadFile(filepath.Join(dir, "findings/sqli-login.md"))
	// Flags after the positional arguments work too.
	code, out, errOut := runIn(t, "", "finding", "set", "F-003", "severity", "critical", "--report", dir)
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if got := pick(t, out, "id", "severity"); got != "F-003 critical\n" {
		t.Errorf("stdout = %q", got)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "findings/sqli-login.md"))
	b, a := strings.Split(string(before), "\n"), strings.Split(string(after), "\n")
	if len(a) != len(b) {
		t.Fatalf("line count %d -> %d", len(b), len(a))
	}
	var changed []string
	for i := range b {
		if a[i] != b[i] {
			changed = append(changed, a[i])
		}
	}
	if len(changed) != 1 || changed[0] != "severity: critical" {
		t.Errorf("changed lines = %q, want only severity: critical", changed)
	}
}

func TestSetUsageErrors(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantCode  int
		wantInErr string
		wantOut   string // the problem's rule
	}{
		// What was asked is wrong: exit 1 and a problem. Bad syntax: exit 2.
		{"unknown ID", []string{"F-404", "severity", "high"}, 1, "no such finding: F-404", "problem exists\n"},
		{"refused key", []string{"F-003", "kind", "scope"}, 1, "key can't be set: kind: kind is not stored in the file", "problem write\n"},
		{"empty title", []string{"F-003", "title", ""}, 1, `bad value: title: must not be empty`, "problem write\n"},
		{"missing value", []string{"F-003", "severity"}, 2, "usage: rpt finding set [--if-rev rev] [--dry-run] <id> <path> <value>...", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := reportCopy(t)
			before := folderState(t, dir)
			code, out, errOut := runIn(t, "", append([]string{"finding", "set", "--report", dir}, tt.args...)...)
			if out != "" {
				out = pick(t, out, "kind", "rule")
			}
			if code != tt.wantCode || out != tt.wantOut {
				t.Errorf("exit %d, stdout %q; want %d and %q", code, out, tt.wantCode, tt.wantOut)
			}
			if !strings.Contains(errOut, tt.wantInErr) {
				t.Errorf("stderr = %q, want %q", errOut, tt.wantInErr)
			}
			if !maps.Equal(before, folderState(t, dir)) {
				t.Error("folder changed")
			}
		})
	}
}

func TestSetValueStartingWithDash(t *testing.T) {
	dir := reportCopy(t)
	code, out, errOut := runIn(t, "", "finding", "set", "--report", dir, "F-003", "offset", "--", "-1")
	if code != 0 || pick(t, out, "offset") != "-1\n" {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

func TestAdd(t *testing.T) {
	dir := reportCopy(t)
	foreign := `{"kind":"scope",  "id":"S-1"}`
	in := strings.Join([]string{
		`{"kind":"finding","title":"Telnet enabled","targets":[{"scope":"S-20","host":"10.0.1.9","port":23,"protocol":"tcp"}],"severity":"high","sections":{"description":"Telnet accepts logins in plaintext."}}`,
		foreign,
		`{"kind":"finding","title":"No severity","targets":[]}`, // 3: refused
		`{"kind":"finding","title":"Weak password policy","targets":[{"scope":"S-12"}],"severity":"medium"}`,
		`{"kind":"finding","title":"Old shape","scope":["S-12"],"severity":"low"}`,                     // 5: refused
		`{"kind":"finding","title":"Not attributed","targets":[{"host":"10.0.0.5"}],"severity":"low"}`, // 6: refused
	}, "\n") + "\n"
	// Three refused records: every one is reported, and nothing is written.
	code, out, errOut := runIn(t, in, "finding", "add", "--report", dir)
	if code != 1 {
		t.Errorf("exit %d, want 1 for the refused records", code)
	}
	if want := "problem - 3 write\nproblem - 5 write\nproblem - 6 write\n"; pick(t, out, "kind", "path", "line", "rule") != want {
		t.Errorf("stdout:\n%s", out)
	}
	if want := "rpt: -:3: bad value: severity is required\n" +
		"rpt: -:5: bad value: scope is from report format 1; it is now targets, a list like [{scope: S-12}] (format 2)\n" +
		"rpt: -:6: bad value: targets[0]: 10.0.0.5 has no scope ID; run it through rpt scope match first, or add scope\n"; errOut != want {
		t.Errorf("stderr\n got: %q\nwant: %q", errOut, want)
	}
	if _, err := os.Stat(filepath.Join(dir, "findings", "F-004-telnet-enabled.md")); err == nil {
		t.Error("a record was written though others were refused")
	}

	// Without the refused records, every finding is written in one go.
	in = strings.Join(slices.Delete(strings.Split(in, "\n"), 2, 3), "\n")
	in = strings.Join(slices.DeleteFunc(strings.Split(in, "\n"), func(l string) bool {
		return strings.Contains(l, "Old shape") || strings.Contains(l, "Not attributed")
	}), "\n")
	code, out, errOut = runIn(t, in, "finding", "add", "--report", dir)
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if want := "F-004 findings/F-004-telnet-enabled.md\nS-1 \nF-005 findings/F-005-weak-password-policy.md\n"; pick(t, out, "id", "path") != want {
		t.Errorf("stdout:\n%s", out)
	}
	if !strings.Contains(out, foreign+"\n") {
		t.Error("foreign record not passed through byte for byte")
	}
	for _, f := range []string{"F-004-telnet-enabled.md", "F-005-weak-password-policy.md"} {
		if _, err := os.Stat(filepath.Join(dir, "findings", f)); err != nil {
			t.Error(err)
		}
	}
}
