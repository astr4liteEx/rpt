package main

import (
	"io/fs"
	"maps"
	"os"
	"path/filepath"
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
	code, out, errOut := runIn(t, "", "set", "F-003", "severity", "critical", "--report", dir)
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
		wantInErr string
	}{
		{"unknown ID", []string{"F-404", "severity", "high"}, "no such finding: F-404"},
		{"refused key", []string{"F-003", "id", "F-010"}, "key can't be set: id: finding IDs are permanent"},
		{"bad severity", []string{"F-003", "severity", "urgent"}, `bad value: severity: "urgent" is not one of`},
		{"missing value", []string{"F-003", "severity"}, "usage: rpt set <id> <key> <value>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := reportCopy(t)
			before := folderState(t, dir)
			code, out, errOut := runIn(t, "", append([]string{"set", "--report", dir}, tt.args...)...)
			if code != 2 || out != "" {
				t.Errorf("exit %d, stdout %q; want 2 and nothing", code, out)
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
	code, out, errOut := runIn(t, "", "set", "--report", dir, "F-003", "offset", "--", "-1")
	if code != 0 || pick(t, out, "offset") != "-1\n" {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

func TestAdd(t *testing.T) {
	dir := reportCopy(t)
	foreign := `{"kind":"scope",  "id":"S-1"}`
	in := strings.Join([]string{
		`{"kind":"finding","title":"Telnet enabled","scope":["S-20"],"severity":"high","target":{"host":"10.0.1.9","port":23,"protocol":"tcp"},"sections":{"description":"Telnet accepts logins in plaintext."}}`,
		foreign,
		`{"kind":"finding","title":"No severity","scope":[]}`, // 3: refused
		`{"kind":"finding","title":"Weak password policy","scope":[],"severity":"medium"}`,
	}, "\n") + "\n"
	code, out, errOut := runIn(t, in, "add", "--report", dir)
	if code != 1 {
		t.Errorf("exit %d, want 1 for the refused record", code)
	}
	if want := "F-004 findings/F-004-telnet-enabled.md\nS-1 \nF-005 findings/F-005-weak-password-policy.md\n"; pick(t, out, "id", "path") != want {
		t.Errorf("stdout:\n%s", out)
	}
	if !strings.Contains(out, foreign+"\n") {
		t.Error("foreign record not passed through byte for byte")
	}
	if want := "rpt: stdin:3: bad value: severity \"\" is not one of [critical high medium low info]\n"; errOut != want {
		t.Errorf("stderr\n got: %q\nwant: %q", errOut, want)
	}
	for _, f := range []string{"F-004-telnet-enabled.md", "F-005-weak-password-policy.md"} {
		if _, err := os.Stat(filepath.Join(dir, "findings", f)); err != nil {
			t.Error(err)
		}
	}
}
