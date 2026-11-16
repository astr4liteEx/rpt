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
	code, out, errOut := runIn(t, "", "set", "F-003", "severity", "critical", "--report", dir, "--format", "{{.id}} {{.severity}}")
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if out != "F-003 critical\n" {
		t.Errorf("stdout = %q", out)
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

const telnet = `{"kind":"finding","key":"9c1d0e7f2a3b4c5d","title":"Telnet enabled","scope":["S-20"],"severity":"high","target":{"host":"10.0.1.9","port":23,"protocol":"tcp"},"sections":{"description":"Telnet accepts logins in plaintext."}}`

// Done-when: rpt add --upsert run twice leaves the folder unchanged.
func TestAddUpsertTwice(t *testing.T) {
	dir := reportCopy(t)
	foreign := `{"kind":"scope",  "id":"S-1"}`
	in := telnet + "\n" + foreign + "\n"
	args := []string{"add", "--report", dir, "--staging", "--upsert", "--format", "{{.id}} {{.path}}"}

	code, out, errOut := runIn(t, in, args[:len(args)-2]...) // JSON Lines
	if code != 0 || errOut != "" {
		t.Fatalf("first run: exit %d, stderr %q", code, errOut)
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], `{"kind":"finding","id":"F-006","key":"9c1d0e7f2a3b4c5d"`) ||
		!strings.Contains(lines[0], `"path":"staging/F-006-telnet-enabled.md"`) || lines[1] != foreign {
		t.Errorf("first run stdout:\n%s", out)
	}

	before := folderState(t, dir)
	code, out, errOut = runIn(t, in, args...)
	if code != 0 || errOut != "" {
		t.Fatalf("second run: exit %d, stderr %q", code, errOut)
	}
	if out != "F-006 staging/F-006-telnet-enabled.md\n" {
		t.Errorf("second run stdout = %q", out)
	}
	if !maps.Equal(before, folderState(t, dir)) {
		t.Error("second run changed the folder")
	}
}

func TestAddSkipsAndRefuses(t *testing.T) {
	dir := reportCopy(t)
	in := strings.Join([]string{
		`{"kind":"finding","key":"01b9b837704da8cf","title":"Open redirect in logout","scope":["S-14"],"severity":"low"}`, // 1: rejected
		`{"kind":"finding","title":"No severity","scope":[]}`,                                                             // 2: refused
		`{"kind":"finding","title":"Weak password policy","scope":[],"severity":"medium"}`,                                // 3: new
	}, "\n") + "\n"
	code, out, errOut := runIn(t, in, "add", "--report", dir, "--staging", "--upsert", "--format", "{{.id}} {{.path}}")
	if code != 1 {
		t.Errorf("exit %d, want 1 for the refused record", code)
	}
	if out != "F-006 staging/F-006-weak-password-policy.md\n" {
		t.Errorf("stdout = %q", out)
	}
	wantErr := "rpt: rejected/F-005-open-redirect.md: kept F-005, already reviewed\n" +
		"rpt: stdin:2: bad value: severity \"\" is not one of [critical high medium low info]\n"
	if errOut != wantErr {
		t.Errorf("stderr\n got: %q\nwant: %q", errOut, wantErr)
	}
}

func TestFindingsStaging(t *testing.T) {
	code, out, errOut := runIn(t, "", "findings", "--staging", "--report", fixture, "--format", "{{.id}} {{.path}}")
	if code != 0 || errOut != "" || out != "F-004 staging/F-004-ssh-weak-ciphers.md\n" {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

func TestSetValueStartingWithDash(t *testing.T) {
	dir := reportCopy(t)
	code, out, errOut := runIn(t, "", "set", "--report", dir, "--format", "{{.offset}}", "F-003", "offset", "--", "-1")
	if code != 0 || out != "-1\n" {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}
