package main

import (
	"encoding/json/v2"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// fixedReport is a copy of the fixture with its planted problem fixed.
func fixedReport(t *testing.T) string {
	t.Helper()
	dir := reportCopy(t)
	p := filepath.Join(dir, "findings/tls-weak.md")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(strings.Replace(string(b), "{scope: S-99}", "{scope: S-12}", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// Done-when: validate exits 1 on the fixture and 0 once its problem is fixed.
func TestValidateVerb(t *testing.T) {
	code, out, errOut := runIn(t, "", "validate", "--report", fixture)
	if code != 1 || errOut != "" {
		t.Errorf("fixture: exit %d, stderr %q; want 1 and nothing", code, errOut)
	}
	if got := pick(t, out, "path", "line", "level", "rule"); got != "findings/tls-weak.md 5 error scopeIDsExist\n" {
		t.Errorf("fixture problems = %q", got)
	}

	code, out, errOut = runIn(t, "", "validate", "--report", fixedReport(t))
	if code != 0 || out != "" || errOut != "" {
		t.Errorf("fixed: exit %d, stdout %q, stderr %q; want 0 and nothing", code, out, errOut)
	}
}

func TestValidateWarningsExitZero(t *testing.T) {
	dir := fixedReport(t)
	if err := os.WriteFile(filepath.Join(dir, "rpt.yaml"), append(mustRead(t, filepath.Join(dir, "rpt.yaml")), "logo: acme.png\n"...), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ := runIn(t, "", "validate", "--report", dir)
	if code != 0 || pick(t, out, "level", "rule") != "warning configUnknownKey\n" {
		t.Errorf("exit %d, stdout %q; want 0 and one warning", code, out)
	}
}

// Done-when: assemble matches the golden report.
func TestAssembleVerb(t *testing.T) {
	code, out, errOut := runIn(t, "", "assemble", "--report", fixture)
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if want := "rpt: findings/tls-weak.md:5: warning: \"S-99\" is not in scope.csv; target left out of the finding\n"; errOut != want {
		t.Errorf("stderr\n got: %q\nwant: %q", errOut, want)
	}
	if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
		t.Errorf("stdout is not one JSON line: %q", out)
	}
	golden := strings.ReplaceAll(string(mustRead(t, "../../testdata/assemble.golden.json")), "$REPORT", fixture)
	var got, want any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(golden), &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("assembled report differs from testdata/assemble.golden.json:\n%s", out)
	}
}

func TestAssembleErrors(t *testing.T) {
	broken := reportCopy(t)
	if err := os.WriteFile(filepath.Join(broken, "rpt.yaml"), []byte("format: [1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		args      []string
		wantCode  int
		wantInErr string
	}{
		{"unreadable config: nothing to assemble", []string{"assemble", "--report", broken}, 1, "rpt: rpt.yaml:"},
		{"--draft is gone: assemble never refuses", []string{"assemble", "--report", fixture, "--draft"}, 2, "flag provided but not defined: -draft"},
		{"no arguments", []string{"assemble", "--report", fixture, "extra"}, 2, "usage: rpt assemble"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, errOut := runIn(t, "", tt.args...)
			if code != tt.wantCode || out != "" || !strings.Contains(errOut, tt.wantInErr) {
				t.Errorf("exit %d, stdout %q, stderr %q; want %d, nothing, %q", code, out, errOut, tt.wantCode, tt.wantInErr)
			}
		})
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
