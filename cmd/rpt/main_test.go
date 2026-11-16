package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixture is absolute because tests change into a temporary directory.
var fixture = func() string {
	p, err := filepath.Abs("../../testdata/fixture")
	if err != nil {
		panic(err)
	}
	return p
}()

// brokenFixture is a copy of the fixture with one malformed finding file.
func brokenFixture(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "report")
	if err := os.CopyFS(dir, os.DirFS(fixture)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "findings", "broken.md"), []byte("---\nid: F-009\ntitle: : bad\n---\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRun(t *testing.T) {
	jsonl := func(ids ...string) func(string) bool {
		return func(out string) bool {
			lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
			if len(lines) != len(ids) {
				return false
			}
			for i, id := range ids {
				if !strings.HasPrefix(lines[i], `{"kind":"finding","id":"`+id+`"`) {
					return false
				}
			}
			return true
		}
	}
	exactly := func(want string) func(string) bool { return func(out string) bool { return out == want } }

	tests := []struct {
		name      string
		args      []string
		env       string // RPT_REPORT_DIR
		wantCode  int
		wantOut   func(string) bool
		wantInErr string
	}{
		{name: "no verb prints usage and exits 2", wantCode: 2, wantOut: exactly(""), wantInErr: "usage: rpt <verb>"},
		{name: "unknown verb exits 2", args: []string{"frobnicate"}, wantCode: 2, wantOut: exactly(""), wantInErr: `unknown verb "frobnicate"`},
		{
			name:     "findings into a pipe is JSON Lines",
			args:     []string{"findings", "--report", fixture},
			wantCode: 0, wantOut: jsonl("F-003", "F-002", "F-001"),
		},
		{
			name:     "findings --format with a shell-escaped tab",
			args:     []string{"findings", "--report", fixture, "--format", `{{.id}}\t{{.severity}}`},
			wantCode: 0, wantOut: exactly("F-003\thigh\nF-002\tinfo\nF-001\tmedium\n"),
		},
		{
			name:     "findings finds the report through RPT_REPORT_DIR",
			args:     []string{"findings", "--format", "{{.id}}"},
			env:      fixture,
			wantCode: 0, wantOut: exactly("F-003\nF-002\nF-001\n"),
		},
		{
			name:     "a broken finding is reported, the rest still printed, exit 1",
			args:     []string{"findings", "--format", "{{.id}}"},
			env:      "BROKEN",
			wantCode: 1, wantOut: exactly("F-003\nF-002\nF-001\n"),
			wantInErr: "rpt: findings/broken.md:3: ",
		},
		{
			name:     "--json with --format is a usage error",
			args:     []string{"findings", "--report", fixture, "--json", "--format", "{{.id}}"},
			wantCode: 2, wantOut: exactly(""), wantInErr: "--json and --format",
		},
		{
			name:     "an unknown flag is a usage error",
			args:     []string{"findings", "--nope"},
			wantCode: 2, wantOut: exactly(""), wantInErr: "flag provided but not defined: -nope",
		},
		{
			name:     "no report anywhere exits 2",
			args:     []string{"findings"},
			wantCode: 2, wantOut: exactly(""), wantInErr: "rpt: no report",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := tt.env
			if env == "BROKEN" {
				env = brokenFixture(t)
			}
			t.Setenv("RPT_REPORT_DIR", env)
			t.Chdir(t.TempDir())
			var stdout, stderr bytes.Buffer
			code := run(tt.args, strings.NewReader(""), &stdout, &stderr)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d (stderr %q)", code, tt.wantCode, stderr.String())
			}
			if !tt.wantOut(stdout.String()) {
				t.Errorf("stdout = %q", stdout.String())
			}
			if !strings.Contains(stderr.String(), tt.wantInErr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.wantInErr)
			}
		})
	}
}
