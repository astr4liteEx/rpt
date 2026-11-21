package main

import (
	"bytes"
	"encoding/json/v2"
	"fmt"
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

// pick reads JSON Lines and returns, for each record, the named fields
// joined with spaces, one line per record; a missing field is empty.
func pick(t *testing.T, jsonl string, fields ...string) string {
	t.Helper()
	var out strings.Builder
	for line := range strings.Lines(jsonl) {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("not JSON Lines: %q: %v", line, err)
		}
		vals := make([]string, len(fields))
		for i, f := range fields {
			if v, ok := m[f]; ok {
				vals[i] = fmt.Sprint(v)
			}
		}
		out.WriteString(strings.Join(vals, " ") + "\n")
	}
	return out.String()
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
	ids := func(want string) func(string) bool {
		return func(out string) bool { return pick(t, out, "id") == want }
	}

	tests := []struct {
		name      string
		args      []string
		env       string // RPT_REPORT_DIR
		wantCode  int
		wantOut   func(string) bool
		wantInErr string
	}{
		{name: "no command prints usage and exits 2", wantCode: 2, wantOut: exactly(""), wantInErr: "usage: rpt <command>"},
		{name: "unknown command exits 2", args: []string{"frobnicate"}, wantCode: 2, wantOut: exactly(""), wantInErr: `unknown command "frobnicate"`},
		{
			name:     "finding get into a pipe is JSON Lines",
			args:     []string{"finding", "get", "--report", fixture},
			wantCode: 0, wantOut: jsonl("F-003", "F-002", "F-001"),
		},
		{
			name:     "finding get finds the report through RPT_REPORT_DIR",
			args:     []string{"finding", "get"},
			env:      fixture,
			wantCode: 0, wantOut: ids("F-003\nF-002\nF-001\n"),
		},
		{
			name:     "a broken finding is reported, the rest still printed, exit 1",
			args:     []string{"finding", "get"},
			env:      "BROKEN",
			wantCode: 1, wantOut: ids("F-003\nF-002\nF-001\n\n"), // then the problem record
			wantInErr: "rpt: findings/broken.md:3: ",
		},
		{
			name:     "--format is gone: use jq",
			args:     []string{"finding", "get", "--report", fixture, "--format", "{{.id}}"},
			wantCode: 2, wantOut: exactly(""), wantInErr: "unknown flag: --format",
		},
		{
			name:     "an unknown flag is a usage error",
			args:     []string{"finding", "get", "--nope"},
			wantCode: 2, wantOut: exactly(""), wantInErr: "unknown flag: --nope",
		},
		{
			name:     "no report anywhere exits 1",
			args:     []string{"finding", "get"},
			wantCode: 1, wantOut: exactly(""), wantInErr: "rpt: no report",
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
