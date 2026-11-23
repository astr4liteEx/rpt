package main

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/astr4liteEx/rpt/internal/plugin"
)

// fixture copies testdata/fixture into a temporary folder, makes it the
// report every command acts on, and returns its path.
func fixture(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "report")
	if err := os.CopyFS(dir, os.DirFS("../../testdata/fixture")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RPT_REPORT_DIR", dir)
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("PATH", "/usr/bin:/bin")
	return dir
}

// rpt runs rpt in-process and returns its exit code, stdout and stderr.
func rpt(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out bytes.Buffer
	errOut := &lockedBuffer{}
	code := run(args, strings.NewReader(stdin), &out, errOut)
	return code, out.String(), errOut.String()
}

// lockedBuffer is stderr shared by rpt and a plugin it runs as a child,
// whose stderr exec copies in from another goroutine.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// records decodes JSON Lines into maps.
func records(t *testing.T, s string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("not a record: %q", l)
		}
		out = append(out, m)
	}
	return out
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return "<absent>"
	}
	return string(b)
}

// plugins puts shell-script plugins on PATH, name to script body, and
// runs them as child processes rather than in place of the test.
func plugins(t *testing.T, scripts map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range scripts {
		if err := os.WriteFile(filepath.Join(dir, "rpt-"+name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	old := plugin.Exec
	plugin.Exec = func(p plugin.Plugin, args, env []string) (int, error) {
		cmd := exec.Command(p.Path, args...)
		cmd.Env, cmd.Stdout, cmd.Stderr = env, pluginOut, pluginOut
		err := cmd.Run()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), nil
		}
		return 0, err
	}
	pluginOut.Reset()
	t.Cleanup(func() { plugin.Exec = old })
	return dir
}

// pluginOut is what the last plugin printed.
var pluginOut = &bytes.Buffer{}

func TestExitCodes(t *testing.T) {
	fixture(t)
	for _, tt := range []struct {
		args []string
		want int
	}{
		{[]string{"version"}, 0},
		{[]string{"validate"}, 1}, // the fixture plants S-99
		{nil, 2},
		{[]string{"--bogus"}, 2},
		{[]string{"finding", "get", "--bogus"}, 2},
		{[]string{"finding", "set", "F-001"}, 2},
		{[]string{"no-such-command"}, 2},
		{[]string{"finding", "get", "F-404"}, 1},
	} {
		if code, _, errOut := rpt(t, "", tt.args...); code != tt.want {
			t.Errorf("rpt %v: exit %d, want %d (stderr %q)", tt.args, code, tt.want, errOut)
		}
	}
}

func TestUsageErrorPointsAtHelp(t *testing.T) {
	fixture(t)
	_, _, errOut := rpt(t, "", "finding", "get", "--bogus")
	if errOut != "rpt: unknown flag: --bogus\nRun 'rpt finding get --help' for usage.\n" {
		t.Errorf("stderr %q", errOut)
	}
}

func TestGlobalFlagsGoEitherSide(t *testing.T) {
	dir := fixture(t)
	t.Setenv("RPT_REPORT_DIR", "")
	for _, args := range [][]string{{"--report", dir, "scope", "get", "S-12"}, {"scope", "get", "S-12", "--report=" + dir}} {
		code, out, errOut := rpt(t, "", args...)
		if code != 0 || len(records(t, out)) != 1 {
			t.Errorf("rpt %v: exit %d, %q %q", args, code, out, errOut)
		}
	}
}

func TestDescribeBuiltin(t *testing.T) {
	fixture(t)
	code, out, _ := rpt(t, "", "scope", "--describe")
	recs := records(t, out)
	if code != 0 || len(recs) != 1 || recs[0]["name"] != "scope" || !strings.Contains(recs[0]["usage"].(string), "rpt scope match") {
		t.Errorf("exit %d: %s", code, out)
	}
}
