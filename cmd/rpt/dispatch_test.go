package main

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/astr4liteEx/rpt/sdk"
)

var (
	binsOnce sync.Once
	binsDir  string
	binsErr  error
)

// bins builds rpt and the stub plugin once per test run into one folder,
// installed as rpt-stub, rpt-hang (never answers --describe), rpt-findings
// (must lose to the built-in) and rpt-broken (executable but not a program).
func bins(t *testing.T) string {
	t.Helper()
	binsOnce.Do(func() {
		binsDir, binsErr = os.MkdirTemp("", "rpt-dispatch-")
		if binsErr != nil {
			return
		}
		for _, b := range [][2]string{{"rpt", "."}, {"rpt-stub", "./testdata/stubplugin"}} {
			out, err := exec.Command("go", "build", "-o", filepath.Join(binsDir, b[0]), b[1]).CombinedOutput()
			if err != nil {
				binsErr = errors.New(string(out))
				return
			}
		}
		stub, _ := os.ReadFile(filepath.Join(binsDir, "rpt-stub"))
		for _, name := range []string{"rpt-hang", "rpt-findings"} {
			if binsErr = os.WriteFile(filepath.Join(binsDir, name), stub, 0o755); binsErr != nil {
				return
			}
		}
		binsErr = os.WriteFile(filepath.Join(binsDir, "rpt-broken"), []byte("not a program\n"), 0o755)
	})
	if binsErr != nil {
		t.Fatal(binsErr)
	}
	return binsDir
}

// rptCmd runs the built rpt in dir with only the bins folder on PATH.
func rptCmd(t *testing.T, dir string, args ...string) (int, string, string) {
	t.Helper()
	b := bins(t)
	cmd := exec.Command(filepath.Join(b, "rpt"), args...)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + b, "HOME=" + t.TempDir()}
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	code := 0
	if ee, ok := errors.AsType[*exec.ExitError](err); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, out.String(), errOut.String()
}

func TestDispatch(t *testing.T) {
	b := bins(t)
	type stubOut struct {
		Args []string          `json:"args"`
		Env  map[string]string `json:"env"`
	}
	args := []string{"a b", "", "--report", "ü", "exit=3"}

	t.Run("inside a report: args byte for byte, RPT_* set, exit code passed on", func(t *testing.T) {
		code, out, errOut := rptCmd(t, filepath.Join(fixture, "findings"), append([]string{"stub"}, args...)...)
		if code != 3 {
			t.Errorf("exit %d, want the stub's 3 (stderr %q)", code, errOut)
		}
		var got stubOut
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatalf("stub output %q: %v", out, err)
		}
		want := stubOut{Args: args, Env: map[string]string{
			"RPT_REPORT_DIR": fixture, "RPT_BIN": filepath.Join(b, "rpt"), "RPT_SCHEMA_VERSION": "2",
		}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("stub saw %+v\nwant %+v", got, want)
		}
	})
	t.Run("outside a report: no RPT_REPORT_DIR", func(t *testing.T) {
		_, out, _ := rptCmd(t, t.TempDir(), "stub")
		if strings.Contains(out, "RPT_REPORT_DIR") || !strings.Contains(out, "RPT_BIN") {
			t.Errorf("stub env = %s", out)
		}
	})
	t.Run("a built-in can't be shadowed", func(t *testing.T) {
		code, out, _ := rptCmd(t, fixture, "findings")
		if code != 0 || !strings.HasPrefix(out, `{"kind":"finding"`) {
			t.Errorf("exit %d, stdout %.60q: rpt-findings ran instead of the built-in", code, out)
		}
	})
	t.Run("a plugin that can't start is 126", func(t *testing.T) {
		code, _, errOut := rptCmd(t, fixture, "broken")
		if code != 126 || !strings.HasPrefix(errOut, "rpt: ") {
			t.Errorf("exit %d, stderr %q; want 126", code, errOut)
		}
	})
	t.Run("no such verb or plugin is a usage error", func(t *testing.T) {
		code, _, errOut := rptCmd(t, fixture, "frobnicate")
		if code != 2 || !strings.Contains(errOut, `unknown verb "frobnicate"`) {
			t.Errorf("exit %d, stderr %q; want 2", code, errOut)
		}
	})
}

func TestVerbsListsPlugins(t *testing.T) {
	b := bins(t)
	t.Setenv("PATH", b)
	old := describeTimeout
	describeTimeout = 300 * time.Millisecond
	t.Cleanup(func() { describeTimeout = old })

	start := time.Now()
	code, out, errOut := runIn(t, "", "verbs")
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("rpt verbs took %v: it waited on the hanging plugin", took)
	}
	if code != 0 {
		t.Errorf("exit %d, want 0: the listing worked", code)
	}
	lines := strings.Split(strings.TrimSuffix(pick(t, out, "source", "name", "shadowed", "path", "summary", "input", "output", "roles", "homepage"), "\n"), "\n")
	if len(lines) != len(builtins)+4 {
		t.Fatalf("got %d verbs, want %d built-ins and 4 plugins:\n%s", len(lines), len(builtins), out)
	}
	for _, l := range lines[:len(builtins)] {
		if !strings.HasPrefix(l, "builtin ") {
			t.Errorf("built-ins come first; got %q", l)
		}
	}
	stub := "Stub plugin for tests records json/stub [checker filter] https://example.com"
	want := []string{
		"plugin broken  " + filepath.Join(b, "rpt-broken") + "     ",
		"plugin findings true " + filepath.Join(b, "rpt-findings") + " " + stub, // hidden by the built-in, but listed
		"plugin hang  " + filepath.Join(b, "rpt-hang") + "     ",
		"plugin stub  " + filepath.Join(b, "rpt-stub") + " " + stub,
	}
	if got := lines[len(builtins):]; !reflect.DeepEqual(got, want) {
		t.Errorf("plugins listed\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if strings.Contains(out, "evil") {
		t.Errorf("a plugin overrode a member rpt owns:\n%s", out)
	}
	for _, w := range []string{
		"rpt: " + filepath.Join(b, "rpt-broken") + ": warning: --describe failed",
		"rpt: " + filepath.Join(b, "rpt-hang") + ": warning: --describe timed out after 300ms",
	} {
		if !strings.Contains(errOut, w) {
			t.Errorf("stderr %q\nlacks %q", errOut, w)
		}
	}
}

func TestBuiltinsAnswerDescribe(t *testing.T) {
	for name, b := range builtins {
		code, out, errOut := runIn(t, "", name, "--describe")
		var d sdk.Description
		if code != 0 || errOut != "" || json.Unmarshal([]byte(out), &d) != nil || strings.Count(out, "\n") != 1 {
			t.Errorf("rpt %s --describe: exit %d, stdout %q, stderr %q; want one JSON line", name, code, out, errOut)
			continue
		}
		if d.Summary != b.desc.Summary || d.Usage != b.desc.Usage || d.Input != b.desc.Input || d.Output != b.desc.Output || !slices.Equal(d.Roles, b.desc.Roles) {
			t.Errorf("rpt %s --describe = %+v, want the table's description %+v", name, d, b.desc)
		}
	}
}

func TestVerbRoles(t *testing.T) {
	for _, tt := range []struct {
		m    map[string]any
		want string
	}{
		{map[string]any{"roles": []any{"checker", "filter"}}, "checker,filter"},
		{map[string]any{"roles": []any{}}, ""},
		{map[string]any{}, ""},
	} {
		if got := verbRoles(tt.m); got != tt.want {
			t.Errorf("verbRoles(%v) = %q, want %q", tt.m, got, tt.want)
		}
	}
}

func TestPluginIO(t *testing.T) {
	tests := []struct{ in, out, want string }{
		{"xml/nessus", "records", "xml/nessus → records"},
		{"", "pdf", "? → pdf"},
		{"records", "", "records → ?"},
		{"", "", ""},
	}
	for _, tt := range tests {
		if got := pluginIO(map[string]any{"input": tt.in, "output": tt.out}); got != tt.want {
			t.Errorf("pluginIO(%q, %q) = %q, want %q", tt.in, tt.out, got, tt.want)
		}
	}
	if got := pluginIO(map[string]any{}); got != "" {
		t.Errorf("no members: %q, want empty", got)
	}
}
