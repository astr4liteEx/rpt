package main

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
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
			"RPT_REPORT_DIR": fixture, "RPT_BIN": filepath.Join(b, "rpt"), "RPT_SCHEMA_VERSION": "1",
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

func TestPluginsVerb(t *testing.T) {
	b := bins(t)
	t.Setenv("PATH", b)
	old := describeTimeout
	describeTimeout = 300 * time.Millisecond
	t.Cleanup(func() { describeTimeout = old })

	start := time.Now()
	code, out, errOut := runIn(t, "", "plugins")
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("rpt plugins took %v: it waited on the hanging plugin", took)
	}
	if code != 0 {
		t.Errorf("exit %d, want 0: the listing worked", code)
	}
	want := "broken " + filepath.Join(b, "rpt-broken") + " \n" +
		"hang " + filepath.Join(b, "rpt-hang") + " \n" +
		"stub " + filepath.Join(b, "rpt-stub") + " Stub plugin for tests\n"
	if got := pick(t, out, "name", "path", "summary"); got != want {
		t.Errorf("listed\n%s\nwant\n%s", got, want)
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
