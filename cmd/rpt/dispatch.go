package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/internal/report"
)

// dispatch runs the plugin rpt-<verb> from PATH in place of rpt, with its
// arguments untouched. It only returns if the plugin can't be started.
// An unknown verb with no plugin is a usage error.
func dispatch(e *env, verb string, args []string) int {
	bin, err := exec.LookPath("rpt-" + verb)
	if err != nil {
		fmt.Fprintf(e.stderr, "rpt: unknown verb %q, and no rpt-%s plugin on PATH\n%s\n", verb, verb, usage())
		return cli.ExitUsage
	}
	if abs, err := filepath.Abs(bin); err == nil {
		bin = abs
	}
	err = execPlugin(bin, args, pluginEnv())
	e.log.Error(fmt.Sprintf("start plugin: %v", err), "path", bin)
	return cli.ExitPluginFailed
}

// pluginEnv is rpt's environment plus what plugins may read: RPT_BIN (this
// rpt, so plugins call back into the same version), RPT_SCHEMA_VERSION, and
// RPT_REPORT_DIR when a report is found the usual way. rpt never parses a
// plugin's arguments, so a --report meant for the plugin isn't seen here.
func pluginEnv() []string {
	set := map[string]string{"RPT_SCHEMA_VERSION": strconv.Itoa(report.SchemaVersion)}
	if self, err := os.Executable(); err == nil {
		set["RPT_BIN"] = self
	}
	if dir, err := report.Root(""); err == nil {
		if abs, err := filepath.Abs(dir); err == nil {
			set["RPT_REPORT_DIR"] = abs
		}
	}
	var out []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if k == "RPT_BIN" || k == "RPT_SCHEMA_VERSION" || k == "RPT_REPORT_DIR" {
			continue
		}
		out = append(out, kv)
	}
	for _, k := range []string{"RPT_BIN", "RPT_REPORT_DIR", "RPT_SCHEMA_VERSION"} {
		if v, ok := set[k]; ok {
			out = append(out, k+"="+v)
		}
	}
	return out
}

var errExecReturned = errors.New("exec returned without an error")
