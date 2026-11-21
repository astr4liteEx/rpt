package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/internal/legacy/report"
)

// dispatch runs the plugin rpt-<name> from PATH in place of rpt, with its
// arguments untouched. It only returns if the plugin can't be started.
// An unknown command with no plugin is a usage error. Of the global flags
// given before the name, --report becomes RPT_REPORT_DIR and --json and
// --help go to the plugin first.
func dispatch(e *env, name string, args []string, g globals) int {
	bin, err := exec.LookPath("rpt-" + name)
	if err != nil {
		msg := fmt.Sprintf("rpt: unknown command %q, and no rpt-%s plugin on PATH\n", name, name)
		if s := newRoot(e, new(int)).SuggestionsFor(name); len(s) > 0 {
			msg += "Did you mean this?\n\t" + strings.Join(s, "\n\t") + "\n"
		}
		fmt.Fprint(e.stderr, msg+"Run 'rpt --help' for the commands.\n")
		return cli.ExitUsage
	}
	if abs, err := filepath.Abs(bin); err == nil {
		bin = abs
	}
	if g.json {
		args = append([]string{"--json"}, args...)
	}
	env, err := pluginEnv(g.report)
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitProblems
	}
	if len(args) == 0 || !slices.Contains([]string{"--describe", "--help", "-h", "__complete", "__completeNoDesc"}, args[0]) {
		warnIncompatible(e, name, bin, env)
	}
	err = execPlugin(bin, args, env)
	e.log.Error(fmt.Sprintf("start plugin: %v", err), "path", bin)
	return cli.ExitPluginFailed
}

// warnIncompatible warns, once, before running a plugin whose requires
// this rpt doesn't fit. A plugin that doesn't answer --describe in time
// is run without a word: rpt help reports that.
func warnIncompatible(e *env, name, bin string, env []string) {
	d, err := askDescription(bin, env)
	if err != nil || d.Requires.Fits(report.SchemaVersion, report.FormatVersion) {
		return
	}
	e.log.Warn(fmt.Sprintf("plugin %s may not work with this rpt: it requires schema_version %v and format %v; this rpt writes schema_version %d and reads format %d",
		name, d.Requires.SchemaVersion, d.Requires.Format, report.SchemaVersion, report.FormatVersion))
}

// pluginEnv is rpt's environment plus what plugins may read: RPT_BIN (this
// rpt, so plugins call back into the same version), RPT_SCHEMA_VERSION, and
// RPT_REPORT_DIR: the --report given before the plugin's name, else the
// report found the usual way, if any. rpt never parses a plugin's own
// arguments, so a --report after its name is the plugin's.
func pluginEnv(reportFlag string) ([]string, error) {
	set := map[string]string{"RPT_SCHEMA_VERSION": strconv.Itoa(report.SchemaVersion)}
	if self, err := os.Executable(); err == nil {
		set["RPT_BIN"] = self
	}
	if reportFlag != "" {
		abs, err := filepath.Abs(reportFlag)
		if err != nil {
			return nil, fmt.Errorf("--report: %w", err)
		}
		set["RPT_REPORT_DIR"] = abs
	} else if dir, err := report.Root(""); err == nil {
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
	return out, nil
}

var errExecReturned = errors.New("exec returned without an error")
