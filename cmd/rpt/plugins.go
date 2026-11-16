package main

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/sdk"
)

// describeTimeout is how long rpt plugins waits for each --describe.
var describeTimeout = 2 * time.Second

var pluginColumns = []cli.Column{
	{Header: "NAME", Field: "name"}, {Header: "SUMMARY", Field: "summary"}, {Header: "PATH", Field: "path"},
}

// pluginsVerb lists the rpt-* programs on PATH that rpt <verb> would run,
// asking each to --describe itself. A plugin that doesn't answer in time,
// fails, or answers with something other than a JSON object is still listed,
// with a warning; the listing itself exits 0.
func pluginsVerb(e *env, args []string) int {
	flags, of := newFlags(e, "plugins")
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(e.stderr, "usage: rpt plugins [--json]")
		return cli.ExitUsage
	}
	out, err := of.output(e, pluginColumns)
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitUsage
	}

	found := findPlugins()
	descs := make([]sdk.Description, len(found))
	errs := make([]error, len(found))
	env := pluginEnv()
	var wg sync.WaitGroup
	for i, p := range found {
		wg.Go(func() { descs[i], errs[i] = askDescription(p.Path, env) })
	}
	wg.Wait()

	for i, p := range found {
		if errs[i] != nil {
			e.log.Warn(errs[i].Error(), "path", p.Path)
		}
		p.Summary, p.Usage, p.Version = descs[i].Summary, descs[i].Usage, descs[i].Version
		if err := out.Write(p); err != nil {
			e.log.Error(err.Error())
			return cli.ExitUsage
		}
	}
	if err := out.Flush(); err != nil {
		e.log.Error(err.Error())
		return cli.ExitUsage
	}
	return cli.ExitOK
}

// findPlugins finds the executable rpt-* files on PATH, sorted by name.
// The first of a name in PATH order wins, as in a shell; names of built-in
// verbs are skipped because the built-in always runs. Empty and relative
// PATH entries are skipped, as exec.LookPath refuses them too.
func findPlugins() []sdk.PluginInfo {
	seen := map[string]bool{}
	var out []sdk.PluginInfo
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" || !filepath.IsAbs(dir) {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, ent := range entries {
			name, ok := strings.CutPrefix(ent.Name(), "rpt-")
			if !ok || name == "" || seen[name] || builtins[name] != nil {
				continue
			}
			p := filepath.Join(dir, ent.Name())
			info, err := os.Stat(p) // follows symlinks
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
				continue
			}
			seen[name] = true
			out = append(out, sdk.PluginInfo{Kind: "plugin", Name: name, Path: p})
		}
	}
	slices.SortFunc(out, func(a, b sdk.PluginInfo) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// askDescription asks one plugin for its --describe line, giving up after
// describeTimeout. WaitDelay stops a child that keeps stdout open from
// holding rpt past the deadline.
func askDescription(bin string, env []string) (sdk.Description, error) {
	ctx, cancel := context.WithTimeout(context.Background(), describeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--describe")
	cmd.Env = env
	cmd.WaitDelay = 100 * time.Millisecond
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return sdk.Description{}, fmt.Errorf("--describe timed out after %v", describeTimeout)
	}
	if err != nil {
		return sdk.Description{}, fmt.Errorf("--describe failed: %w", err)
	}
	line, _, _ := bytes.Cut(out, []byte("\n"))
	var d sdk.Description
	if err := json.Unmarshal(line, &d); err != nil {
		return sdk.Description{}, fmt.Errorf("--describe did not print a JSON object: %w", err)
	}
	return d, nil
}
