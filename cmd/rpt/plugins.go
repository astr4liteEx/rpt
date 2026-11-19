package main

import (
	"bytes"
	"cmp"
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

	"github.com/astr4liteEx/rpt/sdk"
)

// describeTimeout is how long rpt verbs waits for each --describe.
var describeTimeout = 2 * time.Second

// pluginIO renders a plugin's declared input and output for the table,
// "xml/nessus → records", with "?" for a side not said and nothing when
// neither is.
func pluginIO(m map[string]any) string {
	in, _ := m["input"].(string)
	out, _ := m["output"].(string)
	if in == "" && out == "" {
		return ""
	}
	return cmp.Or(in, "?") + " → " + cmp.Or(out, "?")
}

// describePlugins finds the plugins on PATH and asks each to --describe
// itself in parallel, carrying every member of its answer into its verb
// record except the ones rpt owns. A plugin that doesn't answer in time,
// fails, or answers with something other than a JSON object is still
// listed, with a warning.
func describePlugins(e *env) []sdk.Verb {
	found := findPlugins()
	descs := make([]sdk.Description, len(found))
	errs := make([]error, len(found))
	env := pluginEnv()
	var wg sync.WaitGroup
	for i, p := range found {
		wg.Go(func() { descs[i], errs[i] = askDescription(p.Path, env) })
	}
	wg.Wait()
	for i := range found {
		p := &found[i]
		if errs[i] != nil {
			e.log.Warn(errs[i].Error(), "path", p.Path)
		}
		d := descs[i]
		p.Summary, p.Usage, p.Version, p.Input, p.Output = d.Summary, d.Usage, d.Version, d.Input, d.Output
		p.Roles = d.Roles
		p.Extra = d.Extra
		for _, own := range []string{"kind", "name", "source", "path", "shadowed"} {
			delete(p.Extra, own) // the record's own members aren't the plugin's to set
		}
	}
	return found
}

// findPlugins finds the executable rpt-* files on PATH, sorted by name.
// The first of a name in PATH order wins, as in a shell; one named like a
// built-in is marked shadowed, because the built-in always runs. Empty and
// relative PATH entries are skipped, as exec.LookPath refuses them too.
func findPlugins() []sdk.Verb {
	seen := map[string]bool{}
	var out []sdk.Verb
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
			if !ok || name == "" || seen[name] {
				continue
			}
			p := filepath.Join(dir, ent.Name())
			info, err := os.Stat(p) // follows symlinks
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
				continue
			}
			seen[name] = true
			out = append(out, sdk.Verb{Kind: "verb", Name: name, Source: "plugin", Path: p, Shadowed: isBuiltin(name)})
		}
	}
	slices.SortFunc(out, func(a, b sdk.Verb) int { return strings.Compare(a.Name, b.Name) })
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
