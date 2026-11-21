package main

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"

	"github.com/astr4liteEx/rpt/internal/report"
	"github.com/astr4liteEx/rpt/sdk"
)

func (e *env) configCommand() *cobra.Command {
	c := &cobra.Command{
		Use:         "config",
		Short:       "Get, set and unset the report config, plugin settings included",
		Annotations: io_("", "records"),
	}
	c.AddCommand(e.configGet(), e.configSet(), e.configUnset())
	return c
}

// configRev is the config's rev, for --if-rev.
func configRev(m *report.Model) map[string]string {
	return map[string]string{report.ConfigFile: m.ConfigRecord(false).Rev}
}

// writeConfig prints a config record: on a pipe as one record; in a table
// one row per member.
func (e *env) writeConfig(rec sdk.Config) error {
	if !e.out.Table() {
		return e.out.Write(rec)
	}
	b, err := json.Marshal(rec, json.Deterministic(true))
	if err != nil {
		return err
	}
	var members map[string]jsontext.Value
	if err := json.Unmarshal(b, &members); err != nil {
		return err
	}
	for _, k := range slices.Sorted(maps.Keys(members)) {
		if k == "kind" || k == "rev" || k == "lines" {
			continue
		}
		v := string(members[k])
		var s string
		if json.Unmarshal(members[k], &s) == nil {
			v = s
		}
		if err := e.out.Write(map[string]string{"kind": "config", "key": k, "value": v}); err != nil {
			return err
		}
	}
	return nil
}

func (e *env) configGet() *cobra.Command {
	var lines, merged bool
	c := &cobra.Command{
		Use:               "get [path]",
		Short:             "Print the config, or one value of it",
		Example:           "  rpt config get [--lines] [path]\n  rpt config get --merged x-<plugin>",
		Args:              cobra.MaximumNArgs(1),
		ValidArgsFunction: e.completeConfigPath,
		RunE: func(_ *cobra.Command, args []string) error {
			if merged {
				if len(args) != 1 || !report.IsPluginKey(args[0]) || strings.Contains(args[0], ".") {
					return usagef("--merged takes one x-<plugin> section")
				}
				rec, err := e.mergedSettings(args[0])
				if err != nil {
					return err
				}
				return e.writeConfig(rec)
			}
			m, err := e.load()
			if err != nil {
				return err
			}
			defer m.Close()
			if m.Config.Err != nil {
				return e.fail(m.Config.Err)
			}
			rec := m.ConfigRecord(lines)
			if len(args) == 1 {
				if rec, err = only(rec, args[0]); err != nil {
					return e.problems([]report.Problem{{Path: report.ConfigFile, Rule: ruleExists, Level: report.Error, Message: err.Error()}})
				}
			}
			return e.writeConfig(rec)
		},
	}
	c.Flags().BoolVar(&lines, "lines", false, "Add where each key sits in rpt.yaml")
	c.Flags().BoolVar(&merged, "merged", false, "With x-<plugin>: lay the report's section over the user's ~/.config/rpt/plugins/<plugin>/config.yaml")
	return c
}

// only is rec holding just the value at path (dot-separated), nested
// under its top-level key as in the full record.
func only(rec sdk.Config, path string) (sdk.Config, error) {
	b, err := json.Marshal(rec, json.Deterministic(true))
	if err != nil {
		return rec, err
	}
	var all map[string]any
	if err := json.Unmarshal(b, &all); err != nil {
		return rec, err
	}
	parts := strings.Split(path, ".")
	var v any = all
	for _, p := range parts {
		m, ok := v.(map[string]any)
		if !ok {
			return rec, fmt.Errorf("the config has no %s", path)
		}
		if v, ok = m[p]; !ok {
			return rec, fmt.Errorf("the config has no %s", path)
		}
	}
	for i := len(parts) - 1; i > 0; i-- {
		v = map[string]any{parts[i]: v}
	}
	out := map[string]any{"kind": "config", parts[0]: v}
	if r, ok := all["rev"]; ok {
		out["rev"] = r
	}
	if l, ok := all["lines"]; ok {
		out["lines"] = l
	}
	b, err = json.Marshal(out, json.Deterministic(true))
	if err != nil {
		return rec, err
	}
	var got sdk.Config
	return got, json.Unmarshal(b, &got)
}

// userSettings is a plugin's user settings file: $XDG_CONFIG_HOME, else
// ~/.config, then rpt/plugins/<plugin>/config.yaml.
func userSettings(plugin string) (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "rpt", "plugins", strings.TrimPrefix(plugin, "x-"), "config.yaml"), nil
}

// mergedSettings is a config record holding the plugin section key: the
// user's settings file with the report's section laid over it, maps
// merging key by key. With no report in reach, the user's file alone.
func (e *env) mergedSettings(key string) (sdk.Config, error) {
	var user any
	path, err := userSettings(key)
	if err != nil {
		return sdk.Config{}, err
	}
	if b, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(b, &user); err != nil {
			return sdk.Config{}, fmt.Errorf("%s: %w", path, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return sdk.Config{}, err
	}
	rec := sdk.Config{Kind: "config"}
	merged := user
	if _, err := e.reportDir(); err == nil {
		m, err := e.load()
		if err != nil {
			return sdk.Config{}, err
		}
		defer m.Close()
		if m.Config.Err != nil {
			return sdk.Config{}, m.Config.Err
		}
		c := m.ConfigRecord(false)
		rec.Rev = c.Rev
		if raw, ok := c.Extra[key]; ok {
			var over any
			if err := json.Unmarshal(raw, &over); err != nil {
				return sdk.Config{}, err
			}
			merged = merge(user, over)
		}
	}
	if merged == nil {
		merged = map[string]any{}
	}
	b, err := json.Marshal(merged, json.Deterministic(true))
	if err != nil {
		return sdk.Config{}, fmt.Errorf("%s: %w", path, err)
	}
	rec.Extra = map[string]jsontext.Value{key: b}
	return rec, nil
}

// merge lays over on base: maps merge key by key; anything else is
// replaced.
func merge(base, over any) any {
	bm, ok1 := base.(map[string]any)
	om, ok2 := over.(map[string]any)
	if !ok1 || !ok2 {
		return over
	}
	out := maps.Clone(bm)
	for k, v := range om {
		out[k] = merge(bm[k], v)
	}
	return out
}

func (e *env) configSet() *cobra.Command {
	var w writeFlags
	var renames []string
	c := &cobra.Command{
		Use:   "set <path> <value>...",
		Short: "Change one value of the config",
		Long: "Change one value of the config: a list (severities, required_sections, pages, required_pages; " +
			"one value each), sections.<key> for a fixed section's heading, rules.<rule> (error or warning), " +
			"or x-<plugin>[.<key>...], each value YAML. A heading rewritten here is rewritten in every finding.",
		Args:              cobra.MinimumNArgs(2),
		ValidArgsFunction: e.completeConfigPath,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := flagsAmongValues(cmd, args[1:]); err != nil {
				return err
			}
			var rs []report.Rename
			for _, r := range renames {
				old, nw, ok := strings.Cut(r, "=")
				if !ok || old == "" || nw == "" {
					return usagef("--rename %s: give old=new", r)
				}
				rs = append(rs, report.Rename{Old: old, New: nw})
			}
			return e.write(&w, configRev, func(b *batch) error {
				ch, err := b.m.SetConfig(args[0], args[1:], rs, w.cited.force)
				if err != nil {
					return b.refuse(err, "", 0)
				}
				e.printConfigChange(b, ch)
				return nil
			})
		},
	}
	c.Flags().SetInterspersed(false)
	c.Flags().StringArrayVar(&renames, "rename", nil, "With severities or required_sections: keep old's findings under new, old=new (repeatable)")
	c.Flags().BoolVar(&w.cited.force, "force", false, "Drop severity levels findings still use")
	addWriteFlags(c, &w, true)
	return c
}

func (e *env) configUnset() *cobra.Command {
	var w writeFlags
	c := &cobra.Command{
		Use:               "unset <path>...",
		Short:             "Remove values from the config; a list or heading goes back to its default",
		Args:              cobra.MinimumNArgs(1),
		ValidArgsFunction: e.completeConfigPath,
		RunE: func(_ *cobra.Command, args []string) error {
			return e.write(&w, configRev, func(b *batch) error {
				ch, err := b.m.UnsetConfig(w.cited.force, args...)
				if err != nil {
					return b.refuse(err, "", 0)
				}
				e.printConfigChange(b, ch)
				return nil
			})
		},
	}
	c.Flags().BoolVar(&w.cited.force, "force", false, "Go back to the default severities even when findings use a level they lack")
	addWriteFlags(c, &w, true)
	return c
}

// printConfigChange prints the config as written, then the findings the
// change rewrote.
func (e *env) printConfigChange(b *batch, ch report.ConfigChange) {
	b.print(b.m.ConfigRecord(false))
	for _, d := range ch.Rewrote {
		b.print(b.m.FindingRecord(d, report.RecordOpts{}))
	}
}
