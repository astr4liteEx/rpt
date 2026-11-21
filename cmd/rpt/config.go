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

	"go.yaml.in/yaml/v3"

	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/internal/report"
	"github.com/astr4liteEx/rpt/sdk"
	"github.com/spf13/pflag"
)

// configColumns show a config on a terminal: one row per member.
var configColumns = []cli.Column{{Header: "KEY", Field: "key"}, {Header: "VALUE", Field: "value"}}

// configGetVerb prints the report config as one config record. With a
// path, the record holds only that member; with --merged, a plugin's
// section is laid over its user settings file.
func configGetVerb(flags *pflag.FlagSet) runner {
	withLines := flags.Bool("lines", false, "add where each key sits in rpt.yaml")
	merged := flags.Bool("merged", false, "with x-<plugin>: lay the report's section over the user's ~/.config/rpt/plugins/<plugin>/config.yaml")
	return func(e *env, args []string) int {
		pos := args
		if len(pos) > 1 || *merged && (len(pos) != 1 || !strings.HasPrefix(pos[0], "x-") || strings.Contains(pos[0], ".")) {
			return usageError(e, "takes at most one path, and --merged takes one x-<plugin> section")
		}
		out, err := e.output(configColumns)
		if err != nil {
			e.log.Error(err.Error())
			return cli.ExitProblems
		}
		var rec sdk.Config
		if *merged {
			rec, err = mergedSettings(e.report, pos[0])
			if err != nil {
				e.log.Error(err.Error())
				return cli.ExitProblems
			}
		} else {
			r := openReport(e)
			if r == nil {
				return cli.ExitProblems
			}
			defer r.Close()
			if rec, err = r.ConfigRecord(*withLines); err != nil {
				return reportErrors(e, out, err)
			}
		}
		m, err := configMembers(rec)
		if err != nil {
			e.log.Error(err.Error())
			return cli.ExitProblems
		}
		order := []string{"kind", "format", "severities", "sections", "required_sections", "rules", "rev", "lines"}
		if len(pos) == 1 {
			if m, err = pickMember(m, pos[0]); err != nil {
				e.log.Error(err.Error())
				return cli.ExitProblems
			}
		}
		return writeConfig(e, out, m, order)
	}
}

// configMembers is a config record as its members.
func configMembers(rec sdk.Config) (map[string]jsontext.Value, error) {
	b, err := json.Marshal(rec, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	var m map[string]jsontext.Value
	return m, json.Unmarshal(b, &m)
}

// pickMember keeps a config record's kind, rev and lines and the member at path:
// a top-level key, or one key of sections or an x-<plugin> section.
func pickMember(m map[string]jsontext.Value, path string) (map[string]jsontext.Value, error) {
	top, sub, nested := strings.Cut(path, ".")
	if nested && top != "sections" && !strings.HasPrefix(top, "x-") {
		top, sub, nested = path, "", false // the rest are literal
	}
	out := map[string]jsontext.Value{}
	for _, k := range []string{"kind", "rev", "lines"} {
		if v, ok := m[k]; ok {
			out[k] = v
		}
	}
	v, ok := m[top]
	if !ok {
		return nil, fmt.Errorf("the config has no %s", path)
	}
	if nested {
		var inner map[string]jsontext.Value
		if err := json.Unmarshal(v, &inner); err != nil || inner[sub] == nil {
			return nil, fmt.Errorf("the config has no %s", path)
		}
		b, err := json.Marshal(map[string]jsontext.Value{sub: inner[sub]})
		if err != nil {
			return nil, err
		}
		v = b
	}
	out[top] = v
	return out, nil
}

// writeConfig prints a config record's members, those in order first and
// any others (x-<plugin> sections) after them by name: the record itself,
// or on a terminal a row per member.
func writeConfig(e *env, out *cli.Output, m map[string]jsontext.Value, order []string) int {
	var err error
	if out.Table() {
		for _, k := range slices.Sorted(maps.Keys(m)) {
			if k == "kind" || k == "lines" {
				continue
			}
			v := string(m[k])
			if s := ""; json.Unmarshal(m[k], &s) == nil {
				v = s
			}
			if err = out.Write(map[string]string{"key": k, "value": v}); err != nil {
				break
			}
		}
	} else {
		var b []byte
		keys := slices.DeleteFunc(slices.Clone(order), func(k string) bool { return m[k] == nil })
		for _, k := range slices.Sorted(maps.Keys(m)) {
			if !slices.Contains(order, k) {
				keys = append(keys, k)
			}
		}
		b = append(b, '{')
		for i, k := range keys {
			if i > 0 {
				b = append(b, ',')
			}
			name, _ := json.Marshal(k)
			b = append(append(append(b, name...), ':'), m[k]...)
		}
		err = out.WriteRaw(append(b, '}'))
	}
	if err == nil {
		err = out.Flush()
	}
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitProblems
	}
	return cli.ExitOK
}

// userSettings is the path of a plugin's user settings file:
// $XDG_CONFIG_HOME, else ~/.config, then rpt/plugins/<plugin>/config.yaml.
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
// user's settings file with the report's section laid over it. Maps merge
// key by key; lists and values are replaced. With no report in reach, the
// user file alone.
func mergedSettings(reportFlag, key string) (sdk.Config, error) {
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
	if dir, err := report.Root(reportFlag); err == nil {
		r, err := report.Open(dir)
		if err != nil {
			return sdk.Config{}, err
		}
		defer r.Close()
		c, err := r.ConfigRecord(false)
		if err != nil {
			return sdk.Config{}, err
		}
		rec.Rev = c.Rev
		if raw, ok := c.Extra[key]; ok {
			var over any
			if err := json.Unmarshal(raw, &over); err != nil {
				return sdk.Config{}, err
			}
			merged = mergeSettings(user, over)
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

// mergeSettings lays over on base: maps merge key by key, anything else
// is replaced.
func mergeSettings(base, over any) any {
	bm, ok1 := base.(map[string]any)
	om, ok2 := over.(map[string]any)
	if !ok1 || !ok2 {
		return over
	}
	out := maps.Clone(bm)
	for k, v := range om {
		out[k] = mergeSettings(bm[k], v)
	}
	return out
}

// renameFlags collects repeated --rename old=new flags.
type renameFlags []report.Rename

func (r *renameFlags) String() string { return "" }

func (r *renameFlags) Type() string { return "old=new" }

func (r *renameFlags) Set(v string) error {
	o, n, ok := strings.Cut(v, "=")
	if !ok || o == "" || n == "" {
		return fmt.Errorf("want old=new, got %q", v)
	}
	*r = append(*r, report.Rename{Old: o, New: n})
	return nil
}

// configSetVerb sets one value of the report config.
func configSetVerb(flags *pflag.FlagSet) runner {
	var renames renameFlags
	flags.Var(&renames, "rename", "with severities or required_sections: keep old's findings under new (repeatable)")
	force := flags.Bool("force", false, "drop severity levels findings still use")
	wf := addWriteFlags(flags, true)
	return func(e *env, args []string) int {
		pos := args
		if len(pos) < 2 {
			return usageError(e, "needs a path and a value")
		}
		return writeConfigChange(e, wf, func(tx *report.Tx) (report.ConfigChange, error) {
			return tx.SetConfig(pos[0], pos[1:], renames, *force)
		})
	}
}

// configUnsetVerb removes keys from the report config.
func configUnsetVerb(flags *pflag.FlagSet) runner {
	force := flags.Bool("force", false, "go back to the default severities even when findings use a level they lack")
	wf := addWriteFlags(flags, true)
	return func(e *env, args []string) int {
		pos := args
		if len(pos) == 0 {
			return usageError(e, "needs a path")
		}
		return writeConfigChange(e, wf, func(tx *report.Tx) (report.ConfigChange, error) {
			return tx.UnsetConfig(*force, pos...)
		})
	}
}

// writeConfigChange runs a config write and prints the config and every
// finding it rewrote. A --rename that doesn't fit the lists is a usage
// error.
func writeConfigChange(e *env, wf writeFlags, change func(*report.Tx) (report.ConfigChange, error)) int {
	out, err := e.output(findingColumns)
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitProblems
	}
	r := openReport(e)
	if r == nil {
		return cli.ExitProblems
	}
	defer r.Close()
	w, ok := newWrite(e, out, r, wf, []string{report.ConfigID})
	if !ok {
		return cli.ExitUsage
	}
	ch, err := change(w.tx)
	if re, ok := errors.AsType[*report.RenameError](err); ok {
		return usageError(e, "%v", re)
	}
	if err != nil {
		w.refuse(err, report.ConfigFile, 0)
		return w.finish()
	}
	w.done(ch.Config, report.ConfigFile)
	for _, f := range ch.Findings {
		w.done(f, f.Path)
	}
	return w.finish()
}
