package main

import (
	"cmp"
	"encoding/json/v2"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/sdk"
)

var verbColumns = []cli.Column{
	{Header: "NAME", Field: "name"}, {Header: "SOURCE", Value: verbSource}, {Header: "IO", Value: verbIO},
	{Header: "ROLES", Value: verbRoles},
	{Header: "SUMMARY", Field: "summary"}, {Header: "PATH", Field: "path"},
}

// verbSource renders where a verb comes from, flagging a shadowed plugin.
func verbSource(m map[string]any) string {
	src, _ := m["source"].(string)
	if shadowed, _ := m["shadowed"].(bool); shadowed {
		return src + " (shadowed)"
	}
	return src
}

// verbIO renders a verb's input and output for the table. A built-in's
// description is complete, so a missing side is "-", none; a plugin's is
// whatever it said, so a missing side is "?", not said.
func verbIO(m map[string]any) string {
	if src, _ := m["source"].(string); src == "plugin" {
		return pluginIO(m)
	}
	in, _ := m["input"].(string)
	out, _ := m["output"].(string)
	if in == "" && out == "" {
		return ""
	}
	return cmp.Or(in, "-") + " → " + cmp.Or(out, "-")
}

// verbRoles renders a verb's declared roles for the table, "checker,filter",
// and nothing when it declared none.
func verbRoles(m map[string]any) string {
	roles, _ := m["roles"].([]any)
	var names []string
	for _, r := range roles {
		if s, ok := r.(string); ok {
			names = append(names, s)
		}
	}
	return strings.Join(names, ",")
}

// isBuiltin reports whether name is a built-in verb.
func isBuiltin(name string) bool {
	_, ok := builtins[name]
	return ok
}

// verbsVerb lists everything rpt <name> can run: the built-ins by name,
// then the plugins on PATH by name, each described the way --describe
// describes it.
func verbsVerb(e *env, args []string) int {
	flags, of := newFlags(e, "verbs")
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if flags.NArg() != 0 {
		return badUsage(e, "verbs")
	}
	out, err := of.output(e, verbColumns)
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitUsage
	}
	var list []sdk.Verb
	for _, name := range slices.Sorted(maps.Keys(builtins)) {
		d := builtins[name].desc
		d.Kind, d.Name, d.Source = "verb", name, "builtin"
		list = append(list, d)
	}
	for _, v := range append(list, describePlugins(e)...) {
		if err := out.Write(v); err != nil {
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

// describeBuiltin prints a built-in's --describe answer: the members a
// plugin's answer has, on one line.
func describeBuiltin(e *env, b builtin) int {
	d := sdk.Description{Summary: b.desc.Summary, Usage: b.desc.Usage, Input: b.desc.Input, Output: b.desc.Output, Roles: b.desc.Roles}
	line, err := json.Marshal(d, json.Deterministic(true))
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitUsage
	}
	fmt.Fprintf(e.stdout, "%s\n", line)
	return cli.ExitOK
}
