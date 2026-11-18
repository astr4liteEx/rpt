package main

import (
	"cmp"
	"fmt"
	"maps"
	"slices"

	"github.com/astr4liteEx/rpt/internal/cli"
)

var verbColumns = []cli.Column{
	{Header: "NAME", Field: "name"}, {Header: "IO", Value: verbIO}, {Header: "SUMMARY", Field: "summary"},
}

// verbIO renders a built-in's input and output for the table. Unlike a
// plugin, a built-in's description is complete, so a missing side is "-",
// none, not "?", not said.
func verbIO(m map[string]any) string {
	in, _ := m["input"].(string)
	out, _ := m["output"].(string)
	if in == "" && out == "" {
		return ""
	}
	return cmp.Or(in, "-") + " → " + cmp.Or(out, "-")
}

// isBuiltin reports whether name is a built-in verb.
func isBuiltin(name string) bool {
	_, ok := builtins[name]
	return ok
}

// verbsVerb lists rpt's built-in verbs by name, each described the way a
// plugin describes itself. Plugins are rpt plugins' job.
func verbsVerb(e *env, args []string) int {
	flags, of := newFlags(e, "verbs")
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(e.stderr, "usage: rpt verbs [--json]")
		return cli.ExitUsage
	}
	out, err := of.output(e, verbColumns)
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitUsage
	}
	for _, name := range slices.Sorted(maps.Keys(builtins)) {
		d := builtins[name].desc
		d.Kind, d.Name = "verb", name
		if err := out.Write(d); err != nil {
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
