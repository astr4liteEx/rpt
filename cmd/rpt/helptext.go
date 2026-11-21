package main

import (
	"context"
	"io"
	"strings"

	"charm.land/fang/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// fangHelp prints the help for the command at path ("finding set"; none
// for rpt itself) on w, styled by fang in the terminal's own colours.
// Built-ins parse their own flags, so the tree fang reads is built for
// the occasion: each built-in's flags are learned by probing it.
func fangHelp(e *env, w io.Writer, path []string) int {
	root := newRoot(e, new(int), globals{}, true)
	root.Short = "Write penetration-test reports as plain files"
	root.Long = root.Short + ".\n\nAny other command runs the rpt-<command> plugin on PATH; 'rpt help' lists every command as records."
	root.SetHelpTemplate("")
	root.SetUsageTemplate("")
	root.SetHelpCommand(&cobra.Command{Hidden: true})
	for _, g := range root.Groups() {
		g.Title = strings.TrimSuffix(g.Title, ":")
	}
	for _, c := range root.Commands() {
		helpReady(e, c, c.Name())
		for _, sc := range c.Commands() {
			helpReady(e, sc, c.Name()+" "+sc.Name())
		}
	}
	root.SetArgs(append(path, "--help"))
	root.SetOut(w)
	root.SetErr(e.stderr)
	_ = fang.Execute(context.Background(), root,
		fang.WithoutVersion(), fang.WithoutCompletions(), fang.WithoutManpage(),
		fang.WithColorSchemeFunc(fang.AnsiColorScheme))
	return 0
}

// helpReady gives a built-in's cobra command its usage line and flags,
// and lets cobra parse --help for it.
func helpReady(e *env, c *cobra.Command, name string) {
	f := strings.Fields(name)
	b, ok := builtins[f[0]]
	if !ok {
		return // a plugin: its own --help answers
	}
	c.DisableFlagParsing = false
	v := b.run
	if len(f) > 1 {
		for _, s := range b.subs {
			if s.name == f[1] {
				v = s.run
			}
		}
	}
	if len(b.subs) > 0 && len(f) == 1 {
		c.Use = f[0]
		return // a noun: its actions are its help
	}
	alts := strings.Split(usageOf(name), ", or ")
	c.Use = f[len(f)-1] + positionals(alts[0], len(f)+1)
	if len(alts) > 1 {
		c.Example = "  " + strings.Join(alts, "\n  ")
	}
	if len(f) > 1 {
		for _, s := range b.subs {
			if s.name == f[1] {
				c.Short = s.summary
			}
		}
	}
	if fs := flagsOf(e, v); fs != nil {
		fs.VisitAll(func(fl *pflag.Flag) {
			if fl.Name != "json" && fl.Name != "report" && c.Flags().Lookup(fl.Name) == nil {
				c.Flags().AddFlag(fl)
			}
		})
	}
}

// positionals keeps a usage line's arguments, dropping its first skip
// words ("rpt finding get") and every optional flag: "[--lines] [id...]"
// gives " [id...]".
func positionals(usage string, skip int) string {
	var out []string
	words := strings.Fields(usage)
	if len(words) <= skip {
		return ""
	}
	depth := 0
	for _, w := range words[skip:] {
		switch {
		case depth > 0:
			depth += strings.Count(w, "[") - strings.Count(w, "]")
		case strings.HasPrefix(w, "[-"):
			depth = strings.Count(w, "[") - strings.Count(w, "]")
		case strings.HasPrefix(w, "-"):
		default:
			out = append(out, w)
		}
	}
	if len(out) == 0 {
		return ""
	}
	return " " + strings.Join(out, " ")
}
