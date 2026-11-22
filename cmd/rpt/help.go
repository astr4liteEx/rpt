package main

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/internal/plugin"
	"github.com/astr4liteEx/rpt/internal/report"
	"github.com/astr4liteEx/rpt/sdk"
)

// commands are the built-in commands, the tree --describe and help walk.
func (e *env) commands() []*cobra.Command {
	return []*cobra.Command{
		e.assembleCommand(), e.completionCommand(), e.configCommand(), e.evidenceCommand(),
		e.docCommand(report.FindingKind), e.helpCommand(), e.lsCommand(), e.newCommand(),
		e.docCommand(report.PageKind), e.scopeCommand(), e.validateCommand(), e.versionCommand(),
	}
}

// builtin is the built-in command name, or nil.
func (e *env) builtin(name string) *cobra.Command {
	for _, c := range e.commands() {
		if c.Name() == name {
			return c
		}
	}
	return nil
}

// record is a built-in as a command record: its usage lines from its
// examples, or its use; for a noun, each action's.
func record(c *cobra.Command) sdk.Command {
	r := sdk.Command{Kind: "command", Name: c.Name(), Source: "builtin", Summary: c.Short,
		Input: c.Annotations["input"], Output: c.Annotations["output"]}
	if roles := c.Annotations["roles"]; roles != "" {
		r.Roles = strings.Split(roles, ",")
	}
	forms := func(c *cobra.Command, parent string) []string {
		if c.Example != "" {
			var out []string
			for _, l := range strings.Split(c.Example, "\n") {
				out = append(out, strings.TrimSpace(l))
			}
			return out
		}
		return []string{parent + " " + c.Use}
	}
	if c.HasSubCommands() {
		usage := []string{"rpt " + c.Name() + " <action>"}
		for _, sub := range c.Commands() {
			usage = append(usage, strings.Join(forms(sub, "rpt "+c.Name()), ", or "))
		}
		r.Usage = strings.Join(usage, " | ")
	} else {
		r.Usage = strings.Join(forms(c, "rpt"), ", or ")
	}
	return r
}

// describe prints a built-in's command record, as a plugin answers
// --describe.
func (e *env) describe(name string) error {
	return cli.NewOutput(e.stdout, false, true).Write(record(e.builtin(name)))
}

// pluginRecords describes the plugins on PATH. A plugin named like a
// built-in is shadowed: the built-in always runs.
func (e *env) pluginRecords() []sdk.Command {
	ps := plugin.Discover(os.Getenv("PATH"))
	dir, _ := e.reportDir()
	answers := describer(dir).Describe(ps)
	var out []sdk.Command
	for _, p := range ps {
		r := sdk.Command{Kind: "command", Name: p.Name, Source: "plugin", Path: p.Path, Shadowed: isBuiltin(p.Name)}
		a := answers[p.Name]
		if a.Err != nil {
			e.log.Warn(fmt.Sprintf("plugin %s: %v", p.Name, a.Err))
		} else {
			d := a.Desc
			r.Summary, r.Usage, r.Version, r.Input, r.Output, r.Roles, r.Requires = d.Summary, d.Usage, d.Version, d.Input, d.Output, d.Roles, d.Requires
			r.Incompatible = !d.Requires.Fits(report.SchemaVersion, report.FormatVersion)
		}
		out = append(out, r)
	}
	return out
}

func (e *env) helpCommand() *cobra.Command {
	var all bool
	c := &cobra.Command{
		Use:         "help [command [action]]",
		Short:       "List the commands rpt can run, built-in and plugin; with a command, show its usage",
		Annotations: io_("", "records"),
		ValidArgsFunction: func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
			names := slices.Clone(builtinNames)
			for _, p := range plugin.Discover(os.Getenv("PATH")) {
				names = append(names, p.Name)
			}
			return names, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return e.helpFor(cmd.Root(), args)
			}
			for _, c := range e.commands() {
				if err := e.out.Write(record(c)); err != nil {
					return err
				}
			}
			for _, r := range e.pluginRecords() {
				if (r.Incompatible || r.Shadowed) && !all {
					continue
				}
				if err := e.out.Write(r); err != nil {
					return err
				}
			}
			return nil
		},
	}
	c.Flags().BoolVar(&all, "all", false, "List every command, plugins this rpt can't run as they ask or a built-in hides too")
	return c
}

// helpFor shows one command's help: a built-in's from cobra, a plugin's
// from its description, both drawn by root's help function (fang's).
func (e *env) helpFor(root *cobra.Command, args []string) error {
	if isBuiltin(args[0]) {
		c, _, err := root.Find(args)
		if err != nil || c == root {
			return usagef("no command %q", strings.Join(args, " "))
		}
		c.SetOut(e.stdout)
		return c.Help()
	}
	for _, r := range e.pluginRecords() {
		if r.Name == args[0] {
			return e.pluginHelp(root, r)
		}
	}
	return usagef("no command %q: not built in, and no rpt-%s on PATH", args[0], args[0])
}

func (e *env) completionCommand() *cobra.Command {
	return &cobra.Command{
		Use:       "completion bash|zsh|fish|powershell",
		Short:     "Print the shell completion script for bash, zsh, fish or powershell",
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
		RunE: func(cmd *cobra.Command, args []string) error {
			root := cmd.Root()
			switch args[0] {
			case "bash":
				return root.GenBashCompletionV2(e.stdout, true)
			case "zsh":
				return root.GenZshCompletion(e.stdout)
			case "fish":
				return root.GenFishCompletion(e.stdout, true)
			case "powershell":
				return root.GenPowerShellCompletionWithDesc(e.stdout)
			}
			return usagef("no completion for %q: bash, zsh, fish or powershell", args[0])
		},
	}
}

// runPlugin runs rpt-<name> with args untouched, in place of rpt where
// the system allows. A plugin whose requires this rpt doesn't fit runs
// after one warning.
func (e *env) runPlugin(name string, args []string) int {
	p, err := plugin.Lookup(os.Getenv("PATH"), name)
	if errors.Is(err, plugin.ErrNotFound) {
		fmt.Fprintf(e.stderr, "rpt: unknown command %q: not built in, and no rpt-%s on PATH\nRun 'rpt help' for the commands.\n", cli.CleanLine(name), cli.CleanLine(name))
		return cli.ExitUsage
	}
	dir, _ := e.reportDir()
	d := describer(dir)
	if a := d.Describe([]plugin.Plugin{p})[name]; a.Err == nil && !a.Desc.Requires.Fits(report.SchemaVersion, report.FormatVersion) {
		e.log.Warn(fmt.Sprintf("plugin %s may not work with this rpt: it requires schema_version %s and format %s; this rpt writes schema_version %d and reads format %d",
			name, a.Desc.Requires.SchemaVersion, a.Desc.Requires.Format, report.SchemaVersion, report.FormatVersion))
	}
	code, err := plugin.Exec(p, args, d.Env)
	if err != nil {
		e.log.Error(fmt.Sprintf("plugin %s: %v", name, err))
		return cli.ExitPluginFailed
	}
	return code
}

// pluginCompletion completes a plugin's arguments by running it with
// cobra's __complete, as a cobra-built plugin answers.
func pluginCompletion(p plugin.Plugin) cobra.CompletionFunc {
	return func(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return completeFromPlugin(p, args, toComplete)
	}
}

// pluginHelp draws a plugin's help the way a built-in's is drawn, from its
// --describe answer: a command made for the purpose, standing alone so
// rpt's own flags don't show as the plugin's. rpt doesn't know a
// plugin's flags; its usage names them.
func (e *env) pluginHelp(root *cobra.Command, r sdk.Command) error {
	long := cli.Clean(r.Summary)
	var about []string
	if r.Input != "" {
		about = append(about, "input: "+cli.Clean(r.Input))
	}
	if r.Output != "" {
		about = append(about, "output: "+cli.Clean(r.Output))
	}
	if len(r.Roles) > 0 {
		about = append(about, "roles: "+cli.Clean(strings.Join(r.Roles, ", ")))
	}
	about = append(about, "plugin: "+cli.Clean(r.Path))
	long += "\n\n" + strings.Join(about, "\n")
	usage := cli.Clean(r.Usage)
	if usage == "" {
		usage = "rpt " + r.Name + " [args]"
	}
	c := &cobra.Command{Use: "rpt " + r.Name, Short: cli.Clean(r.Summary), Long: long, Example: usage, Run: func(*cobra.Command, []string) {}}
	c.SetOut(e.stdout)
	root.HelpFunc()(c, nil)
	return nil
}
