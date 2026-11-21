// Command rpt defines and enforces the rpt report format over a plain
// folder, and hands every command it doesn't know to an rpt-<command>
// plugin.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"

	"charm.land/fang/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/internal/legacy/report"
	"github.com/astr4liteEx/rpt/sdk"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// env is one invocation: its streams and global flags. Commands never
// touch os.Stdin, os.Stdout or os.Stderr directly, so tests can run them
// in-process.
type env struct {
	stdin          io.Reader
	stdout, stderr io.Writer
	log            *slog.Logger
	command        string // the command running, as problems name it: "scope match"
	report         string // --report, or "" to find the report
	reportSet      bool   // --report was given
	json           bool   // --json
	// diag prints problems compiler-style when stderr is a terminal; nil
	// otherwise, when they are text lines.
	diag *cli.Diagnostics
	// usage is set by usageError: the command was called wrongly.
	usage error
}

// A runner runs a built-in with its arguments, its flags already parsed,
// and returns its exit code. Only main calls os.Exit, so deferred calls
// in runners always run.
type runner func(e *env, args []string) int

// A verb declares a built-in's flags and returns its runner.
type verb func(flags *pflag.FlagSet) runner

// A builtin is one built-in command. A command is built in only if it
// defines or enforces the report format; built-ins are checked before
// plugins, so no plugin can shadow one.
type builtin struct {
	cmd
	desc sdk.Command // what rpt help and --describe print; Usage is filled in from cmd
	subs []cmd       // a noun's actions, in the order usage lists them
}

// A cmd is how a command (or a noun's action) is called: cobra's Use,
// its name and arguments; the forms it takes when there are several;
// longer help when the summary isn't enough; and its verb, nil for a noun.
type cmd struct {
	use     string
	summary string
	verb    verb
	forms   []string
	long    string
}

func (c cmd) name() string { return strings.Fields(c.use)[0] }

// builtins maps each built-in command's name to it. It is the command
// table: the cobra tree is built from it.
var builtins map[string]builtin

func init() {
	builtins = map[string]builtin{
		"assemble":   {cmd{use: "assemble", verb: assembleVerb}, sdk.Command{Summary: "Print the whole report as one record for renderers", Output: "records"}, nil},
		"completion": {cmd{use: "completion bash|zsh|fish|powershell", verb: completionVerb}, sdk.Command{Summary: "Print the shell completion script for bash, zsh, fish or powershell"}, nil},
		"config": {cmd{use: "config"}, sdk.Command{Summary: "Get, set and unset the report config, plugin settings included", Output: "records"}, []cmd{
			{use: "get [path]", summary: "Print the config, or one value of it", verb: configGetVerb, forms: []string{"rpt config get [--lines] [path]", "rpt config get --merged x-<plugin>"}},
			{use: "set <path> <value>...", summary: "Change one value of the config", verb: configSetVerb},
			{use: "unset <path>...", summary: "Remove values from the config", verb: configUnsetVerb},
		}},
		"evidence": {cmd{use: "evidence"}, sdk.Command{Summary: "Get, add, set, unset and remove the evidence findings and pages list and link; prune removes files nothing references", Input: "records", Output: "records"}, []cmd{
			{use: "get [owner...]", summary: "Print the evidence findings and pages reference, or the files nothing references", verb: evidenceGetVerb, forms: []string{"rpt evidence get [owner...]", "rpt evidence get --orphans"}},
			{use: "add <owner> <file>...", summary: "Copy files into the report and list or link them", verb: evidenceAddVerb, forms: []string{"rpt evidence add [--as name] [--link section [--text caption]] <owner> <file>...", "rpt evidence add < records.jsonl"}},
			{use: "set <owner> <ref> caption|path <value>", summary: "Change a reference's caption, or move its file", verb: evidenceSetVerb},
			{use: "unset <owner> <ref> caption", summary: "Empty a reference's caption", verb: evidenceUnsetVerb},
			{use: "remove <owner> <ref>", summary: "Remove a reference; the file stays for prune", verb: evidenceRemoveVerb},
			{use: "prune", summary: "Delete the evidence files nothing references", verb: evidencePruneVerb},
		}},
		"finding": {cmd{use: "finding"}, sdk.Command{Summary: "Get, add, set, unset and remove findings", Input: "records", Output: "records"}, []cmd{
			{use: "get [id...]", summary: "Print findings, or those with the IDs given", verb: findingGetVerb},
			{use: "add", summary: "Add findings from records on stdin or from flags", verb: findingAddVerb, forms: []string{"rpt finding add [--scaffold] < records.jsonl", "rpt finding add --title t --severity s [--target S-N]... [--id F-NNN] [--no-scaffold]"}},
			{use: "set <id> <path> <value>...", summary: "Change one value of a finding", verb: findingSetVerb,
				long: "Change one value of a finding. The path is a frontmatter key, sections.<key> or x-<plugin>.<key>. Each value is YAML: high, S-12 '{scope: S-20, port: 443}', \"9.1\"; several make a list. A section's text comes from stdin when no value is given."},
			{use: "unset <id> <path>...", summary: "Remove values from a finding", verb: findingUnsetVerb},
			{use: "remove <id>...", summary: "Remove findings", verb: findingRemoveVerb},
		}},
		"help": {cmd{use: "help [command [sub]]", verb: helpVerb}, sdk.Command{Summary: "List the commands rpt can run, built-in and plugin; with a command, show its usage", Output: "records"}, nil},
		"ls":   {cmd{use: "ls [dir]", verb: lsVerb, forms: []string{"rpt ls [dir]", "rpt ls --current [--report dir]"}}, sdk.Command{Summary: "List the reports at or under a folder, or with --current the one rpt acts on", Output: "records"}, nil},
		"new":  {cmd{use: "new <dir>", verb: newVerb}, sdk.Command{Summary: "Create an empty report in a new or empty folder"}, nil},
		"page": {cmd{use: "page"}, sdk.Command{Summary: "Get, add, set, unset and remove pages of report-level prose", Input: "records", Output: "records"}, []cmd{
			{use: "get [id...]", summary: "Print pages, or those with the IDs given", verb: pageGetVerb},
			{use: "add", summary: "Add pages from records on stdin or from flags", verb: pageAddVerb, forms: []string{"rpt page add < records.jsonl", "rpt page add --title t [--id P-NNN]"}},
			{use: "set <id> <path> <value>...", summary: "Change one value of a page", verb: pageSetVerb},
			{use: "unset <id> <path>...", summary: "Remove values from a page", verb: pageUnsetVerb},
			{use: "remove <id>...", summary: "Remove pages", verb: pageRemoveVerb},
		}},
		"scope": {cmd{use: "scope"}, sdk.Command{Summary: "Get, add, set, unset and remove scope rows; match attributes finding targets to them", Input: "records", Output: "records"}, []cmd{
			{use: "get [id...]", summary: "Print scope rows, or those with the IDs given", verb: scopeGetVerb},
			{use: "add", summary: "Add scope rows from records on stdin or from flags", verb: scopeAddVerb, forms: []string{"rpt scope add < records.jsonl", "rpt scope add --host h [--port n] [--protocol tcp|udp] [--id S-NNN] [--col name=value]..."}},
			{use: "set <id> <column> <value>", summary: "Change one column of a scope row", verb: scopeSetVerb},
			{use: "unset <id> <column>...", summary: "Empty columns of a scope row", verb: scopeUnsetVerb},
			{use: "remove <id>...", summary: "Remove scope rows", verb: scopeRemoveVerb},
			{use: "match", summary: "Attribute the targets of findings on stdin to scope rows", verb: scopeMatchVerb, forms: []string{"rpt scope match [--drop-out-of-scope] < records.jsonl"}},
		}},
		"validate": {cmd{use: "validate [id...]", verb: validateVerb, forms: []string{"rpt validate [id...]", "rpt validate - < records.jsonl"}}, sdk.Command{Summary: "Check the report, or the records on stdin, and print the problems", Input: "records", Output: "records", Roles: []string{sdk.RoleChecker}}, nil},
		"version":  {cmd{use: "version", verb: versionVerb}, sdk.Command{Summary: "Print the rpt, record schema and report format versions", Output: "records"}, nil},
	}
	for name, b := range builtins {
		b.summary = b.desc.Summary
		b.desc.Usage = usage("rpt", b.cmd)
		if b.subs != nil {
			b.desc.Usage = "rpt " + name + " <action>"
			for _, s := range b.subs {
				b.desc.Usage += " | " + usage("rpt "+name, s)
			}
		}
		builtins[name] = b
	}
}

// usage is a command's usage line for rpt help: its forms, or its use.
func usage(parent string, c cmd) string {
	if c.forms != nil {
		return strings.Join(c.forms, ", or ")
	}
	return parent + " " + c.use
}

// The global flags every command takes, before or after its name.
const (
	jsonUsage   = "write JSON Lines even on a terminal"
	reportUsage = "report folder (default $RPT_REPORT_DIR, then the nearest folder with rpt.yaml)"
)

// run finds the command in args and runs it. The command is found before
// any flag after its name is parsed: a name that isn't a built-in runs the
// rpt-<name> plugin with its arguments untouched, as kubectl does. Only
// the global flags before the name are rpt's.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	e := &env{stdin: stdin, stdout: stdout, stderr: stderr, log: cli.NewLogger(stderr)}
	if isTerminal(stderr) {
		e.diag = cli.NewDiagnostics(stderr)
		defer e.diag.Totals()
	}
	g, rest, err := splitGlobals(args)
	switch {
	case err != nil: // cobra reports the bad flag
	case len(rest) == 0 && !g.help:
		help := *e
		help.stdout = stderr
		execute(&help, []string{"--help"})
		return cli.ExitUsage
	case len(rest) == 0:
	case len(rest) == 2 && isBuiltin(rest[0]) && rest[1] == "--describe":
		return describeBuiltin(e, builtins[rest[0]])
	case !isBuiltin(rest[0]) && !strings.HasPrefix(rest[0], "__complete"):
		return dispatch(e, rest[0], rest[1:], g)
	}
	return execute(e, args)
}

// execute runs a built-in (or cobra's hidden __complete, or help) through
// the cobra tree, with fang's help and errors.
func execute(e *env, args []string) int {
	code := cli.ExitOK
	root := newRoot(e, &code)
	root.SetArgs(args)
	root.SetIn(e.stdin)
	root.SetOut(e.stdout)
	root.SetErr(e.stderr)
	err := fang.Execute(context.Background(), root,
		fang.WithoutVersion(), fang.WithoutCompletions(), fang.WithoutManpage(),
		fang.WithColorSchemeFunc(fang.AnsiColorScheme), fang.WithErrorHandler(errorHandler(e)))
	if err != nil {
		return cli.ExitUsage
	}
	return code
}

// globals are rpt's own flags, given before the command's name, as a
// plugin gets them.
type globals struct {
	report     string
	reportSet  bool
	json, help bool
}

// splitGlobals takes the global flags off the front of args and returns
// them and what follows: the command's name and its arguments.
func splitGlobals(args []string) (globals, []string, error) {
	var g globals
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		a := args[0]
		switch {
		case a == "--json":
			g.json = true
		case a == "-h" || a == "--help":
			g.help = true
		case a == "--report":
			if len(args) < 2 {
				return g, nil, errors.New("flag needs an argument: --report")
			}
			g.report, g.reportSet = args[1], true
			args = args[1:]
		case strings.HasPrefix(a, "--report="):
			g.report, g.reportSet = strings.TrimPrefix(a, "--report="), true
		default:
			return g, nil, fmt.Errorf("unknown flag: %s", a)
		}
		args = args[1:]
	}
	return g, args, nil
}

// newRoot builds the cobra tree from the command table, with a stub for
// each rpt-* on PATH that no built-in shadows, in its own group, for help
// and completion. Running a command sets code.
func newRoot(e *env, code *int) *cobra.Command {
	root := &cobra.Command{
		Use:   "rpt",
		Short: "Write penetration-test reports as plain files",
		Long:  "Write penetration-test reports as plain files.\n\nAny other command runs the rpt-<command> plugin on PATH; 'rpt help' lists every command as records.",
		// SuggestionsFor uses this; cobra sets it only for its own errors.
		SuggestionsMinimumDistance: 2,
	}
	root.CompletionOptions.DisableDefaultCmd = true
	root.PersistentFlags().BoolVar(&e.json, "json", false, jsonUsage)
	root.PersistentFlags().StringVar(&e.report, "report", "", reportUsage)
	_ = root.RegisterFlagCompletionFunc("report", flagCompleter(e, "report"))
	root.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
		return usageErr{command: strings.TrimSpace(strings.TrimPrefix(c.CommandPath(), "rpt")), msg: err.Error()}
	})
	root.AddGroup(&cobra.Group{ID: "builtin", Title: "Commands"}, &cobra.Group{ID: "plugin", Title: "Plugin commands"})
	for _, name := range slices.Sorted(maps.Keys(builtins)) {
		b := builtins[name]
		c := command(e, code, name, b.cmd)
		c.GroupID = "builtin"
		for _, s := range b.subs {
			c.AddCommand(command(e, code, name+" "+s.name(), s))
		}
		if name == "help" {
			root.SetHelpCommand(c)
			continue
		}
		root.AddCommand(c)
	}
	for _, p := range findPlugins() {
		if p.Shadowed {
			continue
		}
		root.AddCommand(&cobra.Command{
			Use: p.Name, Short: "the plugin " + p.Path, GroupID: "plugin", DisableFlagParsing: true,
			ValidArgsFunction: pluginCompleter(p.Path),
			Run: func(_ *cobra.Command, args []string) {
				*code = dispatch(e, p.Name, args, globals{report: e.report, reportSet: e.reportSet, json: e.json})
			},
		})
	}
	return root
}

// command makes one built-in, or one of a noun's actions, a cobra command.
// name is its path below rpt: "finding set".
func command(e *env, code *int, name string, c cmd) *cobra.Command {
	cc := &cobra.Command{Use: c.use, Short: c.summary, Long: c.long}
	if len(c.forms) > 1 {
		cc.Example = "  " + strings.Join(c.forms, "\n  ")
	}
	v := c.verb
	if v == nil {
		v = nounVerb(c.name())
	} else {
		cc.ValidArgsFunction = completer(e, name)
	}
	cc.Flags().SortFlags = false
	run := v(cc.Flags())
	cc.RunE = func(cc *cobra.Command, args []string) error {
		e.command, e.reportSet = name, cc.Flags().Changed("report")
		*code = run(e, args)
		return e.usage
	}
	cc.Flags().VisitAll(func(f *pflag.Flag) {
		if f.Value.Type() != "bool" {
			_ = cc.RegisterFlagCompletionFunc(f.Name, flagCompleter(e, f.Name))
		}
	})
	return cc
}

// usageErr is a command called wrongly: rpt prints why, points at the
// command's help and exits 2.
type usageErr struct{ command, msg string }

func (u usageErr) Error() string { return u.msg }

// usageError records that the running command was called wrongly, and
// returns the usage exit code.
func usageError(e *env, format string, a ...any) int {
	e.usage = usageErr{command: e.command, msg: fmt.Sprintf(format, a...)}
	return cli.ExitUsage
}

// errorHandler prints an error cobra or a command returned: fang's style
// on a terminal, two plain lines elsewhere. A usage error points at the
// command's --help.
func errorHandler(e *env) fang.ErrorHandler {
	return func(w io.Writer, styles fang.Styles, err error) {
		help := "rpt --help"
		if u, ok := errors.AsType[usageErr](err); ok && u.command != "" {
			help = "rpt " + u.command + " --help"
		}
		if !isTerminal(e.stderr) {
			fmt.Fprintf(w, "rpt: %v\nRun '%s' for usage.\n", err, help)
			return
		}
		fmt.Fprintln(w, styles.ErrorHeader.String())
		fmt.Fprintln(w, styles.ErrorText.Render(err.Error()+"."))
		fmt.Fprintln(w)
		fmt.Fprintln(w, styles.ErrorText.UnsetWidth().Render("Run")+styles.Program.Flag.Render(" "+help+" ")+styles.ErrorText.UnsetWidth().UnsetMargins().UnsetTransform().Render("for usage."))
		fmt.Fprintln(w)
	}
}

// output builds the command's writer from the global flags.
func (e *env) output(columns []cli.Column) (*cli.Output, error) {
	return cli.NewOutput(e.stdout, isTerminal(e.stdout), e.json, columns)
}

// openReport finds and opens the report, logging why when it can't.
func openReport(e *env) *report.Report {
	dir, err := report.Root(e.report)
	if err != nil {
		e.log.Error(err.Error())
		return nil
	}
	r, err := report.Open(dir)
	if err != nil {
		e.log.Error(err.Error())
		return nil
	}
	if e.diag != nil {
		e.diag.Root = dir
	}
	return r
}

func unjoin(err error) []error {
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		return j.Unwrap()
	}
	return []error{err}
}

// isTerminal reports whether w is a terminal; anything that isn't a file,
// such as a test buffer, is treated as a pipe.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && cli.IsTerminal(f)
}
