// Command rpt defines and enforces the rpt report format over a plain
// folder, and hands every command it doesn't know to an rpt-<command>
// plugin.
package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/internal/report"
	"github.com/astr4liteEx/rpt/sdk"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// env is one invocation's streams. Verbs never touch os.Stdin, os.Stdout
// or os.Stderr directly, so tests can run them in-process.
type env struct {
	stdin          io.Reader
	stdout, stderr io.Writer
	log            *slog.Logger
	command        string // the command running, as problems name it: "scope match"
}

// A verb runs one built-in and returns its exit code. Only main calls
// os.Exit, so deferred calls in verbs always run.
type verb func(e *env, args []string) int

// A builtin is one built-in command: its function and the description
// rpt help prints. A command is built in only if it defines or enforces the
// report format; built-ins are checked before plugins, so no plugin can
// shadow one.
type builtin struct {
	run  verb
	desc sdk.Command // Kind and Name are filled in by rpt help; Usage gains each sub's usage
	subs []sub       // subcommands, in the order usage lists them
}

// A sub is a subcommand of a built-in: rpt <command> <name> [args].
type sub struct {
	name  string
	run   verb
	usage string
}

// builtins maps each built-in command's name to it. It is the command
// table: the cobra tree is built from it.
var builtins map[string]builtin

func init() {
	builtins = map[string]builtin{
		"assemble": {assembleVerb, sdk.Command{Summary: "Print the whole report as one record for renderers", Usage: "rpt assemble [--report dir]", Output: "records"}, nil},
		"config": {nounVerb("config"), sdk.Command{Summary: "Get, set and unset the report config, plugin settings included", Usage: "rpt config <action>", Output: "records"}, []sub{
			{"get", configGetVerb, "rpt config get [--lines] [path], or rpt config get --merged x-<plugin>"},
			{"set", configSetVerb, "rpt config set [--rename old=new]... [--force] [--if-rev rev] [--dry-run] <path> <value>..."},
			{"unset", configUnsetVerb, "rpt config unset [--force] [--if-rev rev] [--dry-run] <path>..."},
		}},
		"evidence": {evidenceVerb, sdk.Command{Summary: "List the findings' evidence files; add copies files in, prune removes unreferenced ones", Usage: "rpt evidence [--orphans] [--json] [--report dir]", Output: "records"}, []sub{
			{"add", evidenceAddVerb, "rpt evidence add [--as name] [--if-rev rev] [--dry-run] <id> <file>..."},
			{"prune", evidencePruneVerb, "rpt evidence prune [--dry-run]"},
		}},
		"finding": {nounVerb("finding"), sdk.Command{Summary: "Get, add, set, unset and remove findings", Usage: "rpt finding <action>", Input: "records", Output: "records"}, []sub{
			{"get", findingGetVerb, "rpt finding get [--lines] [id...]"},
			{"add", findingAddVerb, "rpt finding add [--scaffold] [--dry-run] < records.jsonl, or rpt finding add --title t --severity s [--target S-N]... [--id F-NNN] [--no-scaffold] [--dry-run]"},
			{"set", findingSetVerb, "rpt finding set [--if-rev rev] [--dry-run] <id> <path> <value>..."},
			{"unset", findingUnsetVerb, "rpt finding unset [--if-rev rev] [--dry-run] <id> <path>..."},
			{"remove", findingRemoveVerb, "rpt finding remove [--yes] [--if-rev id=rev]... [--dry-run] <id>..."},
		}},
		"help": {helpVerb, sdk.Command{Summary: "List the commands rpt can run, built-in and plugin; with a command, show its usage", Usage: "rpt help [--all] [--json] [command [sub]]", Output: "records"}, nil},
		"ls":   {lsVerb, sdk.Command{Summary: "List the reports at or under a folder, or with --current the one rpt acts on", Usage: "rpt ls [--json] [dir], or rpt ls --current [--json] [--report dir]", Output: "records"}, nil},
		"new":  {newVerb, sdk.Command{Summary: "Create an empty report in a new or empty folder", Usage: "rpt new <dir>"}, nil},
		"scope": {nounVerb("scope"), sdk.Command{Summary: "Get, add, set, unset and remove scope rows; match attributes finding targets to them", Usage: "rpt scope <action>", Input: "records", Output: "records"}, []sub{
			{"get", scopeGetVerb, "rpt scope get [--lines] [id...]"},
			{"add", scopeAddVerb, "rpt scope add [--dry-run] < records.jsonl, or rpt scope add --host h [--port n] [--protocol tcp|udp] [--id S-NNN] [--col name=value]... [--dry-run]"},
			{"set", scopeSetVerb, "rpt scope set [--force|--cleanup] [--if-rev rev] [--dry-run] <id> <column> <value>"},
			{"unset", scopeUnsetVerb, "rpt scope unset [--if-rev rev] [--dry-run] <id> <column>..."},
			{"remove", scopeRemoveVerb, "rpt scope remove [--yes] [--force|--cleanup] [--if-rev id=rev]... [--dry-run] <id>..."},
			{"match", scopeMatchVerb, "rpt scope match [--drop-out-of-scope] < records.jsonl"},
		}},
		"validate": {validateVerb, sdk.Command{Summary: "Check the report and print its problems", Usage: "rpt validate [--json] [--report dir]", Output: "records", Roles: []string{sdk.RoleChecker}}, nil},
		"version":  {versionVerb, sdk.Command{Summary: "Print the rpt, record schema and report format versions", Usage: "rpt version [--json]", Output: "records"}, nil},
	}
	for name, b := range builtins {
		for _, s := range b.subs {
			b.desc.Usage += " | " + s.usage
		}
		builtins[name] = b
	}
}

// usageOf returns the usage line for a command or "command sub" name.
func usageOf(name string) string {
	f := strings.Fields(name)
	b := builtins[f[0]]
	if len(f) > 1 {
		for _, s := range b.subs {
			if s.name == f[1] {
				return s.usage
			}
		}
	}
	return b.desc.Usage
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
	g, rest, err := splitGlobals(args)
	if err != nil {
		fmt.Fprintf(stderr, "rpt: %v\n", err)
		return cli.ExitUsage
	}
	if len(rest) == 0 {
		root := newRoot(e, nil, g, true)
		if g.help {
			root.SetOut(stdout)
			root.Help()
			return cli.ExitOK
		}
		root.SetOut(stderr)
		root.Help()
		return cli.ExitUsage
	}
	if name := rest[0]; !isBuiltin(name) && !strings.HasPrefix(name, "__complete") {
		return dispatch(e, name, rest[1:], g)
	}
	return execute(e, g, rest)
}

// execute runs a built-in (or cobra's hidden __complete) through the cobra
// tree, handing the global flags given before its name on to it.
func execute(e *env, g globals, args []string) int {
	var code int
	root := newRoot(e, &code, g, strings.HasPrefix(args[0], "__complete"))
	root.SetArgs(args)
	root.SetIn(e.stdin)
	root.SetOut(e.stdout)
	root.SetErr(e.stderr)
	if err := root.Execute(); err != nil {
		fmt.Fprintf(e.stderr, "rpt: %v\n", err)
		return cli.ExitUsage
	}
	return code
}

// globals are rpt's own flags, given before the command's name.
type globals struct {
	report     string
	reportSet  bool
	json, help bool
}

// args renders the globals as flags a built-in parses itself.
func (g globals) args() []string {
	var out []string
	if g.reportSet {
		out = append(out, "--report", g.report)
	}
	if g.json {
		out = append(out, "--json")
	}
	return out
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
	if g.help && len(args) > 0 {
		args = append(args, "--help")
	}
	return g, args, nil
}

// newRoot builds the cobra tree from the command table. With plugins, it
// also holds a stub for each rpt-* on PATH that no built-in shadows, in
// its own group, for help and completion; running one execs the plugin.
func newRoot(e *env, code *int, g globals, plugins bool) *cobra.Command {
	root := &cobra.Command{
		Use:           "rpt",
		SilenceUsage:  true,
		SilenceErrors: true,
		// SuggestionsFor uses this; cobra sets it only for its own errors.
		SuggestionsMinimumDistance: 2,
	}
	root.CompletionOptions.DisableDefaultCmd = true
	root.PersistentFlags().Bool("json", false, jsonUsage)
	root.PersistentFlags().String("report", "", reportUsage)
	root.AddGroup(&cobra.Group{ID: "builtin", Title: "Commands:"}, &cobra.Group{ID: "plugin", Title: "Plugin commands:"})
	root.SetUsageTemplate(rootUsage)
	root.SetHelpTemplate("{{.UsageString}}")
	for _, name := range slices.Sorted(maps.Keys(builtins)) {
		b := builtins[name]
		c := adapt(e, code, g, name, b.run, b.desc)
		c.GroupID = "builtin"
		for _, s := range b.subs {
			c.AddCommand(adapt(e, code, g, name+" "+s.name, s.run, sdk.Command{Summary: s.usage}))
		}
		if name == "help" {
			root.SetHelpCommand(c)
			continue
		}
		root.AddCommand(c)
	}
	if plugins {
		for _, p := range findPlugins() {
			if p.Shadowed {
				continue
			}
			root.AddCommand(&cobra.Command{
				Use: p.Name, Short: "the plugin " + p.Path, GroupID: "plugin", DisableFlagParsing: true,
				Run: func(_ *cobra.Command, args []string) { *code = dispatch(e, p.Name, args, g) },
			})
		}
	}
	return root
}

const rootUsage = `usage: rpt <command> [args]
{{range .Groups}}{{$id := .ID}}{{$cmds := false}}{{range $.Commands}}{{if and (eq .GroupID $id) .IsAvailableCommand}}{{$cmds = true}}{{end}}{{end}}{{if $cmds}}
{{.Title}}{{range $.Commands}}{{if and (eq .GroupID $id) .IsAvailableCommand}}
  {{rpad .Name .NamePadding}} {{.Short}}{{end}}{{end}}
{{end}}{{end}}
Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}

Run 'rpt help <command>' for a command's usage, and 'rpt help' to list every command as records.
Any other command runs the rpt-<command> plugin on PATH.
`

// adapt makes a built-in a cobra command. The built-in parses its own
// flags, so cobra leaves them alone and passes every argument on, with
// the global flags given before the command's name in front. --help and
// --describe are answered here.
func adapt(e *env, code *int, g globals, name string, v verb, desc sdk.Command) *cobra.Command {
	f := strings.Fields(name)
	return &cobra.Command{
		Use: f[len(f)-1], Short: desc.Summary, DisableFlagParsing: true,
		Run: func(_ *cobra.Command, args []string) {
			e := &env{stdin: e.stdin, stdout: e.stdout, stderr: e.stderr, log: e.log, command: name}
			switch {
			case len(args) == 1 && args[0] == "--describe" && len(f) == 1:
				*code = describeBuiltin(e, builtins[name])
			case wantsHelp(args):
				*code = printHelp(e, v)
			default:
				*code = v(e, append(g.args(), args...))
			}
		},
	}
}

// wantsHelp reports whether args ask for help: -h or --help before any --.
func wantsHelp(args []string) bool {
	for _, a := range args {
		switch a {
		case "--":
			return false
		case "-h", "--help":
			return true
		}
	}
	return false
}

// printHelp prints a built-in's usage line and flags on stdout. The
// built-in prints them itself: asked for --help, its flag parsing stops
// before it does anything and prints the usage it would on a bad flag.
func printHelp(e *env, v verb) int {
	v(&env{stdin: strings.NewReader(""), stdout: io.Discard, stderr: e.stdout, log: e.log}, []string{"--help"})
	return cli.ExitOK
}

// A flagSet is a built-in's flags. Parse reports a bad flag with the
// usage, as pflag does only when it exits on errors itself.
type flagSet struct {
	*pflag.FlagSet
	e *env
}

func (f *flagSet) Parse(args []string) error {
	err := f.FlagSet.Parse(args)
	if err != nil && !errors.Is(err, pflag.ErrHelp) { // pflag printed the usage for --help
		fmt.Fprintf(f.e.stderr, "rpt: %v\n", err)
		f.Usage()
	}
	return err
}

// outputFlags are the global flags as one built-in parsed them.
type outputFlags struct {
	json   *bool
	report *string
}

// badUsage prints the usage line the command table gives a command (or
// "command sub"), and returns the usage exit code. It is the only place commands
// print their usage, so it never drifts from what rpt help lists.
func badUsage(e *env, verb string) int {
	fmt.Fprintln(e.stderr, "usage: "+usageOf(verb))
	return cli.ExitUsage
}

// newFlags returns a FlagSet for command name ("scope match" for a
// subcommand) holding the global flags. On a bad flag, or --help, it
// prints the command's usage line from the command table and its flags.
// Flags may come before, among or after the arguments; everything after
// -- is an argument.
func newFlags(e *env, name string) (*flagSet, outputFlags) {
	flags := &flagSet{pflag.NewFlagSet(name, pflag.ContinueOnError), e}
	flags.SetOutput(e.stderr)
	flags.SortFlags = false
	flags.Usage = func() {
		badUsage(e, name)
		flags.PrintDefaults()
	}
	return flags, outputFlags{
		json:   flags.Bool("json", false, jsonUsage),
		report: flags.String("report", "", reportUsage),
	}
}

// output builds the verb's writer from the shared flags.
func (o outputFlags) output(e *env, columns []cli.Column) (*cli.Output, error) {
	return cli.NewOutput(e.stdout, isTerminal(e.stdout), *o.json, columns)
}

// openReport finds and opens the report, logging why when it can't.
func openReport(e *env, flagValue string) *report.Report {
	dir, err := report.Root(flagValue)
	if err != nil {
		e.log.Error(err.Error())
		return nil
	}
	r, err := report.Open(dir)
	if err != nil {
		e.log.Error(err.Error())
		return nil
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
