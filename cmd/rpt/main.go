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
	"os"
	"slices"
	"strings"

	"charm.land/fang/v2"
	"github.com/spf13/cobra"

	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/internal/plugin"
	"github.com/astr4liteEx/rpt/internal/report"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// env is one run of rpt: its streams and global flags. Commands never
// touch os.Stdin, os.Stdout or os.Stderr, so tests run them in-process.
type env struct {
	stdin          io.Reader
	stdout, stderr io.Writer
	log            *slog.Logger
	diag           *cli.Diagnostics // problems on a terminal's stderr; nil elsewhere
	reportFlag     string           // --report
	json           bool             // --json
	command        string           // the command running, "scope match"
	out            *cli.Output
}

// The ways a command fails, each with its exit code. Anything else is a
// failure (exit 1) whose message rpt prints.
type usageError struct{ msg string } // exit 2: called wrongly

func (u usageError) Error() string { return u.msg }

func usagef(format string, a ...any) error { return usageError{fmt.Sprintf(format, a...)} }

var (
	// errReported: the command has printed its problems; exit 1.
	errReported = errors.New("problems reported")
	// errDeclined: the user answered no; nothing was written. Exit 1.
	errDeclined = errors.New("declined")
)

// run runs rpt with args and returns the exit code. Only main calls
// os.Exit, so deferred calls always run.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	e := &env{stdin: stdin, stdout: stdout, stderr: stderr, log: cli.NewLogger(stderr)}
	if isTerminal(stderr) {
		e.diag = cli.NewDiagnostics(stderr)
		defer e.diag.Totals()
	}
	name, rest, err := e.globals(args)
	if err != nil {
		return e.exit(err)
	}
	switch {
	case name == "":
		if len(rest) == 0 {
			// rpt alone: usage on stderr, exit 2.
			e.stdout = stderr
			e.execute([]string{"--help"})
			return cli.ExitUsage
		}
	case len(rest) == 2 && rest[1] == "--describe" && isBuiltin(name):
		return e.exit(e.describe(name))
	case !isBuiltin(name) && !strings.HasPrefix(name, "__complete"):
		return e.runPlugin(name, rest[1:])
	}
	return e.execute(args)
}

// globals reads the global flags before the command's name, and returns
// the name and the arguments from it on. rpt never parses a plugin's
// own arguments, so only flags before its name are rpt's.
func (e *env) globals(args []string) (string, []string, error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--json":
			e.json = true
		case a == "--report":
			if i+1 == len(args) {
				return "", nil, usagef("flag needs an argument: --report")
			}
			i++
			e.reportFlag = args[i]
		case strings.HasPrefix(a, "--report="):
			e.reportFlag = strings.TrimPrefix(a, "--report=")
		case a == "-h" || a == "--help":
			return "", args[i:], nil
		case strings.HasPrefix(a, "-"):
			return "", nil, usagef("unknown flag: %s", a)
		default:
			return a, args[i:], nil
		}
	}
	return "", nil, nil
}

// execute runs a built-in through the cobra tree, with fang's help.
func (e *env) execute(args []string) int {
	var err error
	root := e.root(&err)
	root.SetArgs(args)
	root.SetIn(e.stdin)
	root.SetOut(e.stdout)
	root.SetErr(e.stderr)
	ferr := fang.Execute(context.Background(), root,
		fang.WithoutVersion(), fang.WithoutCompletions(), fang.WithoutManpage(),
		fang.WithColorSchemeFunc(fang.AnsiColorScheme), fang.WithErrorHandler(e.printUsage))
	if ferr != nil && err == nil {
		return cli.ExitUsage // cobra's own: an unknown flag or command
	}
	return e.exit(err)
}

// exit maps what a command returned to its exit code, printing what
// hasn't been printed.
func (e *env) exit(err error) int {
	var u usageError
	var c *report.ConflictError
	var p pluginExit
	switch {
	case err == nil:
		return cli.ExitOK
	case errors.As(err, &p):
		return p.code
	case errors.As(err, &u):
		return cli.ExitUsage // already printed by printUsage
	case errors.Is(err, errReported), errors.Is(err, errDeclined):
		return cli.ExitProblems
	case errors.As(err, &c):
		e.log.Error(fmt.Sprintf("%s changed while rpt ran; nothing was written: run the command again", c.Path))
		return cli.ExitConflict
	}
	e.log.Error(err.Error())
	return cli.ExitProblems
}

// printUsage prints a usage error, pointing at the command's help: fang's
// style on a terminal, two plain lines elsewhere.
func (e *env) printUsage(w io.Writer, styles fang.Styles, err error) {
	help := "rpt --help"
	if e.command != "" {
		help = "rpt " + e.command + " --help"
	}
	if !isTerminal(e.stderr) {
		fmt.Fprintf(w, "rpt: %s\nRun '%s' for usage.\n", cli.Clean(err.Error()), help)
		return
	}
	fmt.Fprintln(w, styles.ErrorHeader.String())
	fmt.Fprintln(w, styles.ErrorText.Render(cli.Clean(err.Error())+"."))
	fmt.Fprintln(w)
	fmt.Fprintln(w, styles.ErrorText.UnsetWidth().Render("Run")+styles.Program.Flag.Render(" "+help+" ")+styles.ErrorText.UnsetWidth().UnsetMargins().UnsetTransform().Render("for usage."))
	fmt.Fprintln(w)
}

// root builds the command tree. A command's error lands in *err; only
// usage errors go back to cobra, for fang to print.
func (e *env) root(err *error) *cobra.Command {
	root := &cobra.Command{
		Use:          "rpt",
		Short:        "Write penetration-test reports as plain files",
		Long:         "Write penetration-test reports as plain files.\n\nAny other command runs the rpt-<command> plugin on PATH; 'rpt help' lists every command.",
		SilenceUsage: true,
	}
	root.CompletionOptions.DisableDefaultCmd = true
	root.PersistentFlags().BoolVar(&e.json, "json", e.json, "Write JSON Lines even on a terminal")
	root.PersistentFlags().StringVar(&e.reportFlag, "report", e.reportFlag, "Report folder (default $RPT_REPORT_DIR, then the nearest folder with rpt.yaml)")
	root.RegisterFlagCompletionFunc("report", cobra.FixedCompletions(nil, cobra.ShellCompDirectiveFilterDirs))
	root.SetFlagErrorFunc(func(c *cobra.Command, ferr error) error {
		e.command = commandName(c)
		return usageError{ferr.Error()}
	})
	root.AddGroup(&cobra.Group{ID: "builtin", Title: "Commands"}, &cobra.Group{ID: "plugin", Title: "Plugin commands"})
	for _, c := range e.commands() {
		c.GroupID = "builtin"
		wire(e, c, err)
		if c.Name() == "help" {
			root.SetHelpCommand(c)
			continue
		}
		root.AddCommand(c)
	}
	for _, p := range plugin.Discover(os.Getenv("PATH")) {
		if isBuiltin(p.Name) {
			continue
		}
		root.AddCommand(&cobra.Command{
			Use: p.Name, Short: "The plugin " + p.Path, GroupID: "plugin", DisableFlagParsing: true,
			ValidArgsFunction: pluginCompletion(p),
			Run: func(_ *cobra.Command, args []string) {
				*err = pluginExit{e.runPlugin(p.Name, args)}
			},
		})
	}
	return root
}

// pluginExit carries a plugin's exit code out of the cobra tree.
type pluginExit struct{ code int }

func (p pluginExit) Error() string { return fmt.Sprintf("exit %d", p.code) }

// wire sets each runnable command in c's tree to record its name, build
// its output, and leave its error in *err.
func wire(e *env, c *cobra.Command, err *error) {
	for _, sub := range c.Commands() {
		wire(e, sub, err)
	}
	if c.RunE == nil {
		return
	}
	runE := c.RunE
	c.RunE = func(cc *cobra.Command, args []string) error {
		e.command = commandName(cc)
		e.out = cli.NewOutput(e.stdout, isTerminal(e.stdout), e.json)
		rerr := runE(cc, args)
		if ferr := e.out.Flush(); rerr == nil {
			rerr = ferr
		}
		*err = rerr
		var u usageError
		if errors.As(rerr, &u) {
			return rerr
		}
		return nil
	}
}

// commandName is a command's path below rpt: "finding set".
func commandName(c *cobra.Command) string {
	return strings.TrimSpace(strings.TrimPrefix(c.CommandPath(), "rpt"))
}

// isBuiltin reports whether name is a built-in command. Built-ins come
// first, so no plugin can shadow one.
func isBuiltin(name string) bool {
	return slices.Contains(builtinNames, name)
}

var builtinNames = []string{"assemble", "completion", "config", "evidence", "finding", "help", "ls", "new", "page", "scope", "validate", "version"}

// isTerminal reports whether w is a terminal; anything that isn't a file,
// a test's buffer, is a pipe.
func isTerminal(w any) bool {
	f, ok := w.(*os.File)
	return ok && cli.IsTerminal(f)
}

// cwd is the working directory, or "." when it can't be had.
func cwd() string {
	d, err := os.Getwd()
	if err != nil {
		return "."
	}
	return d
}

// reportDir is the report every command acts on.
func (e *env) reportDir() (string, error) {
	return report.Root(report.Where{Flag: e.reportFlag, Env: os.Getenv("RPT_REPORT_DIR"), Cwd: cwd()})
}

// load finds and loads the report. The caller closes it.
func (e *env) load() (*report.Model, error) {
	dir, err := e.reportDir()
	if err != nil {
		return nil, err
	}
	m, err := report.Load(dir)
	if err != nil {
		return nil, err
	}
	if e.diag != nil {
		e.diag.Root = dir
	}
	if e.out != nil && m.Config.Err == nil {
		e.out.Severities = m.Config.Severities
	}
	return m, nil
}

// self is this rpt's path, for plugins to call back into.
func self() string {
	p, err := os.Executable()
	if err != nil {
		return "rpt"
	}
	return p
}
