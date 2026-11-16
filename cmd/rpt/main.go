// Command rpt defines and enforces the rpt report format over a plain
// folder, and hands every verb it doesn't know to an rpt-<verb> plugin.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"

	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/internal/report"
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
}

// A verb runs one built-in and returns its exit code. Only main calls
// os.Exit, so deferred calls in verbs always run.
type verb func(e *env, args []string) int

// builtins maps each built-in verb to its function. A verb is built in only
// if it defines or enforces the report format; built-ins are checked
// before plugins, so no plugin can shadow one.
var builtins map[string]verb

func init() {
	builtins = map[string]verb{
		"add":      addVerb,
		"assemble": assembleVerb,
		"findings": findingsVerb,
		"plugins":  pluginsVerb,
		"scope":    scopeVerb,
		"set":      setVerb,
		"validate": validateVerb,
		"version":  versionVerb,
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	e := &env{stdin: stdin, stdout: stdout, stderr: stderr, log: cli.NewLogger(stderr)}
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage())
		return cli.ExitUsage
	}
	if v, ok := builtins[args[0]]; ok {
		return v(e, args[1:])
	}
	return dispatch(e, args[0], args[1:])
}

func usage() string {
	names := make([]string, 0, len(builtins))
	for n := range builtins {
		names = append(names, n)
	}
	sort.Strings(names)
	return "usage: rpt <verb> [args]\nverbs: " + strings.Join(names, ", ") + "\nany other verb runs the rpt-<verb> plugin on PATH; rpt plugins lists them"
}

// outputFlags are the flags every verb that writes records shares.
type outputFlags struct {
	json   *bool
	report *string
}

// newFlags returns a FlagSet for verb name with the shared output flags.
func newFlags(e *env, name string) (*flag.FlagSet, outputFlags) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(e.stderr)
	return flags, outputFlags{
		json:   flags.Bool("json", false, "write JSON Lines even on a terminal"),
		report: flags.String("report", "", "report folder (default $RPT_REPORT_DIR, then the nearest folder with rpt.yaml)"),
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

// logReportErrors logs each error from reading the report and returns the
// exit code: problems in report files are exit 1, anything else exit 2.
func logReportErrors(log *slog.Logger, err error) int {
	if err == nil {
		return cli.ExitOK
	}
	code := cli.ExitProblems
	for _, e := range unjoin(err) {
		if fe, ok := errors.AsType[*report.FileError](e); ok {
			log.Error(fe.Err.Error(), "path", fe.Path, "line", fe.Line)
			continue
		}
		log.Error(e.Error())
		code = cli.ExitUsage
	}
	return code
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
