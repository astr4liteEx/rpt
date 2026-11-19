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
}

// A verb runs one built-in and returns its exit code. Only main calls
// os.Exit, so deferred calls in verbs always run.
type verb func(e *env, args []string) int

// A builtin is one built-in verb: its function and the description
// rpt verbs prints. A verb is built in only if it defines or enforces the
// report format; built-ins are checked before plugins, so no plugin can
// shadow one.
type builtin struct {
	run  verb
	desc sdk.Verb // Kind and Name are filled in by rpt verbs; Usage gains each sub's usage
	subs []sub    // subcommands, in the order usage lists them
}

// A sub is a subcommand of a built-in: rpt <verb> <name> [args].
type sub struct {
	name  string
	run   verb
	usage string
}

// builtins maps each built-in verb's name to it.
var builtins map[string]builtin

func init() {
	builtins = map[string]builtin{
		"assemble": {assembleVerb, sdk.Verb{Summary: "Print the whole report as one record for renderers", Usage: "rpt assemble [--report dir]", Output: "records"}, nil},
		"findings": {findingsVerb, sdk.Verb{Summary: "List findings; add, set, unset and delete change them", Usage: "rpt findings [--lines] [--json] [--report dir]", Input: "records", Output: "records"}, []sub{
			{"add", addVerb, "rpt findings add [--scaffold] < records.jsonl, or rpt findings add --title t --severity s [--scope a,b] [--id F-NNN]"},
			{"set", setVerb, "rpt findings set <id> <key> <value>"},
			{"unset", unsetVerb, "rpt findings unset <id> <key>..."},
			{"delete", deleteVerb, "rpt findings delete <id>..."},
		}},
		"ls":  {lsVerb, sdk.Verb{Summary: "List the reports at or under a folder", Usage: "rpt ls [--json] [dir]", Output: "records"}, nil},
		"new": {newVerb, sdk.Verb{Summary: "Create an empty report in a new or empty folder", Usage: "rpt new <dir>"}, nil},
		"scope": {scopeVerb, sdk.Verb{Summary: "List scope rows; scope match adds matching scope IDs to finding records", Usage: "rpt scope [--json]", Input: "records", Output: "records"}, []sub{
			{"match", scopeMatchVerb, "rpt scope match [--drop-out-of-scope] < records.jsonl"},
		}},
		"sections":   {sectionsVerb, sdk.Verb{Summary: "List the report's sections, headings and which are required", Usage: "rpt sections [--json]", Output: "records"}, nil},
		"severities": {severitiesVerb, sdk.Verb{Summary: "List the report's severity levels, most severe first", Usage: "rpt severities [--json]", Output: "records"}, nil},
		"validate":   {validateVerb, sdk.Verb{Summary: "Check the report and print its problems", Usage: "rpt validate [--json] [--report dir]", Output: "records"}, nil},
		"verbs":      {verbsVerb, sdk.Verb{Summary: "List the built-in verbs and the plugins on PATH", Usage: "rpt verbs [--json]", Output: "records"}, nil},
		"version":    {versionVerb, sdk.Verb{Summary: "Print the rpt, record schema and report format versions", Usage: "rpt version [--json]", Output: "records"}, nil},
	}
	for name, b := range builtins {
		for _, s := range b.subs {
			b.desc.Usage += " | " + s.usage
		}
		builtins[name] = b
	}
}

// usageOf returns the usage line for a verb or "verb sub" name.
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

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	e := &env{stdin: stdin, stdout: stdout, stderr: stderr, log: cli.NewLogger(stderr)}
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage())
		return cli.ExitUsage
	}
	if b, ok := builtins[args[0]]; ok {
		if len(args) == 2 && args[1] == "--describe" {
			return describeBuiltin(e, b)
		}
		if len(args) > 1 {
			for _, s := range b.subs {
				if s.name == args[1] {
					return s.run(e, args[2:])
				}
			}
		}
		return b.run(e, args[1:])
	}
	return dispatch(e, args[0], args[1:])
}

func usage() string {
	names := make([]string, 0, len(builtins))
	for n := range builtins {
		names = append(names, n)
	}
	sort.Strings(names)
	return "usage: rpt <verb> [args]\nverbs: " + strings.Join(names, ", ") + "\nany other verb runs the rpt-<verb> plugin on PATH; rpt verbs lists them all"
}

// outputFlags are the flags every verb that writes records shares.
type outputFlags struct {
	json   *bool
	report *string
}

// badUsage prints the usage line the built-ins table gives verb (or
// "verb sub"), and returns the usage exit code. It is the only place verbs
// print their usage, so it never drifts from what rpt verbs lists.
func badUsage(e *env, verb string) int {
	fmt.Fprintln(e.stderr, "usage: "+usageOf(verb))
	return cli.ExitUsage
}

// newFlagSet returns an empty FlagSet for verb name ("scope match" for a
// subcommand) that, on a bad flag, prints the verb's usage line from the
// built-ins table and its flags.
func newFlagSet(e *env, name string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(e.stderr)
	flags.Usage = func() {
		badUsage(e, name)
		flags.PrintDefaults()
	}
	return flags
}

// newFlags returns a FlagSet for verb name with the shared output flags.
func newFlags(e *env, name string) (*flag.FlagSet, outputFlags) {
	flags := newFlagSet(e, name)
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
