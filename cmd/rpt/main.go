// Command rpt defines and enforces the rpt report format over a plain,
// git-tracked folder, and hands every verb it doesn't know to an rpt-<verb>
// plugin.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/internal/report"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run executes one rpt invocation and returns its exit code. Only main calls
// os.Exit, so deferred calls in verbs always run.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: rpt <verb> [args]")
		return cli.ExitUsage
	}
	switch args[0] {
	case "findings":
		return findings(args[1:], stdout, stderr)
	}
	fmt.Fprintf(stderr, "rpt: unknown verb %q\nusage: rpt <verb> [args]\n", args[0])
	return cli.ExitUsage
}

// findings prints every finding in the report.
func findings(args []string, stdout, stderr io.Writer) int {
	log := cli.NewLogger(stderr)
	flags := flag.NewFlagSet("findings", flag.ContinueOnError)
	flags.SetOutput(stderr)
	jsonFlag := flags.Bool("json", false, "write JSON Lines even on a terminal")
	format := flags.String("format", "", "Go template run against each record's JSON fields")
	reportFlag := flags.String("report", "", "report folder (default $RPT_REPORT_DIR, then the nearest folder with rpt.yaml)")
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}

	out, err := cli.NewOutput(stdout, isTerminal(stdout), *jsonFlag, *format, []cli.Column{
		{Header: "ID", Field: "id"}, {Header: "SEVERITY", Field: "severity"},
		{Header: "TITLE", Field: "title"}, {Header: "SCOPE", Field: "scope"},
	})
	if err != nil {
		log.Error(err.Error())
		return cli.ExitUsage
	}
	r, code := openReport(*reportFlag, log)
	if r == nil {
		return code
	}
	defer r.Close()

	list, err := r.Findings()
	for _, f := range list {
		if err := out.Write(f); err != nil {
			log.Error(err.Error())
			return cli.ExitUsage
		}
	}
	if err := out.Flush(); err != nil {
		log.Error(err.Error())
		return cli.ExitUsage
	}
	return logReportErrors(log, err)
}

// openReport finds and opens the report, logging why when it can't.
func openReport(flag string, log *slog.Logger) (*report.Report, int) {
	dir, err := report.Root(flag)
	if err != nil {
		log.Error(err.Error())
		return nil, cli.ExitUsage
	}
	r, err := report.Open(dir)
	if err != nil {
		log.Error(err.Error())
		return nil, cli.ExitUsage
	}
	return r, cli.ExitOK
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
