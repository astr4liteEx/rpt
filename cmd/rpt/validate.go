package main

import (
	"encoding/json/v2"
	"io"

	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/sdk"
)

var problemColumns = []cli.Column{
	{Header: "PATH", Field: "path"}, {Header: "LINE", Field: "line"}, {Header: "LEVEL", Field: "level"},
	{Header: "RULE", Field: "rule"}, {Header: "MESSAGE", Field: "message"},
}

// validateVerb checks the report and prints one problem record per broken
// rule. It exits 1 if any problem is an error, 0 otherwise: it is the gate
// before assemble.
func validateVerb(e *env, args []string) int {
	flags, of := newFlags(e, "validate")
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if flags.NArg() != 0 {
		return badUsage(e, "validate")
	}
	out, err := of.output(e, problemColumns)
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitUsage
	}
	r := openReport(e, *of.report)
	if r == nil {
		return cli.ExitProblems
	}
	defer r.Close()

	problems, err := r.Validate()
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitUsage
	}
	code := cli.ExitOK
	for _, p := range problems {
		if p.Level == sdk.Error {
			code = cli.ExitProblems
		}
		if err := out.Write(p); err != nil {
			e.log.Error(err.Error())
			return cli.ExitUsage
		}
	}
	if err := out.Flush(); err != nil {
		e.log.Error(err.Error())
		return cli.ExitUsage
	}
	return code
}

// assembleVerb writes the whole report as one report record on one JSON
// line, on a terminal too. It never refuses: whatever it had to leave out
// is a warning on stderr. Run rpt validate first to gate on problems.
func assembleVerb(e *env, args []string) int {
	flags, of := newFlags(e, "assemble")
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if flags.NArg() != 0 {
		return badUsage(e, "assemble")
	}
	r := openReport(e, *of.report)
	if r == nil {
		return cli.ExitProblems
	}
	defer r.Close()

	rep, warnings, err := r.Assemble()
	if err != nil {
		return logReportErrors(e.log, err)
	}
	for _, w := range warnings {
		e.log.Warn(w.Message, "path", w.Path, "line", w.Line)
	}
	if err := json.MarshalWrite(e.stdout, rep, json.Deterministic(true)); err != nil {
		e.log.Error("write report: " + err.Error())
		return cli.ExitUsage
	}
	if _, err := io.WriteString(e.stdout, "\n"); err != nil {
		e.log.Error("write report: " + err.Error())
		return cli.ExitUsage
	}
	return cli.ExitOK
}
