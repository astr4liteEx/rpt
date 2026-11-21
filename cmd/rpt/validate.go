package main

import (
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
		return cli.ExitProblems
	}
	r := openReport(e, *of.report)
	if r == nil {
		return cli.ExitProblems
	}
	defer r.Close()

	problems, err := r.Validate()
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitProblems
	}
	code := cli.ExitOK
	for _, p := range problems {
		if p.Level == sdk.Error {
			code = cli.ExitProblems
		}
		if err := e.problem(out, p); err != nil {
			e.log.Error(err.Error())
			return cli.ExitProblems
		}
	}
	if err := out.Flush(); err != nil {
		e.log.Error(err.Error())
		return cli.ExitProblems
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

	out, _ := cli.NewOutput(e.stdout, false, true, nil) // JSON Lines on a terminal too
	rep, warnings, err := r.Assemble()
	if err != nil {
		return reportErrors(e, out, err)
	}
	if err := out.Write(rep); err != nil {
		e.log.Error("write report: " + err.Error())
		return cli.ExitProblems
	}
	for _, w := range warnings {
		if err := e.problem(out, w); err != nil {
			e.log.Error(err.Error())
			return cli.ExitProblems
		}
	}
	return cli.ExitOK
}
