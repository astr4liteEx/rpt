package main

import (
	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/internal/report"
)

// newVerb creates an empty report folder, optionally set up like another
// report. It prints nothing on success unless --json asks for the new
// report's location record.
func newVerb(e *env, args []string) int {
	flags, of := newFlags(e, "new")
	like := flags.String("like", "", "copy rpt.yaml and the scope.csv columns from this report")
	withPages := flags.Bool("with-pages", false, "with --like, also copy its pages and their evidence")
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if flags.NArg() != 1 || *withPages && *like == "" {
		return badUsage(e, "new")
	}
	dir := flags.Arg(0)
	if err := report.NewLike(dir, *like, *withPages); err != nil {
		e.log.Error(err.Error())
		return cli.ExitProblems
	}
	if !*of.json {
		return cli.ExitOK
	}
	loc, _ := report.Locate(dir)
	out, err := of.output(e, locationColumns)
	if err == nil {
		if err = out.Write(loc); err == nil {
			err = out.Flush()
		}
	}
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitProblems
	}
	return cli.ExitOK
}
