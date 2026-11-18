package main

import (
	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/internal/report"
)

// newVerb creates an empty report folder. It prints nothing on success:
// stdout carries records only, and there is no record to give.
func newVerb(e *env, args []string) int {
	if len(args) != 1 {
		return badUsage(e, "new")
	}
	if err := report.New(args[0]); err != nil {
		e.log.Error(err.Error())
		return cli.ExitProblems
	}
	return cli.ExitOK
}
