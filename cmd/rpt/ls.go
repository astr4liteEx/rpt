package main

import (
	"errors"

	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/internal/report"
)

var locationColumns = []cli.Column{
	{Header: "PATH", Field: "path"}, {Header: "FORMAT", Field: "format"}, {Header: "FINDINGS", Field: "findings"},
}

// lsVerb lists the reports at or under a folder, the current one by
// default. Problems reading a report are warnings: the listing exits 0,
// and rpt validate is the check.
func lsVerb(e *env, args []string) int {
	flags := newFlagSet(e, "ls")
	json := flags.Bool("json", false, "write JSON Lines even on a terminal")
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if flags.NArg() > 1 {
		return badUsage(e, "ls")
	}
	dir := "."
	if flags.NArg() == 1 {
		dir = flags.Arg(0)
	}
	out, err := cli.NewOutput(e.stdout, isTerminal(e.stdout), *json, locationColumns)
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitUsage
	}
	found, errs := report.Find(dir)
	if found == nil && len(errs) == 1 {
		if _, ok := errors.AsType[*report.FileError](errs[0]); !ok {
			e.log.Error(errs[0].Error())
			return cli.ExitUsage
		}
	}
	for _, err := range errs {
		if fe, ok := errors.AsType[*report.FileError](err); ok {
			e.log.Warn(fe.Err.Error(), "path", fe.Path, "line", fe.Line)
		} else {
			e.log.Warn(err.Error())
		}
	}
	for _, loc := range found {
		if err := out.Write(loc); err != nil {
			e.log.Error(err.Error())
			return cli.ExitUsage
		}
	}
	if err := out.Flush(); err != nil {
		e.log.Error(err.Error())
		return cli.ExitUsage
	}
	return cli.ExitOK
}
