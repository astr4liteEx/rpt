package main

import (
	"errors"
	"flag"

	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/internal/report"
	"github.com/astr4liteEx/rpt/sdk"
)

var locationColumns = []cli.Column{
	{Header: "PATH", Field: "path"}, {Header: "FORMAT", Field: "format"}, {Header: "FINDINGS", Field: "findings"},
}

// lsVerb lists the reports at or under a folder, the current one by
// default. With --current it prints the one report every other verb would
// act on instead. Problems reading a report are warnings: the listing
// exits 0, and rpt validate is the check.
func lsVerb(e *env, args []string) int {
	flags, of := newFlags(e, "ls")
	current := flags.Bool("current", false, "print the report other verbs would act on from here")
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	reportSet := false
	flags.Visit(func(f *flag.Flag) { reportSet = reportSet || f.Name == "report" })
	if flags.NArg() > 1 || *current && flags.NArg() > 0 || reportSet && !*current {
		return badUsage(e, "ls")
	}
	dir := "."
	if flags.NArg() == 1 {
		dir = flags.Arg(0)
	}
	out, err := of.output(e, locationColumns)
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitUsage
	}
	var (
		found []sdk.Location
		errs  []error
	)
	if *current {
		loc, locErrs, err := report.Current(*of.report)
		if err != nil {
			e.log.Error(err.Error())
			return cli.ExitProblems
		}
		found, errs = []sdk.Location{loc}, locErrs
	} else {
		found, errs = report.Find(dir)
	}
	if !*current && found == nil && len(errs) == 1 {
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
