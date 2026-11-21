package main

import (
	"errors"

	"github.com/spf13/pflag"

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
func lsVerb(flags *pflag.FlagSet) runner {
	current := flags.Bool("current", false, "print the report other verbs would act on from here")
	return func(e *env, args []string) int {
		if len(args) > 1 || *current && len(args) > 0 || e.reportSet && !*current {
			return usageError(e, "takes one folder, or --current and no folder; --report goes only with --current")
		}
		dir := "."
		if len(args) == 1 {
			dir = args[0]
		}
		out, err := e.output(locationColumns)
		if err != nil {
			e.log.Error(err.Error())
			return cli.ExitProblems
		}
		var (
			found []sdk.Location
			errs  []error
		)
		if *current {
			loc, locErrs, err := report.Current(e.report)
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
				return cli.ExitProblems
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
				return cli.ExitProblems
			}
		}
		if err := out.Flush(); err != nil {
			e.log.Error(err.Error())
			return cli.ExitProblems
		}
		return cli.ExitOK
	}
}
