package main

import (
	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/internal/report"
	"github.com/spf13/pflag"
)

// newVerb creates an empty report folder, optionally set up like another
// report. It prints nothing on success unless --json asks for the new
// report's location record.
func newVerb(flags *pflag.FlagSet) runner {
	like := flags.String("like", "", "copy rpt.yaml and the scope.csv columns from this report")
	withPages := flags.Bool("with-pages", false, "with --like, also copy its pages and their evidence")
	return func(e *env, args []string) int {
		if len(args) != 1 || *withPages && *like == "" {
			return usageError(e, "needs one folder, and --with-pages needs --like")
		}
		dir := args[0]
		if err := report.NewLike(dir, *like, *withPages); err != nil {
			e.log.Error(err.Error())
			return cli.ExitProblems
		}
		if !e.json {
			return cli.ExitOK
		}
		loc, _ := report.Locate(dir)
		out, err := e.output(locationColumns)
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
}
