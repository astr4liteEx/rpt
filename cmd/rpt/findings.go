package main

import (
	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/internal/report"
)

var findingColumns = []cli.Column{
	{Header: "ID", Field: "id"}, {Header: "SEVERITY", Field: "severity"},
	{Header: "TITLE", Field: "title"}, {Header: "SCOPE", Field: "scope"},
}

// findingsVerb prints every finding in the report, or with --staging every
// finding awaiting review.
func findingsVerb(e *env, args []string) int {
	flags, of := newFlags(e, "findings")
	staging := flags.Bool("staging", false, "list findings in staging/ awaiting review")
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	out, err := of.output(e, findingColumns)
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitUsage
	}
	r := openReport(e, *of.report)
	if r == nil {
		return cli.ExitUsage
	}
	defer r.Close()

	dir := report.FindingsDir
	if *staging {
		dir = report.StagingDir
	}
	list, readErr := r.FindingsIn(dir)
	for _, f := range list {
		if err := out.Write(f); err != nil {
			e.log.Error(err.Error())
			return cli.ExitUsage
		}
	}
	if err := out.Flush(); err != nil {
		e.log.Error(err.Error())
		return cli.ExitUsage
	}
	return logReportErrors(e.log, readErr)
}
