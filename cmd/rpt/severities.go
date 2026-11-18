package main

import (
	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/sdk"
)

var severityColumns = []cli.Column{{Header: "RANK", Field: "rank"}, {Header: "LEVEL", Field: "level"}}

// severitiesVerb prints the report's severity levels, most severe first:
// the levels rpt.yaml lists, or the defaults when it lists none.
func severitiesVerb(e *env, args []string) int {
	flags, of := newFlags(e, "severities")
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if flags.NArg() != 0 {
		return badUsage(e, "severities")
	}
	out, err := of.output(e, severityColumns)
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitUsage
	}
	r := openReport(e, *of.report)
	if r == nil {
		return cli.ExitUsage
	}
	defer r.Close()

	cfg, err := r.Config()
	if err != nil {
		return logReportErrors(e.log, err)
	}
	for i, s := range cfg.Severities {
		if err := out.Write(sdk.SeverityLevel{Kind: "severity", Level: s, Rank: i + 1}); err != nil {
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
