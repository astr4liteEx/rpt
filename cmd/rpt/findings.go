package main

import "github.com/astr4liteEx/rpt/internal/cli"

var findingColumns = []cli.Column{
	{Header: "ID", Field: "id"}, {Header: "SEVERITY", Field: "severity"},
	{Header: "TITLE", Field: "title"}, {Header: "SCOPE", Field: "scope"},
}

// findingsVerb prints every finding in the report; with --lines, each
// record also says where its keys and sections sit in its file.
func findingsVerb(e *env, args []string) int {
	flags, of := newFlags(e, "findings")
	withLines := flags.Bool("lines", false, "add each finding's lines: where its frontmatter keys and sections sit in its file")
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if flags.NArg() != 0 {
		return badUsage(e, "findings")
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

	read := r.Findings
	if *withLines {
		read = r.FindingsWithLines
	}
	list, readErr := read()
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
