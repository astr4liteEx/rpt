package main

import (
	"slices"
	"strings"

	"github.com/astr4liteEx/rpt/internal/cli"
)

var findingColumns = []cli.Column{
	{Header: "ID", Field: "id"}, {Header: "SEVERITY", Field: "severity"},
	{Header: "TITLE", Field: "title"}, {Header: "SCOPE", Value: findingScope},
}

// findingScope renders the scope rows a finding's targets fall in, once
// each, in order: "S-12,S-14".
func findingScope(m map[string]any) string {
	targets, _ := m["targets"].([]any)
	var ids []string
	for _, t := range targets {
		tm, _ := t.(map[string]any)
		if id, _ := tm["scope"].(string); id != "" && !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	return strings.Join(ids, ",")
}

// findingsVerb prints every finding in the report; with --lines, each
// record also says where its keys and sections sit in its file.
func findingsVerb(e *env, args []string) int {
	flags, of := newFlags(e, "findings")
	withLines := flags.Bool("lines", false, "add each finding's lines: its file's absolute path and where its frontmatter keys and sections sit in it")
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
		return cli.ExitProblems
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
