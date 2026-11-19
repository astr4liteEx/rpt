package main

import (
	"io"

	"github.com/astr4liteEx/rpt/internal/cli"
)

var sectionColumns = []cli.Column{{Header: "KEY", Field: "key"}, {Header: "HEADING", Field: "heading"}, {Header: "REQUIRED", Field: "required"}}

// sectionsVerb prints the report's sections: the fixed ones with the
// headings rpt.yaml gives them, then the custom ones it requires.
func sectionsVerb(e *env, args []string) int {
	flags, of := newFlags(e, "sections")
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if flags.NArg() != 0 {
		return badUsage(e, "sections")
	}
	out, err := of.output(e, sectionColumns)
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitUsage
	}
	r := openReport(e, *of.report)
	if r == nil {
		return cli.ExitProblems
	}
	defer r.Close()

	cfg, err := r.Config()
	if err != nil {
		return logReportErrors(e.log, err)
	}
	for _, s := range cfg.SectionList() {
		if err := out.Write(s); err != nil {
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

// sectionsSetVerb replaces one section's text in one finding with stdin.
func sectionsSetVerb(e *env, args []string) int {
	flags, of := newFlags(e, "sections set")
	pos, err := parseInterspersed(flags, args)
	if err != nil {
		return cli.ExitUsage
	}
	if len(pos) != 2 {
		return badUsage(e, "sections set")
	}
	out, err := of.output(e, findingColumns)
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitUsage
	}
	text, err := io.ReadAll(e.stdin)
	if err != nil {
		e.log.Error("read stdin: " + err.Error())
		return cli.ExitUsage
	}
	r := openReport(e, *of.report)
	if r == nil {
		return cli.ExitProblems
	}
	defer r.Close()

	f, err := r.SetSection(pos[0], pos[1], string(text))
	if err != nil {
		return logEditError(e, err, 0)
	}
	if err := out.Write(f); err != nil {
		e.log.Error(err.Error())
		return cli.ExitUsage
	}
	if err := out.Flush(); err != nil {
		e.log.Error(err.Error())
		return cli.ExitUsage
	}
	return cli.ExitOK
}
