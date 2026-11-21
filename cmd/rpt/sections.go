package main

import (

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
		return cli.ExitProblems
	}
	r := openReport(e, *of.report)
	if r == nil {
		return cli.ExitProblems
	}
	defer r.Close()

	cfg, err := r.Config()
	if err != nil {
		return reportErrors(e, out, err)
	}
	for _, s := range cfg.SectionList() {
		if err := out.Write(s); err != nil {
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
