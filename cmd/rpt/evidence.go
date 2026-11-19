package main

import (
	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/sdk"
)

var evidenceColumns = []cli.Column{
	{Header: "FINDING", Field: "finding"}, {Header: "SOURCE", Field: "source"},
	{Header: "PATH", Field: "path"}, {Header: "EXISTS", Field: "exists"},
}

// writeEvidence prints evidence records and returns the exit code for
// readErr, the error from reading them.
func writeEvidence(e *env, out *cli.Output, list []sdk.Evidence, readErr error) int {
	for _, ev := range list {
		if err := out.Write(ev); err != nil {
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

// evidenceVerb lists every reference the findings make to evidence files,
// and with --orphans the files under findings/evidence/ nothing references.
func evidenceVerb(e *env, args []string) int {
	flags, of := newFlags(e, "evidence")
	orphans := flags.Bool("orphans", false, "also list files under findings/evidence/ that no finding references")
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if flags.NArg() != 0 {
		return badUsage(e, "evidence")
	}
	out, err := of.output(e, evidenceColumns)
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitUsage
	}
	r := openReport(e, *of.report)
	if r == nil {
		return cli.ExitProblems
	}
	defer r.Close()
	list, readErr := r.Evidence(*orphans)
	return writeEvidence(e, out, list, readErr)
}

// evidencePruneVerb removes the files under findings/evidence/ that no
// finding references, printing each; --dry-run only prints them.
func evidencePruneVerb(e *env, args []string) int {
	flags, of := newFlags(e, "evidence prune")
	dryRun := flags.Bool("dry-run", false, "print what would be removed, and remove nothing")
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if flags.NArg() != 0 {
		return badUsage(e, "evidence prune")
	}
	out, err := of.output(e, evidenceColumns)
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitUsage
	}
	r := openReport(e, *of.report)
	if r == nil {
		return cli.ExitProblems
	}
	defer r.Close()
	gone, err := r.PruneEvidence(*dryRun)
	return writeEvidence(e, out, gone, err)
}

// evidenceAddVerb copies files into findings/evidence/ and lists them in
// one finding's evidence, printing the finding as stored.
func evidenceAddVerb(e *env, args []string) int {
	flags, of := newFlags(e, "evidence add")
	as := flags.String("as", "", "the copy's file name, exactly (one file only); it must not exist")
	pos, err := parseInterspersed(flags, args)
	if err != nil {
		return cli.ExitUsage
	}
	if len(pos) < 2 || *as != "" && len(pos) != 2 {
		return badUsage(e, "evidence add")
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

	f, err := r.AddEvidence(pos[0], pos[1:], *as)
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
