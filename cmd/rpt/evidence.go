package main

import (
	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/internal/report"
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
			return cli.ExitProblems
		}
	}
	if err := out.Flush(); err != nil {
		e.log.Error(err.Error())
		return cli.ExitProblems
	}
	return reportErrors(e, out, readErr)
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
		return cli.ExitProblems
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
	wf := addWriteFlags(flags, false)
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if flags.NArg() != 0 {
		return badUsage(e, "evidence prune")
	}
	out, err := of.output(e, evidenceColumns)
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitProblems
	}
	r := openReport(e, *of.report)
	if r == nil {
		return cli.ExitProblems
	}
	defer r.Close()
	w, _ := newWrite(e, out, r, wf, "evidence prune", nil)
	gone, err := w.tx.PruneEvidence()
	if err != nil {
		return reportErrors(e, out, err)
	}
	for _, ev := range gone {
		w.done(ev, ev.Path)
	}
	return w.finish()
}

// evidenceAddVerb copies files into findings/evidence/ and lists them in
// one finding's evidence, printing the finding as stored.
func evidenceAddVerb(e *env, args []string) int {
	flags, of := newFlags(e, "evidence add")
	as := flags.String("as", "", "the copy's file name, exactly (one file only); it must not exist")
	wf := addWriteFlags(flags, true)
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	pos := flags.Args()
	if len(pos) < 2 || *as != "" && len(pos) != 2 {
		return badUsage(e, "evidence add")
	}
	return writeFinding(e, of, wf, "evidence add", pos[0], func(tx *report.Tx) (sdk.Finding, error) {
		return tx.AddEvidence(pos[0], pos[1:], *as)
	})
}
