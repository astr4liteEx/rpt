package main

import (
	"encoding/json/v2"
	"path"
	"strings"

	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/internal/report"
	"github.com/astr4liteEx/rpt/sdk"
	"github.com/spf13/pflag"
)

var evidenceColumns = []cli.Column{
	{Header: "OWNER", Value: func(m map[string]any) string {
		if f, _ := m["finding"].(string); f != "" {
			return f
		}
		p, _ := m["page"].(string)
		return p
	}},
	{Header: "SOURCE", Field: "source"}, {Header: "PATH", Field: "path"}, {Header: "EXISTS", Field: "exists"},
}

// recordPath is where a record a write printed lives, for the write's
// bookkeeping.
func recordPath(rec any) string {
	switch r := rec.(type) {
	case sdk.Finding:
		return r.Path
	case sdk.Page:
		return r.Path
	}
	return ""
}

// evidenceGetVerb lists every reference the findings and pages make to
// evidence files, or with owner IDs only theirs, and with --orphans the
// files in the evidence folders that nothing references.
func evidenceGetVerb(flags *pflag.FlagSet) runner {
	orphans := flags.Bool("orphans", false, "also list files in findings/evidence/ and pages/evidence/ that nothing references")
	return func(e *env, args []string) int {
		ids := findingIDs(args)
		if *orphans && len(ids) > 0 {
			return usageError(e, "--orphans takes no owners")
		}
		out, err := e.output(evidenceColumns)
		if err != nil {
			e.log.Error(err.Error())
			return cli.ExitProblems
		}
		r := openReport(e)
		if r == nil {
			return cli.ExitProblems
		}
		defer r.Close()
		list, readErr := r.Evidence(ids, *orphans)
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
}

// evidencePruneVerb removes the files in the evidence folders that nothing
// references, printing each. On a terminal it asks first; otherwise it
// needs --yes.
func evidencePruneVerb(flags *pflag.FlagSet) runner {
	yes := addYesFlag(flags)
	wf := addWriteFlags(flags, false)
	return func(e *env, args []string) int {
		if len(args) != 0 {
			return usageError(e, "takes no arguments")
		}
		if !mayAsk(e, *yes, *wf.dryRun) {
			return cli.ExitUsage
		}
		return writeOwners(e, wf, nil, func(w *write) {
			gone, err := w.tx.PruneEvidence()
			if err != nil {
				w.refuse(err, "", 0)
				return
			}
			var things []string
			for _, ev := range gone {
				w.done(ev, ev.Path)
				things = append(things, ev.Path)
			}
			if len(things) > 0 && !*yes && !*wf.dryRun && !confirm(e, "evidence file", things, nil) {
				w.declined = true
			}
		})
	}
}

// writeOwners runs a write on findings and pages named by ids.
func writeOwners(e *env, wf writeFlags, ids []string, do func(*write)) int {
	out, err := e.output(evidenceColumns)
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitProblems
	}
	r := openReport(e)
	if r == nil {
		return cli.ExitProblems
	}
	defer r.Close()
	w, ok := newWrite(e, out, r, wf, ids)
	if !ok {
		return cli.ExitUsage
	}
	do(w)
	return w.finish()
}

// evidenceAddVerb lists files in one finding's or page's evidence, copying
// in those not already in the report, and with --link links them in a
// section. With no files it reads evidence records naming their owner and
// file instead. It prints the owners as stored.
func evidenceAddVerb(flags *pflag.FlagSet) runner {
	as := flags.String("as", "", "the copy's file name, exactly (one file only); it must not exist")
	linkTo := flags.String("link", "", "also link each file in this section (a finding's section key or heading, or body for a page)")
	text := flags.String("text", "", "the link's text, its caption (with --link); default: the file's name")
	wf := addWriteFlags(flags, true)
	return func(e *env, args []string) int {
		pos := args
		if len(pos) == 1 || *as != "" && len(pos) != 2 || *text != "" && *linkTo == "" {
			return usageError(e, "needs an owner and a file, --as takes one file, and --text needs --link")
		}
		if len(pos) == 0 {
			return evidenceAddRecords(e, wf)
		}
		id := report.CanonicalID(pos[0])
		var srcs []report.EvidenceSource
		for _, f := range pos[1:] {
			caption := *text
			if caption == "" {
				caption = strings.TrimSuffix(path.Base(f), path.Ext(f))
			}
			srcs = append(srcs, report.EvidenceSource{Path: f, Section: *linkTo, Text: caption})
		}
		return writeOwners(e, wf, []string{id}, func(w *write) {
			rec, err := w.tx.AddEvidence(id, srcs, *as)
			if err != nil {
				w.refuse(err, "", 0)
				return
			}
			w.done(rec, recordPath(rec))
		})
	}
}

// evidenceAddRecords adds the evidence records on stdin: each names its
// owner (finding or page), the file to add, and with section a link and
// its text. Other records pass through.
func evidenceAddRecords(e *env, wf writeFlags) int {
	return writeOwners(e, wf, nil, func(w *write) {
		recs, _, ok := readInput(e, w.out)
		if !ok {
			w.failed = true
			return
		}
		for _, rec := range recs {
			if rec.Kind != "evidence" {
				w.pass(rec.Raw)
				continue
			}
			var ev struct {
				sdk.Evidence
				Source string `json:"file"`
			}
			bad := func(msg string) {
				w.refused = append(w.refused, sdk.Problem{Path: stdinPath, Line: rec.Line, Rule: ruleInput, Level: sdk.Error, Message: "evidence: " + msg})
			}
			if err := json.Unmarshal(rec.Raw, &ev); err != nil {
				bad(err.Error())
				continue
			}
			id := report.CanonicalID(ev.Finding + ev.Page)
			if id == "" || ev.Source == "" || ev.Finding != "" && ev.Page != "" {
				bad("name one owner, finding or page, and the file to add")
				continue
			}
			got, err := w.tx.AddEvidence(id, []report.EvidenceSource{{Path: ev.Source, Section: ev.Section, Text: ev.Text}}, "")
			if err != nil {
				w.refuse(err, stdinPath, rec.Line)
				continue
			}
			w.done(got, recordPath(got))
		}
	})
}

// evidenceRemoveVerb detaches one file from a finding or page: its list
// entry and image links go, text links keep their words unless
// --drop-text. The file stays, for prune. On a terminal it asks first;
// otherwise it needs --yes.
func evidenceRemoveVerb(flags *pflag.FlagSet) runner {
	yes := addYesFlag(flags)
	dropText := flags.Bool("drop-text", false, "drop text links to the file, words and all")
	wf := addWriteFlags(flags, true)
	return func(e *env, args []string) int {
		pos := args
		if len(pos) != 2 {
			return usageError(e, "needs an owner and a reference")
		}
		if !mayAsk(e, *yes, *wf.dryRun) {
			return cli.ExitUsage
		}
		id := report.CanonicalID(pos[0])
		return writeOwners(e, wf, []string{id}, func(w *write) {
			rec, err := w.tx.RemoveEvidence(id, pos[1], *dropText)
			if err != nil {
				w.refuse(err, "", 0)
				return
			}
			w.done(rec, recordPath(rec))
			effect := "its list entry and image links go; text links keep their words; the file stays for rpt evidence prune"
			if *dropText {
				effect = "its list entry and every link go, --drop-text taking text links' words too; the file stays for rpt evidence prune"
			}
			if !*yes && !*wf.dryRun && !confirm(e, "evidence reference", []string{id + "  " + pos[1]}, []string{effect}) {
				w.declined = true
			}
		})
	}
}

// evidenceSetVerb sets the caption of every link to one file, or moves
// the file and rewrites every reference to it.
func evidenceSetVerb(flags *pflag.FlagSet) runner {
	wf := addWriteFlags(flags, true)
	return func(e *env, args []string) int {
		pos := args
		if len(pos) != 4 || pos[2] != "caption" && pos[2] != "path" {
			return usageError(e, "needs an owner, a reference, caption or path, and a value")
		}
		return setEvidence(e, wf, pos[0], pos[1], pos[2], pos[3])
	}
}

// evidenceUnsetVerb empties the caption of every link to one file.
func evidenceUnsetVerb(flags *pflag.FlagSet) runner {
	wf := addWriteFlags(flags, true)
	return func(e *env, args []string) int {
		pos := args
		if len(pos) != 3 || pos[2] != "caption" {
			return usageError(e, "needs an owner, a reference and caption")
		}
		return setEvidence(e, wf, pos[0], pos[1], "caption", "")
	}
}

func setEvidence(e *env, wf writeFlags, owner, ref, what, value string) int {
	id := report.CanonicalID(owner)
	return writeOwners(e, wf, []string{id}, func(w *write) {
		recs, err := w.tx.SetEvidence(id, ref, what, value)
		if err != nil {
			w.refuse(err, "", 0)
			return
		}
		for _, rec := range recs {
			w.done(rec, recordPath(rec))
		}
	})
}
