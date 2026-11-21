package main

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/internal/report"
	"github.com/astr4liteEx/rpt/sdk"
)

// Rules for refused and unfinished writes.
const (
	ruleRev        = "rev"        // the thing changed since the caller read it
	ruleWrite      = "write"      // the write would break a rule; nothing was written
	ruleNotWritten = "notWritten" // a write stopped partway; run it again to finish
)

// writeFlags are the flags every write command takes.
type writeFlags struct {
	dryRun *bool
	ifRev  *[]string // nil for a command that names no existing thing
}

// addWriteFlags adds --dry-run, and with named (the command changes things
// it names by ID) --if-rev.
func addWriteFlags(f *flagSet, named bool) writeFlags {
	w := writeFlags{dryRun: f.Bool("dry-run", false, "check the write and print what it would give, and write nothing")}
	if named {
		w.ifRev = f.StringArray("if-rev", nil, "refuse the write if the thing changed since you read this rev: ID=rev, or the rev alone when one thing is named (repeatable)")
	}
	return w
}

// A write is one run of a write command: what it will print, what it
// refused, and the report.Tx holding its changes. Nothing is printed until
// finish: then either every record (and the write is committed), or only
// problems (and nothing is written).
type write struct {
	e       *env
	out     *cli.Output
	tx      *report.Tx
	dryRun  bool
	items   []writeItem
	refused []sdk.Problem
	failed  bool // an error that isn't a problem, already logged
	// declined: the user said no when asked; nothing is written or printed.
	declined bool
}

// A writeItem is one record the write prints: one it made (rec, from the
// file at path) or one passing through (raw).
type writeItem struct {
	rec  any
	path string
	raw  []byte
}

// newWrite starts a write on r for a command naming the things in named.
// A bad --if-rev is a usage error: it prints why and returns ok false.
func newWrite(e *env, out *cli.Output, r *report.Report, wf writeFlags, usageName string, named []string) (*write, bool) {
	w := &write{e: e, out: out, tx: r.Begin(), dryRun: *wf.dryRun}
	if wf.ifRev == nil {
		return w, true
	}
	for _, v := range *wf.ifRev {
		id, rev, ok := strings.Cut(v, "=")
		// An ID may be given in any case.
		if i := slices.IndexFunc(named, func(n string) bool { return strings.EqualFold(n, id) }); i >= 0 {
			id = named[i]
		}
		switch {
		case !ok && len(named) == 1:
			id, rev = named[0], v
		case !ok:
			fmt.Fprintf(e.stderr, "rpt: --if-rev %s: name the thing as ID=rev when the command names more than one\n", v)
			badUsage(e, usageName)
			return nil, false
		case !slices.Contains(named, id):
			fmt.Fprintf(e.stderr, "rpt: --if-rev %s: %s isn't one of the things this command changes\n", v, id)
			badUsage(e, usageName)
			return nil, false
		}
		w.tx.IfRev[id] = rev
	}
	return w, true
}

// done adds a record the write made from the file at path.
func (w *write) done(rec any, path string) {
	w.items = append(w.items, writeItem{rec: rec, path: path})
}

// pass adds a record passing through unchanged.
func (w *write) pass(raw []byte) { w.items = append(w.items, writeItem{raw: raw}) }

// refuse records why one part of the write can't be done. path and line
// locate it when the error doesn't: "-" and the line for a stdin record.
func (w *write) refuse(err error, path string, line int) {
	p := sdk.Problem{Path: path, Line: line, Rule: ruleWrite, Level: sdk.Error, Message: err.Error()}
	if re, ok := errors.AsType[*report.RevError](err); ok {
		p.Path, p.Line, p.Rule = re.Path, 0, ruleRev
	} else if errors.Is(err, report.ErrNoFinding) || errors.Is(err, report.ErrNoScopeRow) {
		p.Rule = ruleExists
	} else if fe, ok := errors.AsType[*report.FileError](err); ok {
		p.Path, p.Line, p.Rule, p.Message = fe.Path, fe.Line, ruleReadable, fe.Err.Error()
	} else if !isRequestError(err) {
		w.e.log.Error(err.Error())
		w.failed = true
		return
	}
	w.refused = append(w.refused, p)
}

// finish commits the write and prints its records, or, if anything was
// refused, prints only the problems and writes nothing. It returns the
// exit code.
func (w *write) finish() int {
	if w.declined {
		return cli.ExitProblems
	}
	if len(w.refused) > 0 || w.failed {
		return w.problems(w.refused)
	}
	err := w.tx.Commit(w.dryRun)
	if nw, ok := errors.AsType[*report.NotWrittenError](err); ok {
		var printed []writeItem
		for _, it := range w.items {
			if it.raw != nil || slices.Contains(nw.Written, it.path) {
				printed = append(printed, it)
			}
		}
		if code := w.print(printed); code != cli.ExitOK {
			return code
		}
		var ps []sdk.Problem
		for _, n := range nw.NotWritten {
			ps = append(ps, sdk.Problem{Path: n.Path, Rule: ruleNotWritten, Level: sdk.Error,
				Message: "not written: " + n.Reason + "; run the same command again to finish"})
		}
		return w.problems(ps)
	}
	if err != nil {
		w.refuse(err, "", 0)
		return w.problems(w.refused)
	}
	return w.print(w.items)
}

// print writes the items and flushes, returning the exit code.
func (w *write) print(items []writeItem) int {
	for _, it := range items {
		var err error
		if it.raw != nil {
			err = w.out.WriteRaw(it.raw)
		} else {
			err = w.out.Write(it.rec)
		}
		if err != nil {
			w.e.log.Error(err.Error())
			return cli.ExitProblems
		}
	}
	if err := w.out.Flush(); err != nil {
		w.e.log.Error(err.Error())
		return cli.ExitProblems
	}
	return cli.ExitOK
}

// problems reports ps and returns exit 1.
func (w *write) problems(ps []sdk.Problem) int {
	for _, p := range ps {
		if err := w.e.problem(w.out, p); err != nil {
			w.e.log.Error(err.Error())
			break
		}
	}
	if err := w.out.Flush(); err != nil {
		w.e.log.Error(err.Error())
	}
	return cli.ExitProblems
}
