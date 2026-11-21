package main

import (
	"bufio"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/internal/report"
	"github.com/astr4liteEx/rpt/sdk"
)

// Rules for problems that aren't validate's.
const (
	ruleExists = "exists" // an ID or file that isn't there
	ruleInput  = "input"  // a stdin line that isn't a record rpt can use
	ruleRev    = "rev"    // the thing changed since the caller read it
	ruleWrite  = "write"  // the write would break the report; nothing was written
)

// problem reports p both ways: a line on stderr, and a record on stdout
// unless stdout shows tables.
func (e *env) problem(p report.Problem) error {
	rec := report.ProblemRecord(p)
	rec.Command = e.command
	if e.diag != nil {
		e.diag.Print(cli.Diagnostic{Path: p.Path, Rule: p.Rule, Message: p.Message, Error: p.Level == report.Error, Line: p.Line})
	} else {
		level := slog.LevelError
		if p.Level != report.Error {
			level = slog.LevelWarn
		}
		e.log.Log(context.Background(), level, p.Message, "path", p.Path, "line", p.Line)
	}
	if e.out == nil || e.out.Table() {
		return nil
	}
	return e.out.Write(rec)
}

// problems reports each problem, and returns errReported when one is an
// error.
func (e *env) problems(ps []report.Problem) error {
	failed := false
	for _, p := range ps {
		if err := e.problem(p); err != nil {
			return err
		}
		failed = failed || p.Level == report.Error
	}
	if failed {
		return errReported
	}
	return nil
}

// failure is the problem err is, when it is a refusal of what the caller
// asked rather than rpt failing; path and line place it when err doesn't.
func failure(err error, path string, line int) (report.Problem, bool) {
	p := report.Problem{Path: path, Line: line, Rule: ruleWrite, Level: report.Error, Message: err.Error()}
	var ref *report.Refusal
	var fe *report.FileError
	switch {
	case errors.As(err, &ref):
		if path == "" {
			p.Path = ref.Path
		}
		p.Message = ref.Msg
	case errors.Is(err, report.ErrNotFound):
		p.Rule = ruleExists
		if p.Path == "" {
			p.Path = "."
		}
	case errors.As(err, &fe):
		p.Path, p.Line, p.Rule, p.Message = fe.Path, fe.Line, "readable", fe.Err.Error()
	default:
		return p, false
	}
	return p, true
}

// fail reports err as a problem when it is one, and returns what the
// command returns.
func (e *env) fail(err error) error {
	if p, ok := failure(err, "", 0); ok {
		if perr := e.problem(p); perr != nil {
			return perr
		}
		return errReported
	}
	return err
}

// readStdin reads every record on stdin before the command acts on any.
// A line that isn't a record, or an error-level problem from an earlier
// stage, stops the command: the problems are passed on, the bad lines
// reported, and it returns errReported. Warnings pass.
func (e *env) readStdin() ([]sdk.Rec, error) {
	var recs []sdk.Rec
	var bad []report.Problem
	stop := false
	for rec, err := range sdk.Records(e.stdin) {
		var le *sdk.LineError
		switch {
		case errors.As(err, &le):
			bad = append(bad, report.Problem{Path: report.StreamPath, Line: le.Line, Rule: ruleInput, Level: report.Error, Message: le.Err.Error()})
			continue
		case err != nil:
			return nil, err
		}
		recs = append(recs, rec)
		if rec.Kind == "problem" {
			var p sdk.Problem
			stop = stop || json.Unmarshal(rec.Raw, &p) == nil && p.Level == sdk.Error
		}
	}
	if len(bad) == 0 && !stop {
		return recs, nil
	}
	for _, rec := range recs {
		if rec.Kind != "problem" {
			continue
		}
		var p sdk.Problem
		if json.Unmarshal(rec.Raw, &p) == nil && e.out.Table() {
			e.problem(report.Problem{Path: p.Path, Line: p.Line, Rule: p.Rule, Level: string(p.Level), Message: p.Message})
		} else if err := e.out.WriteRaw(rec.Raw); err != nil {
			return nil, err
		}
	}
	for _, p := range bad {
		if err := e.problem(p); err != nil {
			return nil, err
		}
	}
	return nil, errReported
}

// writeFlags are the flags write commands take.
type writeFlags struct {
	dryRun bool
	ifRev  []string
	yes    bool
	cited  struct{ force, cleanup bool }
}

// addWriteFlags adds --dry-run, and when the command changes things it
// names, --if-rev.
func addWriteFlags(c *cobra.Command, w *writeFlags, named bool) {
	c.Flags().BoolVar(&w.dryRun, "dry-run", false, "Check the write and print what it would give, and write nothing")
	if named {
		c.Flags().StringArrayVar(&w.ifRev, "if-rev", nil, "Refuse the write if the thing changed since you read this rev: ID=rev, or the rev alone when one thing is named (repeatable)")
	}
}

// addYesFlag adds --yes, for commands that remove.
func addYesFlag(c *cobra.Command, w *writeFlags) {
	c.Flags().BoolVar(&w.yes, "yes", false, "Remove without asking; needed when stdin or stderr isn't a terminal")
}

// addCitedFlags adds --force and --cleanup, saying what they do to the
// things that point at what the command changes.
func addCitedFlags(c *cobra.Command, w *writeFlags, force, cleanup string) {
	c.Flags().BoolVar(&w.cited.force, "force", false, force)
	c.Flags().BoolVar(&w.cited.cleanup, "cleanup", false, cleanup)
	c.MarkFlagsMutuallyExclusive("force", "cleanup")
}

func (w *writeFlags) mode() report.Cited {
	switch {
	case w.cited.force:
		return report.Force
	case w.cited.cleanup:
		return report.Cleanup
	}
	return report.Refuse
}

// A batch is one write command's work: the records it will print and the
// problems that stop it. Nothing is written or printed until it ends.
type batch struct {
	m        *report.Model
	items    []item
	refused  []report.Problem
	removing []string // what a remove takes away, for the question
}

type item struct {
	rec any
	raw []byte
}

func (b *batch) print(rec any)   { b.items = append(b.items, item{rec: rec}) }
func (b *batch) pass(raw []byte) { b.items = append(b.items, item{raw: raw}) }

// refuse notes why part of the write can't be done, placed at path and
// line when err doesn't say; it returns err when it is a failure rather
// than a refusal.
func (b *batch) refuse(err error, path string, line int) error {
	p, ok := failure(err, path, line)
	if !ok {
		return err
	}
	b.refused = append(b.refused, p)
	return nil
}

// write runs one write command: load the report, check --if-rev against
// the revs of what it names, do the work, then either report the
// refusals and write nothing, or (after asking, for a remove) save and
// print the records.
func (e *env) write(w *writeFlags, named func(*report.Model) map[string]string, do func(*batch) error) error {
	m, err := e.load()
	if err != nil {
		return err
	}
	defer m.Close()
	if named != nil {
		if err := e.checkRevs(w.ifRev, named(m)); err != nil {
			return err
		}
	}
	b := &batch{m: m}
	if err := do(b); err != nil {
		return e.fail(err)
	}
	if len(b.refused) > 0 {
		return e.problems(b.refused)
	}
	if len(b.removing) > 0 && !w.yes && !w.dryRun {
		if !isTerminal(e.stdin) || !isTerminal(e.stderr) {
			return usagef("removing needs --yes when stdin or stderr isn't a terminal")
		}
		if !e.confirm(b.removing) {
			return errDeclined
		}
	}
	if err := m.Save(w.dryRun); err != nil {
		return err
	}
	for _, it := range b.items {
		var err error
		switch rec := it.rec.(type) {
		case nil:
			err = e.out.WriteRaw(it.raw)
		case sdk.Config:
			err = e.writeConfig(rec)
		default:
			err = e.out.Write(rec)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// checkRevs refuses when a thing named changed since the caller read it.
// revs maps the IDs the command names to their revs now.
func (e *env) checkRevs(ifRev []string, revs map[string]string) error {
	ids := make([]string, 0, len(revs))
	for id := range revs {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	var ps []report.Problem
	for _, v := range ifRev {
		id, want, ok := strings.Cut(v, "=")
		switch {
		case !ok && len(ids) == 1:
			id, want = ids[0], v
		case !ok:
			return usagef("--if-rev %s: name the thing as ID=rev when the command names more than one", v)
		}
		i := slices.IndexFunc(ids, func(n string) bool { return strings.EqualFold(n, id) })
		if i < 0 {
			return usagef("--if-rev %s: %s isn't one of the things this command changes", v, id)
		}
		if now := revs[ids[i]]; now != want {
			ps = append(ps, report.Problem{Path: ".", Rule: ruleRev, Level: report.Error,
				Message: fmt.Sprintf("%s changed since rev %s (it is now %s); read it again", ids[i], want, now)})
		}
	}
	return e.problems(ps)
}

// confirm asks on stderr whether to remove what, reading the answer from
// stdin, both terminals.
func (e *env) confirm(what []string) bool {
	var lines []string
	for _, w := range what {
		lines = append(lines, cli.CleanLine(w))
	}
	fmt.Fprintln(e.stderr, cli.Box("Remove:\n  "+strings.Join(lines, "\n  ")))
	fmt.Fprint(e.stderr, "Remove? [y/N] ")
	answer, _ := bufio.NewReader(e.stdin).ReadString('\n')
	return strings.EqualFold(strings.TrimSpace(answer), "y") || strings.EqualFold(strings.TrimSpace(answer), "yes")
}

// writeOwn writes a record the command changed, which arrived on stdin:
// on a pipe its bytes as raw holds them, in a table rec.
func (e *env) writeOwn(rec any, raw []byte) error {
	if e.out.Table() {
		return e.out.Write(rec)
	}
	return e.out.WriteRaw(raw)
}

// docRevs are the revs of the documents of kind k named by ids, for
// --if-rev; an ID that isn't there is left out.
func docRevs(k *report.Kind, ids ...string) func(*report.Model) map[string]string {
	return func(m *report.Model) map[string]string {
		out := map[string]string{}
		for _, id := range ids {
			if d, err := m.Get(k, id); err == nil {
				out[d.ID] = d.Rev
			}
		}
		return out
	}
}

// docRecord is a finding or page as its record.
func docRecord(m *report.Model, d *report.Doc, o report.RecordOpts) any {
	if d.Kind == report.PageKind {
		return m.PageRecord(d, o)
	}
	return m.FindingRecord(d, o)
}

// flagsAmongValues refuses a value that is one of the command's flags. A
// set command reads everything after the ID as values, so values may
// start with -; a flag put there by habit would otherwise be written into
// the report. With -- before the arguments, every one is a value.
func flagsAmongValues(c *cobra.Command, values []string) error {
	if c.ArgsLenAtDash() >= 0 {
		return nil
	}
	for _, v := range values {
		name, ok := strings.CutPrefix(v, "--")
		if !ok {
			if len(v) == 2 && v[0] == '-' && c.Flags().ShorthandLookup(v[1:]) != nil {
				return usagef("%s comes after the values, so it would be written as one: put flags before the arguments, or -- before them to write it", v)
			}
			continue
		}
		name, _, _ = strings.Cut(name, "=")
		if c.Flags().Lookup(name) != nil || c.InheritedFlags().Lookup(name) != nil {
			return usagef("%s comes after the values, so it would be written as one: put flags before the arguments, or -- before them to write it", v)
		}
	}
	return nil
}
