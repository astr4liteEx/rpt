package main

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"github.com/spf13/pflag"
	"slices"

	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/internal/report"
	"github.com/astr4liteEx/rpt/sdk"
)

// setVerb changes one frontmatter value of one finding.
func setVerb(e *env, args []string) int {
	flags, of := newFlags(e, "findings set")
	wf := addWriteFlags(flags, true)
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	pos := flags.Args()
	if len(pos) != 3 {
		code := badUsage(e, "findings set")
		fmt.Fprintln(e.stderr, `value is YAML: high, '[S-12, S-14]', "9.1"`)
		return code
	}
	return writeFinding(e, of, wf, "findings set", pos[0], func(tx *report.Tx) (sdk.Finding, error) {
		return tx.Set(pos[0], pos[1], pos[2])
	})
}

// unsetVerb removes frontmatter keys from one finding.
func unsetVerb(e *env, args []string) int {
	flags, of := newFlags(e, "findings unset")
	wf := addWriteFlags(flags, true)
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	pos := flags.Args()
	if len(pos) < 2 {
		return badUsage(e, "findings unset")
	}
	return writeFinding(e, of, wf, "findings unset", pos[0], func(tx *report.Tx) (sdk.Finding, error) {
		return tx.Unset(pos[0], pos[1:]...)
	})
}

// writeFinding runs a write that changes the one finding id, printing it
// as stored.
func writeFinding(e *env, of outputFlags, wf writeFlags, name, id string, change func(*report.Tx) (sdk.Finding, error)) int {
	out, err := of.output(e, findingColumns)
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitProblems
	}
	r := openReport(e, *of.report)
	if r == nil {
		return cli.ExitProblems
	}
	defer r.Close()
	w, ok := newWrite(e, out, r, wf, name, []string{id})
	if !ok {
		return cli.ExitUsage
	}
	if f, err := change(w.tx); err != nil {
		w.refuse(err, report.FindingsDir, 0)
	} else {
		w.done(f, f.Path)
	}
	return w.finish()
}

// uniq returns ids in order, each once.
func uniq(ids []string) []string {
	var out []string
	for _, id := range ids {
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

// requestErrors are mistakes in what was asked: refusals, not failures.
var requestErrors = []error{
	report.ErrNoFinding, report.ErrRefusedKey, report.ErrRefusedUnset, report.ErrBadValue,
	report.ErrNoScopeRow, report.ErrCited, report.ErrBadSource,
}

func isRequestError(err error) bool {
	return slices.ContainsFunc(requestErrors, func(target error) bool { return errors.Is(err, target) })
}

// targetFlags collects repeated --target flags.
type targetFlags []sdk.Target

func (t *targetFlags) String() string { return "" }

func (t *targetFlags) Type() string { return "target" }

func (t *targetFlags) Set(v string) error {
	target, err := report.ParseTarget(v)
	if err != nil {
		return err
	}
	*t = append(*t, target)
	return nil
}

// addVerb writes each finding record on stdin into the report as a new
// finding file and prints the finding as stored. Other records pass
// through untouched. With --title and --severity it writes one blank
// finding from its flags instead, with a heading for every required
// section, and doesn't read stdin. Every record is checked before any is
// written: one refusal and nothing is written.
func addVerb(e *env, args []string) int {
	flags, of := newFlags(e, "findings add")
	title := flags.String("title", "", "write one finding with this title instead of reading stdin")
	severity := flags.String("severity", "", "the finding's severity (with --title)")
	var targets targetFlags
	flags.Var(&targets, "target", "a target: a scope ID, or a map like '{scope: S-20, host: 10.0.1.5, port: 22}' (with --title; repeatable)")
	id := flags.String("id", "", "the finding's ID (with --title); default: the next free one")
	scaffold := flags.Bool("scaffold", false, "give stdin records an empty heading for each required section they lack")
	wf := addWriteFlags(flags, false)
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	pos := flags.Args()
	fromFlags := false
	flags.Visit(func(f *pflag.Flag) {
		fromFlags = fromFlags || slices.Contains([]string{"title", "severity", "target", "id"}, f.Name)
	})
	if len(pos) != 0 || fromFlags && (*title == "" || *severity == "") {
		return badUsage(e, "findings add")
	}
	out, err := of.output(e, findingColumns)
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitProblems
	}
	r := openReport(e, *of.report)
	if r == nil {
		return cli.ExitProblems
	}
	defer r.Close()
	w, _ := newWrite(e, out, r, wf, "findings add", nil)

	add := func(f sdk.Finding, line int, scaffold bool) {
		path := report.FindingsDir
		if line > 0 {
			path = stdinPath
		}
		if scaffold {
			if f, err = r.Scaffold(f); err != nil {
				w.refuse(err, path, line)
				return
			}
		}
		added, err := w.tx.Add(f)
		if err != nil {
			w.refuse(err, path, line)
			return
		}
		w.done(added, added.Path)
	}

	if fromFlags {
		add(sdk.Finding{Kind: "finding", ID: *id, Title: *title, Severity: sdk.Severity(*severity), Targets: targets}, 0, true)
		return w.finish()
	}
	recs, code, ok := readInput(e, out)
	if !ok {
		return code
	}
	for _, rec := range recs {
		if rec.Kind != "finding" {
			w.pass(rec.Raw)
			continue
		}
		var f sdk.Finding
		if err := json.Unmarshal(rec.Raw, &f); err != nil {
			w.refused = append(w.refused, sdk.Problem{Path: stdinPath, Line: rec.Line, Rule: ruleInput, Level: sdk.Error, Message: "finding: " + err.Error()})
			continue
		}
		add(f, rec.Line, *scaffold)
	}
	return w.finish()
}

// deleteVerb removes each named finding's file and prints the finding as it
// was. One unknown ID and nothing is deleted.
func deleteVerb(e *env, args []string) int {
	flags, of := newFlags(e, "findings delete")
	wf := addWriteFlags(flags, true)
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	ids := uniq(flags.Args())
	if len(ids) == 0 {
		return badUsage(e, "findings delete")
	}
	out, err := of.output(e, findingColumns)
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitProblems
	}
	r := openReport(e, *of.report)
	if r == nil {
		return cli.ExitProblems
	}
	defer r.Close()
	w, ok := newWrite(e, out, r, wf, "findings delete", ids)
	if !ok {
		return cli.ExitUsage
	}
	for _, id := range ids {
		f, err := w.tx.Delete(id)
		if err != nil {
			w.refuse(err, report.FindingsDir, 0)
			continue
		}
		w.done(f, f.Path)
	}
	return w.finish()
}
