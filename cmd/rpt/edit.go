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
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	pos := flags.Args()
	if len(pos) != 3 {
		code := badUsage(e, "findings set")
		fmt.Fprintln(e.stderr, `value is YAML: high, '[S-12, S-14]', "9.1"`)
		return code
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

	f, err := r.Set(pos[0], pos[1], pos[2])
	if err != nil {
		return logEditError(e, err, 0)
	}
	if err := out.Write(f); err != nil {
		e.log.Error(err.Error())
		return cli.ExitProblems
	}
	if err := out.Flush(); err != nil {
		e.log.Error(err.Error())
		return cli.ExitProblems
	}
	return cli.ExitOK
}

// unsetVerb removes frontmatter keys from one finding.
func unsetVerb(e *env, args []string) int {
	flags, of := newFlags(e, "findings unset")
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	pos := flags.Args()
	if len(pos) < 2 {
		return badUsage(e, "findings unset")
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

	f, err := r.Unset(pos[0], pos[1:]...)
	if err != nil {
		return logEditError(e, err, 0)
	}
	if err := out.Write(f); err != nil {
		e.log.Error(err.Error())
		return cli.ExitProblems
	}
	if err := out.Flush(); err != nil {
		e.log.Error(err.Error())
		return cli.ExitProblems
	}
	return cli.ExitOK
}

// requestErrors are mistakes in what was asked: exit 1, not 2.
var requestErrors = []error{
	report.ErrNoFinding, report.ErrRefusedKey, report.ErrRefusedUnset, report.ErrBadValue,
	report.ErrNoScopeRow, report.ErrCited, report.ErrBadSource,
}

func isRequestError(err error) bool {
	return slices.ContainsFunc(requestErrors, func(target error) bool { return errors.Is(err, target) })
}

// logEditError logs an error from editing and returns its exit code. A
// problem in a report file, or anything wrong with what was asked (an
// unknown finding, a key that can't be set, a bad value), is exit 1; any
// other failure, such as a failed write, is too. line > 0 locates the
// record on stdin.
func logEditError(e *env, err error, line int) int {
	if fe, ok := errors.AsType[*report.FileError](err); ok {
		e.log.Error(fe.Err.Error(), "path", fe.Path, "line", fe.Line)
		return cli.ExitProblems
	}
	if isRequestError(err) {
		if line > 0 {
			e.log.Error(err.Error(), "path", stdinPath, "line", line)
		} else {
			e.log.Error(err.Error())
		}
		return cli.ExitProblems
	}
	e.log.Error(err.Error())
	return cli.ExitProblems
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
// section, and doesn't read stdin.
func addVerb(e *env, args []string) int {
	flags, of := newFlags(e, "findings add")
	title := flags.String("title", "", "write one finding with this title instead of reading stdin")
	severity := flags.String("severity", "", "the finding's severity (with --title)")
	var targets targetFlags
	flags.Var(&targets, "target", "a target: a scope ID, or a map like '{scope: S-20, host: 10.0.1.5, port: 22}' (with --title; repeatable)")
	id := flags.String("id", "", "the finding's ID (with --title); default: the next free one")
	scaffold := flags.Bool("scaffold", false, "give stdin records an empty heading for each required section they lack")
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

	add := func(f sdk.Finding, line int, scaffold bool) int {
		if scaffold {
			if f, err = r.Scaffold(f); err != nil {
				return logEditError(e, err, line)
			}
		}
		added, err := r.Add(f)
		if err != nil {
			return logEditError(e, err, line)
		}
		if err := out.Write(added); err != nil {
			e.log.Error(err.Error())
			return cli.ExitProblems
		}
		return cli.ExitOK
	}
	finish := func(code int) int {
		if err := out.Flush(); err != nil {
			e.log.Error(err.Error())
			return cli.ExitProblems
		}
		return code
	}

	if fromFlags {
		f := sdk.Finding{Kind: "finding", ID: *id, Title: *title, Severity: sdk.Severity(*severity), Targets: targets}
		return finish(add(f, 0, true))
	}

	recs, code, ok := readInput(e, out)
	if !ok {
		return finish(code)
	}
	for _, rec := range recs {
		if rec.Kind != "finding" {
			if err := out.WriteRaw(rec.Raw); err != nil {
				e.log.Error(err.Error())
				return cli.ExitProblems
			}
			continue
		}
		var f sdk.Finding
		if err := json.Unmarshal(rec.Raw, &f); err != nil {
			e.log.Error("finding: "+err.Error(), "path", stdinPath, "line", rec.Line)
			code = cli.ExitProblems
			continue
		}
		switch c := add(f, rec.Line, *scaffold); c {
		case cli.ExitUsage:
			return c
		case cli.ExitProblems:
			code = c
		}
	}
	return finish(code)
}

// deleteVerb removes each named finding's file and prints the finding as it
// was. An unknown ID is logged and the rest are still deleted (exit 1).
func deleteVerb(e *env, args []string) int {
	flags, of := newFlags(e, "findings delete")
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	pos := flags.Args()
	if len(pos) == 0 {
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

	code := cli.ExitOK
	for _, id := range pos {
		f, err := r.Delete(id)
		if err != nil {
			code = max(code, logEditError(e, err, 0))
			continue
		}
		if err := out.Write(f); err != nil {
			e.log.Error(err.Error())
			return cli.ExitProblems
		}
	}
	if err := out.Flush(); err != nil {
		e.log.Error(err.Error())
		return cli.ExitProblems
	}
	return code
}
