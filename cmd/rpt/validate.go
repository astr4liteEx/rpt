package main

import (
	"bytes"
	"cmp"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/internal/report"
	"github.com/astr4liteEx/rpt/sdk"
	"github.com/spf13/pflag"
)

var problemColumns = []cli.Column{
	{Header: "PATH", Field: "path"}, {Header: "LINE", Field: "line"}, {Header: "LEVEL", Field: "level"},
	{Header: "RULE", Field: "rule"}, {Header: "MESSAGE", Field: "message"},
}

// validateVerb checks the report, or the findings, pages and scope rows
// named, and prints one problem record per broken rule. It exits 1 if any
// problem is an error, 0 otherwise: it is the gate before assemble. With
// -, it checks the records on stdin instead (validateStream).
func validateVerb(flags *pflag.FlagSet) runner {
	return func(e *env, args []string) int {
		ids := args
		stream := slices.Equal(ids, []string{"-"})
		if !stream && slices.Contains(ids, "-") {
			return usageError(e, "- can't be given with IDs")
		}
		out, err := e.output(problemColumns)
		if err != nil {
			e.log.Error(err.Error())
			return cli.ExitProblems
		}
		r := openReport(e)
		if r == nil {
			return cli.ExitProblems
		}
		defer r.Close()
		if stream {
			return validateStream(e, out, r)
		}

		problems, err := r.Validate()
		if err != nil {
			e.log.Error(err.Error())
			return cli.ExitProblems
		}
		problems = append(problems, newSchemaChecker().problems(gatherNames(r, nil), ruleLevels(r))...)
		sortProblems(problems)
		if len(ids) > 0 {
			var missing []error
			if problems, missing, err = r.ProblemsFor(problems, ids); err != nil {
				return reportErrors(e, out, err)
			}
			for _, m := range missing {
				where := report.ScopeFile
				if errors.Is(m, report.ErrNoFinding) {
					where = report.FindingsDir
				} else if errors.Is(m, report.ErrNoPage) {
					where = report.PagesDir
				}
				problems = append(problems, sdk.Problem{Path: where, Rule: ruleExists, Level: sdk.Error, Message: m.Error()})
			}
		}
		return printProblems(e, out, problems)
	}
}

// printProblems prints problems and returns 1 if any is an error.
func printProblems(e *env, out *cli.Output, problems []sdk.Problem) int {
	code := cli.ExitOK
	for _, p := range problems {
		if p.Level == sdk.Error {
			code = cli.ExitProblems
		}
		if err := e.problem(out, p); err != nil {
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

// A claim says which stdin record a file, or a scope row, came from.
type claim struct {
	line int
	id   string // the record's own ID, if it gave one
}

// validateStream checks the records on stdin as if they were written to
// the report: a finding, page or scope row with an ID the report has
// replaces it, one without is new, and a config record is the new
// rpt.yaml. They are checked together, so a finding may cite a scope row
// added in the same stream. Problems in what the records wrote are given
// at path - and the record's line; problems they cause elsewhere keep
// their place; problems the report already had are left out. A clean
// stream is copied to stdout byte for byte, warnings going to stderr
// only. Otherwise only problems come out, the incoming ones passed on as
// they are, and the exit code is 1.
func validateStream(e *env, out *cli.Output, r *report.Report) int {
	input, err := io.ReadAll(e.stdin)
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitProblems
	}
	baseline, err := r.Validate()
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitProblems
	}
	sc := newSchemaChecker()
	baseline = append(baseline, sc.problems(gatherNames(r, nil), ruleLevels(r))...)
	var recs []sdk.Rec
	w := &write{e: e, out: out, tx: r.Begin(), dryRun: true}
	var incoming [][]byte // error-level problems on stdin
	claims := map[string]claim{}
	scopeClaims := map[string]claim{}
	seen := map[string]int{} // kind and ID -> line
	for rec, err := range sdk.Records(bytes.NewReader(input)) {
		if le, ok := errors.AsType[*sdk.LineError](err); ok {
			w.refused = append(w.refused, sdk.Problem{Path: stdinPath, Line: le.Line, Rule: ruleInput, Level: sdk.Error, Message: le.Err.Error()})
			continue
		} else if err != nil {
			e.log.Error(err.Error())
			return cli.ExitProblems
		}
		recs = append(recs, rec)
		if rec.Kind == "problem" {
			if isError(rec) {
				incoming = append(incoming, rec.Raw)
			}
			continue
		}
		bad := func(err error) {
			w.refuse(err, stdinPath, rec.Line)
		}
		var id string
		var probe struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(rec.Raw, &probe) == nil {
			id = report.CanonicalID(probe.ID)
		}
		if id != "" || rec.Kind == "config" {
			key := rec.Kind + " " + strings.ToUpper(id)
			if first, ok := seen[key]; ok {
				w.refused = append(w.refused, sdk.Problem{Path: stdinPath, Line: rec.Line, Rule: ruleDuplicate, Level: sdk.Error,
					Message: fmt.Sprintf("%s %s is in the stream twice; the first is on line %d", rec.Kind, cmp.Or(id, "record"), first)})
				continue
			}
			seen[key] = rec.Line
		}
		switch rec.Kind {
		case "finding":
			var f sdk.Finding
			if err := json.Unmarshal(rec.Raw, &f); err != nil {
				bad(fmt.Errorf("%w: finding: %v", report.ErrBadValue, err))
				continue
			}
			f.ID = id
			var got sdk.Finding
			if _, ok := r.FindingPath(id); ok {
				got, err = w.tx.ReplaceFinding(f)
			} else {
				got, err = w.tx.Add(f)
			}
			if err != nil {
				bad(err)
				continue
			}
			claims[got.Path] = claim{rec.Line, id}
		case "page":
			var p sdk.Page
			if err := json.Unmarshal(rec.Raw, &p); err != nil {
				bad(fmt.Errorf("%w: page: %v", report.ErrBadValue, err))
				continue
			}
			p.ID = id
			var got sdk.Page
			if _, ok := r.PagePath(id); ok {
				got, err = w.tx.ReplacePage(p)
			} else {
				got, err = w.tx.AddPage(p)
			}
			if err != nil {
				bad(err)
				continue
			}
			claims[got.Path] = claim{rec.Line, id}
		case "scope":
			var row sdk.ScopeRow
			if err := json.Unmarshal(rec.Raw, &row); err != nil {
				bad(fmt.Errorf("%w: scope: %v", report.ErrBadValue, err))
				continue
			}
			var got sdk.ScopeRow
			if r.HasScopeRow(row.ID) {
				got, err = w.tx.ReplaceScope(row)
			} else {
				got, err = w.tx.AddScope(row)
			}
			if err != nil {
				bad(err)
				continue
			}
			scopeClaims[got.ID] = claim{rec.Line, row.ID}
		case "config":
			var c sdk.Config
			if err := json.Unmarshal(rec.Raw, &c); err != nil {
				bad(fmt.Errorf("%w: config: %v", report.ErrBadValue, err))
				continue
			}
			if err := w.tx.ReplaceConfig(c); err != nil {
				bad(err)
				continue
			}
			claims[report.ConfigFile] = claim{line: rec.Line}
		}
	}
	if w.failed {
		return cli.ExitProblems
	}

	view := w.tx.View()
	staged, err := view.Validate()
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitProblems
	}
	staged = append(staged, sc.problems(gatherNames(view, recs), ruleLevels(view))...)
	sortProblems(staged)
	// Scope problems sit on a row's line: find the stdin row there.
	rowAt := map[int]claim{}
	if rows, _ := view.ScopeWithLines(); len(scopeClaims) > 0 {
		for _, row := range rows {
			if c, ok := scopeClaims[row.ID]; ok {
				rowAt[row.Lines.Row] = c
			}
		}
	}
	had := map[string]bool{}
	for _, p := range baseline {
		had[p.Path+"\x00"+p.Rule+"\x00"+p.Message] = true
	}
	problems := w.refused
	for _, p := range staged {
		c, ok := claims[p.Path]
		if !ok && p.Path == report.ScopeFile {
			c, ok = rowAt[p.Line]
		}
		switch {
		case ok:
			if c.id != "" {
				p.Message = c.id + ": " + p.Message
			}
			p.Path, p.Line, p.Column, p.Rev = stdinPath, c.line, 0, ""
		case had[p.Path+"\x00"+p.Rule+"\x00"+p.Message]:
			continue
		}
		problems = append(problems, p)
	}
	failed := len(incoming) > 0 || slices.ContainsFunc(problems, func(p sdk.Problem) bool { return p.Level == sdk.Error })
	if !failed {
		for _, p := range problems {
			e.logProblem(p)
		}
		if _, err := e.stdout.Write(input); err != nil {
			e.log.Error(err.Error())
			return cli.ExitProblems
		}
		return cli.ExitOK
	}
	if !out.Table() {
		for _, raw := range incoming {
			if err := out.WriteRaw(raw); err != nil {
				e.log.Error(err.Error())
				return cli.ExitProblems
			}
		}
	}
	printProblems(e, out, problems)
	return cli.ExitProblems
}

// assembleVerb writes the whole report as one report record on one JSON
// line, on a terminal too. It never refuses: whatever it had to leave out
// is a warning on stderr. Run rpt validate first to gate on problems.
func assembleVerb(flags *pflag.FlagSet) runner {
	return func(e *env, args []string) int {
		if len(args) != 0 {
			return usageError(e, "takes no arguments")
		}
		r := openReport(e)
		if r == nil {
			return cli.ExitProblems
		}
		defer r.Close()

		out, _ := cli.NewOutput(e.stdout, false, true, nil) // JSON Lines on a terminal too
		rep, warnings, err := r.Assemble()
		if err != nil {
			return reportErrors(e, out, err)
		}
		if err := out.Write(rep); err != nil {
			e.log.Error("write report: " + err.Error())
			return cli.ExitProblems
		}
		for _, w := range warnings {
			if err := e.problem(out, w); err != nil {
				e.log.Error(err.Error())
				return cli.ExitProblems
			}
		}
		return cli.ExitOK
	}
}

// ruleLevels are the rule levels rpt.yaml sets, if it can be read.
func ruleLevels(r *report.Report) map[string]sdk.Level {
	cfg, err := r.Config()
	if err != nil {
		return nil
	}
	return cfg.Rules
}
