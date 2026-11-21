package main

import (
	"bufio"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/spf13/pflag"

	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/internal/report"
	"github.com/astr4liteEx/rpt/sdk"
)

var findingColumns = []cli.Column{
	{Header: "ID", Field: "id"}, {Header: "SEVERITY", Field: "severity", Severity: true},
	{Header: "TITLE", Field: "title"}, {Header: "SCOPE", Value: findingScope},
}

// findingScope renders the scope rows a finding's targets fall in, once
// each, in order: "S-12,S-14".
func findingScope(m map[string]any) string {
	targets, _ := m["targets"].([]any)
	var ids []string
	for _, t := range targets {
		tm, _ := t.(map[string]any)
		if id, _ := tm["scope"].(string); id != "" && !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	return strings.Join(ids, ",")
}

// scopeMap gives findingScope a finding's targets as its record has them.
func scopeMap(f sdk.Finding) map[string]any {
	var targets []any
	for _, t := range f.Targets {
		targets = append(targets, map[string]any{"scope": t.Scope})
	}
	return map[string]any{"targets": targets}
}

// nounVerb is a noun given no action: it prints the noun's usage and exits
// 2, or with --help prints it and exits 0.
func nounVerb(name string) verb {
	return func(e *env, args []string) int {
		flags, _ := newFlags(e, name)
		if err := flags.Parse(args); err != nil {
			if errors.Is(err, pflag.ErrHelp) {
				return cli.ExitOK
			}
			return cli.ExitUsage
		}
		if flags.NArg() > 0 {
			fmt.Fprintf(e.stderr, "rpt: %s: unknown action %q\n", name, flags.Arg(0))
		}
		return badUsage(e, name)
	}
}

// findingIDs returns ids in order, each once, as they are stored: an ID
// may be given in any case.
func findingIDs(ids []string) []string {
	var out []string
	for _, id := range ids {
		if id = report.CanonicalID(id); !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

// findingGetVerb prints every finding, or with IDs those findings in the
// order given; with --lines, each record also says where its keys and
// sections sit in its file.
func findingGetVerb(e *env, args []string) int {
	flags, of := newFlags(e, "finding get")
	withLines := flags.Bool("lines", false, "add each finding's lines: its file's absolute path and where its frontmatter keys and sections sit in it")
	withAssets := flags.Bool("assets", false, "add each finding's assets: every file it lists or links, with its absolute path, to carry it to another report with rpt finding add")
	asTable := flags.Bool("table", false, "on a terminal, show the findings named as a table rather than for reading")
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	ids := findingIDs(flags.Args())
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

	read := r.Findings
	if *withLines {
		read = r.FindingsWithLines
	}
	list, readErr := read()
	var missing []string
	if len(ids) > 0 {
		var picked []sdk.Finding
		for _, id := range ids {
			i := slices.IndexFunc(list, func(f sdk.Finding) bool { return f.ID == id })
			if i < 0 {
				missing = append(missing, id)
				continue
			}
			picked = append(picked, list[i])
		}
		list = picked
	}
	if *withAssets {
		for i := range list {
			assets, err := r.AssetsOf(list[i].Path)
			if err != nil {
				readErr = errors.Join(readErr, err)
				continue
			}
			list[i].Assets = assets
		}
	}
	if cfg, err := r.Config(); err == nil {
		var order []string
		for _, l := range cfg.Severities {
			order = append(order, string(l))
		}
		out.Totals = cli.SeverityTotals(order)
	}
	if out.Table() && len(ids) > 0 && !*asTable {
		v := cli.NewReadingView(e.stdout)
		for _, f := range list {
			body, err := r.Body(f.Path)
			if err != nil {
				readErr = errors.Join(readErr, err)
				continue
			}
			facts := cli.Facts(cli.Severity(string(f.Severity)), cli.Dim(findingScope(scopeMap(f))), cli.Dim(f.Path))
			if err := v.Record(f.ID, f.Title, facts, body); err != nil {
				e.log.Error(err.Error())
				return cli.ExitProblems
			}
		}
		list = nil
	}
	for _, f := range list {
		if err := out.Write(f); err != nil {
			e.log.Error(err.Error())
			return cli.ExitProblems
		}
	}
	for _, id := range missing {
		p := sdk.Problem{Path: report.FindingsDir, Rule: ruleExists, Level: sdk.Error, Message: fmt.Sprintf("%v: %s", report.ErrNoFinding, id)}
		if err := e.problem(out, p); err != nil {
			e.log.Error(err.Error())
			return cli.ExitProblems
		}
	}
	if err := out.Flush(); err != nil {
		e.log.Error(err.Error())
		return cli.ExitProblems
	}
	if code := reportErrors(e, out, readErr); code != cli.ExitOK || len(missing) == 0 {
		return code
	}
	return cli.ExitProblems
}

// findingSetVerb changes one value of one finding: a frontmatter key,
// sections.<key> (the text from stdin when no value is given) or
// x-<plugin>.<key>. Several values make a list.
func findingSetVerb(e *env, args []string) int {
	flags, of := newFlags(e, "finding set")
	wf := addWriteFlags(flags, true)
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	pos := flags.Args()
	section := len(pos) == 2 && strings.HasPrefix(pos[1], "sections.")
	if len(pos) < 3 && !section {
		code := badUsage(e, "finding set")
		fmt.Fprintln(e.stderr, `each value is YAML: high, S-12 '{scope: S-20, port: 443}', "9.1"; a section's text comes from stdin when no value is given`)
		return code
	}
	id := report.CanonicalID(pos[0])
	values := pos[2:]
	if section {
		text, err := io.ReadAll(e.stdin)
		if err != nil {
			e.log.Error(err.Error())
			return cli.ExitProblems
		}
		values = []string{string(text)}
	}
	return writeFinding(e, of, wf, "finding set", id, func(tx *report.Tx) (sdk.Finding, error) {
		return tx.Set(id, pos[1], values...)
	})
}

// findingUnsetVerb removes keys, sections and plugin keys from one
// finding.
func findingUnsetVerb(e *env, args []string) int {
	flags, of := newFlags(e, "finding unset")
	wf := addWriteFlags(flags, true)
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	pos := flags.Args()
	if len(pos) < 2 {
		return badUsage(e, "finding unset")
	}
	id := report.CanonicalID(pos[0])
	return writeFinding(e, of, wf, "finding unset", id, func(tx *report.Tx) (sdk.Finding, error) {
		return tx.Unset(id, pos[1:]...)
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
	report.ErrNoFinding, report.ErrNoPage, report.ErrRefusedKey, report.ErrRefusedUnset, report.ErrBadValue,
	report.ErrNoScopeRow, report.ErrCited, report.ErrBadSource, report.ErrInUse, report.ErrNoEvidence, report.ErrBadAsset,
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

// findingAddVerb writes each finding record on stdin into the report as a
// new finding file and prints the finding as stored. Other records pass
// through untouched. With --title and --severity it writes one finding
// from its flags instead, with a heading for every required section, and
// doesn't read stdin. Every record is checked before any is written: one
// refusal and nothing is written.
func findingAddVerb(e *env, args []string) int {
	flags, of := newFlags(e, "finding add")
	title := flags.String("title", "", "write one finding with this title instead of reading stdin")
	severity := flags.String("severity", "", "the finding's severity (with --title)")
	var targets targetFlags
	flags.Var(&targets, "target", "a target: a scope ID, or a map like '{scope: S-20, host: 10.0.1.5, port: 22}' (with --title; repeatable)")
	id := flags.String("id", "", "the finding's ID (with --title); default: the next free one")
	scaffold := flags.Bool("scaffold", false, "give stdin records an empty heading for each required section they lack")
	noScaffold := flags.Bool("no-scaffold", false, "with --title, leave out the required sections' headings")
	wf := addWriteFlags(flags, false)
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	pos := flags.Args()
	fromFlags := false
	flags.Visit(func(f *pflag.Flag) {
		fromFlags = fromFlags || slices.Contains([]string{"title", "severity", "target", "id", "no-scaffold"}, f.Name)
	})
	if len(pos) != 0 || fromFlags && (*title == "" || *severity == "") {
		return badUsage(e, "finding add")
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
	w, _ := newWrite(e, out, r, wf, "finding add", nil)

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
		add(sdk.Finding{Kind: "finding", ID: report.CanonicalID(*id), Title: *title, Severity: sdk.Severity(*severity), Targets: targets}, 0, !*noScaffold)
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

// findingRemoveVerb removes each named finding's file and prints the
// finding as it was. Every ID is checked first: one unknown and nothing is
// removed. On a terminal it asks first; otherwise it needs --yes.
func findingRemoveVerb(e *env, args []string) int {
	flags, of := newFlags(e, "finding remove")
	yes := addYesFlag(flags)
	wf := addWriteFlags(flags, true)
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	ids := findingIDs(flags.Args())
	if len(ids) == 0 {
		return badUsage(e, "finding remove")
	}
	if !mayAsk(e, *yes, *wf.dryRun) {
		return cli.ExitUsage
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
	w, ok := newWrite(e, out, r, wf, "finding remove", ids)
	if !ok {
		return cli.ExitUsage
	}
	var lines []string
	evidence := false
	for _, id := range ids {
		f, err := w.tx.Delete(id)
		if err != nil {
			w.refuse(err, report.FindingsDir, 0)
			continue
		}
		w.done(f, f.Path)
		lines = append(lines, fmt.Sprintf("%s  %s  %s", f.ID, f.Title, f.Path))
		evidence = evidence || len(f.Evidence) > 0
	}
	if len(w.refused) == 0 && !w.failed && !*yes && !*wf.dryRun {
		var effects []string
		if evidence {
			effects = append(effects, "their evidence files stay; rpt evidence prune removes them")
		}
		w.declined = !confirm(e, "finding", lines, effects)
	}
	return w.finish()
}

// addYesFlag adds --yes, which a remove needs when it can't ask.
func addYesFlag(f *flagSet) *bool {
	return f.Bool("yes", false, "remove without asking; needed when stdin or stderr isn't a terminal")
}

// interactive reports whether rpt can ask the user: stdin and stderr are
// both terminals. Tests replace it.
var interactive = func(e *env) bool {
	in, ok := e.stdin.(*os.File)
	return ok && cli.IsTerminal(in) && isTerminal(e.stderr)
}

// mayAsk checks that a remove can go ahead: given --yes or --dry-run, or
// able to ask. If not, it says so and returns false, for exit 2, before
// anything is read.
func mayAsk(e *env, yes, dryRun bool) bool {
	if yes || dryRun || interactive(e) {
		return true
	}
	fmt.Fprintf(e.stderr, "rpt: %s: pass --yes to remove without asking\n", e.command)
	return false
}

// confirm lists what a remove will do and asks; only y or yes, in any
// case, is yes. On no it says nothing was removed.
func confirm(e *env, noun string, things, effects []string) bool {
	const most = 20
	name := noun
	if len(things) != 1 {
		name += "s"
	}
	lines := []string{cli.Bold(fmt.Sprintf("Remove %d %s:", len(things), name))}
	for i, t := range things {
		if i == most {
			lines = append(lines, fmt.Sprintf("  …and %d more", len(things)-most))
			break
		}
		lines = append(lines, "  "+t)
	}
	if len(effects) > 0 {
		lines = append(lines, "")
		lines = append(lines, effects...)
	}
	w := cli.Styled(e.stderr)
	fmt.Fprintln(w, cli.Box(strings.Join(lines, "\n")))
	fmt.Fprint(w, cli.Bold("Remove?")+" "+cli.Dim("[y/N]")+" ")
	answer, _ := bufio.NewReader(e.stdin).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return true
	}
	fmt.Fprintln(e.stderr, "rpt: nothing removed")
	return false
}
