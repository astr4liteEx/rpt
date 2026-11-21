package main

import (
	"cmp"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"github.com/spf13/pflag"
	"slices"
	"strings"

	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/internal/report"
	"github.com/astr4liteEx/rpt/sdk"
)

var scopeColumns = []cli.Column{
	{Header: "ID", Field: "id"}, {Header: "HOST", Field: "host"},
	{Header: "PORT", Field: "port"}, {Header: "PROTOCOL", Field: "protocol"},
}

// scopeVerb prints the report's scope rows, or with IDs only those rows in
// the order given; with --lines, each record also says which line of
// scope.csv it starts on.
func scopeVerb(e *env, args []string) int {
	flags, of := newFlags(e, "scope")
	withLines := flags.Bool("lines", false, "add each row's lines: scope.csv's absolute path and the line the row starts on")
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	ids := flags.Args()
	out, err := of.output(e, scopeColumns)
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitProblems
	}
	r := openReport(e, *of.report)
	if r == nil {
		return cli.ExitProblems
	}
	defer r.Close()

	read := r.Scope
	if *withLines {
		read = r.ScopeWithLines
	}
	rows, readErr := read()
	var missing []string
	if len(ids) > 0 {
		var picked []sdk.ScopeRow
		for _, id := range slices.Compact(ids) {
			i := slices.IndexFunc(rows, func(r sdk.ScopeRow) bool { return r.ID == id })
			if i < 0 {
				missing = append(missing, id)
				continue
			}
			picked = append(picked, rows[i])
		}
		rows = picked
	}
	for _, row := range rows {
		if err := out.Write(row); err != nil {
			e.log.Error(err.Error())
			return cli.ExitProblems
		}
	}
	for _, id := range missing {
		p := sdk.Problem{Path: report.ScopeFile, Rule: ruleExists, Level: sdk.Error, Message: fmt.Sprintf("%s: %v", id, report.ErrNoScopeRow)}
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

// scopeMatchVerb reads JSON Lines and attributes each finding's targets to
// scope: a target with a host and no scope ID gets the ID of the most
// specific row it falls in, losing the host when that row is one asset.
// A finding whose targets change has only its targets member replaced, and
// every other record passes through byte for byte.
func scopeMatchVerb(e *env, args []string) int {
	flags, of := newFlags(e, "scope match")
	drop := flags.Bool("drop-out-of-scope", false, "drop targets that fall in no scope row, and findings left with none")
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if flags.NArg() != 0 {
		return badUsage(e, "scope match")
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
	rows, err := r.Scope()
	if code := reportErrors(e, out, err); code != cli.ExitOK {
		return code
	}
	recs, code, ok := readInput(e, out)
	if !ok {
		return code
	}
	for _, rec := range recs {
		if rec.Kind != "finding" {
			err = out.WriteRaw(rec.Raw)
		} else {
			err = matchFinding(e, out, rec, rows, *drop)
		}
		if err != nil {
			e.log.Error(err.Error(), "path", stdinPath, "line", rec.Line)
			code = cli.ExitProblems
		}
	}
	if err := out.Flush(); err != nil {
		e.log.Error(err.Error())
		return cli.ExitProblems
	}
	return code
}

// matchFinding writes one finding record with its targets attributed to
// scope rows; with drop, it leaves out the targets no row covers, and the
// finding when none is left.
func matchFinding(e *env, out *cli.Output, rec sdk.Rec, rows []sdk.ScopeRow, drop bool) error {
	var f sdk.Finding
	if err := json.Unmarshal(rec.Raw, &f); err != nil {
		return fmt.Errorf("finding: %w", err)
	}
	if len(f.Targets) == 0 {
		return out.WriteOwn(f, rec.Raw)
	}
	info := func(format string, a ...any) {
		e.log.Info(fmt.Sprintf(format, a...), "path", stdinPath, "line", rec.Line)
	}
	kept := make([]sdk.Target, 0, len(f.Targets))
	var dropped []string
	changed := false
	for _, t := range f.Targets {
		at, ok := report.Attribute(t, rows)
		switch {
		case !ok && drop:
			dropped = append(dropped, describe(t))
			changed = true
		case !ok:
			kept = append(kept, t)
		default:
			changed = changed || at.Scope != t.Scope || at.Host != t.Host
			kept = append(kept, at)
		}
	}
	switch {
	case len(kept) == 0 && len(dropped) == 1:
		info("dropped %q: %s is out of scope", f.Title, dropped[0])
		return nil
	case len(kept) == 0:
		info("dropped %q: none of its targets is in scope (%s)", f.Title, strings.Join(dropped, ", "))
		return nil
	}
	for _, d := range dropped {
		info("dropped a target of %q: %s is out of scope", f.Title, d)
	}
	if !changed {
		return out.WriteOwn(f, rec.Raw)
	}
	raw, err := sdk.SetMember(rec.Raw, "targets", kept)
	if err != nil {
		return err
	}
	f.Targets = kept
	return out.WriteOwn(f, raw)
}

// describe renders a target for a message, e.g. "10.9.9.9 tcp/23".
func describe(t sdk.Target) string {
	host := cmp.Or(t.Host, "a target with no host")
	switch {
	case t.Port != 0 && t.Protocol != "":
		return fmt.Sprintf("%s %s/%d", host, t.Protocol, t.Port)
	case t.Port != 0:
		return fmt.Sprintf("%s port %d", host, t.Port)
	default:
		return host
	}
}

// colFlags collects repeated --col name=value flags.
type colFlags map[string]string

func (c colFlags) String() string { return "" }

func (c colFlags) Type() string { return "name=value" }

func (c colFlags) Set(v string) error {
	k, val, ok := strings.Cut(v, "=")
	if !ok || k == "" {
		return fmt.Errorf("want name=value, got %q", v)
	}
	c[k] = val
	return nil
}

// scopeAddVerb appends scope rows: each scope record on stdin, passing
// other records through, or one row from its flags. Every row is checked
// before any is written: one refusal and nothing is written.
func scopeAddVerb(e *env, args []string) int {
	flags, of := newFlags(e, "scope add")
	host := flags.String("host", "", "add one row for this host instead of reading stdin")
	port := flags.Int("port", 0, "the row's port (with --host)")
	protocol := flags.String("protocol", "", "the row's protocol, tcp or udp (with --host)")
	id := flags.String("id", "", "the row's ID (with --host); default: the next free S-N")
	cols := colFlags{}
	flags.Var(cols, "col", "another column's value, name=value (with --host; repeatable)")
	wf := addWriteFlags(flags, false)
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	pos := flags.Args()
	fromFlags := false
	flags.Visit(func(f *pflag.Flag) {
		fromFlags = fromFlags || slices.Contains([]string{"host", "port", "protocol", "id", "col"}, f.Name)
	})
	if len(pos) != 0 || fromFlags && *host == "" {
		return badUsage(e, "scope add")
	}
	out, err := of.output(e, scopeColumns)
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitProblems
	}
	r := openReport(e, *of.report)
	if r == nil {
		return cli.ExitProblems
	}
	defer r.Close()
	w, _ := newWrite(e, out, r, wf, "scope add", nil)

	add := func(row sdk.ScopeRow, line int) {
		added, err := w.tx.AddScope(row)
		if err != nil {
			path := report.ScopeFile
			if line > 0 {
				path = stdinPath
			}
			w.refuse(err, path, line)
			return
		}
		w.done(added, report.ScopeFile)
	}

	if fromFlags {
		row := sdk.ScopeRow{Kind: "scope", ID: *id, Host: *host, Port: *port, Protocol: *protocol}
		for k, v := range cols {
			b, _ := json.Marshal(v)
			if row.Extra == nil {
				row.Extra = map[string]jsontext.Value{}
			}
			row.Extra[k] = b
		}
		add(row, 0)
		return w.finish()
	}
	recs, code, ok := readInput(e, out)
	if !ok {
		return code
	}
	for _, rec := range recs {
		if rec.Kind != "scope" {
			w.pass(rec.Raw)
			continue
		}
		var row sdk.ScopeRow
		if err := json.Unmarshal(rec.Raw, &row); err != nil {
			w.refused = append(w.refused, sdk.Problem{Path: stdinPath, Line: rec.Line, Rule: ruleInput, Level: sdk.Error, Message: "scope: " + err.Error()})
			continue
		}
		delete(row.Extra, "kind")
		row.Rev = "" // rpt's, not a column
		add(row, rec.Line)
	}
	return w.finish()
}

// scopeDeleteVerb removes scope rows by ID and prints each as it was. A
// row a finding cites is refused unless --force; one refusal and nothing
// is deleted.
func scopeDeleteVerb(e *env, args []string) int {
	flags, of := newFlags(e, "scope delete")
	force := flags.Bool("force", false, "delete rows even when findings cite them")
	wf := addWriteFlags(flags, true)
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	ids := uniq(flags.Args())
	if len(ids) == 0 {
		return badUsage(e, "scope delete")
	}
	out, err := of.output(e, scopeColumns)
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitProblems
	}
	r := openReport(e, *of.report)
	if r == nil {
		return cli.ExitProblems
	}
	defer r.Close()
	w, ok := newWrite(e, out, r, wf, "scope delete", ids)
	if !ok {
		return cli.ExitUsage
	}
	for _, id := range ids {
		row, err := w.tx.DeleteScope(id, *force)
		if err != nil {
			w.refuse(err, report.ScopeFile, 0)
			continue
		}
		w.done(row, report.ScopeFile)
	}
	return w.finish()
}
