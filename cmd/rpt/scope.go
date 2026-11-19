package main

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
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

// scopeVerb prints the report's scope rows; `rpt scope match` is its filter.
func scopeVerb(e *env, args []string) int {
	flags, of := newFlags(e, "scope")
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if flags.NArg() != 0 {
		return badUsage(e, "scope")
	}
	out, err := of.output(e, scopeColumns)
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitUsage
	}
	r := openReport(e, *of.report)
	if r == nil {
		return cli.ExitUsage
	}
	defer r.Close()

	rows, readErr := r.Scope()
	for _, row := range rows {
		if err := out.Write(row); err != nil {
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

// scopeMatchVerb reads JSON Lines and adds to each finding the IDs of the
// scope rows its target falls in. It never rewrites a target; a finding
// whose scope changes has only its scope member replaced, and every other
// record passes through byte for byte.
func scopeMatchVerb(e *env, args []string) int {
	flags, of := newFlags(e, "scope match")
	drop := flags.Bool("drop-out-of-scope", false, "drop findings whose target matches no scope row")
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if flags.NArg() != 0 {
		return badUsage(e, "scope match")
	}
	out, err := of.output(e, findingColumns)
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitUsage
	}
	r := openReport(e, *of.report)
	if r == nil {
		return cli.ExitUsage
	}
	defer r.Close()
	rows, err := r.Scope()
	if code := logReportErrors(e.log, err); code != cli.ExitOK {
		return code
	}

	code := cli.ExitOK
	for rec, err := range sdk.Records(e.stdin) {
		if le, ok := errors.AsType[*sdk.LineError](err); ok {
			e.log.Error(le.Err.Error(), "path", "stdin", "line", le.Line)
			code = cli.ExitProblems
			continue
		} else if err != nil {
			e.log.Error(err.Error())
			return cli.ExitUsage
		}
		if rec.Kind != "finding" {
			err = out.WriteRaw(rec.Raw)
		} else {
			err = matchFinding(e, out, rec, rows, *drop)
		}
		if err != nil {
			e.log.Error(err.Error(), "path", "stdin", "line", rec.Line)
			code = cli.ExitProblems
		}
	}
	if err := out.Flush(); err != nil {
		e.log.Error(err.Error())
		return cli.ExitUsage
	}
	return code
}

// matchFinding writes one finding record with its matched scope IDs added,
// or drops it when it is out of scope and drop is set.
func matchFinding(e *env, out *cli.Output, rec sdk.Rec, rows []sdk.ScopeRow, drop bool) error {
	var f sdk.Finding
	if err := json.Unmarshal(rec.Raw, &f); err != nil {
		return fmt.Errorf("finding: %w", err)
	}
	if f.Target == nil {
		return out.WriteOwn(f, rec.Raw)
	}
	matched := report.MatchScope(*f.Target, rows)
	if len(matched) == 0 {
		if drop {
			e.log.Info(fmt.Sprintf("dropped %q: %s is out of scope", f.Title, describe(*f.Target)), "path", "stdin", "line", rec.Line)
			return nil
		}
		return out.WriteOwn(f, rec.Raw)
	}
	ids := slices.Compact(slices.Sorted(slices.Values(append(slices.Clone(f.Scope), matched...))))
	if slices.Equal(ids, f.Scope) {
		return out.WriteOwn(f, rec.Raw)
	}
	raw, err := sdk.SetMember(rec.Raw, "scope", ids)
	if err != nil {
		return err
	}
	f.Scope = ids
	return out.WriteOwn(f, raw)
}

// describe renders a target for a message, e.g. "10.9.9.9 tcp/23".
func describe(t sdk.Target) string {
	switch {
	case t.Port != 0 && t.Protocol != "":
		return fmt.Sprintf("%s %s/%d", t.Host, t.Protocol, t.Port)
	case t.Port != 0:
		return fmt.Sprintf("%s port %d", t.Host, t.Port)
	default:
		return t.Host
	}
}

// colFlags collects repeated --col name=value flags.
type colFlags map[string]string

func (c colFlags) String() string { return "" }

func (c colFlags) Set(v string) error {
	k, val, ok := strings.Cut(v, "=")
	if !ok || k == "" {
		return fmt.Errorf("want name=value, got %q", v)
	}
	c[k] = val
	return nil
}

// scopeAddVerb appends scope rows: each scope record on stdin, passing
// other records through, or one row from its flags.
func scopeAddVerb(e *env, args []string) int {
	flags, of := newFlags(e, "scope add")
	host := flags.String("host", "", "add one row for this host instead of reading stdin")
	port := flags.Int("port", 0, "the row's port (with --host)")
	protocol := flags.String("protocol", "", "the row's protocol, tcp or udp (with --host)")
	id := flags.String("id", "", "the row's ID (with --host); default: the next free S-N")
	cols := colFlags{}
	flags.Var(cols, "col", "another column's value, name=value (with --host; repeatable)")
	pos, err := parseInterspersed(flags, args)
	if err != nil {
		return cli.ExitUsage
	}
	fromFlags := false
	flags.Visit(func(f *flag.Flag) { fromFlags = fromFlags || f.Name != "json" && f.Name != "report" })
	if len(pos) != 0 || fromFlags && *host == "" {
		return badUsage(e, "scope add")
	}
	out, err := of.output(e, scopeColumns)
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitUsage
	}
	r := openReport(e, *of.report)
	if r == nil {
		return cli.ExitUsage
	}
	defer r.Close()

	add := func(row sdk.ScopeRow, line int) int {
		added, err := r.AddScope(row)
		if err != nil {
			return logEditError(e, err, line)
		}
		if err := out.Write(added); err != nil {
			e.log.Error(err.Error())
			return cli.ExitUsage
		}
		return cli.ExitOK
	}
	finish := func(code int) int {
		if err := out.Flush(); err != nil {
			e.log.Error(err.Error())
			return cli.ExitUsage
		}
		return code
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
		return finish(add(row, 0))
	}

	code := cli.ExitOK
	for rec, err := range sdk.Records(e.stdin) {
		if le, ok := errors.AsType[*sdk.LineError](err); ok {
			e.log.Error(le.Err.Error(), "path", "stdin", "line", le.Line)
			code = cli.ExitProblems
			continue
		} else if err != nil {
			e.log.Error(err.Error())
			return cli.ExitUsage
		}
		if rec.Kind != "scope" {
			if err := out.WriteRaw(rec.Raw); err != nil {
				e.log.Error(err.Error())
				return cli.ExitUsage
			}
			continue
		}
		var row sdk.ScopeRow
		if err := json.Unmarshal(rec.Raw, &row); err != nil {
			e.log.Error("scope: "+err.Error(), "path", "stdin", "line", rec.Line)
			code = cli.ExitProblems
			continue
		}
		delete(row.Extra, "kind")
		switch c := add(row, rec.Line); c {
		case cli.ExitUsage:
			return c
		case cli.ExitProblems:
			code = c
		}
	}
	return finish(code)
}

// scopeDeleteVerb removes scope rows by ID and prints each as it was. A
// row a finding cites is refused unless --force; the rest are still
// deleted (exit 1).
func scopeDeleteVerb(e *env, args []string) int {
	flags, of := newFlags(e, "scope delete")
	force := flags.Bool("force", false, "delete rows even when findings cite them")
	pos, err := parseInterspersed(flags, args)
	if err != nil {
		return cli.ExitUsage
	}
	if len(pos) == 0 {
		return badUsage(e, "scope delete")
	}
	out, err := of.output(e, scopeColumns)
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitUsage
	}
	r := openReport(e, *of.report)
	if r == nil {
		return cli.ExitUsage
	}
	defer r.Close()

	code := cli.ExitOK
	for _, id := range pos {
		row, err := r.DeleteScope(id, *force)
		if err != nil {
			code = max(code, logEditError(e, err, 0))
			continue
		}
		if err := out.Write(row); err != nil {
			e.log.Error(err.Error())
			return cli.ExitUsage
		}
	}
	if err := out.Flush(); err != nil {
		e.log.Error(err.Error())
		return cli.ExitUsage
	}
	return code
}
