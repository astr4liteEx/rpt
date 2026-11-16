package main

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"

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
	if len(args) > 0 && args[0] == "match" {
		return scopeMatchVerb(e, args[1:])
	}
	flags, of := newFlags(e, "scope")
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
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
