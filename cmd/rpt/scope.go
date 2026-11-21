package main

import (
	"encoding/json/v2"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/astr4liteEx/rpt/internal/report"
	"github.com/astr4liteEx/rpt/sdk"
)

func (e *env) scopeCommand() *cobra.Command {
	c := &cobra.Command{
		Use:         "scope",
		Short:       "Get, add, set, unset and remove scope rows; match attributes finding targets to them",
		Annotations: io_("records", "records"),
	}
	c.AddCommand(e.scopeGet(), e.scopeAdd(), e.scopeSet(), e.scopeUnset(), e.scopeRemove(), e.scopeMatch())
	return c
}

const (
	citedForce   = "Leave finding targets citing the row dangling, or unfit for it"
	citedCleanup = "Drop the finding targets the change leaves dangling or unfit"
)

// rowRevs are the revs of the scope rows named, for --if-rev.
func rowRevs(ids ...string) func(*report.Model) map[string]string {
	return func(m *report.Model) map[string]string {
		out := map[string]string{}
		for _, id := range ids {
			if r, err := m.Scope.Row(id); err == nil {
				out[r.ID] = r.Rev
			}
		}
		return out
	}
}

// printChange prints a scope write: the row, then the findings it
// rewrote, and warns of those left citing it as they were.
func (e *env) printChange(b *batch, ch report.ScopeChange) {
	if ch.Row != nil {
		b.print(b.m.ScopeRecord(ch.Row, false))
	}
	for _, d := range ch.Rewrote {
		b.print(b.m.FindingRecord(d, report.RecordOpts{}))
	}
	for _, d := range ch.Left {
		e.log.Warn(fmt.Sprintf("%s still cites the row, left as it was (--force)", d.ID), "path", d.Path)
	}
}

func (e *env) scopeGet() *cobra.Command {
	var lines bool
	c := &cobra.Command{
		Use:               "get [id...]",
		Short:             "Print scope rows, or those with the IDs given",
		ValidArgsFunction: e.completeScopeIDs,
		RunE: func(_ *cobra.Command, ids []string) error {
			m, err := e.load()
			if err != nil {
				return err
			}
			defer m.Close()
			var ps []report.Problem
			if m.Scope.Err != nil {
				p, _ := failure(m.Scope.Err, report.ScopeFile, 0)
				return e.problems([]report.Problem{p})
			}
			rows := m.Scope.Rows
			if len(ids) > 0 {
				rows = nil
				for _, id := range ids {
					r, err := m.Scope.Row(id)
					if err != nil {
						p, _ := failure(err, report.ScopeFile, 0)
						ps = append(ps, p)
						continue
					}
					rows = append(rows, r)
				}
			} else {
				for _, err := range m.Scope.RowErrs {
					p, _ := failure(err, report.ScopeFile, 0)
					ps = append(ps, p)
				}
			}
			for _, r := range rows {
				if err := e.out.Write(m.ScopeRecord(r, lines)); err != nil {
					return err
				}
			}
			return e.problems(ps)
		},
	}
	c.Flags().BoolVar(&lines, "lines", false, "Add scope.csv's absolute path and the line each row starts on")
	return c
}

func (e *env) scopeAdd() *cobra.Command {
	var w writeFlags
	var host, protocol, id string
	var port int
	var cols []string
	c := &cobra.Command{
		Use:     "add",
		Short:   "Add scope rows from records on stdin, or one from flags",
		Example: "  rpt scope add < records.jsonl\n  rpt scope add --host h [--port n] [--protocol tcp|udp] [--id S-NNN] [--col name=value]...",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if host == "" {
				for _, f := range []string{"port", "protocol", "id", "col"} {
					if cmd.Flags().Changed(f) {
						return usagef("--%s goes with --host", f)
					}
				}
				return e.scopeFromStdin(&w)
			}
			row := report.Row{ID: id, Host: host, Port: port, Protocol: protocol}
			for _, kv := range cols {
				k, v, ok := strings.Cut(kv, "=")
				if !ok || k == "" {
					return usagef("--col %s: give name=value", kv)
				}
				if row.Extra == nil {
					row.Extra = map[string]string{}
				}
				row.Extra[strings.ToLower(strings.TrimSpace(k))] = v
			}
			return e.write(&w, nil, func(b *batch) error {
				r, err := b.m.AddScope(row)
				if err != nil {
					return b.refuse(err, "", 0)
				}
				b.print(b.m.ScopeRecord(r, false))
				return nil
			})
		},
	}
	c.Flags().StringVar(&host, "host", "", "Add one row for this host, address, range or CIDR instead of reading stdin")
	c.Flags().IntVar(&port, "port", 0, "The row's port (with --host)")
	c.Flags().StringVar(&protocol, "protocol", "", "The row's protocol, tcp or udp (with --host)")
	c.Flags().StringVar(&id, "id", "", "The row's ID (with --host); default: the next free S-NNN")
	c.Flags().StringArrayVar(&cols, "col", nil, "Another column's value, name=value (with --host; repeatable)")
	c.RegisterFlagCompletionFunc("protocol", cobra.FixedCompletions([]string{"tcp", "udp"}, cobra.ShellCompDirectiveNoFileComp))
	addWriteFlags(c, &w, false)
	return c
}

// scopeFromStdin adds or replaces the scope records on stdin, by ID;
// others pass through.
func (e *env) scopeFromStdin(w *writeFlags) error {
	recs, err := e.readStdin()
	if err != nil {
		return err
	}
	return e.write(w, nil, func(b *batch) error {
		for _, rec := range recs {
			if rec.Kind != "scope" {
				b.pass(rec.Raw)
				continue
			}
			var s sdk.ScopeRow
			err := json.Unmarshal(rec.Raw, &s)
			var row report.Row
			if err == nil {
				row, err = report.ScopeDraft(s)
			}
			if err != nil {
				b.refused = append(b.refused, report.Problem{Path: report.StreamPath, Line: rec.Line, Rule: ruleInput, Level: report.Error, Message: "scope: " + err.Error()})
				continue
			}
			r, err := b.m.AddScope(row)
			if err != nil {
				if err := b.refuse(err, report.StreamPath, rec.Line); err != nil {
					return err
				}
				continue
			}
			b.print(b.m.ScopeRecord(r, false))
		}
		return nil
	})
}

func (e *env) scopeSet() *cobra.Command {
	var w writeFlags
	c := &cobra.Command{
		Use:               "set <id> <column> <value>",
		Short:             "Change one column of a scope row; a new id or host carries into the findings citing it",
		Args:              cobra.ExactArgs(3),
		ValidArgsFunction: e.completeScopeColumn,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := flagsAmongValues(cmd, args[2:]); err != nil {
				return err
			}
			return e.write(&w, rowRevs(args[0]), func(b *batch) error {
				ch, err := b.m.SetScope(args[0], args[1], args[2], w.mode())
				if err != nil {
					return b.refuse(err, "", 0)
				}
				e.printChange(b, ch)
				return nil
			})
		},
	}
	c.Flags().SetInterspersed(false)
	addCitedFlags(c, &w, citedForce, citedCleanup)
	addWriteFlags(c, &w, true)
	return c
}

func (e *env) scopeUnset() *cobra.Command {
	var w writeFlags
	c := &cobra.Command{
		Use:               "unset <id> <column>...",
		Short:             "Empty columns of a scope row",
		Args:              cobra.MinimumNArgs(2),
		ValidArgsFunction: e.completeScopeColumn,
		RunE: func(_ *cobra.Command, args []string) error {
			return e.write(&w, rowRevs(args[0]), func(b *batch) error {
				ch, err := b.m.UnsetScope(args[0], args[1:]...)
				if err != nil {
					return b.refuse(err, "", 0)
				}
				e.printChange(b, ch)
				return nil
			})
		},
	}
	addWriteFlags(c, &w, true)
	return c
}

func (e *env) scopeRemove() *cobra.Command {
	var w writeFlags
	c := &cobra.Command{
		Use:               "remove <id>...",
		Short:             "Remove scope rows",
		Args:              cobra.MinimumNArgs(1),
		ValidArgsFunction: e.completeScopeIDs,
		RunE: func(_ *cobra.Command, ids []string) error {
			return e.write(&w, rowRevs(ids...), func(b *batch) error {
				for _, id := range ids {
					row, _ := b.m.Scope.Row(id)
					ch, err := b.m.RemoveScope(id, w.mode())
					if err != nil {
						if err := b.refuse(err, "", 0); err != nil {
							return err
						}
						continue
					}
					if row != nil {
						b.removing = append(b.removing, row.ID+"  "+row.Host+portText(row.Port))
					}
					e.printChange(b, ch)
				}
				return nil
			})
		},
	}
	addYesFlag(c, &w)
	addCitedFlags(c, &w, citedForce, citedCleanup)
	addWriteFlags(c, &w, true)
	return c
}

func portText(p int) string {
	if p == 0 {
		return ""
	}
	return ":" + strconv.Itoa(p)
}

// scopeMatch attributes the targets of the findings on stdin to scope
// rows: a target with a host and no scope ID gets the most specific row
// covering it. Other records, and members rpt doesn't touch, pass
// through byte for byte. The report isn't written.
func (e *env) scopeMatch() *cobra.Command {
	var drop bool
	c := &cobra.Command{
		Use:     "match",
		Short:   "Attribute the targets of findings on stdin to scope rows",
		Example: "  rpt-nessus scan.nessus | rpt scope match [--drop-out-of-scope] | rpt finding add",
		Args:    cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			recs, err := e.readStdin()
			if err != nil {
				return err
			}
			m, err := e.load()
			if err != nil {
				return err
			}
			defer m.Close()
			if m.Scope.Err != nil {
				return e.fail(m.Scope.Err)
			}
			var ps []report.Problem
			for _, rec := range recs {
				if rec.Kind != "finding" {
					if err := e.out.WriteRaw(rec.Raw); err != nil {
						return err
					}
					continue
				}
				var f sdk.Finding
				if err := json.Unmarshal(rec.Raw, &f); err != nil {
					ps = append(ps, report.Problem{Path: report.StreamPath, Line: rec.Line, Rule: ruleInput, Level: report.Error, Message: "finding: " + err.Error()})
					continue
				}
				var kept []sdk.Target
				for _, t := range f.Targets {
					if t.Scope != "" || t.Host == "" {
						kept = append(kept, t)
						continue
					}
					got, row, ok := m.Scope.Attribute(report.Target{Host: t.Host, Port: t.Port, Protocol: t.Protocol})
					if !ok {
						ps = append(ps, report.Problem{Path: report.StreamPath, Line: rec.Line, Rule: "targets", Level: report.Warning,
							Message: fmt.Sprintf("%s: %s is in no scope row%s", cmpID(f.ID, f.Title), t.Host, map[bool]string{true: "; dropped", false: ""}[drop])})
						if !drop {
							kept = append(kept, t)
						}
						continue
					}
					t.Scope, t.Host = row.ID, got.Host
					kept = append(kept, t)
				}
				if len(kept) == 0 && len(f.Targets) > 0 && drop {
					ps = append(ps, report.Problem{Path: report.StreamPath, Line: rec.Line, Rule: "targets", Level: report.Warning,
						Message: fmt.Sprintf("%s: no target is in scope; finding dropped", cmpID(f.ID, f.Title))})
					continue
				}
				if kept == nil {
					kept = []sdk.Target{}
				}
				raw, err := sdk.SetMember(rec.Raw, "targets", kept)
				if err != nil {
					return err
				}
				f.Targets = kept
				if err := e.writeOwn(f, raw); err != nil {
					return err
				}
			}
			return e.problems(ps)
		},
	}
	c.Flags().BoolVar(&drop, "drop-out-of-scope", false, "Drop targets that fall in no scope row, and findings left with none")
	return c
}

// cmpID names a stream finding: its ID, else its title.
func cmpID(id, title string) string {
	if id != "" {
		return id
	}
	return fmt.Sprintf("%q", title)
}
