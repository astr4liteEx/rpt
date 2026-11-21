package main

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/internal/report"
	"github.com/astr4liteEx/rpt/sdk"
)

// docCommand is the finding or page command: one implementation over the
// kind table.
func (e *env) docCommand(k *report.Kind) *cobra.Command {
	finding := k == report.FindingKind
	c := &cobra.Command{
		Use:         k.Name,
		Short:       "Get, add, set, unset and remove findings",
		Annotations: io_("records", "records"),
	}
	if !finding {
		c.Short = "Get, add, set, unset and remove pages of report-level prose"
	}
	c.AddCommand(e.docGet(k), e.docAdd(k), e.docSet(k), e.docUnset(k), e.docRemove(k))
	return c
}

func (e *env) docGet(k *report.Kind) *cobra.Command {
	var lines, assets, table bool
	c := &cobra.Command{
		Use:               "get [id...]",
		Short:             fmt.Sprintf("Print %ss, or those with the IDs given", k.Name),
		ValidArgsFunction: e.completeIDs(k),
		RunE: func(_ *cobra.Command, ids []string) error {
			m, err := e.load()
			if err != nil {
				return err
			}
			defer m.Close()
			var docs []*report.Doc
			var ps []report.Problem
			if len(ids) == 0 {
				for _, d := range m.Docs(k) {
					if d.Err != nil {
						p, _ := failure(d.Err, d.Path, 0)
						ps = append(ps, p)
						continue
					}
					docs = append(docs, d)
				}
			}
			for _, id := range ids {
				d, err := m.Get(k, id)
				if err != nil {
					p, ok := failure(err, ".", 0)
					if !ok {
						return err
					}
					ps = append(ps, p)
					continue
				}
				docs = append(docs, d)
			}
			o := report.RecordOpts{Lines: lines, Assets: assets}
			reading := e.out.Table() && len(ids) > 0 && !table
			view := cli.NewReadingView(e.stdout)
			for _, d := range docs {
				if reading {
					if err := view.Record(d.ID, d.Title, facts(d), d.Body()); err != nil {
						return err
					}
					continue
				}
				if err := e.out.Write(docRecord(m, d, o)); err != nil {
					return err
				}
			}
			return e.problems(ps)
		},
	}
	c.Flags().BoolVar(&lines, "lines", false, fmt.Sprintf("Add where each part of the %s sits in its file", k.Name))
	c.Flags().BoolVar(&assets, "assets", false, fmt.Sprintf("Add every file the %s lists or links, with its absolute path", k.Name))
	c.Flags().BoolVar(&table, "table", false, fmt.Sprintf("On a terminal, show the %ss named as a table rather than for reading", k.Name))
	return c
}

// facts is the line under a document's title in the reading view.
func facts(d *report.Doc) string {
	if d.Kind != report.FindingKind {
		return cli.Facts(cli.Dim(d.Path))
	}
	var scope []string
	for _, t := range d.Targets {
		if t.Scope != "" && !slices.Contains(scope, t.Scope) {
			scope = append(scope, t.Scope)
		}
	}
	return cli.Facts(cli.Severity(d.Severity), cli.Dim(strings.Join(scope, ", ")), cli.Dim(d.Path))
}

func (e *env) docAdd(k *report.Kind) *cobra.Command {
	var w writeFlags
	var title, severity, id string
	var targets []string
	finding := k == report.FindingKind
	c := &cobra.Command{
		Use:   "add",
		Short: fmt.Sprintf("Add %ss from records on stdin, or one from flags", k.Name),
		Example: fmt.Sprintf("  rpt %s add < records.jsonl\n  rpt %s add --title t", k.Name, k.Name) +
			map[bool]string{true: " --severity s [--target S-N]... [--id F-NNN]", false: " [--id P-NNN]"}[finding],
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if title == "" {
				for _, f := range []string{"severity", "target", "id"} {
					if cmd.Flags().Changed(f) {
						return usagef("--%s goes with --title", f)
					}
				}
				return e.addFromStdin(k, &w)
			}
			if finding && severity == "" {
				return usagef("--title needs --severity")
			}
			return e.write(&w, nil, func(b *batch) error {
				dr := report.Draft{ID: id, Title: title, Severity: severity}
				ts, err := report.ParseTargets(targets)
				if err != nil {
					return usagef("--target: %v", err)
				}
				dr.Targets = ts
				d, err := b.m.Add(k, dr)
				if err != nil {
					return b.refuse(err, "", 0)
				}
				b.print(docRecord(b.m, d, report.RecordOpts{}))
				return nil
			})
		},
	}
	c.Flags().StringVar(&title, "title", "", fmt.Sprintf("Write one %s with this title instead of reading stdin", k.Name))
	if finding {
		c.Flags().StringVar(&severity, "severity", "", "The finding's severity (with --title)")
		c.Flags().StringArrayVar(&targets, "target", nil, "A target: a scope ID, or a map like '{scope: S-20, host: 10.0.1.5, port: 22}' (with --title; repeatable)")
		c.RegisterFlagCompletionFunc("severity", e.completeSeverity)
		c.RegisterFlagCompletionFunc("target", e.completeScopeIDs)
	}
	c.Flags().StringVar(&id, "id", "", fmt.Sprintf("The %s's ID (with --title); default: the next free one", k.Name))
	addWriteFlags(c, &w, false)
	return c
}

// addFromStdin adds the records of kind k on stdin; others pass through.
func (e *env) addFromStdin(k *report.Kind, w *writeFlags) error {
	recs, err := e.readStdin()
	if err != nil {
		return err
	}
	return e.write(w, nil, func(b *batch) error {
		for _, rec := range recs {
			if rec.Kind != k.Name {
				b.pass(rec.Raw)
				continue
			}
			var dr report.Draft
			var err error
			if k == report.PageKind {
				var p sdk.Page
				if err = json.Unmarshal(rec.Raw, &p); err == nil {
					dr, err = report.PageDraft(p)
				}
			} else {
				var f sdk.Finding
				if err = json.Unmarshal(rec.Raw, &f); err == nil {
					dr, err = report.FindingDraft(f)
				}
			}
			if err != nil {
				b.refused = append(b.refused, report.Problem{Path: report.StreamPath, Line: rec.Line, Rule: ruleInput, Level: report.Error, Message: fmt.Sprintf("%s: %v", k.Name, err)})
				continue
			}
			d, err := b.m.Add(k, dr)
			if err != nil {
				if err := b.refuse(err, report.StreamPath, rec.Line); err != nil {
					return err
				}
				continue
			}
			b.print(docRecord(b.m, d, report.RecordOpts{}))
		}
		return nil
	})
}

func (e *env) docSet(k *report.Kind) *cobra.Command {
	var w writeFlags
	text := "sections.<key>"
	if !k.Sectioned {
		text = "body"
	}
	c := &cobra.Command{
		Use:   "set <id> <path> [value...]",
		Short: fmt.Sprintf("Change one value of a %s", k.Name),
		Long: fmt.Sprintf("Change one value of a %s. The path is a frontmatter key, %s or x-<plugin>.<key>. "+
			"Each value is YAML: high, S-12, '{scope: S-20, port: 443}', \"9.1\"; several make a list. "+
			"With no value, %s's text is read from stdin. Flags go before the ID, so a value may start with -.", k.Name, text, text),
		Args:              cobra.MinimumNArgs(2),
		ValidArgsFunction: e.completeDocPath(k),
		RunE: func(_ *cobra.Command, args []string) error {
			id, key, values := args[0], args[1], args[2:]
			if len(values) == 0 && (strings.HasPrefix(key, "sections.") || key == "body") {
				b, err := io.ReadAll(e.stdin)
				if err != nil {
					return err
				}
				values = []string{string(b)}
			}
			return e.write(&w, docRevs(k, id), func(b *batch) error {
				d, err := b.m.Set(k, id, key, values...)
				if err != nil {
					return b.refuse(err, "", 0)
				}
				b.print(docRecord(b.m, d, report.RecordOpts{}))
				return nil
			})
		},
	}
	c.Flags().SetInterspersed(false)
	addWriteFlags(c, &w, true)
	return c
}

func (e *env) docUnset(k *report.Kind) *cobra.Command {
	var w writeFlags
	c := &cobra.Command{
		Use:               "unset <id> <path>...",
		Short:             fmt.Sprintf("Remove values from a %s", k.Name),
		Args:              cobra.MinimumNArgs(2),
		ValidArgsFunction: e.completeDocPath(k),
		RunE: func(_ *cobra.Command, args []string) error {
			return e.write(&w, docRevs(k, args[0]), func(b *batch) error {
				d, err := b.m.Unset(k, args[0], args[1:]...)
				if err != nil {
					return b.refuse(err, "", 0)
				}
				b.print(docRecord(b.m, d, report.RecordOpts{}))
				return nil
			})
		},
	}
	addWriteFlags(c, &w, true)
	return c
}

func (e *env) docRemove(k *report.Kind) *cobra.Command {
	var w writeFlags
	c := &cobra.Command{
		Use:               "remove <id>...",
		Short:             fmt.Sprintf("Remove %ss", k.Name),
		Args:              cobra.MinimumNArgs(1),
		ValidArgsFunction: e.completeIDs(k),
		RunE: func(_ *cobra.Command, ids []string) error {
			return e.write(&w, docRevs(k, ids...), func(b *batch) error {
				for _, id := range ids {
					d, left, err := b.m.Remove(k, id, w.mode())
					if err != nil {
						if err := b.refuse(err, "", 0); err != nil {
							return err
						}
						continue
					}
					b.removing = append(b.removing, d.ID+"  "+d.Title+"  ("+d.Path+")")
					for _, key := range left {
						e.log.Warn(fmt.Sprintf("%s still lists %s", key, d.ID), "path", report.ConfigFile)
					}
					b.print(docRecord(b.m, d, report.RecordOpts{}))
				}
				return nil
			})
		},
	}
	addYesFlag(c, &w)
	if k == report.PageKind {
		addCitedFlags(c, &w,
			"Remove a page rpt.yaml's pages or required_pages lists, and leave it listed",
			"Remove a page rpt.yaml lists, and take it out of the lists")
	}
	addWriteFlags(c, &w, true)
	return c
}

// io_ is the annotations saying what a command reads and writes, for
// rpt help and --describe.
func io_(input, output string) map[string]string {
	a := map[string]string{}
	if input != "" {
		a["input"] = input
	}
	if output != "" {
		a["output"] = output
	}
	return a
}
