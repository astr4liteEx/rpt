package main

import (
	"encoding/json/v2"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/astr4liteEx/rpt/internal/report"
	"github.com/astr4liteEx/rpt/sdk"
)

func (e *env) evidenceCommand() *cobra.Command {
	c := &cobra.Command{
		Use:         "evidence",
		Short:       "Get, add, set, unset and remove the files findings and pages list and link; prune removes files nothing references",
		Annotations: io_("records", "records"),
	}
	c.AddCommand(e.evidenceGet(), e.evidenceAdd(), e.evidenceSet(), e.evidenceUnset(), e.evidenceRemove(), e.evidencePrune())
	return c
}

// owner finds the finding or page an ID names.
func owner(m *report.Model, id string) (*report.Doc, error) {
	k := report.KindOf(id)
	if k == nil {
		return nil, &report.Refusal{Path: ".", Msg: id + " is not a finding or page ID (F-NNN, P-NNN)"}
	}
	return m.Get(k, id)
}

// ownerRevs is the owner's rev, for --if-rev.
func ownerRevs(id string) func(*report.Model) map[string]string {
	return func(m *report.Model) map[string]string {
		if d, err := owner(m, id); err == nil {
			return map[string]string{d.ID: d.Rev}
		}
		return nil
	}
}

func (e *env) evidenceGet() *cobra.Command {
	var orphans bool
	c := &cobra.Command{
		Use:               "get [owner...]",
		Short:             "Print the files findings and pages list and link, or those of the owners given",
		Example:           "  rpt evidence get [owner...]\n  rpt evidence get --orphans",
		ValidArgsFunction: e.completeOwners,
		RunE: func(_ *cobra.Command, ids []string) error {
			m, err := e.load()
			if err != nil {
				return err
			}
			defer m.Close()
			var docs []*report.Doc
			var ps []report.Problem
			if len(ids) == 0 {
				for _, k := range report.Kinds {
					docs = append(docs, m.Docs(k)...)
				}
			}
			for _, id := range ids {
				d, err := owner(m, id)
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
			for _, d := range docs {
				refs, errs := m.Refs(d)
				for _, r := range refs {
					if err := e.out.Write(m.EvidenceRecord(r)); err != nil {
						return err
					}
				}
				for _, err := range errs {
					p, _ := failure(err, d.Path, 0)
					p.Rule, p.Level = "evidence", report.Warning
					ps = append(ps, p)
				}
			}
			if orphans {
				files, err := m.Orphans()
				if err != nil {
					return e.fail(err)
				}
				for _, f := range files {
					if err := e.out.Write(m.OrphanRecord(f)); err != nil {
						return err
					}
				}
			}
			return e.problems(ps)
		},
	}
	c.Flags().BoolVar(&orphans, "orphans", false, "Also list the files in findings/evidence/ and pages/evidence/ that nothing references")
	return c
}

func (e *env) evidenceAdd() *cobra.Command {
	var w writeFlags
	var as, link, text string
	c := &cobra.Command{
		Use:     "add <owner> <file>...",
		Short:   "Copy files into the report and list them, and with --link link them",
		Example: "  rpt evidence add [--as name] [--link section [--text caption]] <owner> <file>...\n  rpt evidence add < records.jsonl",
		ValidArgsFunction: func(c *cobra.Command, args []string, s string) ([]string, cobra.ShellCompDirective) {
			if len(args) == 0 {
				return e.completeOwners(c, args, s)
			}
			return nil, cobra.ShellCompDirectiveDefault
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				if cmd.Flags().Changed("as") || cmd.Flags().Changed("link") || cmd.Flags().Changed("text") {
					return usagef("--as, --link and --text go with an owner and files")
				}
				return e.evidenceFromStdin(&w)
			}
			if len(args) < 2 {
				return usagef("needs an owner and at least one file")
			}
			if text != "" && link == "" {
				return usagef("--text goes with --link")
			}
			return e.write(&w, ownerRevs(args[0]), func(b *batch) error {
				d, err := owner(b.m, args[0])
				if err != nil {
					return b.refuse(err, "", 0)
				}
				var srcs []report.EvidenceSource
				for _, f := range args[1:] {
					t := text
					if t == "" && link != "" {
						t = filepath.Base(f)
					}
					srcs = append(srcs, report.EvidenceSource{Path: f, Section: link, Text: t})
				}
				d, err = b.m.AddEvidence(d, srcs, as)
				if err != nil {
					return b.refuse(err, "", 0)
				}
				b.print(docRecord(b.m, d, report.RecordOpts{Assets: true}))
				return nil
			})
		},
	}
	c.Flags().StringVar(&as, "as", "", "The copy's file name, exactly (one file only); it must not exist")
	c.Flags().StringVar(&link, "link", "", "Also link each file in this section (a finding's section key or heading, or body for a page)")
	c.Flags().StringVar(&text, "text", "", "The link's text, its caption (with --link); default: the file's name")
	addWriteFlags(c, &w, true)
	return c
}

// evidenceFromStdin adds the evidence records on stdin, each naming its
// owner (finding or page), the file to add as file, and with section a
// link and its text. Other records pass through.
func (e *env) evidenceFromStdin(w *writeFlags) error {
	recs, err := e.readStdin()
	if err != nil {
		return err
	}
	return e.write(w, nil, func(b *batch) error {
		for _, rec := range recs {
			if rec.Kind != "evidence" {
				b.pass(rec.Raw)
				continue
			}
			var ev struct {
				sdk.Evidence
				File string `json:"file"`
			}
			bad := func(msg string) {
				b.refused = append(b.refused, report.Problem{Path: report.StreamPath, Line: rec.Line, Rule: ruleInput, Level: report.Error, Message: "evidence: " + msg})
			}
			if err := json.Unmarshal(rec.Raw, &ev); err != nil {
				bad(err.Error())
				continue
			}
			if (ev.Finding == "") == (ev.Page == "") || ev.File == "" {
				bad("name one owner, finding or page, and the file to add")
				continue
			}
			d, err := owner(b.m, ev.Finding+ev.Page)
			if err == nil {
				d, err = b.m.AddEvidence(d, []report.EvidenceSource{{Path: ev.File, Section: ev.Section, Text: ev.Text}}, "")
			}
			if err != nil {
				if err := b.refuse(err, report.StreamPath, rec.Line); err != nil {
					return err
				}
				continue
			}
			b.print(docRecord(b.m, d, report.RecordOpts{Assets: true}))
		}
		return nil
	})
}

func (e *env) evidenceSet() *cobra.Command {
	var w writeFlags
	c := &cobra.Command{
		Use:               "set <owner> <ref> caption|path <value>",
		Short:             "Change the caption of every link to a file, or move the file and rewrite every reference to it",
		Args:              cobra.ExactArgs(4),
		ValidArgsFunction: e.completeEvidence("caption", "path"),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := flagsAmongValues(cmd, args[3:]); err != nil {
				return err
			}
			if args[2] != "caption" && args[2] != "path" {
				return usagef("the third argument is caption or path, not %q", args[2])
			}
			return e.setEvidence(&w, args[0], args[1], args[2], args[3])
		},
	}
	c.Flags().SetInterspersed(false)
	addWriteFlags(c, &w, true)
	return c
}

func (e *env) evidenceUnset() *cobra.Command {
	var w writeFlags
	c := &cobra.Command{
		Use:               "unset <owner> <ref> caption",
		Short:             "Empty the caption of every link to a file",
		Args:              cobra.ExactArgs(3),
		ValidArgsFunction: e.completeEvidence("caption"),
		RunE: func(_ *cobra.Command, args []string) error {
			if args[2] != "caption" {
				return usagef("only a caption can be unset")
			}
			return e.setEvidence(&w, args[0], args[1], "caption", "")
		},
	}
	addWriteFlags(c, &w, true)
	return c
}

func (e *env) setEvidence(w *writeFlags, id, ref, what, value string) error {
	return e.write(w, ownerRevs(id), func(b *batch) error {
		d, err := owner(b.m, id)
		if err != nil {
			return b.refuse(err, "", 0)
		}
		if what == "caption" {
			d, err = b.m.SetCaption(d, ref, value)
			if err != nil {
				return b.refuse(err, "", 0)
			}
			b.print(docRecord(b.m, d, report.RecordOpts{Assets: true}))
			return nil
		}
		changed, err := b.m.MoveEvidence(d, ref, value)
		if err != nil {
			return b.refuse(err, "", 0)
		}
		for _, d := range changed {
			b.print(docRecord(b.m, d, report.RecordOpts{Assets: true}))
		}
		return nil
	})
}

func (e *env) evidenceRemove() *cobra.Command {
	var w writeFlags
	var dropText bool
	c := &cobra.Command{
		Use:               "remove <owner> <ref>",
		Short:             "Take a file out of a finding or page: its list entry and image links; the file stays for prune",
		Args:              cobra.ExactArgs(2),
		ValidArgsFunction: e.completeEvidence(),
		RunE: func(_ *cobra.Command, args []string) error {
			return e.write(&w, ownerRevs(args[0]), func(b *batch) error {
				d, err := owner(b.m, args[0])
				if err != nil {
					return b.refuse(err, "", 0)
				}
				d, err = b.m.RemoveEvidence(d, args[1], dropText)
				if err != nil {
					return b.refuse(err, "", 0)
				}
				b.removing = append(b.removing, d.ID+"  "+args[1])
				b.print(docRecord(b.m, d, report.RecordOpts{Assets: true}))
				return nil
			})
		},
	}
	c.Flags().BoolVar(&dropText, "drop-text", false, "Drop text links to the file, words and all")
	addYesFlag(c, &w)
	addWriteFlags(c, &w, true)
	return c
}

func (e *env) evidencePrune() *cobra.Command {
	var w writeFlags
	c := &cobra.Command{
		Use:   "prune",
		Short: "Delete the evidence files nothing references",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return e.write(&w, nil, func(b *batch) error {
				gone, err := b.m.PruneEvidence()
				if err != nil {
					return b.refuse(err, "", 0)
				}
				for _, f := range gone {
					b.removing = append(b.removing, f)
					rec := b.m.OrphanRecord(f)
					rec.Exists = false
					b.print(rec)
				}
				return nil
			})
		},
	}
	addYesFlag(c, &w)
	addWriteFlags(c, &w, false)
	return c
}
