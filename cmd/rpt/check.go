package main

import (
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/internal/plugin"
	"github.com/astr4liteEx/rpt/internal/report"
	"github.com/astr4liteEx/rpt/sdk"
)

// describer asks plugins to describe themselves, with the answers cached
// in the user's cache folder.
func describer(reportDir string) *plugin.Describer {
	d := &plugin.Describer{Env: plugin.Env(os.Environ(), reportDir, self(), report.SchemaVersion), Timeout: 2 * time.Second}
	if dir, err := os.UserCacheDir(); err == nil {
		d.CacheFile = filepath.Join(dir, "rpt", "describe.json")
	}
	return d
}

// schemaProblems checks names against the schemas their plugins declare.
func schemaProblems(m *report.Model, names []report.XName) []report.Problem {
	installed := plugin.Discover(os.Getenv("PATH"))
	want := plugin.Wanted(names, installed)
	if len(want) == 0 {
		return nil
	}
	return plugin.Check(names, installed, describer(m.Dir).Describe(want))
}

func (e *env) validateCommand() *cobra.Command {
	var withRecords bool
	c := &cobra.Command{
		Use:               "validate [id...]",
		Short:             "Check the report, or the records on stdin, and print the problems",
		Example:           "  rpt validate [--records] [id...]\n  rpt validate - < records.jsonl",
		Annotations:       map[string]string{"input": "records", "output": "records", "roles": sdk.RoleChecker},
		ValidArgsFunction: e.completeAnyID,
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 1 && args[0] == "-" {
				if withRecords {
					return usagef("--records reads the report, not stdin")
				}
				return e.validateStream()
			}
			m, err := e.load()
			if err != nil {
				return err
			}
			defer m.Close()
			ps := m.Leveled(append(m.Check(), schemaProblems(m, m.XNames())...))
			if len(args) > 0 {
				if ps, err = only_(m, ps, args); err != nil {
					return e.fail(err)
				}
			}
			if withRecords {
				e.out = cli.NewOutput(e.stdout, false, true) // records, on a terminal too
				if err := e.checkedRecords(m, args); err != nil {
					return err
				}
			}
			return e.problems(ps)
		},
	}
	c.Flags().BoolVar(&withRecords, "records", false,
		"Print the records checked before the problems, as the get commands print them with --lines: the config, findings, pages, scope rows and evidence, orphans included; with IDs, only those and their evidence")
	return c
}

// checkedRecords prints the records validate --records checked, from the
// same read as its problems, each as its get command prints it with
// --lines. What doesn't read has no record; its problem says why. With
// ids, only the findings, pages and scope rows named, and the evidence
// of those findings and pages.
func (e *env) checkedRecords(m *report.Model, ids []string) error {
	var docs []*report.Doc
	var rows []*report.Row
	if len(ids) == 0 {
		if m.Config.Err == nil {
			if err := e.out.Write(m.ConfigRecord(true)); err != nil {
				return err
			}
		}
		for _, k := range report.Kinds {
			docs = append(docs, m.Docs(k)...)
		}
		if m.Scope.Err == nil {
			rows = m.Scope.Rows
		}
	} else {
		for _, id := range ids { // only_ has checked each is there
			if k := report.KindOf(id); k != nil {
				d, _ := m.Get(k, id)
				docs = append(docs, d)
			} else if r, err := m.Scope.Row(id); err == nil {
				rows = append(rows, r)
			}
		}
	}
	for _, d := range docs {
		if d.Err == nil {
			if err := e.out.Write(docRecord(m, d, report.RecordOpts{Lines: true})); err != nil {
				return err
			}
		}
	}
	for _, r := range rows {
		if err := e.out.Write(m.ScopeRecord(r, true)); err != nil {
			return err
		}
	}
	for _, d := range docs {
		refs, _ := m.Refs(d)
		for _, r := range refs {
			if err := e.out.Write(m.EvidenceRecord(r)); err != nil {
				return err
			}
		}
	}
	if len(ids) > 0 {
		return nil
	}
	// Orphans refuses while a document doesn't parse, since that one may
	// reference what looks orphaned; validate reports the document.
	files, err := m.Orphans()
	if err != nil {
		return nil
	}
	for _, f := range files {
		if err := e.out.Write(m.OrphanRecord(f)); err != nil {
			return err
		}
	}
	return nil
}

// only_ keeps the problems in the findings, pages and scope rows named.
func only_(m *report.Model, ps []report.Problem, ids []string) ([]report.Problem, error) {
	type place struct {
		path string
		line int // a scope row's line; 0 for a whole file
	}
	var places []place
	for _, id := range ids {
		if k := report.KindOf(id); k != nil {
			d, err := m.Get(k, id)
			if err != nil {
				return nil, err
			}
			places = append(places, place{d.Path, 0})
			continue
		}
		r, err := m.Scope.Row(id)
		if err != nil {
			return nil, err
		}
		places = append(places, place{report.ScopeFile, r.Line})
	}
	var out []report.Problem
	for _, p := range ps {
		for _, pl := range places {
			if p.Path == pl.path && (pl.line == 0 || p.Line == pl.line) {
				out = append(out, p)
				break
			}
		}
	}
	return out, nil
}

// validateStream checks the records on stdin as if they were written to
// the report, which isn't written. A clean stream is copied to stdout
// byte for byte, its warnings on stderr only. Otherwise only problems
// come out, and the exit code is 1.
func (e *env) validateStream() error {
	recs, err := e.readStdin()
	if err != nil {
		return err
	}
	m, err := e.load()
	if err != nil {
		return err
	}
	defer m.Close()
	var in []report.Record
	var names []report.XName
	for _, r := range recs {
		in = append(in, report.Record{Kind: r.Kind, Line: r.Line, Raw: r.Raw})
		if report.IsPluginKey(r.Kind) {
			names = append(names, report.XName{Noun: "kinds", Name: r.Kind, Path: report.StreamPath, Line: r.Line, Value: r.Raw})
		}
	}
	ps := m.CheckRecords(in)
	ps = append(ps, schemaProblems(m, append(names, m.XNames()...))...)
	ps = m.Leveled(ps)
	failed := false
	for _, p := range ps {
		failed = failed || p.Level == report.Error
	}
	if failed {
		for _, r := range recs {
			if r.Kind == "problem" {
				if err := e.out.WriteRaw(r.Raw); err != nil {
					return err
				}
			}
		}
		return e.problems(ps)
	}
	for _, r := range recs {
		if err := e.out.WriteRaw(r.Raw); err != nil {
			return err
		}
	}
	out := e.out
	e.out = nil // warnings on stderr only: the stream is the output
	defer func() { e.out = out }()
	return e.problems(ps)
}

func (e *env) assembleCommand() *cobra.Command {
	return &cobra.Command{
		Use:         "assemble",
		Short:       "Print the whole report as one record for renderers",
		Annotations: io_("", "records"),
		Args:        cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			m, err := e.load()
			if err != nil {
				return err
			}
			defer m.Close()
			e.out = cli.NewOutput(e.stdout, false, true) // one JSON line, on a terminal too
			r, warn := m.Assemble()
			if err := e.out.Write(r); err != nil {
				return err
			}
			return e.problems(warn)
		},
	}
}
