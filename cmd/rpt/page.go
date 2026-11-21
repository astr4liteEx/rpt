package main

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/spf13/pflag"

	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/internal/legacy/report"
	"github.com/astr4liteEx/rpt/sdk"
)

var pageColumns = []cli.Column{{Header: "ID", Field: "id"}, {Header: "TITLE", Field: "title"}, {Header: "PATH", Field: "path"}}

// pageGetVerb prints every page, or with IDs those pages in the order
// given; with --lines, where each page's parts sit in its file.
func pageGetVerb(flags *pflag.FlagSet) runner {
	withLines := flags.Bool("lines", false, "add each page's lines: its file's absolute path, where its frontmatter keys sit and the line its body starts on")
	withAssets := flags.Bool("assets", false, "add each page's assets: every file it lists or links, with its absolute path, to carry it to another report with rpt page add")
	asTable := flags.Bool("table", false, "on a terminal, show the pages named as a table rather than for reading")
	return func(e *env, args []string) int {
		ids := findingIDs(args)
		out, err := e.output(pageColumns)
		if err != nil {
			e.log.Error(err.Error())
			return cli.ExitProblems
		}
		r := openReport(e)
		if r == nil {
			return cli.ExitProblems
		}
		defer r.Close()
		read := r.Pages
		if *withLines {
			read = r.PagesWithLines
		}
		list, readErr := read()
		var missing []string
		if len(ids) > 0 {
			var picked []sdk.Page
			for _, id := range ids {
				i := slices.IndexFunc(list, func(p sdk.Page) bool { return p.ID == id })
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
		if out.Table() && len(ids) > 0 && !*asTable {
			v := cli.NewReadingView(e.stdout)
			for _, p := range list {
				if err := v.Record(p.ID, p.Title, cli.Dim(p.Path), p.Body); err != nil {
					e.log.Error(err.Error())
					return cli.ExitProblems
				}
			}
			list = nil
		}
		for _, p := range list {
			if err := out.Write(p); err != nil {
				e.log.Error(err.Error())
				return cli.ExitProblems
			}
		}
		for _, id := range missing {
			p := sdk.Problem{Path: report.PagesDir, Rule: ruleExists, Level: sdk.Error, Message: fmt.Sprintf("%v: %s", report.ErrNoPage, id)}
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
}

// pageAddVerb writes each page record on stdin as a new page file, or one
// page from --title, and prints the pages as stored. Other records pass
// through. One refusal and nothing is written.
func pageAddVerb(flags *pflag.FlagSet) runner {
	title := flags.String("title", "", "write one page with this title instead of reading stdin")
	id := flags.String("id", "", "the page's ID (with --title); default: the next free P-NNN")
	wf := addWriteFlags(flags, false)
	return func(e *env, args []string) int {
		fromFlags := false
		flags.Visit(func(f *pflag.Flag) { fromFlags = fromFlags || f.Name == "title" || f.Name == "id" })
		if len(args) != 0 || fromFlags && *title == "" {
			return usageError(e, "reads records on stdin, or takes --title")
		}
		return writePages(e, wf, nil, func(w *write) {
			add := func(p sdk.Page, line int) {
				added, err := w.tx.AddPage(p)
				if err != nil {
					path := report.PagesDir
					if line > 0 {
						path = stdinPath
					}
					w.refuse(err, path, line)
					return
				}
				w.done(added, added.Path)
			}
			if fromFlags {
				add(sdk.Page{Kind: "page", ID: *id, Title: *title}, 0)
				return
			}
			recs, _, ok := readInput(e, w.out)
			if !ok {
				w.failed = true
				return
			}
			for _, rec := range recs {
				if rec.Kind != "page" {
					w.pass(rec.Raw)
					continue
				}
				var p sdk.Page
				if err := json.Unmarshal(rec.Raw, &p); err != nil {
					w.refused = append(w.refused, sdk.Problem{Path: stdinPath, Line: rec.Line, Rule: ruleInput, Level: sdk.Error, Message: "page: " + err.Error()})
					continue
				}
				add(p, rec.Line)
			}
		})
	}
}

// writePages runs a write on pages named by ids.
func writePages(e *env, wf writeFlags, ids []string, do func(*write)) int {
	out, err := e.output(pageColumns)
	if err != nil {
		e.log.Error(err.Error())
		return cli.ExitProblems
	}
	r := openReport(e)
	if r == nil {
		return cli.ExitProblems
	}
	defer r.Close()
	w, ok := newWrite(e, out, r, wf, ids)
	if !ok {
		return cli.ExitUsage
	}
	do(w)
	return w.finish()
}

// pageChanged adds what one page write did to w: the page, then the
// config if the write changed it.
func pageChanged(w *write, ch report.PageChange) {
	w.done(ch.Page, ch.Page.Path)
	if ch.Config != nil {
		w.done(*ch.Config, report.ConfigFile)
	}
}

// pageSetVerb sets one value of one page: title, evidence, body (from
// stdin when no value is given), id, or any other key.
func pageSetVerb(flags *pflag.FlagSet) runner {
	wf := addWriteFlags(flags, true)
	return func(e *env, args []string) int {
		pos := args
		body := len(pos) == 2 && pos[1] == "body"
		if len(pos) < 3 && !body {
			return usageError(e, "needs an ID, a path and a value")
		}
		id := report.CanonicalID(pos[0])
		values := pos[2:]
		if body {
			text, err := io.ReadAll(e.stdin)
			if err != nil {
				e.log.Error(err.Error())
				return cli.ExitProblems
			}
			values = []string{string(text)}
		}
		return writePages(e, wf, []string{id}, func(w *write) {
			ch, err := w.tx.SetPage(id, pos[1], values...)
			if err != nil {
				w.refuse(err, report.PagesDir, 0)
				return
			}
			pageChanged(w, ch)
		})
	}
}

// pageUnsetVerb removes keys from one page; unsetting body empties it.
func pageUnsetVerb(flags *pflag.FlagSet) runner {
	wf := addWriteFlags(flags, true)
	return func(e *env, args []string) int {
		pos := args
		if len(pos) < 2 {
			return usageError(e, "needs an ID and a path")
		}
		id := report.CanonicalID(pos[0])
		return writePages(e, wf, []string{id}, func(w *write) {
			p, err := w.tx.UnsetPage(id, pos[1:]...)
			if err != nil {
				w.refuse(err, report.PagesDir, 0)
				return
			}
			w.done(p, p.Path)
		})
	}
}

// pageRemoveVerb removes pages. A page rpt.yaml's pages or required_pages
// names is refused unless --force or --cleanup. On a terminal it asks
// first; otherwise it needs --yes.
func pageRemoveVerb(flags *pflag.FlagSet) runner {
	yes := addYesFlag(flags)
	cited := citedFlags(flags)
	wf := addWriteFlags(flags, true)
	return func(e *env, args []string) int {
		ids := findingIDs(args)
		mode, ok := cited()
		if len(ids) == 0 || !ok {
			return usageError(e, "needs an ID, and --force and --cleanup don't go together")
		}
		if !mayAsk(e, *yes, *wf.dryRun) {
			return cli.ExitUsage
		}
		return writePages(e, wf, ids, func(w *write) {
			var things, effects []string
			for _, id := range ids {
				ch, err := w.tx.RemovePage(id, mode)
				if err != nil {
					w.refuse(err, report.PagesDir, 0)
					continue
				}
				pageChanged(w, ch)
				things = append(things, fmt.Sprintf("%s  %s  %s", ch.Page.ID, ch.Page.Title, ch.Page.Path))
				if ch.Config != nil {
					effects = append(effects, fmt.Sprintf("--cleanup drops %s from rpt.yaml", ch.Page.ID))
				}
				if len(ch.Left) > 0 {
					effects = append(effects, fmt.Sprintf("--force leaves %s in %s", ch.Page.ID, strings.Join(ch.Left, " and ")))
				}
			}
			if len(w.refused) == 0 && !w.failed && !*yes && !*wf.dryRun && !confirm(e, "page", things, effects) {
				w.declined = true
			}
		})
	}
}
