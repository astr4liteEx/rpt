package main

import (
	"context"
	"encoding/json/v2"
	"errors"
	"log/slog"

	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/internal/legacy/report"
	"github.com/astr4liteEx/rpt/sdk"
)

// Rules for problems that aren't validate's: a file that can't be read, an
// ID that isn't there, and a stdin line that isn't a record.
const (
	ruleReadable = "readable"
	ruleExists   = "exists"
	ruleInput    = "input"
)

// stdinPath is a problem's path for a record on stdin; its line is the
// record's line in the stream.
const stdinPath = "-"

// problem reports p both ways (ADR 0011): a text line on stderr, and a
// record on stdout unless out is nil or prints a table, where a problem
// doesn't fit. A problem with no command is given this one.
func (e *env) problem(out *cli.Output, p sdk.Problem) error {
	p.Kind = "problem"
	if p.Command == "" {
		p.Command = e.command
	}
	e.logProblem(p)
	if out == nil || out.Table() {
		return nil
	}
	return out.Write(p)
}

// logProblem writes p on stderr: compiler-style on a terminal, else as
// one text line.
func (e *env) logProblem(p sdk.Problem) {
	if e.diag != nil {
		e.diag.Print(cli.Diagnostic{Path: p.Path, Rule: p.Rule, Message: p.Message, Error: p.Level == sdk.Error,
			Line: p.Line, Column: p.Column, End: p.EndColumn})
		return
	}
	level := slog.LevelError
	if p.Level != sdk.Error {
		level = slog.LevelWarn
	}
	e.log.Log(context.Background(), level, p.Message, "path", p.Path, "line", p.Line)
}

// reportErrors reports each error from reading the report: a problem in a
// report file is a readable problem; anything else, such as a failed
// read, is stderr text. Either is exit 1.
func reportErrors(e *env, out *cli.Output, err error) int {
	if err == nil {
		return cli.ExitOK
	}
	for _, err := range unjoin(err) {
		fe, ok := errors.AsType[*report.FileError](err)
		if !ok {
			e.log.Error(err.Error())
			continue
		}
		p := sdk.Problem{Path: fe.Path, Line: fe.Line, Rule: ruleReadable, Level: sdk.Error, Message: fe.Err.Error()}
		if werr := e.problem(out, p); werr != nil {
			e.log.Error(werr.Error())
			return cli.ExitProblems
		}
	}
	return cli.ExitProblems
}

// readInput reads every record on stdin before a command acts on any. If
// a line isn't a record, or an error-level problem arrives, the command
// must stop: readInput passes the incoming problems on (on a table, as
// text, since nothing else would show them), reports the bad lines, and
// returns exit 1 with ok false. Warnings never stop anything.
func readInput(e *env, out *cli.Output) (recs []sdk.Rec, code int, ok bool) {
	var bad []sdk.Problem
	var stop []sdk.Rec
	for rec, err := range sdk.Records(e.stdin) {
		if le, isLine := errors.AsType[*sdk.LineError](err); isLine {
			bad = append(bad, sdk.Problem{Path: stdinPath, Line: le.Line, Rule: ruleInput, Level: sdk.Error, Message: le.Err.Error()})
			continue
		} else if err != nil {
			e.log.Error(err.Error())
			return nil, cli.ExitProblems, false
		}
		recs = append(recs, rec)
		if rec.Kind == "problem" && isError(rec) {
			stop = append(stop, rec)
		}
	}
	if len(bad) == 0 && len(stop) == 0 {
		return recs, cli.ExitOK, true
	}
	for _, rec := range recs {
		if rec.Kind != "problem" {
			continue
		}
		if out.Table() {
			var p sdk.Problem
			if json.Unmarshal(rec.Raw, &p) == nil {
				e.logProblem(p)
			}
			continue
		}
		if err := out.WriteRaw(rec.Raw); err != nil {
			e.log.Error(err.Error())
			return nil, cli.ExitProblems, false
		}
	}
	for _, p := range bad {
		if err := e.problem(out, p); err != nil {
			e.log.Error(err.Error())
			return nil, cli.ExitProblems, false
		}
	}
	return nil, cli.ExitProblems, false
}

// isError reports whether a problem record is error-level.
func isError(rec sdk.Rec) bool {
	var p struct {
		Level sdk.Level `json:"level"`
	}
	return json.Unmarshal(rec.Raw, &p) == nil && p.Level == sdk.Error
}
