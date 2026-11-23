package main

import (
	"bufio"
	"bytes"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/internal/plugin"
	"github.com/astr4liteEx/rpt/internal/report"
	"github.com/astr4liteEx/rpt/sdk"
)

// stdoutIsTerminal decides between tables and JSON Lines; tests swap it.
var stdoutIsTerminal = isTerminal

func (e *env) tableCommand() *cobra.Command {
	return &cobra.Command{
		Use:         "table",
		Short:       "Show records from stdin as tables on a terminal, and pass them on unchanged elsewhere",
		Example:     `  rpt finding get | jq -c 'select(.severity=="high")' | rpt table`,
		Annotations: io_("records", "records"),
		Args:        cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			e.severities()
			return e.table(e.stdin, false)
		},
	}
}

// severities orders the findings totals by the report's levels, when
// there is a report.
func (e *env) severities() {
	if !e.out.Table() {
		return
	}
	if dir, err := e.reportDir(); err == nil {
		e.out.Severities = report.Severities(dir)
	}
}

// table shows the records read from r through e.out: byte for byte in
// JSON Lines, tables on a terminal, where records of kinds with no table
// follow as lines. It shows everything that arrives, errors upstream
// included, and returns errReported when a line isn't a record or a
// problem is an error. On a terminal a problem is stderr text, as the
// built-ins show theirs; a plugin rpt runs (fromPlugin) has printed its
// own there already, so they're left out. A config record's severities
// order the findings totals.
func (e *env) table(r io.Reader, fromPlugin bool) error {
	failed := false
	for rec, err := range sdk.Records(r) {
		var le *sdk.LineError
		switch {
		case errors.As(err, &le):
			failed = true
			if err := e.problem(report.Problem{Path: report.StreamPath, Line: le.Line, Rule: ruleInput, Level: report.Error, Message: le.Err.Error()}); err != nil {
				return err
			}
			continue
		case err != nil:
			return err
		}
		switch rec.Kind {
		case "problem":
			var p sdk.Problem
			ok := json.Unmarshal(rec.Raw, &p) == nil
			failed = failed || ok && p.Level == sdk.Error
			if ok && e.out.Table() {
				if !fromPlugin {
					e.problem(report.Problem{Path: p.Path, Line: p.Line, Rule: p.Rule, Level: string(p.Level), Message: p.Message})
				}
				continue
			}
		case "config":
			var c struct {
				Severities []string `json:"severities"`
			}
			if json.Unmarshal(rec.Raw, &c) == nil && len(c.Severities) > 0 {
				e.out.Severities = c.Severities
			}
		}
		if err := e.out.Render(rec.Raw); err != nil {
			return err
		}
	}
	if failed {
		return errReported
	}
	return nil
}

// tablesFor reports whether rpt shows a plugin's output as tables: its
// --describe says it prints records, rpt's stdout is a terminal, and
// nothing asks for JSON, help, its description or completions, which
// pass through as they are.
func (e *env) tablesFor(desc sdk.Description, args []string) bool {
	if desc.Output != "records" || e.json || !stdoutIsTerminal(e.stdout) {
		return false
	}
	for _, a := range args {
		if a == "--json" || a == "--help" || a == "-h" || a == "--describe" || strings.HasPrefix(a, "__complete") {
			return false
		}
	}
	return true
}

// pluginTables runs a plugin as rpt's child and shows its records as
// tables. Its exit code is the plugin's, or 1 when it exited 0 but
// printed a line that isn't a record. A plugin killed by a signal shows
// nothing.
func (e *env) pluginTables(p plugin.Plugin, args, env []string) int {
	e.command = p.Name
	e.out = cli.NewOutput(e.stdout, true, false)
	e.severities()
	var rerr error
	code, err := plugin.Pipe(p, args, env, e.stdin, e.stderr, func(r io.Reader) { rerr = e.pluginStdout(r) })
	if err != nil {
		e.log.Error(fmt.Sprintf("plugin %s: %v", p.Name, err))
		return cli.ExitPluginFailed
	}
	if code >= 128 {
		return code
	}
	if ferr := e.out.Flush(); rerr == nil {
		rerr = ferr
	}
	if rerr != nil && !errors.Is(rerr, errReported) {
		e.log.Error(rerr.Error())
	}
	if rerr != nil && code == 0 {
		return cli.ExitProblems
	}
	return code
}

// pluginStdout shows what a plugin printed. Output that doesn't start
// with a record, such as the plugin's own help or version text, is
// copied through as it is.
func (e *env) pluginStdout(r io.Reader) error {
	br := bufio.NewReader(r)
	var lead bytes.Buffer
	for {
		b, err := br.ReadByte()
		if err != nil {
			_, werr := e.stdout.Write(lead.Bytes())
			return werr
		}
		lead.WriteByte(b)
		if b == '{' {
			return e.table(io.MultiReader(&lead, br), true)
		}
		if b != ' ' && b != '\t' && b != '\r' && b != '\n' {
			_, err := io.Copy(e.stdout, io.MultiReader(&lead, br))
			return err
		}
	}
}
