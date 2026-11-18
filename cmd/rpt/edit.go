package main

import (
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"

	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/internal/report"
	"github.com/astr4liteEx/rpt/sdk"
)

// parseInterspersed parses flags wherever they appear among the arguments,
// so `rpt set F-003 severity high --report dir` works, and returns the
// positional arguments. "--" ends flag parsing.
func parseInterspersed(flags *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := flags.Parse(args); err != nil {
			return nil, err
		}
		rest := flags.Args()
		if n := len(args) - len(rest); n > 0 && args[n-1] == "--" {
			return append(pos, rest...), nil // everything after -- is positional
		}
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

// setVerb changes one frontmatter value of one finding.
func setVerb(e *env, args []string) int {
	flags, of := newFlags(e, "set")
	pos, err := parseInterspersed(flags, args)
	if err != nil {
		return cli.ExitUsage
	}
	if len(pos) != 3 {
		code := badUsage(e, "set")
		fmt.Fprintln(e.stderr, `value is YAML: high, '[S-12, S-14]', "9.1"`)
		return code
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

	f, err := r.Set(pos[0], pos[1], pos[2])
	if err != nil {
		return logEditError(e, err, 0)
	}
	if err := out.Write(f); err != nil {
		e.log.Error(err.Error())
		return cli.ExitUsage
	}
	if err := out.Flush(); err != nil {
		e.log.Error(err.Error())
		return cli.ExitUsage
	}
	return cli.ExitOK
}

// logEditError logs an error from editing and returns its exit code: a
// problem in a report file or (for rpt add) in one input record is exit 1;
// a bad request or a failure to write is exit 2. line > 0 locates the
// record on stdin.
func logEditError(e *env, err error, line int) int {
	if fe, ok := errors.AsType[*report.FileError](err); ok {
		e.log.Error(fe.Err.Error(), "path", fe.Path, "line", fe.Line)
		return cli.ExitProblems
	}
	if line > 0 && errors.Is(err, report.ErrBadValue) {
		e.log.Error(err.Error(), "path", "stdin", "line", line)
		return cli.ExitProblems
	}
	e.log.Error(err.Error())
	return cli.ExitUsage
}

// addVerb writes each finding record on stdin into the report as a new
// finding file and prints the finding as stored. Other records pass
// through untouched.
func addVerb(e *env, args []string) int {
	flags, of := newFlags(e, "add")
	pos, err := parseInterspersed(flags, args)
	if err != nil {
		return cli.ExitUsage
	}
	if len(pos) != 0 {
		return badUsage(e, "add")
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
			if err := out.WriteRaw(rec.Raw); err != nil {
				e.log.Error(err.Error())
				return cli.ExitUsage
			}
			continue
		}
		var f sdk.Finding
		if err := json.Unmarshal(rec.Raw, &f); err != nil {
			e.log.Error("finding: "+err.Error(), "path", "stdin", "line", rec.Line)
			code = cli.ExitProblems
			continue
		}
		added, err := r.Add(f)
		if err != nil {
			if c := logEditError(e, err, rec.Line); c == cli.ExitUsage {
				return c
			}
			code = cli.ExitProblems
			continue
		}
		if err := out.Write(added); err != nil {
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

// deleteVerb removes each named finding's file and prints the finding as it
// was. An unknown ID is logged and the rest are still deleted (exit 1).
func deleteVerb(e *env, args []string) int {
	flags, of := newFlags(e, "delete")
	pos, err := parseInterspersed(flags, args)
	if err != nil {
		return cli.ExitUsage
	}
	if len(pos) == 0 {
		return badUsage(e, "delete")
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

	code := cli.ExitOK
	for _, id := range pos {
		f, err := r.Delete(id)
		if err != nil {
			if errors.Is(err, report.ErrNoFinding) {
				e.log.Error(err.Error())
				code = max(code, cli.ExitProblems)
			} else {
				code = max(code, logEditError(e, err, 0))
			}
			continue
		}
		if err := out.Write(f); err != nil {
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
