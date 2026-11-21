package sdk

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os/exec"
)

// Result is what one rpt command printed and how it exited.
type Result struct {
	Records []Rec  // stdout, record by record
	Code    int    // the exit code: 0 ok, 1 problems, 2 usage
	Stderr  string // the text rpt wrote for people
}

// Problems are the problem records in the result's records.
func (r Result) Problems() []Problem {
	var out []Problem
	for _, rec := range r.Records {
		if rec.Kind != "problem" {
			continue
		}
		var p Problem
		if json.Unmarshal(rec.Raw, &p) == nil {
			out = append(out, p)
		}
	}
	return out
}

// Stale reports whether a write was refused because something changed
// since it was read (rule rev): read again and decide again. rpt never
// retries on its own.
func (r Result) Stale() bool {
	for _, p := range r.Problems() {
		if p.Rule == "rev" {
			return true
		}
	}
	return false
}

// Call runs Bin() with args, feeding it stdin (nil for none), and returns
// what it printed. A command that runs and exits non-zero is a Result
// with that Code, not an error: the error is for an rpt that couldn't be
// started, a canceled ctx, or output that isn't records.
//
//	res, err := sdk.Call(ctx, nil, "finding", "get", "F-001")
func Call(ctx context.Context, stdin io.Reader, args ...string) (Result, error) {
	cmd := exec.CommandContext(ctx, Bin(), args...)
	cmd.Stdin = stdin
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	res := Result{Stderr: errOut.String()}
	if ee, ok := errors.AsType[*exec.ExitError](err); ok && ctx.Err() == nil {
		res.Code = ee.ExitCode()
	} else if err != nil {
		return res, fmt.Errorf("rpt %v: %w", args, err)
	}
	for rec, err := range Records(&out) {
		if err != nil {
			return res, fmt.Errorf("rpt %v: %w", args, err)
		}
		res.Records = append(res.Records, rec)
	}
	return res, nil
}

// Settings reads the plugin's settings into v, which holds its defaults:
// the user's ~/.config/rpt/plugins/<plugin>/config.yaml with the report's
// x-<plugin> section of rpt.yaml laid over it, as rpt config get --merged
// gives them. Members neither sets keep their defaults; parse flags after,
// so they win. plugin is the command name, as in rpt <plugin>.
func Settings(plugin string, v any) error {
	return settings(context.Background(), plugin, v)
}

func settings(ctx context.Context, plugin string, v any) error {
	member := "x-" + plugin
	res, err := Call(ctx, nil, "config", "get", "--merged", "--json", member)
	if err != nil {
		return err
	}
	if res.Code != 0 {
		if ps := res.Problems(); len(ps) > 0 {
			return fmt.Errorf("settings: %s", ps[0].Message)
		}
		return fmt.Errorf("settings: rpt config get exited %d: %s", res.Code, bytes.TrimSpace([]byte(res.Stderr)))
	}
	for _, rec := range res.Records {
		if rec.Kind != "config" {
			continue
		}
		var m map[string]jsontext.Value
		if err := json.Unmarshal(rec.Raw, &m); err != nil {
			return fmt.Errorf("settings: %w", err)
		}
		raw, ok := m[member]
		if !ok {
			return nil // nothing set: the defaults stand
		}
		if err := json.Unmarshal(raw, v); err != nil {
			return fmt.Errorf("settings: %s: %w", member, err)
		}
		return nil
	}
	return nil
}

// Emit writes v as one record: one deterministic JSON line. v is usually
// one of this package's record types, with Kind set.
func Emit(w io.Writer, v any) error {
	b, err := json.Marshal(v, json.Deterministic(true))
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}
