package report

import (
	"errors"
	"fmt"

	"go.yaml.in/yaml/v3"

	"github.com/astr4liteEx/rpt/sdk"
)

// Errors from editing a finding, all mistakes in the request.
var (
	ErrNoFinding    = errors.New("no such finding")
	ErrRefusedKey   = errors.New("key can't be set")
	ErrRefusedUnset = errors.New("key can't be unset")
	ErrBadValue     = errors.New("bad value")
)

// refusedKeys can't be set as top-level keys: sections are set one at a
// time as sections.<key>, and kind, path, rev and lines aren't stored in
// the file. Setting id renames the finding.
var refusedKeys = map[string]string{
	"kind":     "kind is not stored in the file",
	"path":     "path is where the file is",
	"rev":      "rev is the file's revision; rpt sets it on records",
	"sections": "set one section as sections.<key>",
	"lines":    "lines are where the file's parts sit",
}

// unsetRefused are the keys Unset refuses: a finding needs id, title and
// severity, and the rest aren't stored in the file.
var unsetRefused = []string{"id", "title", "severity", "kind", "path", "rev", "sections", "lines"}

// locate returns the path of the finding with the given ID.
func (r *Report) locate(id string) (string, error) {
	list, err := r.Findings()
	if err != nil && !onlyFileErrors(err) {
		return "", err
	}
	var found []string
	for _, f := range list {
		if f.ID == id {
			found = append(found, f.Path)
		}
	}
	switch len(found) {
	case 0:
		return "", fmt.Errorf("%w: %s in %s/", ErrNoFinding, id, FindingsDir)
	case 1:
		return found[0], nil
	default:
		return "", fmt.Errorf("%s is in more than one file: %v", id, found)
	}
}

// edit reads the finding file rel as this write sees it, refuses if the
// caller's --if-rev for id doesn't match, applies change, and puts the
// result in the write if any byte changed. The edited file must still
// parse, or the write is refused.
func (tx *Tx) edit(id, rel string, change func(*findingFile) error) (sdk.Finding, error) {
	src, exists, err := tx.read(rel)
	if err != nil {
		return sdk.Finding{}, err
	}
	if !exists {
		return sdk.Finding{}, fmt.Errorf("%w: %s in %s/", ErrNoFinding, id, FindingsDir)
	}
	if err := tx.checkRev(id, rel, Rev(src)); err != nil {
		return sdk.Finding{}, err
	}
	ff, err := splitFindingFile(src)
	if err != nil {
		return sdk.Finding{}, &FileError{Path: rel, Line: 1, Err: err}
	}
	if err := change(&ff); err != nil {
		return sdk.Finding{}, fmt.Errorf("%w: %s: %v", ErrBadValue, rel, err)
	}
	out := ff.bytes()
	f, err := parseFinding(rel, out, tx.headings())
	if err != nil {
		return sdk.Finding{}, fmt.Errorf("%w: the change would break %s: %v", ErrBadValue, rel, err)
	}
	if err := tx.put(rel, out, rankFinding); err != nil {
		return sdk.Finding{}, err
	}
	f.Lines = nil
	return f, nil
}

// checkValue type-checks a value for a declared finding field before it is
// written. Undeclared keys take any value.
func checkValue(key string, val *yaml.Node) error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s: %s", ErrBadValue, key, fmt.Sprintf(format, a...))
	}
	scalarText := func() (string, error) {
		if val.Kind != yaml.ScalarNode || val.Tag == "!!null" {
			return "", bad("must be a single value")
		}
		if val.Value == "" {
			return "", bad("must not be empty")
		}
		return val.Value, nil
	}
	switch key {
	case "title":
		_, err := scalarText()
		return err
	case "severity":
		_, err := scalarText() // whether it's one of the report's is validate's to say
		return err
	case "evidence":
		if val.Kind != yaml.SequenceNode {
			return bad("must be a list, like [evidence/F-001-login.png]")
		}
		for _, item := range val.Content {
			if item.Kind != yaml.ScalarNode || item.Value == "" {
				return bad("every item must be a single value")
			}
		}
	case "targets":
		var data any
		if val.Kind != yaml.SequenceNode || val.Decode(&data) != nil {
			return bad("must be a list, like [{scope: S-12}, {scope: S-20, host: 10.0.1.5, port: 443}]")
		}
		ts, err := decodeTargets(data)
		if err != nil {
			return bad("%v", err)
		}
		for i, t := range ts {
			if err := checkTarget(t); err != nil {
				return bad("item %d: %v", i, err)
			}
		}
	}
	return nil
}

// ParseTarget reads one target from the command line: a scope ID alone,
// such as S-12, or a YAML map, such as {scope: S-20, host: 10.0.1.5,
// port: 22, protocol: tcp}. It checks the target's own members.
func ParseTarget(s string) (sdk.Target, error) {
	n, err := parseValue(s)
	if err != nil {
		return sdk.Target{}, fmt.Errorf("%w: target %q: %v", ErrBadValue, s, err)
	}
	var t sdk.Target
	switch n.Kind {
	case yaml.ScalarNode:
		t.Scope = n.Value
	case yaml.MappingNode:
		var data any
		if err := n.Decode(&data); err != nil {
			return sdk.Target{}, fmt.Errorf("%w: target %q: %v", ErrBadValue, s, err)
		}
		ts, err := decodeTargets([]any{data})
		if err != nil {
			return sdk.Target{}, fmt.Errorf("%w: target %q: %v", ErrBadValue, s, err)
		}
		t = ts[0]
	default:
		return sdk.Target{}, fmt.Errorf("%w: target %q: want a scope ID or a map like {scope: S-12, port: 443}", ErrBadValue, s)
	}
	if err := checkTarget(t); err != nil {
		return sdk.Target{}, fmt.Errorf("%w: target %q: %v", ErrBadValue, s, err)
	}
	return t, nil
}

// checkTarget checks a stored target's own members: it names a scope row,
// and its port and protocol are valid. Whether it fits the row is
// rpt validate's targets rule.
func checkTarget(t sdk.Target) error {
	switch {
	case t.Scope == "" && t.Host != "":
		return fmt.Errorf("%s has no scope ID; run it through rpt scope match first, or add scope", t.Host)
	case t.Scope == "":
		return errors.New("scope is required: the ID of the scope row it falls in")
	case t.Port < 0 || t.Port > 65535:
		return fmt.Errorf("port %d is out of range", t.Port)
	case t.Protocol != "" && t.Protocol != "tcp" && t.Protocol != "udp":
		return fmt.Errorf("protocol %q is not tcp or udp", t.Protocol)
	}
	return nil
}
