package report

import (
	"errors"
	"fmt"
	"slices"

	"go.yaml.in/yaml/v3"

	"github.com/astr4liteEx/rpt/sdk"
)

// Errors from editing a finding, all mistakes in the request.
var (
	ErrNoFinding  = errors.New("no such finding")
	ErrRefusedKey = errors.New("key can't be set")
	ErrBadValue   = errors.New("bad value")
)

// refusedKeys can't be set: IDs are permanent, sections are edited by hand,
// and kind and path aren't stored in the file.
var refusedKeys = map[string]string{
	"id":       "finding IDs are permanent",
	"kind":     "kind is not stored in the file",
	"path":     "path is where the file is",
	"sections": "edit section text in the file",
}

// Set changes one top-level frontmatter key of the finding with the given
// ID, and returns the finding as now stored. value
// is YAML. Nothing else in the file changes.
func (r *Report) Set(id, key, value string) (sdk.Finding, error) {
	if why, ok := refusedKeys[key]; ok {
		return sdk.Finding{}, fmt.Errorf("%w: %s: %s", ErrRefusedKey, key, why)
	}
	val, err := parseValue(value)
	if err != nil {
		return sdk.Finding{}, fmt.Errorf("%w: %s: %v", ErrBadValue, key, err)
	}
	cfg, err := r.Config()
	if err != nil {
		return sdk.Finding{}, err
	}
	if err := checkValue(key, val, cfg.Severities); err != nil {
		return sdk.Finding{}, err
	}
	rel, err := r.locate(id)
	if err != nil {
		return sdk.Finding{}, err
	}
	return r.edit(rel, func(ff *findingFile) error { return ff.setEntry(key, val) })
}

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

// edit reads the finding file rel, applies change, and writes the result
// atomically if any byte changed. The edited file must still parse, or
// nothing is written.
func (r *Report) edit(rel string, change func(*findingFile) error) (sdk.Finding, error) {
	src, err := r.root.ReadFile(rel)
	if err != nil {
		return sdk.Finding{}, &FileError{Path: rel, Err: err}
	}
	ff, err := splitFindingFile(src)
	if err != nil {
		return sdk.Finding{}, &FileError{Path: rel, Line: 1, Err: err}
	}
	if err := change(&ff); err != nil {
		return sdk.Finding{}, &FileError{Path: rel, Err: err}
	}
	out := ff.bytes()
	f, err := parseFinding(rel, out, r.headings())
	if err != nil {
		return sdk.Finding{}, fmt.Errorf("edit would break %s: %w", rel, err)
	}
	if string(out) != string(src) {
		if err := writeAtomic(r.root, rel, out); err != nil {
			return sdk.Finding{}, err
		}
	}
	return f, nil
}

// checkValue type-checks a value for a declared finding field before it is
// written. Undeclared keys take any value.
func checkValue(key string, val *yaml.Node, severities []sdk.Severity) error {
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
		s, err := scalarText()
		if err != nil {
			return err
		}
		if !slices.Contains(severities, sdk.Severity(s)) {
			return bad("%q is not one of %v", s, severities)
		}
	case "scope", "evidence":
		if val.Kind != yaml.SequenceNode {
			return bad("must be a list, like [S-12, S-14]")
		}
		for _, item := range val.Content {
			if item.Kind != yaml.ScalarNode || item.Value == "" {
				return bad("every item must be a single value")
			}
		}
	case "target":
		var data any
		if val.Kind != yaml.MappingNode || val.Decode(&data) != nil {
			return bad("must be a map, like {host: 10.0.0.5, port: 443, protocol: tcp}")
		}
		t, err := decodeTarget(data)
		if err != nil {
			return bad("%v", err)
		}
		if err := checkTarget(*t); err != nil {
			return bad("%v", err)
		}
	}
	return nil
}

// checkTarget checks a target's declared members.
func checkTarget(t sdk.Target) error {
	switch {
	case t.Host == "":
		return errors.New("host is required")
	case t.Port < 0 || t.Port > 65535:
		return fmt.Errorf("port %d is out of range", t.Port)
	case t.Protocol != "" && t.Protocol != "tcp" && t.Protocol != "udp":
		return fmt.Errorf("protocol %q is not tcp or udp", t.Protocol)
	}
	return nil
}
