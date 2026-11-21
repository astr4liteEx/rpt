package report

import (
	"bytes"
	"fmt"
	"path"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/astr4liteEx/rpt/sdk"
)

// A finding path names what finding set and unset change: a top-level
// frontmatter key, sections.<key> for a section's text, or
// x-<plugin>.<key> for one key of a plugin's map. Every other path is a
// top-level key, dots and all.
const sectionsPrefix = "sections."

// pluginPath splits x-<plugin>.<key> into its plugin map and key.
func pluginPath(p string) (plugin, key string, ok bool) {
	if !strings.HasPrefix(p, "x-") {
		return "", "", false
	}
	plugin, key, ok = strings.Cut(p, ".")
	return plugin, key, ok && key != ""
}

// listKeys are the finding keys that hold lists: each value given is one
// item, unless a single value is a whole YAML list.
var listKeys = map[string]bool{"targets": true, "evidence": true}

// Set changes one value of the finding with the given ID, and returns the
// finding as now stored. path is a top-level key, sections.<key> or
// x-<plugin>.<key>. Each value is YAML; several values make a list, and a
// list key (targets, evidence) takes its items one value each. Nothing
// else in the file changes. Setting id renames the finding, and its file
// when the file is named for its ID.
func (r *Report) Set(id, path string, values ...string) (sdk.Finding, error) {
	return one(r, func(tx *Tx) (sdk.Finding, error) { return tx.Set(id, path, values...) })
}

// Set is Report.Set as part of the write tx.
func (tx *Tx) Set(id, p string, values ...string) (sdk.Finding, error) {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s: %s", ErrBadValue, p, fmt.Sprintf(format, a...))
	}
	if len(values) == 0 {
		return sdk.Finding{}, bad("give a value")
	}
	if key, ok := strings.CutPrefix(p, sectionsPrefix); ok {
		if len(values) != 1 {
			return sdk.Finding{}, bad("a section takes one value: its text")
		}
		return tx.SetSection(id, key, values[0])
	}
	if p == "id" {
		if len(values) != 1 {
			return sdk.Finding{}, bad("give one ID")
		}
		return tx.rename(id, values[0])
	}
	val, err := valueNode(p, values)
	if err != nil {
		return sdk.Finding{}, bad("%v", err)
	}
	rel, err := tx.r.locate(id)
	if err != nil {
		return sdk.Finding{}, err
	}
	if plugin, key, ok := pluginPath(p); ok {
		return tx.edit(id, rel, func(ff *findingFile) error { return ff.setNested(plugin, key, val) })
	}
	if why, ok := refusedKeys[p]; ok {
		return sdk.Finding{}, fmt.Errorf("%w: %s: %s", ErrRefusedKey, p, why)
	}
	if now, ok := formerKeys[p]; ok {
		return sdk.Finding{}, fmt.Errorf("%w: %s: it is from report format 1; set %s", ErrRefusedKey, p, now)
	}
	if err := checkValue(p, val); err != nil {
		return sdk.Finding{}, err
	}
	return tx.edit(id, rel, func(ff *findingFile) error { return ff.setEntry(p, val) })
}

// valueNode makes the YAML value values give path p.
func valueNode(p string, values []string) (*yaml.Node, error) {
	whole := len(values) == 1 && (!listKeys[p] || strings.HasPrefix(strings.TrimSpace(values[0]), "["))
	if whole {
		return parseValue(values[0])
	}
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, v := range values {
		var item *yaml.Node
		var err error
		switch p {
		case "targets":
			var t sdk.Target
			if t, err = ParseTarget(v); err == nil {
				item, err = toNode(t)
			}
		case "evidence":
			item = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v}
		default:
			item, err = parseValue(v)
		}
		if err != nil {
			return nil, err
		}
		seq.Content = append(seq.Content, item)
	}
	return seq, nil
}

// rename gives the finding id the ID to, and renames its file when the
// file is named for its ID (F-001-login.md becomes F-010-login.md).
func (tx *Tx) rename(id, to string) (sdk.Finding, error) {
	to = CanonicalID(to)
	if !ValidID(to) {
		return sdk.Finding{}, fmt.Errorf("%w: id: %q is not F- and at least three digits", ErrBadValue, to)
	}
	rel, err := tx.r.locate(id)
	if err != nil {
		return sdk.Finding{}, err
	}
	if to == id {
		return tx.edit(id, rel, func(*findingFile) error { return nil })
	}
	if _, err := tx.r.locate(to); err == nil || tx.newIDs[to] {
		return sdk.Finding{}, fmt.Errorf("%w: id: %s is already taken", ErrBadValue, to)
	}
	val := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: to}
	f, err := tx.edit(id, rel, func(ff *findingFile) error { return ff.setEntry("id", val) })
	if err != nil {
		return sdk.Finding{}, err
	}
	tx.newIDs[to] = true
	base := path.Base(rel)
	if base != id+".md" && !strings.HasPrefix(base, id+"-") {
		return f, nil
	}
	newRel := path.Join(path.Dir(rel), to+base[len(id):])
	if _, exists, err := tx.read(newRel); err != nil {
		return sdk.Finding{}, err
	} else if exists {
		return sdk.Finding{}, fmt.Errorf("%w: id: %s already exists", ErrBadValue, newRel)
	}
	data, _, err := tx.read(rel)
	if err != nil {
		return sdk.Finding{}, err
	}
	if err := tx.put(newRel, data, rankFinding); err != nil {
		return sdk.Finding{}, err
	}
	if err := tx.del(rel, rankFinding); err != nil {
		return sdk.Finding{}, err
	}
	f.Path = newRel
	return f, nil
}

// CanonicalID writes a finding ID the way it is stored: f-001 is F-001.
func CanonicalID(id string) string {
	if len(id) > 2 && (id[:2] == "f-") {
		return "F-" + id[2:]
	}
	return id
}

// Unset removes values from the finding with the given ID: top-level
// keys, sections (sections.<key>, heading and text) and plugin keys
// (x-<plugin>.<key>; the plugin's map goes when it empties). A path the
// finding doesn't have is no change. A refused key stops every change.
func (r *Report) Unset(id string, paths ...string) (sdk.Finding, error) {
	return one(r, func(tx *Tx) (sdk.Finding, error) { return tx.Unset(id, paths...) })
}

// Unset is Report.Unset as part of the write tx.
func (tx *Tx) Unset(id string, paths ...string) (sdk.Finding, error) {
	for _, p := range paths {
		if _, ok := strings.CutPrefix(p, sectionsPrefix); ok {
			continue
		}
		if _, _, ok := pluginPath(p); ok {
			continue
		}
		for _, k := range unsetRefused {
			if p == k {
				return sdk.Finding{}, fmt.Errorf("%w: %s: a finding needs it, or rpt sets it", ErrRefusedUnset, p)
			}
		}
	}
	rel, err := tx.r.locate(id)
	if err != nil {
		return sdk.Finding{}, err
	}
	h := tx.r.headings()
	return tx.edit(id, rel, func(ff *findingFile) error {
		for _, p := range paths {
			var err error
			if key, ok := strings.CutPrefix(p, sectionsPrefix); ok {
				err = ff.removeSection(h, h.key(strings.TrimSpace(key)))
			} else if plugin, key, ok := pluginPath(p); ok {
				err = ff.unsetNested(plugin, key)
			} else {
				err = ff.removeEntry(p)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// setNested sets key in the top-level map plugin, making the map if it
// isn't there.
func (f *findingFile) setNested(plugin, key string, val *yaml.Node) error {
	m, err := f.topMap(plugin)
	if err != nil {
		return err
	}
	if m == nil {
		m = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1] = val
			return f.setEntry(plugin, m)
		}
	}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, val)
	return f.setEntry(plugin, m)
}

// unsetNested removes key from the top-level map plugin, and the map when
// it is left empty.
func (f *findingFile) unsetNested(plugin, key string) error {
	m, err := f.topMap(plugin)
	if err != nil || m == nil {
		return err
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			if len(m.Content) == 0 {
				return f.removeEntry(plugin)
			}
			return f.setEntry(plugin, m)
		}
	}
	return nil
}

// topMap returns a copy of the top-level key's value if it is a map, nil
// if the key isn't there, and an error for any other value.
func (f *findingFile) topMap(key string) (*yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(f.head, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, nil
	}
	m := doc.Content[0].Content
	for i := 0; i+1 < len(m); i += 2 {
		if m[i].Value != key {
			continue
		}
		if m[i+1].Kind != yaml.MappingNode {
			return nil, fmt.Errorf("%s is not a map", key)
		}
		return clean(m[i+1]), nil
	}
	return nil, nil
}

// removeSection deletes a section, heading and text, from the body. A
// section the finding doesn't have is no change.
func (f *findingFile) removeSection(h Headings, key string) error {
	var at []span
	for _, sp := range sectionSpans(f.body, h) {
		if sp.key == key {
			at = append(at, sp)
		}
	}
	switch len(at) {
	case 0:
		return nil
	case 1:
	default:
		return fmt.Errorf("the %q section is in the file twice; merge them by hand first", h.heading(key))
	}
	sp := at[0]
	body := append(append([]byte{}, f.body[:sp.lineStart]...), f.body[sp.end:]...)
	for bytes.HasSuffix(body, []byte("\n\n")) {
		body = body[:len(body)-1]
	}
	f.body = body
	return nil
}
