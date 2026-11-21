package report

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/astr4liteEx/rpt/sdk"
)

// ErrInUse refuses a config change that drops something findings still
// use: a mistake in the request.
var ErrInUse = errors.New("still in use")

// ConfigID is the name --if-rev gives the config: rpt config takes no ID.
const ConfigID = "config"

// configKeys are the top-level keys rpt.yaml may hold besides x-<plugin>
// sections.
var configKeys = []string{"format", "severities", "required_sections", "sections", "rules", "pages", "required_pages"}

// isPluginKey reports whether a config key or frontmatter key is a
// plugin's: x-<plugin>.
func isPluginKey(k string) bool { return strings.HasPrefix(k, "x-") && len(k) > 2 }

// ConfigRecord returns the config as a "config" record: as in effect, with
// rpt.yaml's rev, its plugin sections, and with lines, where each key sits.
func (r *Report) ConfigRecord(withLines bool) (sdk.Config, error) {
	src, err := r.configBytes()
	if err != nil {
		return sdk.Config{}, fmt.Errorf("read report config: %w", err)
	}
	cfg, err := r.Config()
	if err != nil {
		return sdk.Config{}, err
	}
	rec := sdk.Config{
		Kind:             "config",
		Format:           cfg.Format,
		Severities:       cfg.Severities,
		Sections:         maps.Clone(map[string]string(cfg.Headings)),
		RequiredSections: cfg.RequiredSections,
		Rules:            cfg.Rules,
		Pages:            cfg.Pages,
		RequiredPages:    cfg.RequiredPages,
		Rev:              Rev(src),
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(normaliseNewlines(src), &doc); err != nil {
		return sdk.Config{}, yamlFileError(ConfigFile, 0, err)
	}
	if len(doc.Content) > 0 && doc.Content[0].Kind == yaml.MappingNode {
		m := doc.Content[0].Content
		for i := 0; i+1 < len(m); i += 2 {
			if !isPluginKey(m[i].Value) {
				continue
			}
			var v any
			if err := m[i+1].Decode(&v); err != nil {
				return sdk.Config{}, &FileError{Path: ConfigFile, Line: m[i].Line, Err: err}
			}
			b, err := json.Marshal(v, json.Deterministic(true))
			if err != nil {
				return sdk.Config{}, &FileError{Path: ConfigFile, Line: m[i].Line, Err: err}
			}
			if rec.Extra == nil {
				rec.Extra = map[string]jsontext.Value{}
			}
			rec.Extra[m[i].Value] = b
		}
		if withLines {
			rec.Lines = &sdk.ConfigLines{File: filepath.Join(r.abs, ConfigFile), Keys: map[string]sdk.Position{}}
			for i := 0; i+1 < len(m); i += 2 {
				rec.Lines.Keys[m[i].Value] = sdk.Position{Line: m[i].Line, Column: m[i].Column}
			}
		}
	}
	return rec, nil
}

// headings is the section headings this write sees: the config's, or
// those a config change in this write sets.
func (tx *Tx) headings() Headings {
	if tx.h != nil {
		return tx.h
	}
	return tx.r.headings()
}

// configFile reads rpt.yaml for editing, checking the config's rev. It
// returns the YAML as a findingFile with no body.
func (tx *Tx) configFile() (findingFile, error) {
	src, exists, err := tx.read(ConfigFile)
	if err != nil {
		return findingFile{}, err
	}
	if !exists {
		return findingFile{}, fmt.Errorf("read report config: %s is missing", ConfigFile)
	}
	if err := tx.checkRev(ConfigID, ConfigFile, Rev(src)); err != nil {
		return findingFile{}, err
	}
	n := normaliseNewlines(src)
	if len(n) > 0 && !bytes.HasSuffix(n, []byte("\n")) {
		n = append(n, '\n')
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(n, &doc); err != nil {
		return findingFile{}, yamlFileError(ConfigFile, 0, err)
	}
	if len(doc.Content) > 0 && doc.Content[0].Kind != yaml.MappingNode {
		return findingFile{}, &FileError{Path: ConfigFile, Line: 1, Err: errors.New("rpt.yaml is not a mapping")}
	}
	return findingFile{crlf: bytes.Contains(src, []byte("\r\n")), head: n}, nil
}

// putConfig writes ff back as rpt.yaml, after checking it still reads.
func (tx *Tx) putConfig(ff findingFile) error {
	out := ff.head
	if ff.crlf {
		out = bytes.ReplaceAll(out, []byte("\n"), []byte("\r\n"))
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(ff.head, &doc); err != nil {
		return fmt.Errorf("%w: the change would break %s: %v", ErrBadValue, ConfigFile, err)
	}
	return tx.put(ConfigFile, out, rankConfig)
}

// ConfigChange is what one config write did: the config as now stored,
// and the findings it rewrote.
type ConfigChange struct {
	Config   sdk.Config
	Findings []sdk.Finding
}

// A Rename is one --rename old=new: a severity level or a custom required
// section that keeps its findings under a new name.
type Rename struct{ Old, New string }

// RenameError is a --rename pair that doesn't fit the lists: a usage
// mistake, so nothing is written.
type RenameError struct{ Msg string }

func (e *RenameError) Error() string { return e.Msg }

// SetConfig sets one value of rpt.yaml: a top-level key, sections.<key> (a
// fixed section's heading) or x-<plugin>.<key>. Several values make a
// list. renames apply to severities and required_sections. A fixed
// section's new heading is written into every finding using the old one.
// A severity still in use that the new list drops is refused unless force.
func (tx *Tx) SetConfig(p string, values []string, renames []Rename, force bool) (ConfigChange, error) {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s: %s", ErrBadValue, p, fmt.Sprintf(format, a...))
	}
	if len(values) == 0 {
		return ConfigChange{}, bad("give a value")
	}
	if len(renames) > 0 && p != "severities" && p != "required_sections" {
		return ConfigChange{}, &RenameError{"--rename works on severities and required_sections only"}
	}
	val, err := configValue(p, values)
	if err != nil {
		return ConfigChange{}, bad("%v", err)
	}
	cfg, err := tx.r.Config()
	if err != nil {
		return ConfigChange{}, err
	}
	ff, err := tx.configFile()
	if err != nil {
		return ConfigChange{}, err
	}
	var ch ConfigChange
	switch key, nested := strings.CutPrefix(p, "sections."); {
	case nested:
		if !slices.Contains(FixedSections, key) {
			return ConfigChange{}, bad("%q is not a fixed section; use one of %s", key, strings.Join(FixedSections, ", "))
		}
		if err := ff.setNested("sections", key, val); err != nil {
			return ConfigChange{}, bad("%v", err)
		}
		next := maps.Clone(cfg.Headings)
		next[key] = strings.TrimSpace(val.Value)
		if ch.Findings, err = tx.reheading(cfg.Headings, next); err != nil {
			return ConfigChange{}, err
		}
	case isPluginKey(p) && strings.Contains(p, "."):
		plugin, k, _ := strings.Cut(p, ".")
		if err := ff.setNested(plugin, k, val); err != nil {
			return ConfigChange{}, bad("%v", err)
		}
	default:
		if err := ff.setEntry(p, val); err != nil {
			return ConfigChange{}, bad("%v", err)
		}
		switch p {
		case "sections":
			var secs map[string]string
			_ = val.Decode(&secs) // configValue checked it
			if ch.Findings, err = tx.reheading(cfg.Headings, newHeadings(secs)); err != nil {
				return ConfigChange{}, err
			}
		case "severities":
			var levels []sdk.Severity
			_ = val.Decode(&levels)
			if ch.Findings, err = tx.renameSeverities(cfg.Severities, levels, renames, force); err != nil {
				return ConfigChange{}, err
			}
		case "required_sections":
			var secs []string
			_ = val.Decode(&secs)
			if ch.Findings, err = tx.renameSections(cfg, secs, renames); err != nil {
				return ConfigChange{}, err
			}
		}
	}
	if err := tx.putConfig(ff); err != nil {
		return ConfigChange{}, err
	}
	ch.Config, err = tx.configRecord()
	return ch, err
}

// UnsetConfig removes keys from rpt.yaml: top-level keys (severities,
// required_sections and sections go back to the defaults), sections.<key>
// and x-<plugin>.<key>. format can't be removed. Going back to the default
// severities when a finding uses a level they lack is refused unless force.
func (tx *Tx) UnsetConfig(force bool, paths ...string) (ConfigChange, error) {
	for _, p := range paths {
		if p == "format" {
			return ConfigChange{}, fmt.Errorf("%w: format: every report needs it", ErrRefusedUnset)
		}
	}
	cfg, err := tx.r.Config()
	if err != nil {
		return ConfigChange{}, err
	}
	ff, err := tx.configFile()
	if err != nil {
		return ConfigChange{}, err
	}
	sections := maps.Clone(cfg.Sections)
	for _, p := range paths {
		var err error
		if key, ok := strings.CutPrefix(p, "sections."); ok {
			err = ff.unsetNested("sections", key)
			delete(sections, key)
		} else if plugin, k, ok := strings.Cut(p, "."); ok && isPluginKey(plugin) {
			err = ff.unsetNested(plugin, k)
		} else {
			err = ff.removeEntry(p)
			if p == "sections" {
				sections = nil
			}
		}
		if err != nil {
			return ConfigChange{}, fmt.Errorf("%w: %s: %v", ErrBadValue, p, err)
		}
	}
	var ch ConfigChange
	if ch.Findings, err = tx.reheading(cfg.Headings, newHeadings(sections)); err != nil {
		return ConfigChange{}, err
	}
	if slices.Contains(paths, "severities") {
		if _, err := tx.renameSeverities(cfg.Severities, DefaultSeverities, nil, force); err != nil {
			return ConfigChange{}, err
		}
	}
	if err := tx.putConfig(ff); err != nil {
		return ConfigChange{}, err
	}
	ch.Config, err = tx.configRecord()
	return ch, err
}

// configRecord is the config as this write leaves it.
func (tx *Tx) configRecord() (sdk.Config, error) {
	src, _, err := tx.read(ConfigFile)
	if err != nil {
		return sdk.Config{}, err
	}
	shadow := &Report{root: tx.r.root, abs: tx.r.abs, configSrc: src}
	return shadow.ConfigRecord(false)
}

// configValue makes the YAML value values give config path p, checking
// its form.
func configValue(p string, values []string) (*yaml.Node, error) {
	list := slices.Contains([]string{"severities", "required_sections", "pages", "required_pages"}, p)
	var val *yaml.Node
	var err error
	if len(values) == 1 && (!list || strings.HasPrefix(strings.TrimSpace(values[0]), "[")) {
		val, err = parseValue(values[0])
	} else {
		val = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for _, v := range values {
			val.Content = append(val.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v})
		}
	}
	if err != nil {
		return nil, err
	}
	scalar := func(n *yaml.Node) bool {
		return n.Kind == yaml.ScalarNode && n.Tag != "!!null" && strings.TrimSpace(n.Value) != ""
	}
	switch {
	case p == "format":
		if _, err := strconv.Atoi(val.Value); val.Kind != yaml.ScalarNode || err != nil {
			return nil, errors.New("must be a whole number")
		}
	case list:
		if val.Kind != yaml.SequenceNode {
			return nil, errors.New("must be a list, like [critical, high, medium, low, info]")
		}
		seen := map[string]bool{}
		for _, it := range val.Content {
			if !scalar(it) {
				return nil, errors.New("every item must be a name")
			}
			if seen[it.Value] {
				return nil, fmt.Errorf("%q is listed twice", it.Value)
			}
			seen[it.Value] = true
		}
	case p == "sections":
		if val.Kind != yaml.MappingNode {
			return nil, errors.New("must be a map, like {poc: PoC}")
		}
		for i := 0; i+1 < len(val.Content); i += 2 {
			if !slices.Contains(FixedSections, val.Content[i].Value) {
				return nil, fmt.Errorf("%q is not a fixed section; use one of %s", val.Content[i].Value, strings.Join(FixedSections, ", "))
			}
			if !scalar(val.Content[i+1]) {
				return nil, fmt.Errorf("%s: the heading must be text", val.Content[i].Value)
			}
		}
	case strings.HasPrefix(p, "sections."):
		if !scalar(val) {
			return nil, errors.New("the heading must be text")
		}
	case p == "rules":
		if val.Kind != yaml.MappingNode {
			return nil, errors.New("must be a map, like {targets: warning}")
		}
		for i := 0; i+1 < len(val.Content); i += 2 {
			if lv := val.Content[i+1].Value; lv != string(sdk.Error) && lv != string(sdk.Warning) {
				return nil, fmt.Errorf("%s: level %q is not error or warning", val.Content[i].Value, lv)
			}
		}
	case isPluginKey(strings.SplitN(p, ".", 2)[0]):
	case slices.Contains([]string{"kind", "rev", "lines"}, p):
		return nil, fmt.Errorf("%s is not stored in rpt.yaml", p)
	default:
		return nil, fmt.Errorf("rpt.yaml has no %s key; a plugin's settings go under x-<plugin>", p)
	}
	return val, nil
}

// renameSeverities checks a new severities list against the old one and
// the renames, and rewrites each finding using a renamed level.
func (tx *Tx) renameSeverities(old, next []sdk.Severity, renames []Rename, force bool) ([]sdk.Finding, error) {
	to := map[sdk.Severity]sdk.Severity{}
	for _, rn := range renames {
		o, n := sdk.Severity(rn.Old), sdk.Severity(rn.New)
		switch {
		case !slices.Contains(old, o):
			return nil, &RenameError{fmt.Sprintf("--rename %s=%s: %s is not one of the current severities %v", o, n, o, old)}
		case !slices.Contains(next, n):
			return nil, &RenameError{fmt.Sprintf("--rename %s=%s: %s is not in the new list", o, n, n)}
		case slices.Contains(next, o):
			return nil, &RenameError{fmt.Sprintf("--rename %s=%s: %s is still in the new list", o, n, o)}
		}
		to[o] = n
	}
	cites, err := tx.citations()
	if err != nil {
		return nil, err
	}
	var out []sdk.Finding
	var unused []string
	for _, c := range cites {
		n, renamed := to[c.f.Severity]
		switch {
		case renamed:
			val := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: string(n)}
			f, err := tx.edit(c.f.ID, c.rel, func(ff *findingFile) error { return ff.setEntry("severity", val) })
			if err != nil {
				return nil, err
			}
			out = append(out, f)
		case slices.Contains(old, c.f.Severity) && !slices.Contains(next, c.f.Severity):
			unused = append(unused, fmt.Sprintf("%s (%s)", c.f.ID, c.f.Severity))
		}
	}
	if len(unused) > 0 && !force {
		return nil, fmt.Errorf("%w: the new list drops levels used by %s; rename them with --rename old=new, or pass --force", ErrInUse, strings.Join(unused, ", "))
	}
	return out, nil
}

// renameSections checks a new required_sections list against the renames
// and rewrites each renamed custom section's heading in every finding. A
// rename onto a section a finding already has is refused, naming them.
func (tx *Tx) renameSections(cfg Config, next []string, renames []Rename) ([]sdk.Finding, error) {
	h := tx.headings()
	for _, rn := range renames {
		switch {
		case !slices.Contains(cfg.RequiredSections, rn.Old):
			return nil, &RenameError{fmt.Sprintf("--rename %s=%s: %s is not one of the current required sections", rn.Old, rn.New, rn.Old)}
		case !slices.Contains(next, rn.New):
			return nil, &RenameError{fmt.Sprintf("--rename %s=%s: %s is not in the new list", rn.Old, rn.New, rn.New)}
		case slices.Contains(next, rn.Old):
			return nil, &RenameError{fmt.Sprintf("--rename %s=%s: %s is still in the new list", rn.Old, rn.New, rn.Old)}
		case slices.Contains(FixedSections, h.key(rn.Old)) || slices.Contains(FixedSections, h.key(rn.New)):
			return nil, &RenameError{fmt.Sprintf("--rename %s=%s: a fixed section's heading is set with rpt config set sections.<key>", rn.Old, rn.New)}
		}
	}
	var out []sdk.Finding
	for _, rn := range renames {
		fs, err := tx.renameHeading(h, rn.Old, rn.New)
		if err != nil {
			return nil, err
		}
		out = append(out, fs...)
	}
	return out, nil
}

// reheading writes each fixed section's new heading into every finding
// that uses its old one.
func (tx *Tx) reheading(old, next Headings) ([]sdk.Finding, error) {
	tx.h = next // findings this write rewrites are read with the new headings
	var out []sdk.Finding
	for _, k := range FixedSections {
		if old[k] == next[k] {
			continue
		}
		fs, err := tx.renameHeading(old, k, next[k])
		if err != nil {
			return nil, err
		}
		out = append(out, fs...)
	}
	return out, nil
}

// renameHeading rewrites the ## heading of the section key (read with
// headings h) to heading to in every finding that has it. A finding that
// already has another section under to is refused.
func (tx *Tx) renameHeading(h Headings, key, to string) ([]sdk.Finding, error) {
	cites, err := tx.citations()
	if err != nil {
		return nil, err
	}
	var out []sdk.Finding
	var both []string
	for _, c := range cites {
		src, _, err := tx.read(c.rel)
		if err != nil {
			return nil, err
		}
		ff, err := splitFindingFile(src)
		if err != nil {
			continue
		}
		spans := sectionSpans(ff.body, h)
		if !slices.ContainsFunc(spans, func(sp span) bool { return sp.key == key }) {
			continue
		}
		if slices.ContainsFunc(spans, func(sp span) bool { return sp.key != key && strings.EqualFold(h.heading(sp.key), to) }) {
			both = append(both, c.f.ID)
			continue
		}
		f, err := tx.edit(c.f.ID, c.rel, func(ff *findingFile) error {
			var b []byte
			last := 0
			for _, sp := range sectionSpans(ff.body, h) {
				if sp.key != key {
					continue
				}
				b = append(b, ff.body[last:sp.lineStart]...)
				b = append(b, "## "+to+"\n"...)
				last = sp.bodyAt
			}
			ff.body = append(b, ff.body[last:]...)
			return nil
		})
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if len(both) > 0 {
		return nil, fmt.Errorf("%w: %s already have a %q section; merge it by hand first", ErrInUse, strings.Join(both, ", "), to)
	}
	return out, nil
}
