package report

import (
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/astr4liteEx/rpt/internal/doc"
)

// A Rename carries findings from an old severity or custom section name
// to a new one when the config's list changes.
type Rename struct{ Old, New string }

// A ConfigChange is what a config write did: the findings it rewrote.
type ConfigChange struct{ Rewrote []*Doc }

// listKeys are the config keys that hold a list of names.
var listKeys = []string{"severities", "required_sections", "pages", "required_pages"}

// SetConfig sets one value of rpt.yaml: format, a list key (several
// values, each taken as text), sections.<fixed key> (that section's
// heading), rules.<rule> (error or warning), or x-<plugin>.<key> at any
// depth (YAML). Renames carry findings along a severity or custom section
// renamed in the list. A new heading is written into every finding. A
// severity in use that the new list drops is refused unless force.
func (m *Model) SetConfig(key string, values []string, renames []Rename, force bool) (ConfigChange, error) {
	if m.Config.Err != nil {
		return ConfigChange{}, refuse(ConfigFile, "%s doesn't parse; fix it first: %v", ConfigFile, m.Config.Err)
	}
	path := strings.Split(key, ".")
	if len(renames) > 0 && key != "severities" && key != "required_sections" {
		return ConfigChange{}, refuse(ConfigFile, "--rename goes with severities or required_sections")
	}
	switch {
	case key == "format":
		if len(values) != 1 || values[0] != "2" {
			return ConfigChange{}, refuse(ConfigFile, "format 2 is the only one rpt reads")
		}
		return ConfigChange{}, m.editConfig(func(s *doc.Doc) error {
			return s.Set(&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: "2"}, "format")
		})
	case slices.Contains(listKeys, key):
		return m.setList(key, values, renames, force)
	case path[0] == "sections" && len(path) == 2:
		if len(values) != 1 || strings.TrimSpace(values[0]) == "" {
			return ConfigChange{}, refuse(ConfigFile, "%s takes one heading", key)
		}
		return m.setHeading(path[1], strings.TrimSpace(values[0]))
	case path[0] == "rules" && len(path) == 2:
		if len(values) != 1 || values[0] != "error" && values[0] != "warning" {
			return ConfigChange{}, refuse(ConfigFile, "%s takes error or warning", key)
		}
		return ConfigChange{}, m.editConfig(func(s *doc.Doc) error { return s.Set(StringNode(values[0]), path...) })
	case IsPluginKey(path[0]) && !slices.Contains(path, ""):
		v, err := valuesNode(values)
		if err != nil {
			return ConfigChange{}, refuse(ConfigFile, "%v", err)
		}
		return ConfigChange{}, m.editConfig(func(s *doc.Doc) error { return s.Set(v, path...) })
	}
	return ConfigChange{}, refuse(ConfigFile, "%s is not a key rpt sets: format, severities, required_sections, sections.<key>, pages, required_pages, rules.<rule> or x-<plugin>.<key>", key)
}

// setList sets a list key, carrying findings along renames.
func (m *Model) setList(key string, values []string, renames []Rename, force bool) (ConfigChange, error) {
	if key == "pages" || key == "required_pages" {
		for i, v := range values {
			values[i] = CanonicalID(v)
		}
	}
	for _, r := range renames {
		if !slices.Contains(values, r.New) {
			return ConfigChange{}, refuse(ConfigFile, "--rename %s=%s: %s is not in the new list", r.Old, r.New, r.New)
		}
	}
	if key == "severities" {
		if err := m.checkSeverities(values, renames, force); err != nil {
			return ConfigChange{}, err
		}
	}
	if err := m.editConfig(func(s *doc.Doc) error { return s.Set(listNode(values), key) }); err != nil {
		return ConfigChange{}, err
	}
	var ch ConfigChange
	for _, d := range m.docs[FindingKind] {
		if d.Err != nil {
			continue
		}
		nd, err := m.carry(d, key, renames)
		if err != nil {
			return ConfigChange{}, err
		}
		if nd != d {
			ch.Rewrote = append(ch.Rewrote, nd)
		}
	}
	return ch, nil
}

// carry moves one finding along renames of severities or custom sections.
func (m *Model) carry(d *Doc, key string, renames []Rename) (*Doc, error) {
	for _, r := range renames {
		switch {
		case key == "severities" && d.Severity == r.Old:
			return m.edit(d, func(s *doc.Doc) error { return s.Set(keepStyle(s.Get("severity"), StringNode(r.New)), "severity") })
		case key == "required_sections":
			if i := sectionIndex(d, r.Old); i >= 0 {
				return m.edit(d, func(s *doc.Doc) error { return s.SetHeading(i, r.New) })
			}
		}
	}
	return d, nil
}

// sectionIndex is the index of a finding's section headed exactly h.
func sectionIndex(d *Doc, h string) int {
	return slices.IndexFunc(d.Sections, func(s Section) bool { return s.Heading == h })
}

// checkSeverities refuses a severities list that drops a level a finding
// uses, unless force.
func (m *Model) checkSeverities(list []string, renames []Rename, force bool) error {
	if force {
		return nil
	}
	for _, d := range m.docs[FindingKind] {
		if d.Err != nil || d.Severity == "" || slices.Contains(list, d.Severity) {
			continue
		}
		if slices.ContainsFunc(renames, func(r Rename) bool { return r.Old == d.Severity }) {
			continue
		}
		return refuse(ConfigFile, "%s uses %q, which the list drops: --rename %s=<new> carries it, --force leaves it", d.ID, d.Severity, d.Severity)
	}
	return nil
}

// headingsNow is the fixed sections' headings in effect.
func (m *Model) headingsNow() map[string]string {
	out := map[string]string{}
	for _, k := range FixedSections {
		out[k] = m.Config.Heading(k)
	}
	return out
}

// setHeading gives a fixed section a new heading, written into every
// finding that uses the old one.
func (m *Model) setHeading(key, heading string) (ConfigChange, error) {
	if !slices.Contains(FixedSections, key) {
		return ConfigChange{}, refuse(ConfigFile, "sections renames only %s", strings.Join(FixedSections, ", "))
	}
	for _, k := range FixedSections {
		if k != key && strings.EqualFold(m.Config.Heading(k), heading) {
			return ConfigChange{}, refuse(ConfigFile, "%q is already %s's heading", heading, k)
		}
	}
	return m.retitle(map[string]string{key: heading}, func(s *doc.Doc) error {
		return s.Set(StringNode(heading), "sections", key)
	})
}

// retitle changes the config through change, then writes the fixed
// sections' new headings into every finding using the old ones.
func (m *Model) retitle(want map[string]string, change func(*doc.Doc) error) (ConfigChange, error) {
	old := m.headingsNow()
	if err := m.editConfig(change); err != nil {
		return ConfigChange{}, err
	}
	var ch ConfigChange
	for _, d := range slices.Clone(m.docs[FindingKind]) {
		if d.Err != nil {
			continue
		}
		var idx []int
		var heads []string
		for k, h := range want {
			for i, s := range d.Sections {
				if strings.EqualFold(s.Heading, old[k]) {
					idx, heads = append(idx, i), append(heads, h)
				}
			}
		}
		if len(idx) == 0 {
			continue
		}
		nd, err := m.edit(d, func(s *doc.Doc) error {
			for j, i := range idx {
				if err := s.SetHeading(i, heads[j]); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return ConfigChange{}, err
		}
		ch.Rewrote = append(ch.Rewrote, nd)
	}
	return ch, nil
}

// UnsetConfig removes keys from rpt.yaml, all or none: a top-level key
// (severities, required_sections and sections go back to their defaults),
// sections.<key>, rules.<rule>, or x-<plugin>.<key> (the plugin's section
// goes when it empties). format can't be removed. Going back to the
// default severities while a finding uses another level is refused
// unless force.
func (m *Model) UnsetConfig(force bool, keys ...string) (ConfigChange, error) {
	if m.Config.Err != nil {
		return ConfigChange{}, refuse(ConfigFile, "%s doesn't parse; fix it first: %v", ConfigFile, m.Config.Err)
	}
	want := map[string]string{}
	for _, key := range keys {
		path := strings.Split(key, ".")
		switch {
		case key == "format":
			return ConfigChange{}, refuse(ConfigFile, "format can't be removed")
		case key == "severities":
			if err := m.checkSeverities(DefaultSeverities, nil, force); err != nil {
				return ConfigChange{}, err
			}
		case key == "sections":
			for _, k := range FixedSections {
				want[k] = defaultHeadings[k]
			}
		case path[0] == "sections" && len(path) == 2 && slices.Contains(FixedSections, path[1]):
			want[path[1]] = defaultHeadings[path[1]]
		}
	}
	return m.retitle(want, func(s *doc.Doc) error {
		for _, key := range keys {
			path := strings.Split(key, ".")
			if _, err := s.Unset(path...); err != nil {
				return err
			}
			for len(path) > 1 { // an emptied section goes
				path = path[:len(path)-1]
				if n := s.Get(path...); n == nil || n.Kind != yaml.MappingNode || len(n.Content) > 0 {
					break
				}
				if _, err := s.Unset(path...); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
