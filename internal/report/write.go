package report

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/astr4liteEx/rpt/internal/doc"
)

// A Refusal is a write rpt won't make: a mistake in the request, or a
// change that would break the report. Nothing is changed.
type Refusal struct {
	Path string // the file it concerns, when there is one
	Msg  string
}

func (e *Refusal) Error() string { return e.Msg }

func refuse(rel, format string, a ...any) error {
	return &Refusal{Path: rel, Msg: fmt.Sprintf(format, a...)}
}

// RevOf is the rev of the file at rel as this command first read it, for
// --if-rev. Checking against the first read means a command that edits a
// file twice still matches the rev the caller saw.
func (m *Model) RevOf(rel string) string {
	if f, ok := m.files[rel]; ok && f.existed {
		return Rev(f.old)
	}
	return ""
}

// edit changes the document d's file through change. The result must
// parse, or nothing changes. It returns the document as changed.
func (m *Model) edit(d *Doc, change func(*doc.Doc) error) (*Doc, error) {
	if d.Err != nil {
		return nil, refuse(d.Path, "%s doesn't parse; fix it first: %v", d.Path, d.Err)
	}
	src, _, err := m.read(d.Path)
	if err != nil {
		return nil, err
	}
	s, err := doc.Parse(src)
	if err != nil {
		return nil, refuse(d.Path, "%s: %v", d.Path, err)
	}
	if err := change(s); err != nil {
		var r *Refusal
		if errors.As(err, &r) {
			return nil, err
		}
		return nil, refuse(d.Path, "%s: %v", d.Path, err)
	}
	out := s.Bytes()
	nd := parseDoc(d.Kind, d.Path, out, m.Config)
	if nd.Err != nil {
		return nil, refuse(d.Path, "the change would leave %s unreadable: %v", d.Path, nd.Err)
	}
	if err := m.put(d.Path, out); err != nil {
		return nil, err
	}
	m.swap(d, nd)
	return nd, nil
}

// swap replaces the document old with nd in the model; a nil nd removes
// it, a nil old adds nd.
func (m *Model) swap(old, nd *Doc) {
	k := cmpKind(old, nd)
	list := m.docs[k]
	if i := slices.Index(list, old); old != nil && i >= 0 {
		list = slices.Delete(list, i, i+1)
	}
	if nd != nil {
		i, _ := slices.BinarySearchFunc(list, nd.Path, func(d *Doc, p string) int { return strings.Compare(d.Path, p) })
		list = slices.Insert(list, i, nd)
	}
	m.docs[k] = list
}

func cmpKind(a, b *Doc) *Kind {
	if a != nil {
		return a.Kind
	}
	return b.Kind
}

// A Draft is a document to write: what a new finding or page holds.
type Draft struct {
	ID, Title string
	Evidence  []string
	Extra     []KeyValue // other frontmatter keys, in order

	// Findings only.
	Severity string
	Targets  []Target
	Sections []Section // Key and Text; order doesn't matter

	// Pages only.
	Body string
}

// A KeyValue is one frontmatter key and its value.
type KeyValue struct {
	Key   string
	Value *yaml.Node
}

// Add writes a new document of kind k from dr, taking dr's ID or the next
// free one, in a file named <ID>-<title-slug>.md. A finding gets an empty
// section for each required section it lacks.
func (m *Model) Add(k *Kind, dr Draft) (*Doc, error) {
	if dr.ID == "" {
		dr.ID = m.NextID(k)
	}
	dr.ID = CanonicalID(dr.ID)
	if !k.Valid(dr.ID) {
		return nil, refuse(k.Dir, "%q is not a %s ID: %sNNN", dr.ID, k.Name, k.Prefix)
	}
	if m.Taken(k, dr.ID) {
		return nil, refuse(k.Dir, "%s is taken", dr.ID)
	}
	rel := m.freePath(k.Dir, dr.ID+"-"+slug(dr.Title, k.Name), ".md")
	return m.write(k, rel, nil, dr)
}

// Replace rewrites the document id of kind k from dr, in its own file.
func (m *Model) Replace(k *Kind, id string, dr Draft) (*Doc, error) {
	d, err := m.Get(k, id)
	if err != nil {
		return nil, err
	}
	dr.ID = d.ID
	return m.write(k, d.Path, d, dr)
}

// write writes dr as the file rel, replacing old if there is one.
func (m *Model) write(k *Kind, rel string, old *Doc, dr Draft) (*Doc, error) {
	if strings.TrimSpace(dr.Title) == "" {
		return nil, refuse(rel, "a %s needs a title", k.Name)
	}
	if k == FindingKind {
		if m.Config.Err == nil && !slices.Contains(m.Config.Severities, dr.Severity) {
			return nil, refuse(rel, "severity %q is not one of %s", dr.Severity, strings.Join(m.Config.Severities, ", "))
		}
		for i, t := range dr.Targets {
			if t.Scope == "" {
				return nil, refuse(rel, "target %d has no scope ID: run rpt scope match first", i+1)
			}
		}
	}
	for _, kv := range dr.Extra {
		if slices.Contains(k.Reserved, kv.Key) || slices.Contains(declared[k], kv.Key) {
			return nil, refuse(rel, "the key %q is reserved", kv.Key)
		}
	}
	s, _ := doc.Parse([]byte("---\n---\n"))
	set := func(key string, v *yaml.Node) {
		if err := s.Set(v, key); err != nil {
			panic(err) // an empty head takes any key
		}
	}
	set("id", StringNode(dr.ID))
	set("title", StringNode(dr.Title))
	if k == FindingKind {
		set("targets", targetsNode(dr.Targets))
		set("severity", StringNode(dr.Severity))
	}
	if len(dr.Evidence) > 0 {
		set("evidence", listNode(dr.Evidence))
	}
	for _, kv := range dr.Extra {
		set(kv.Key, kv.Value)
	}
	if k.Sectioned {
		for _, sec := range m.orderSections(dr.Sections) {
			if err := s.AppendSection(m.Config.Heading(sec.Key), []byte(sec.Text)); err != nil {
				return nil, refuse(rel, "section %s: %v", sec.Key, err)
			}
		}
	} else if dr.Body != "" {
		s.SetBody([]byte("\n" + strings.Trim(dr.Body, "\n") + "\n"))
	}
	out := s.Bytes()
	nd := parseDoc(k, rel, out, m.Config)
	if nd.Err != nil {
		return nil, refuse(rel, "the %s would be unreadable: %v", k.Name, nd.Err)
	}
	if err := m.put(rel, out); err != nil {
		return nil, err
	}
	m.swap(old, nd)
	return nd, nil
}

// orderSections puts a finding's sections in the order rpt writes them:
// the fixed ones, then the custom ones the config requires, in its order,
// then the rest by key. A required section the draft lacks is added
// empty, so the file has a heading to fill in.
func (m *Model) orderSections(secs []Section) []Section {
	byKey := map[string]Section{}
	for _, s := range secs {
		byKey[s.Key] = s
	}
	var keys []string
	keys = append(keys, FixedSections...)
	for _, k := range m.Config.RequiredSections {
		if !slices.Contains(keys, m.Config.SectionKey(k)) {
			keys = append(keys, m.Config.SectionKey(k))
		}
	}
	var rest []string
	for k := range byKey {
		if !slices.Contains(keys, k) {
			rest = append(rest, k)
		}
	}
	slices.Sort(rest)
	var out []Section
	for _, k := range append(keys, rest...) {
		s, ok := byKey[k]
		required := slices.ContainsFunc(m.Config.RequiredSections, func(r string) bool { return m.Config.SectionKey(r) == k })
		if ok || required {
			out = append(out, Section{Key: k, Text: s.Text})
		}
	}
	return out
}

func targetsNode(ts []Target) *yaml.Node {
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, t := range ts {
		mp := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Style: yaml.FlowStyle}
		add := func(k string, v *yaml.Node) {
			mp.Content = append(mp.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k}, v)
		}
		add("scope", StringNode(t.Scope))
		if t.Host != "" {
			add("host", StringNode(t.Host))
		}
		if t.Port != 0 {
			add("port", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: fmt.Sprint(t.Port)})
		}
		if t.Protocol != "" {
			add("protocol", StringNode(t.Protocol))
		}
		for _, e := range t.Extra {
			add(e.Key.Value, e.Value)
		}
		seq.Content = append(seq.Content, mp)
	}
	if len(ts) == 0 {
		seq.Style = yaml.FlowStyle
	}
	return seq
}

func listNode(vs []string) *yaml.Node {
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle}
	for _, v := range vs {
		seq.Content = append(seq.Content, StringNode(v))
	}
	return seq
}

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

// slug is a file-name form of s: lower case, runs of other characters as
// one -, at most 40 characters, or fallback when nothing is left.
func slug(s, fallback string) string {
	s = strings.Trim(nonSlug.ReplaceAllString(strings.ToLower(s), "-"), "-")
	if len(s) > 40 {
		s = strings.TrimRight(s[:40], "-")
	}
	if s == "" {
		return fallback
	}
	return s
}

// freePath is dir/name+ext, or with -2, -3 and so on when that's taken.
func (m *Model) freePath(dir, name, ext string) string {
	for n := 1; ; n++ {
		rel := path.Join(dir, name+ext)
		if n > 1 {
			rel = path.Join(dir, fmt.Sprintf("%s-%d%s", name, n, ext))
		}
		if _, ok, _ := m.read(rel); !ok {
			return rel
		}
	}
}

// Set sets one value of the document id: a declared key, a section
// (sections.<key>) of a finding, the body of a page, an x-<plugin> key
// at any depth (x-foo.a.b), or any other top-level key. Title, severity,
// id and evidence take their values as text; other keys read them as
// YAML. Several values make a list. Setting id renames the document.
func (m *Model) Set(k *Kind, id, key string, values ...string) (*Doc, error) {
	d, err := m.Get(k, id)
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, refuse(d.Path, "%s needs a value", key)
	}
	one := func() (string, error) {
		if len(values) > 1 {
			return "", refuse(d.Path, "%s takes one value", key)
		}
		return values[0], nil
	}
	switch {
	case key == "id":
		v, err := one()
		if err != nil {
			return nil, err
		}
		return m.Rename(d, v)
	case key == "title", key == "severity" && k == FindingKind:
		v, err := one()
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(v) == "" {
			return nil, refuse(d.Path, "%s can't be empty", key)
		}
		if key == "severity" && m.Config.Err == nil && !slices.Contains(m.Config.Severities, v) {
			return nil, refuse(d.Path, "severity %q is not one of %s", v, strings.Join(m.Config.Severities, ", "))
		}
		return m.edit(d, func(s *doc.Doc) error { return s.Set(keepStyle(s.Get(key), StringNode(v)), key) })
	case key == "evidence":
		return m.edit(d, func(s *doc.Doc) error { return s.Set(listNode(values), key) })
	case key == "targets" && k == FindingKind:
		return m.setTargets(d, values)
	case strings.HasPrefix(key, "sections.") && k.Sectioned:
		text := strings.Join(values, " ")
		return m.setSection(d, strings.TrimPrefix(key, "sections."), text)
	case key == "body" && !k.Sectioned:
		text := strings.Join(values, " ")
		return m.edit(d, func(s *doc.Doc) error {
			s.SetBody([]byte("\n" + strings.Trim(text, "\n") + "\n"))
			return nil
		})
	case slices.Contains(k.Reserved, key) || slices.Contains(declared[k], key):
		return nil, refuse(d.Path, "%s can't be set", key)
	}
	path := []string{key}
	if IsPluginKey(key) {
		path = strings.Split(key, ".")
		if slices.Contains(path, "") {
			return nil, refuse(d.Path, "%q has an empty part", key)
		}
	}
	val, err := valuesNode(values)
	if err != nil {
		return nil, refuse(d.Path, "%v", err)
	}
	return m.edit(d, func(s *doc.Doc) error { return s.Set(val, path...) })
}

// keepStyle gives a new string the old value's quoting when it still
// reads as a string that way.
func keepStyle(old, v *yaml.Node) *yaml.Node {
	if old != nil && old.Kind == yaml.ScalarNode && v.Style == 0 {
		v.Style = old.Style
	}
	return v
}

func valuesNode(values []string) (*yaml.Node, error) {
	if len(values) == 1 {
		return ParseValue(values[0])
	}
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle}
	for _, v := range values {
		n, err := ParseValue(v)
		if err != nil {
			return nil, err
		}
		seq.Content = append(seq.Content, n)
	}
	return seq, nil
}

// setTargets reads each value as a target, {scope: S-1, port: 443}, or a
// list of them.
func (m *Model) setTargets(d *Doc, values []string) (*Doc, error) {
	ts, err := ParseTargets(values)
	if err != nil {
		return nil, refuse(d.Path, "%v", err)
	}
	return m.setTargetList(d, ts)
}

// ParseTargets reads targets as rpt set and rpt finding add --target take
// them: each value a scope ID, a YAML map like {scope: S-20, port: 22},
// or a list of either.
func ParseTargets(values []string) ([]Target, error) {
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, v := range values {
		n, err := ParseValue(v)
		if err != nil {
			return nil, err
		}
		items := []*yaml.Node{n}
		if n.Kind == yaml.SequenceNode {
			items = n.Content
		}
		for _, it := range items {
			if it.Kind == yaml.ScalarNode {
				// A scope ID alone.
				it = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{StringNode("scope"), StringNode(it.Value)}}
			}
			seq.Content = append(seq.Content, it)
		}
	}
	ts, err := targets(seq, func(*yaml.Node) int { return 0 })
	if err != nil {
		return nil, fmt.Errorf("targets: %w", err)
	}
	for i, t := range ts {
		if t.Scope == "" {
			return nil, fmt.Errorf("target %d has no scope ID", i+1)
		}
	}
	return ts, nil
}

// setSection sets the text of a finding's section, adding the section
// with this report's heading when the finding lacks it.
func (m *Model) setSection(d *Doc, key, text string) (*Doc, error) {
	key = m.Config.SectionKey(key)
	return m.edit(d, func(s *doc.Doc) error {
		secs, _ := s.Sections()
		for i, sec := range secs {
			if m.Config.SectionKey(sec.Heading) == key {
				return s.SetSection(i, []byte(text))
			}
		}
		return s.AppendSection(m.Config.Heading(key), []byte(text))
	})
}

// Unset removes values from the document id, all or none: top-level
// keys, x-<plugin> keys at any depth (a plugin's section goes when it
// empties), a finding's sections (sections.<key>) or a page's body. A key
// the document lacks is no change. id, title, and a finding's severity
// and targets can't be unset.
func (m *Model) Unset(k *Kind, id string, keys ...string) (*Doc, error) {
	d, err := m.Get(k, id)
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		if key == "id" || key == "title" || k == FindingKind && (key == "severity" || key == "targets") {
			return nil, refuse(d.Path, "%s can't be unset", key)
		}
	}
	return m.edit(d, func(s *doc.Doc) error {
		for _, key := range keys {
			switch {
			case strings.HasPrefix(key, "sections.") && k.Sectioned:
				want := m.Config.SectionKey(strings.TrimPrefix(key, "sections."))
				secs, _ := s.Sections()
				for i := len(secs) - 1; i >= 0; i-- {
					if m.Config.SectionKey(secs[i].Heading) == want {
						if err := s.RemoveSection(i); err != nil {
							return err
						}
					}
				}
			case key == "body" && !k.Sectioned:
				s.SetBody(nil)
			default:
				path := []string{key}
				if IsPluginKey(key) {
					path = strings.Split(key, ".")
				}
				if _, err := s.Unset(path...); err != nil {
					return err
				}
				// A plugin's section goes when it empties.
				for len(path) > 1 {
					path = path[:len(path)-1]
					if n := s.Get(path...); n == nil || n.Kind != yaml.MappingNode || len(n.Content) > 0 {
						break
					}
					if _, err := s.Unset(path...); err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
}

// Rename gives the document d a new ID, renaming a file named for the
// old one. A page's ID in the config's page lists changes with it.
func (m *Model) Rename(d *Doc, newID string) (*Doc, error) {
	k := d.Kind
	newID = CanonicalID(newID)
	if newID == d.ID {
		return d, nil
	}
	if !k.Valid(newID) {
		return nil, refuse(d.Path, "%q is not a %s ID: %sNNN", newID, k.Name, k.Prefix)
	}
	if m.Taken(k, newID) {
		return nil, refuse(d.Path, "%s is taken", newID)
	}
	oldID, oldPath := d.ID, d.Path
	nd, err := m.edit(d, func(s *doc.Doc) error { return s.Set(keepStyle(s.Get("id"), StringNode(newID)), "id") })
	if err != nil {
		return nil, err
	}
	if base := path.Base(oldPath); strings.HasPrefix(base, oldID) && k.file.MatchString(base) {
		newPath := m.freePath(path.Dir(oldPath), newID+strings.TrimSuffix(strings.TrimPrefix(base, oldID), ".md"), ".md")
		data, _, _ := m.read(oldPath)
		if err := m.put(newPath, data); err != nil {
			return nil, err
		}
		if err := m.remove(oldPath); err != nil {
			return nil, err
		}
		moved := parseDoc(k, newPath, data, m.Config)
		m.swap(nd, moved)
		nd = moved
	}
	if k == PageKind {
		if err := m.renameInConfig(oldID, newID); err != nil {
			return nil, err
		}
	}
	return nd, nil
}

// renameInConfig replaces a page ID in the config's page lists.
func (m *Model) renameInConfig(oldID, newID string) error {
	if m.Config.Err != nil {
		if slices.Contains(m.Config.Pages, oldID) || slices.Contains(m.Config.RequiredPages, oldID) {
			return refuse(ConfigFile, "%s doesn't parse, so its page lists can't follow the rename", ConfigFile)
		}
		return nil
	}
	return m.editConfig(func(s *doc.Doc) error {
		for _, key := range []string{"pages", "required_pages"} {
			n := s.Get(key)
			if n == nil || n.Kind != yaml.SequenceNode {
				continue
			}
			changed := false
			list := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: n.Style}
			for _, c := range n.Content {
				if c.Value == oldID {
					c = StringNode(newID)
					changed = true
				}
				list.Content = append(list.Content, c)
			}
			if changed {
				if err := s.Set(list, key); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// editConfig changes rpt.yaml through change. The result must parse.
// Findings are read again under the new headings.
func (m *Model) editConfig(change func(*doc.Doc) error) error {
	src, _, err := m.read(ConfigFile)
	if err != nil {
		return err
	}
	s, err := doc.ParseYAML(src)
	if err != nil {
		return refuse(ConfigFile, "%s: %v", ConfigFile, err)
	}
	if err := change(s); err != nil {
		return refuse(ConfigFile, "%s: %v", ConfigFile, err)
	}
	out := s.Bytes()
	c := parseConfig(out)
	if c.Err != nil {
		return refuse(ConfigFile, "the change would leave %s unreadable: %v", ConfigFile, c.Err)
	}
	if err := m.put(ConfigFile, out); err != nil {
		return err
	}
	m.Config = c
	for _, d := range m.docs[FindingKind] {
		if d.Err == nil {
			d.Sections = sectionsOf(d.src, c)
		}
	}
	return nil
}

// Cited says what to do when a write would leave something pointing at
// what it removes or changes: a scope row findings cite, a page the
// config names.
type Cited int

const (
	Refuse  Cited = iota // refuse the write
	Force                // write it, leaving the pointers dangling or unfit
	Cleanup              // write it and drop the pointers
)

// Remove removes the document id. A page the config's page lists name is
// refused, unless mode says otherwise. It returns the document as it was,
// and the config lists a Force left naming it.
func (m *Model) Remove(k *Kind, id string, mode Cited) (*Doc, []string, error) {
	d, err := m.Get(k, id)
	if err != nil {
		return nil, nil, err
	}
	var cited []string
	if k == PageKind && m.Config.Err == nil {
		if slices.Contains(m.Config.Pages, d.ID) {
			cited = append(cited, "pages")
		}
		if slices.Contains(m.Config.RequiredPages, d.ID) {
			cited = append(cited, "required_pages")
		}
	}
	switch {
	case len(cited) > 0 && mode == Refuse:
		return nil, nil, refuse(d.Path, "%s is in %s's %s: pass --force to leave it there, or --cleanup to drop it", d.ID, ConfigFile, strings.Join(cited, " and "))
	case len(cited) > 0 && mode == Cleanup:
		if err := m.dropFromConfig(d.ID); err != nil {
			return nil, nil, err
		}
		cited = nil
	}
	if err := m.remove(d.Path); err != nil {
		return nil, nil, err
	}
	m.swap(d, nil)
	return d, cited, nil
}

// dropFromConfig removes a page ID from the config's page lists.
func (m *Model) dropFromConfig(id string) error {
	return m.editConfig(func(s *doc.Doc) error {
		for _, key := range []string{"pages", "required_pages"} {
			n := s.Get(key)
			if n == nil || n.Kind != yaml.SequenceNode {
				continue
			}
			list := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: n.Style}
			for _, c := range n.Content {
				if c.Value != id {
					list.Content = append(list.Content, c)
				}
			}
			if len(list.Content) == 0 {
				list.Style = yaml.FlowStyle
			}
			if err := s.Set(list, key); err != nil {
				return err
			}
		}
		return nil
	})
}
