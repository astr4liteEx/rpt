package report

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Problem levels.
const (
	Error   = "error"
	Warning = "warning"
)

// A Problem is one broken rule, where it is broken.
type Problem struct {
	Path    string // relative to the report root; "." for the report as a whole
	Line    int    // 1-based, 0 when the whole file
	Rule    string
	Level   string
	Message string
}

// Rules are validate's rules and their own levels.
var Rules = map[string]string{
	"readable": Error, "findingID": Error, "title": Error, "knownSeverity": Error,
	"scopeIDsExist": Error, "targets": Error, "requiredSections": Error, "evidence": Error,
	"config": Error, "pageID": Error, "pageTitle": Error, "pageOrder": Error,
	"requiredPages": Error, "pluginSchema": Error, "scope": Error,
	"textBeforeHeading": Warning, "configUnknownKey": Warning, "evidenceUnlinked": Warning,
}

// A checker adds the problems one rule finds.
type checker struct {
	m   *Model
	out []Problem
}

func (c *checker) add(path string, line int, rule, format string, a ...any) {
	c.out = append(c.out, Problem{Path: path, Line: line, Rule: rule, Level: Rules[rule], Message: fmt.Sprintf(format, a...)})
}

func (c *checker) file(err error) {
	var fe *FileError
	if !errors.As(err, &fe) {
		c.add(".", 0, "readable", "%v", err)
		return
	}
	rule := cmp.Or(fe.Rule, "readable")
	c.add(fe.Path, fe.Line, rule, "%v", fe.Err)
}

// Check runs every rule on the report and returns the problems, at the
// levels the config gives them, sorted by file and line.
func (m *Model) Check() []Problem {
	c := &checker{m: m}
	c.config()
	c.scope()
	c.docs(FindingKind, "findingID", "title")
	c.docs(PageKind, "pageID", "pageTitle")
	for _, d := range m.docs[FindingKind] {
		if d.Err == nil {
			c.finding(d)
		}
	}
	c.pages()
	c.evidence()
	return m.leveled(c.out)
}

// leveled applies the config's rule levels and sorts.
func (m *Model) leveled(ps []Problem) []Problem {
	for i, p := range ps {
		if lv, ok := m.Config.Rules[p.Rule]; ok && m.Config.Err == nil && (lv == Error || lv == Warning) {
			ps[i].Level = lv
		}
	}
	SortProblems(ps)
	return ps
}

// SortProblems orders problems by file, line, rule and message.
func SortProblems(ps []Problem) {
	slices.SortStableFunc(ps, func(a, b Problem) int {
		return cmp.Or(strings.Compare(a.Path, b.Path), cmp.Compare(a.Line, b.Line), strings.Compare(a.Rule, b.Rule), strings.Compare(a.Message, b.Message))
	})
}

func (c *checker) config() {
	cfg := c.m.Config
	if cfg.Err != nil {
		c.file(cfg.Err)
		return
	}
	at := func(key string) int { return cfg.KeyLine(key) }
	if cfg.Format != 2 {
		c.add(ConfigFile, at("format"), "config", "format is %d; rpt reads format 2", cfg.Format)
	}
	if len(cfg.Severities) == 0 {
		c.add(ConfigFile, at("severities"), "config", "severities is empty")
	}
	for _, l := range []struct {
		key  string
		list []string
	}{{"severities", cfg.Severities}, {"required_sections", cfg.RequiredSections}, {"pages", cfg.Pages}, {"required_pages", cfg.RequiredPages}} {
		seen := map[string]bool{}
		for _, v := range l.list {
			switch {
			case strings.TrimSpace(v) == "":
				c.add(ConfigFile, at(l.key), "config", "%s has an empty name", l.key)
			case seen[v]:
				c.add(ConfigFile, at(l.key), "config", "%s names %q twice", l.key, v)
			}
			seen[v] = true
		}
	}
	headings := map[string]string{}
	for k, h := range cfg.Sections {
		switch {
		case !slices.Contains(FixedSections, k):
			c.add(ConfigFile, at("sections"), "config", "sections renames %q, which isn't a fixed section (%s)", k, strings.Join(FixedSections, ", "))
		case strings.TrimSpace(h) == "":
			c.add(ConfigFile, at("sections"), "config", "sections gives %s an empty heading", k)
		}
	}
	for _, k := range FixedSections {
		h := strings.ToLower(cfg.Heading(k))
		if other, ok := headings[h]; ok {
			c.add(ConfigFile, at("sections"), "config", "%s and %s have the same heading, %q", other, k, cfg.Heading(k))
		}
		headings[h] = k
	}
	for rule, lv := range cfg.Rules {
		if lv != Error && lv != Warning {
			c.add(ConfigFile, at("rules"), "config", "rules gives %s %q; a level is error or warning", rule, lv)
		}
	}
	for _, k := range cfg.Unknown {
		c.add(ConfigFile, at(k), "configUnknownKey", "%s isn't a key rpt knows; plugins keep settings under x-<plugin>", k)
	}
}

func (c *checker) scope() {
	s := c.m.Scope
	switch {
	case !s.Exists:
		c.add(ScopeFile, 0, "scope", "the report has no %s", ScopeFile)
	case s.Err != nil:
		c.file(s.Err)
	}
	for _, err := range s.RowErrs {
		c.file(err)
	}
}

// docs checks every document of a kind reads and has a well-formed,
// unique ID and a title.
func (c *checker) docs(k *Kind, idRule, titleRule string) {
	byID := map[string][]*Doc{}
	for _, d := range c.m.docs[k] {
		if d.Err != nil {
			c.file(d.Err)
			continue
		}
		line := max(d.KeyLine("id"), 1)
		switch {
		case d.ID == "":
			c.add(d.Path, line, idRule, "no id: the next free one is %s", c.m.NextID(k))
		case !k.Valid(d.ID):
			c.add(d.Path, line, idRule, "id %q is not of the form %sNNN: the next free one is %s", d.ID, k.Prefix, c.m.NextID(k))
		default:
			byID[d.ID] = append(byID[d.ID], d)
		}
		if strings.TrimSpace(d.Title) == "" {
			c.add(d.Path, max(d.KeyLine("title"), 1), titleRule, "no title")
		}
	}
	for id, ds := range byID {
		for _, d := range ds[min(1, len(ds)-1):] {
			if len(ds) > 1 {
				c.add(d.Path, max(d.KeyLine("id"), 1), idRule, "%s is also the id of %s: the next free one is %s", id, ds[0].Path, c.m.NextID(k))
			}
		}
	}
}

func (c *checker) finding(d *Doc) {
	cfg := c.m.Config
	if cfg.Err == nil && !slices.Contains(cfg.Severities, d.Severity) {
		c.add(d.Path, max(d.KeyLine("severity"), 1), "knownSeverity", "severity %q is not one of %s", d.Severity, strings.Join(cfg.Severities, ", "))
	}
	if len(d.Targets) == 0 {
		c.add(d.Path, max(d.KeyLine("targets"), 1), "targets", "no targets: a finding names the scope rows it was found on")
	}
	for _, t := range d.Targets {
		if t.Scope == "" {
			c.add(d.Path, t.Line, "targets", "a target has no scope ID: run rpt scope match")
			continue
		}
		if c.m.Scope.Err != nil {
			continue
		}
		row, err := c.m.Scope.Row(t.Scope)
		if err != nil {
			c.add(d.Path, t.Line, "scopeIDsExist", "%s is not in %s", t.Scope, ScopeFile)
			continue
		}
		if err := Fits(row, t); err != nil {
			c.add(d.Path, t.Line, "targets", "%v", err)
		}
	}
	for _, req := range cfg.RequiredSections {
		key := cfg.SectionKey(req)
		s, ok := d.Section(key)
		switch {
		case !ok:
			c.add(d.Path, d.BodyLine(), "requiredSections", "no %q section", cfg.Heading(key))
		case strings.TrimSpace(s.Text) == "":
			c.add(d.Path, s.Line, "requiredSections", "the %q section is empty", s.Heading)
		}
	}
	if d.Lead() != "" {
		c.add(d.Path, d.BodyLine(), "textBeforeHeading", "text before the first ## heading belongs to no section")
	}
}

func (c *checker) pages() {
	cfg := c.m.Config
	if cfg.Err != nil {
		return
	}
	for _, id := range cfg.Pages {
		if id == FindingsSlot {
			continue
		}
		if _, err := c.m.Get(PageKind, id); errors.Is(err, ErrNotFound) {
			c.add(ConfigFile, cfg.KeyLine("pages"), "pageOrder", "pages names %s, which isn't a page", id)
		}
	}
	for _, id := range cfg.RequiredPages {
		p, err := c.m.Get(PageKind, id)
		switch {
		case errors.Is(err, ErrNotFound):
			c.add(ConfigFile, cfg.KeyLine("required_pages"), "requiredPages", "required page %s doesn't exist", id)
		case err == nil && strings.TrimSpace(p.Body()) == "":
			c.add(p.Path, p.BodyLine(), "requiredPages", "required page %s has no body", id)
		}
	}
}

func (c *checker) evidence() {
	for _, k := range Kinds {
		for _, d := range c.m.docs[k] {
			refs, _ := c.m.Refs(d)
			for _, r := range refs {
				switch {
				case r.Path == "":
					c.add(d.Path, r.Line, "evidence", "%q leaves the report", r.Ref)
				case !c.m.exists(r.Path):
					c.add(d.Path, r.Line, "evidence", "%q doesn't exist (as %s)", r.Ref, r.Path)
				}
			}
		}
	}
	orphans, err := c.m.Orphans()
	if err != nil {
		return // a file doesn't parse: it is already a problem
	}
	for _, p := range orphans {
		c.add(p, 0, "evidenceUnlinked", "no finding or page lists or links this file")
	}
}
