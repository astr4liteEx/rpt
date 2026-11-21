package report

import (
	"errors"
	"slices"
	"strings"

	"github.com/astr4liteEx/rpt/internal/doc"
)

// Config is rpt.yaml as in effect: an absent key gives its default.
type Config struct {
	// Err is why rpt.yaml doesn't parse, a *FileError. Nothing below is
	// set then.
	Err error

	Format           int
	Severities       []string          // most severe first
	RequiredSections []string          // section keys, or a custom section's heading
	Sections         map[string]string // as written: fixed key -> heading
	Headings         map[string]string // every fixed key -> its heading in this report
	Pages            []string          // page IDs and FindingsSlot, in reading order
	RequiredPages    []string
	Rules            map[string]string // rule -> level
	// Unknown are top-level keys rpt doesn't define, other than x-
	// plugin sections, in file order.
	Unknown []string

	src *doc.Doc
}

// FindingsSlot is the entry in pages where the findings go.
const FindingsSlot = "findings"

// The fixed sections, their default headings, and the defaults for an
// absent key.
var (
	FixedSections           = []string{"description", "remediation", "poc"}
	defaultHeadings         = map[string]string{"description": "Description", "remediation": "Remediation", "poc": "Proof of concept"}
	DefaultSeverities       = []string{"critical", "high", "medium", "low", "info"}
	DefaultRequiredSections = []string{"description", "remediation", "poc"}
)

var configKeys = []string{"format", "severities", "required_sections", "sections", "pages", "required_pages", "rules"}

// IsPluginKey reports whether key is a plugin's: x-<name>.
func IsPluginKey(key string) bool { return strings.HasPrefix(key, "x-") && len(key) > 2 }

func parseConfig(src []byte) *Config {
	fail := func(line int, err error) *Config {
		return &Config{Err: &FileError{Path: ConfigFile, Line: line, Err: err}}
	}
	s, err := doc.ParseYAML(src)
	if err != nil {
		var e *doc.Error
		errors.As(err, &e)
		return fail(e.Line, errors.New(e.Msg))
	}
	var raw struct {
		Format           int               `yaml:"format"`
		Severities       []string          `yaml:"severities"`
		RequiredSections []string          `yaml:"required_sections"`
		Sections         map[string]string `yaml:"sections"`
		Pages            []string          `yaml:"pages"`
		RequiredPages    []string          `yaml:"required_pages"`
		Rules            map[string]string `yaml:"rules"`
	}
	if err := s.Head().Decode(&raw); err != nil {
		return fail(0, err)
	}
	c := &Config{
		Format: raw.Format, Severities: raw.Severities, RequiredSections: raw.RequiredSections,
		Sections: raw.Sections, Pages: raw.Pages, RequiredPages: raw.RequiredPages, Rules: raw.Rules,
		Headings: map[string]string{}, src: s,
	}
	has := map[string]bool{}
	for _, e := range s.Entries() {
		k := e.Key.Value
		has[k] = true
		if !slices.Contains(configKeys, k) && !IsPluginKey(k) {
			c.Unknown = append(c.Unknown, k)
		}
	}
	// A default applies only when the key is absent: an explicit empty
	// list stays empty.
	if !has["severities"] {
		c.Severities = slices.Clone(DefaultSeverities)
	}
	if !has["required_sections"] {
		c.RequiredSections = slices.Clone(DefaultRequiredSections)
	} else if c.RequiredSections == nil {
		c.RequiredSections = []string{}
	}
	for _, k := range FixedSections {
		c.Headings[k] = defaultHeadings[k]
		if h := strings.TrimSpace(raw.Sections[k]); h != "" {
			c.Headings[k] = h
		}
	}
	return c
}

// SectionKey is the key a heading files its section under: the fixed key
// whose heading it matches, whatever its case, else the heading itself.
func (c *Config) SectionKey(heading string) string {
	for _, k := range FixedSections {
		if strings.EqualFold(heading, c.heading(k)) {
			return k
		}
	}
	return heading
}

// heading is the heading of a fixed section, with the defaults when the
// config doesn't parse.
func (c *Config) heading(key string) string {
	if h, ok := c.Headings[key]; ok {
		return h
	}
	return defaultHeadings[key]
}

// Heading is the heading the section with the given key is written under.
func (c *Config) Heading(key string) string {
	if slices.Contains(FixedSections, key) {
		return c.heading(key)
	}
	return key
}

// KeyLine is the file line of a top-level key, or 0.
func (c *Config) KeyLine(key string) int {
	if c.src == nil {
		return 0
	}
	for _, e := range c.src.Entries() {
		if e.Key.Value == key {
			return e.Key.Line
		}
	}
	return 0
}

// Plugin returns a plugin's section, x-<name>, and whether it has one.
func (c *Config) Plugin(key string) (doc.Entry, bool) {
	if c.src == nil {
		return doc.Entry{}, false
	}
	for _, e := range c.src.Entries() {
		if e.Key.Value == key {
			return e, true
		}
	}
	return doc.Entry{}, false
}
