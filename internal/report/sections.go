package report

import (
	"slices"
	"strings"

	"github.com/astr4liteEx/rpt/sdk"
)

// SectionList is the report's sections as its config maps them: the fixed
// sections in the order rpt writes them, with their headings, then each
// custom section required_sections names, in config order.
func (c Config) SectionList() []sdk.Section {
	required := map[string]bool{}
	var custom []string
	for _, name := range c.RequiredSections {
		if strings.TrimSpace(name) == "" {
			continue // the config rule reports it
		}
		key := c.Headings.key(name)
		if !required[key] && !slices.Contains(FixedSections, key) {
			custom = append(custom, key)
		}
		required[key] = true
	}
	var out []sdk.Section
	for _, k := range FixedSections {
		out = append(out, sdk.Section{Kind: "section", Key: k, Heading: c.Headings.heading(k), Fixed: true, Required: required[k]})
	}
	for _, k := range custom {
		out = append(out, sdk.Section{Kind: "section", Key: k, Heading: k, Required: true})
	}
	return out
}
