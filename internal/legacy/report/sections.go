package report

import (
	"fmt"
	"slices"
	"strings"

	"github.com/astr4liteEx/rpt/sdk"
)

// sectionKeys are the report's sections as its config maps them: the
// fixed sections in the order rpt writes them, then each custom section
// required_sections names, in config order.
func (c Config) sectionKeys() []string {
	keys := slices.Clone(FixedSections)
	for _, name := range c.RequiredSections {
		if strings.TrimSpace(name) == "" {
			continue // the config rule reports it
		}
		if key := c.Headings.key(name); !slices.Contains(keys, key) {
			keys = append(keys, key)
		}
	}
	return keys
}

// SetSection replaces the text of one section of the finding with the given
// ID, and returns the finding as now stored. key is a section key or a
// fixed section's heading. A section the finding lacks is appended after
// its others, under the report's heading. Every other byte of the file is
// kept. Text holding a ## heading of its own, which would split the
// section, is refused, as is a finding with the section twice.
func (r *Report) SetSection(id, key, text string) (sdk.Finding, error) {
	return one(r, func(tx *Tx) (sdk.Finding, error) { return tx.SetSection(id, key, text) })
}

// SetSection is Report.SetSection as part of the write tx.
func (tx *Tx) SetSection(id, key, text string) (sdk.Finding, error) {
	r := tx.r
	h := tx.headings()
	key = h.key(strings.TrimSpace(key))
	text = strings.TrimRight(strings.TrimLeft(string(normaliseNewlines([]byte(text))), "\n"), " \t\n")
	if n := len(sectionSpans([]byte(text), h)); n > 0 {
		return sdk.Finding{}, fmt.Errorf("%w: %s: the text has a ## heading of its own, which would start another section", ErrBadValue, key)
	}
	rel, err := r.locate(id)
	if err != nil {
		return sdk.Finding{}, err
	}
	return tx.edit(id, rel, func(ff *findingFile) error {
		spans := sectionSpans(ff.body, h)
		var at []span
		for _, sp := range spans {
			if sp.key == key {
				at = append(at, sp)
			}
		}
		switch len(at) {
		case 0:
			ff.appendSection(h.heading(key), text)
			return nil
		case 1:
		default:
			return fmt.Errorf("the %q section is in the file twice; merge them by hand first", h.heading(key))
		}
		sp := at[0]
		// The heading line, then one blank line before the text and one
		// before the next heading; an empty section has a single blank
		// line, or none at the end of the file.
		repl := ""
		if text != "" {
			repl = "\n" + text + "\n"
		}
		if sp.end < len(ff.body) {
			repl += "\n"
		}
		ff.body = append(append(append([]byte{}, ff.body[:sp.bodyAt]...), repl...), ff.body[sp.end:]...)
		return nil
	})
}
