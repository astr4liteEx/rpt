package report

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/astr4liteEx/rpt/sdk"
)

// Add writes one finding record into findings/ as a new file named
// F-NNN-<slug>.md, taking the record's id or the next free one, and
// returns the finding as stored. Nothing is written if the record fails
// its checks.
func (r *Report) Add(rec sdk.Finding) (sdk.Finding, error) {
	cfg, err := r.Config()
	if err != nil {
		return sdk.Finding{}, err
	}
	if err := checkRecord(rec, cfg.Severities); err != nil {
		return sdk.Finding{}, err
	}
	id := rec.ID
	if id == "" {
		if id, err = r.NextID(); err != nil {
			return sdk.Finding{}, err
		}
	} else if _, err := r.locate(id); err == nil {
		return sdk.Finding{}, fmt.Errorf("%w: id: %s is already taken", ErrBadValue, id)
	}
	rec.ID = id
	rel := path.Join(FindingsDir, id+"-"+slug(rec.Title)+".md")
	if _, err := r.root.Stat(rel); !errors.Is(err, fs.ErrNotExist) {
		return sdk.Finding{}, fmt.Errorf("add %s: file already exists", rel)
	}

	out, err := newFindingFile(rec)
	if err != nil {
		return sdk.Finding{}, err
	}
	f, err := parseFinding(rel, out)
	if err != nil {
		return sdk.Finding{}, fmt.Errorf("add would write a broken %s: %w", rel, err)
	}
	if err := r.root.MkdirAll(FindingsDir, 0o755); err != nil {
		return sdk.Finding{}, fmt.Errorf("add: %w", err)
	}
	if err := writeAtomic(r.root, rel, out); err != nil {
		return sdk.Finding{}, err
	}
	return f, nil
}

// checkRecord checks a record before anything is written.
func checkRecord(rec sdk.Finding, severities []sdk.Severity) error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrBadValue, fmt.Sprintf(format, a...))
	}
	switch {
	case rec.Title == "":
		return bad("title is required")
	case !slices.Contains(severities, rec.Severity):
		return bad("severity %q is not one of %v", rec.Severity, severities)
	case rec.ID != "" && !ValidID(rec.ID):
		return bad("id %q is not F- and at least three digits", rec.ID)
	}
	if rec.Target != nil {
		if err := checkTarget(*rec.Target); err != nil {
			return bad("target: %v", err)
		}
	}
	return nil
}

// newFindingFile renders a record as a finding file: frontmatter in a
// fixed order starting with id, unknown fields after it by name, then the
// sections.
func newFindingFile(rec sdk.Finding) ([]byte, error) {
	type field struct {
		key string
		val any
	}
	fields := []field{{"id", rec.ID}, {"title", rec.Title}, {"scope", nonNil(rec.Scope)}, {"severity", rec.Severity}}
	if rec.Evidence != nil {
		fields = append(fields, field{"evidence", rec.Evidence})
	}
	if rec.Target != nil {
		fields = append(fields, field{"target", rec.Target})
	}
	for _, k := range slices.Sorted(maps.Keys(rec.Extra)) {
		fields = append(fields, field{k, rec.Extra[k]})
	}
	var ff findingFile
	for _, fl := range fields {
		n, err := toNode(fl.val)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", fl.key, err)
		}
		if err := ff.setEntry(fl.key, n); err != nil {
			return nil, fmt.Errorf("%s: %w", fl.key, err)
		}
	}
	for _, key := range sectionOrder(rec.Sections) {
		ff.appendSection(key, rec.Sections[key])
	}
	return ff.bytes(), nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// slug turns a title into a file-name part: lowercase ASCII letters and
// digits joined by single hyphens, at most 50 characters, cut at a hyphen
// rather than mid-word.
func slug(title string) string {
	var b strings.Builder
	gap := false
	for _, c := range strings.ToLower(title) {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			if gap && b.Len() > 0 {
				b.WriteByte('-')
			}
			gap = false
			b.WriteRune(c)
			continue
		}
		gap = true
	}
	s := b.String()
	if len(s) > 50 {
		cut := s[:50]
		if s[50] != '-' {
			if i := strings.LastIndexByte(cut, '-'); i > 0 {
				cut = cut[:i]
			}
		}
		s = strings.TrimRight(cut, "-")
	}
	if s == "" {
		return "finding"
	}
	return s
}
