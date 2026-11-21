package report

import (
	"fmt"
	"maps"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/astr4liteEx/rpt/sdk"
)

// Add writes one finding record into findings/ as a new file named
// F-NNN-<slug>.md, taking the record's id or the next free one, and
// returns the finding as stored. Nothing is written if the record fails
// its checks.
func (r *Report) Add(rec sdk.Finding) (sdk.Finding, error) {
	return one(r, func(tx *Tx) (sdk.Finding, error) { return tx.Add(rec) })
}

// Add is Report.Add as part of the write tx: several adds in one write
// take IDs one after another.
func (tx *Tx) Add(rec sdk.Finding) (sdk.Finding, error) {
	r := tx.r
	cfg, err := r.Config()
	if err != nil {
		return sdk.Finding{}, err
	}
	if err := checkRecord(rec); err != nil {
		return sdk.Finding{}, err
	}
	id := rec.ID
	if id == "" {
		if id, err = tx.nextID(); err != nil {
			return sdk.Finding{}, err
		}
	} else if _, err := r.locate(id); err == nil || tx.newIDs[id] {
		return sdk.Finding{}, fmt.Errorf("%w: id: %s is already taken", ErrBadValue, id)
	}
	rec.ID = id
	rel := path.Join(FindingsDir, id+"-"+slug(rec.Title)+".md")
	if _, exists, err := tx.read(rel); err != nil {
		return sdk.Finding{}, err
	} else if exists {
		return sdk.Finding{}, fmt.Errorf("%w: %s already exists", ErrBadValue, rel)
	}

	out, err := newFindingFile(rec, cfg.Headings)
	if err != nil {
		return sdk.Finding{}, err
	}
	f, err := parseFinding(rel, out, cfg.Headings)
	if err != nil {
		return sdk.Finding{}, fmt.Errorf("add would write a broken %s: %w", rel, err)
	}
	if err := tx.put(rel, out, rankFinding); err != nil {
		return sdk.Finding{}, err
	}
	tx.newIDs[id] = true
	f.Lines = nil
	return f, nil
}

// nextID is the next free finding ID, counting the ones this write adds.
func (tx *Tx) nextID() (string, error) {
	if tx.nextN == 0 {
		id, err := tx.r.NextID()
		if err != nil {
			return "", err
		}
		m := findingID.FindStringSubmatch(id)
		if tx.nextN, err = strconv.Atoi(m[1]); err != nil {
			return "", err
		}
	}
	for {
		id := fmt.Sprintf("F-%03d", tx.nextN)
		tx.nextN++
		if !tx.newIDs[id] {
			return id, nil
		}
	}
}

// Scaffold returns rec with an empty section for every required section it
// lacks, so the finding file gets a heading to fill in for each.
func (r *Report) Scaffold(rec sdk.Finding) (sdk.Finding, error) {
	cfg, err := r.Config()
	if err != nil {
		return sdk.Finding{}, err
	}
	secs := maps.Clone(rec.Sections)
	for _, name := range cfg.RequiredSections {
		if strings.TrimSpace(name) == "" {
			continue // the config rule reports it
		}
		key := cfg.Headings.key(name) // a fixed section may be named by its heading
		if _, ok := secs[key]; !ok {
			if secs == nil {
				secs = map[string]string{}
			}
			secs[key] = ""
		}
	}
	rec.Sections = secs
	return rec, nil
}

// checkRecord checks a record's form before anything is written. Whether
// its severity is one of the report's, or its targets fit scope, is
// rpt validate's to say (ADR 0008).
func checkRecord(rec sdk.Finding) error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrBadValue, fmt.Sprintf(format, a...))
	}
	switch {
	case rec.Title == "":
		return bad("title is required")
	case rec.Severity == "":
		return bad("severity is required")
	case rec.ID != "" && !ValidID(rec.ID):
		return bad("id %q is not F- and at least three digits", rec.ID)
	}
	for k, now := range formerKeys {
		if _, ok := rec.Extra[k]; ok {
			return bad("%s is from report format 1; it is now %s", k, now)
		}
	}
	for i, t := range rec.Targets {
		if err := checkTarget(t); err != nil {
			return bad("targets[%d]: %v", i, err)
		}
	}
	return nil
}

// newFindingFile renders a record as a finding file: frontmatter in a
// fixed order starting with id, unknown fields after it by name, then the
// sections.
func newFindingFile(rec sdk.Finding, h Headings) ([]byte, error) {
	type field struct {
		key string
		val any
	}
	fields := []field{{"id", rec.ID}, {"title", rec.Title}, {"targets", nonNil(rec.Targets)}, {"severity", rec.Severity}}
	if rec.Evidence != nil {
		fields = append(fields, field{"evidence", rec.Evidence})
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
		ff.appendSection(h.heading(key), rec.Sections[key])
	}
	return ff.bytes(), nil
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
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
