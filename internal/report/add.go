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

// AddOptions says where rpt add writes and whether it matches keys.
type AddOptions struct {
	Staging bool // write to staging/ instead of findings/
	Upsert  bool // update the finding with the same key instead of adding
}

// AddResult is what Add did with one record.
type AddResult struct {
	// Finding is the finding as stored. When Skipped, it is the reviewed
	// finding in another folder that holds the same key.
	Finding sdk.Finding
	Skipped bool
}

// Add writes one finding record into findings/ (or staging/). With Upsert
// and a key, a finding with that key in the folder being written is
// updated in place: the record's fields and sections are set into it and
// everything else in the file, including its ID, stays. A finding with that
// key in another review folder means it has already been reviewed, so the
// record is skipped. Anything else is a new file named F-NNN-<slug>.md,
// taking the record's id or the next free one.
func (r *Report) Add(rec sdk.Finding, opts AddOptions) (AddResult, error) {
	cfg, err := r.Config()
	if err != nil {
		return AddResult{}, err
	}
	if err := checkRecord(rec, cfg.Severities); err != nil {
		return AddResult{}, err
	}
	dir := FindingsDir
	if opts.Staging {
		dir = StagingDir
	}

	if opts.Upsert && rec.Key != "" {
		match, err := r.findKey(rec.Key, dir)
		if err != nil {
			return AddResult{}, err
		}
		if match != nil {
			if path.Dir(match.Path) != dir {
				return AddResult{Finding: *match, Skipped: true}, nil
			}
			f, err := r.edit(match.Path, func(ff *findingFile) error { return ff.apply(rec, false) })
			return AddResult{Finding: f}, err
		}
	}

	id := rec.ID
	if id == "" {
		if id, err = r.NextID(); err != nil {
			return AddResult{}, err
		}
	} else if _, err := r.locate(id); err == nil {
		return AddResult{}, fmt.Errorf("%w: id: %s is already taken", ErrBadValue, id)
	}
	rec.ID = id
	rel := path.Join(dir, id+"-"+slug(rec.Title)+".md")
	if _, err := r.root.Stat(rel); !errors.Is(err, fs.ErrNotExist) {
		return AddResult{}, fmt.Errorf("add %s: file already exists", rel)
	}

	var ff findingFile
	if err := ff.apply(rec, true); err != nil {
		return AddResult{}, err
	}
	out := ff.bytes()
	f, err := parseFinding(rel, out)
	if err != nil {
		return AddResult{}, fmt.Errorf("add would write a broken %s: %w", rel, err)
	}
	if err := r.root.MkdirAll(dir, 0o755); err != nil {
		return AddResult{}, fmt.Errorf("add: %w", err)
	}
	if err := writeAtomic(r.root, rel, out); err != nil {
		return AddResult{}, err
	}
	return AddResult{Finding: f}, nil
}

// findKey returns the finding holding key, looking first in the folder
// being written, then in the other review folders; nil when none does.
func (r *Report) findKey(key, dir string) (*sdk.Finding, error) {
	order := []string{dir}
	for _, d := range []string{FindingsDir, StagingDir, RejectedDir} {
		if d != dir {
			order = append(order, d)
		}
	}
	for _, d := range order {
		list, err := r.FindingsIn(d)
		if err != nil && !onlyFileErrors(err) {
			return nil, err
		}
		for _, f := range list {
			if f.Key == key {
				return &f, nil
			}
		}
	}
	return nil, nil
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

// apply sets a record's fields and sections into the file. A new file
// gets them all, in a fixed order, starting with id; an existing file keeps
// its id and every field and section the record leaves out.
func (ff *findingFile) apply(rec sdk.Finding, isNew bool) error {
	type field struct {
		key string
		val any
	}
	var fields []field
	if isNew {
		fields = append(fields, field{"id", rec.ID})
	}
	if rec.Key != "" {
		fields = append(fields, field{"key", rec.Key})
	}
	fields = append(fields, field{"title", rec.Title})
	if rec.Scope != nil || isNew {
		fields = append(fields, field{"scope", nonNil(rec.Scope)})
	}
	fields = append(fields, field{"severity", rec.Severity})
	if rec.Evidence != nil {
		fields = append(fields, field{"evidence", rec.Evidence})
	}
	if rec.Target != nil {
		fields = append(fields, field{"target", rec.Target})
	}
	for _, k := range slices.Sorted(maps.Keys(rec.Extra)) {
		fields = append(fields, field{k, rec.Extra[k]})
	}
	for _, fl := range fields {
		n, err := toNode(fl.val)
		if err != nil {
			return fmt.Errorf("%s: %w", fl.key, err)
		}
		if err := ff.setEntry(fl.key, n); err != nil {
			return fmt.Errorf("%s: %w", fl.key, err)
		}
	}
	for _, key := range sectionOrder(rec.Sections) {
		ff.setSection(key, rec.Sections[key])
	}
	return nil
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
