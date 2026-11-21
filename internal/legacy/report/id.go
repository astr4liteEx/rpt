package report

import (
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strconv"
)

// findingID is the form every finding ID takes: F- and at least three digits.
var findingID = regexp.MustCompile(`^F-([0-9]{3,})$`)

// fileID matches a finding file named for its ID: F-NNN.md or F-NNN-....
var fileID = regexp.MustCompile(`^F-([0-9]{3,})(?:-.*)?\.md$`)

// ValidID reports whether id is a well-formed finding ID.
func ValidID(id string) bool { return findingID.MatchString(id) }

// NextID returns the next free finding ID: the highest F- number in
// findings/, plus one. Files that don't parse, and malformed IDs, are
// ignored here; validate reports them.
func (r *Report) NextID() (string, error) {
	list, err := r.Findings()
	if err != nil && !onlyFileErrors(err) {
		return "", err
	}
	highest := 0
	// A file named F-NNN-... counts too, so the ID of a file that doesn't
	// parse is never given out again.
	if ents, err := fs.ReadDir(r.fsys(), FindingsDir); err == nil {
		for _, ent := range ents {
			if m := fileID.FindStringSubmatch(ent.Name()); m != nil {
				if n, err := strconv.Atoi(m[1]); err == nil && n > highest {
					highest = n
				}
			}
		}
	}
	for _, f := range list {
		m := findingID.FindStringSubmatch(f.ID)
		if m == nil {
			continue
		}
		if n, err := strconv.Atoi(m[1]); err == nil && n > highest {
			highest = n
		}
	}
	return fmt.Sprintf("F-%03d", highest+1), nil
}

// onlyFileErrors reports whether err holds nothing but *FileError values.
func onlyFileErrors(err error) bool {
	errs := []error{err}
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		errs = j.Unwrap()
	}
	for _, e := range errs {
		if _, ok := errors.AsType[*FileError](e); !ok {
			return false
		}
	}
	return true
}
