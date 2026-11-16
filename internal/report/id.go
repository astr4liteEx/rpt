package report

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
)

// findingID is the form every finding ID takes: F- and at least three digits.
var findingID = regexp.MustCompile(`^F-([0-9]{3,})$`)

// ValidID reports whether id is a well-formed finding ID.
func ValidID(id string) bool { return findingID.MatchString(id) }

// NextID returns the next free finding ID: the highest F- number in
// findings/, staging/ and rejected/, plus one. Counting rejected/ means a
// rejected finding's number is never handed out again. Files that don't
// parse, and malformed IDs, are ignored here; validate reports them.
func (r *Report) NextID() (string, error) {
	highest := 0
	for _, dir := range []string{FindingsDir, StagingDir, RejectedDir} {
		list, err := r.FindingsIn(dir)
		if err != nil && !onlyFileErrors(err) {
			return "", err
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
