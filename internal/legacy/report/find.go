package report

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/astr4liteEx/rpt/sdk"
)

// Find lists every report at or under dir, in path order, with absolute
// paths. It doesn't descend into a report it found (reports don't nest),
// skips hidden folders below dir, and never follows symlinks. Problems
// don't stop the search: a report whose config doesn't parse is listed
// without its format and finding count, and each problem comes back as a
// *FileError (path absolute) next to the list.
func Find(dir string) ([]sdk.Location, []error) {
	root, err := filepath.Abs(dir)
	if err != nil {
		return nil, []error{err}
	}
	var (
		found []sdk.Location
		errs  []error
	)
	walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == root {
				return err // the folder asked for can't be searched at all
			}
			errs = append(errs, &FileError{Path: p, Err: errors.Unwrap(err)})
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		if p != root && strings.HasPrefix(d.Name(), ".") {
			return filepath.SkipDir
		}
		if info, err := os.Lstat(filepath.Join(p, ConfigFile)); err != nil || !info.Mode().IsRegular() {
			return nil
		}
		loc, locErrs := locate(p)
		found = append(found, loc)
		errs = append(errs, locErrs...)
		return filepath.SkipDir
	})
	if walkErr != nil {
		return nil, []error{fmt.Errorf("search %s: %w", root, walkErr)}
	}
	return found, errs
}

// locate describes the report at dir: its format version and how many
// findings parse. Problems reading it come back with their paths absolute.
func locate(dir string) (sdk.Location, []error) {
	loc := sdk.Location{Kind: "location", Path: dir}
	abs := func(err error) error {
		if fe, ok := errors.AsType[*FileError](err); ok {
			return &FileError{Path: filepath.Join(dir, fe.Path), Line: fe.Line, Err: fe.Err}
		}
		return fmt.Errorf("%s: %w", dir, err)
	}
	r, err := Open(dir)
	if err != nil {
		return loc, []error{abs(err)}
	}
	defer r.Close()
	cfg, err := r.Config()
	if err != nil {
		return loc, []error{abs(err)}
	}
	list, err := r.Findings()
	n := len(list)
	loc.Format, loc.Findings = &cfg.Format, &n
	var errs []error
	for _, e := range unjoin(err) {
		errs = append(errs, abs(e))
	}
	return loc, errs
}

// ErrNotReport means the folder rpt was pointed at has no rpt.yaml.
var ErrNotReport = errors.New("not a report: no " + ConfigFile)

// Current describes the report every verb would act on, found by Root from
// flag (the value of --report). The error is why there is no such report:
// none found, a folder that can't be opened, or one without rpt.yaml.
// Problems reading the report itself come back in the slice, as Find
// gives them, next to a location without its format or finding count.
func Current(flag string) (sdk.Location, []error, error) {
	dir, err := Root(flag)
	if err != nil {
		return sdk.Location{}, nil, err
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return sdk.Location{}, nil, fmt.Errorf("open report %s: %w", dir, err)
	}
	if _, err := os.Stat(abs); err != nil {
		return sdk.Location{}, nil, fmt.Errorf("open report %s: %w", dir, err)
	}
	if info, err := os.Stat(filepath.Join(abs, ConfigFile)); err != nil || !info.Mode().IsRegular() {
		return sdk.Location{}, nil, fmt.Errorf("%s: %w", abs, ErrNotReport)
	}
	loc, errs := locate(abs)
	return loc, errs, nil
}
