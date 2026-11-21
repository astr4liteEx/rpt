package report

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ErrNoReport is no report named and none around the working directory.
var ErrNoReport = errors.New("no report: pass --report, set RPT_REPORT_DIR, or run inside a folder with " + ConfigFile)

// Where is how the caller says which report: the --report flag, the
// RPT_REPORT_DIR variable and the working directory.
type Where struct{ Flag, Env, Cwd string }

// Root finds the report folder: Flag, else Env, else the nearest folder
// at or above Cwd that holds rpt.yaml.
func Root(w Where) (string, error) {
	if w.Flag != "" {
		return w.Flag, nil
	}
	if w.Env != "" {
		return w.Env, nil
	}
	for dir := w.Cwd; ; {
		if isReport(dir) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", ErrNoReport
		}
		dir = parent
	}
}

// isReport reports whether dir holds rpt.yaml, a regular file or a link
// to one.
func isReport(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, ConfigFile))
	return err == nil && info.Mode().IsRegular()
}

// Find lists every report at or under dir, by absolute path, never
// looking inside a report for another and skipping hidden folders and
// symlinks to folders.
func Find(dir string) ([]string, error) {
	root, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	var found []string
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		switch {
		case err != nil && p == root:
			return err
		case err != nil || !d.IsDir():
			return nil
		case p != root && strings.HasPrefix(d.Name(), "."):
			return filepath.SkipDir
		case isReport(p):
			found = append(found, p)
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("search %s: %w", root, err)
	}
	return found, nil
}
