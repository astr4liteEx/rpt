package report

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrNoReport means no report folder was named and none contains the
// working directory.
var ErrNoReport = errors.New("no report: pass --report, set RPT_REPORT_DIR, or run inside a folder with " + ConfigFile)

// Root finds the report folder the way git finds .git: flag (the value of
// --report, which the CLI passes in), then $RPT_REPORT_DIR, then the nearest
// directory at or above the working directory that holds rpt.yaml.
func Root(flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	if env := os.Getenv("RPT_REPORT_DIR"); env != "" {
		return env, nil
	}
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("find report: %w", err)
	}
	for {
		info, err := os.Stat(filepath.Join(dir, ConfigFile))
		if err == nil && info.Mode().IsRegular() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", ErrNoReport
		}
		dir = parent
	}
}
