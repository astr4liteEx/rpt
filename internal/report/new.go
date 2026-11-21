package report

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// scopeHeader is the header row of a new report's scope.csv.
const scopeHeader = "id,host,port,protocol\n"

// New creates an empty report at dir: a report config naming this format
// version and the default severities and required sections, a scope.csv
// with only its header row, and empty findings and pages folders. Parent folders
// are created as needed. It refuses, changing nothing, when dir is anything
// but a missing path or an empty folder, or lies inside a report.
func New(dir string) error {
	if err := checkNewDir(dir); err != nil {
		return fmt.Errorf("new report %s: %w", dir, err)
	}
	for _, d := range []string{FindingsDir, PagesDir} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			return fmt.Errorf("new report: %w", err)
		}
	}
	sevs := make([]string, len(DefaultSeverities))
	for i, s := range DefaultSeverities {
		sevs[i] = string(s)
	}
	config := fmt.Sprintf("format: %d\nseverities: [%s]\nrequired_sections: [%s]\n",
		FormatVersion, strings.Join(sevs, ", "), strings.Join(DefaultRequiredSections, ", "))
	for name, body := range map[string]string{ConfigFile: config, ScopeFile: scopeHeader} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			return fmt.Errorf("new report: %w", err)
		}
	}
	return nil
}

// checkNewDir says why dir can't hold a new report, or returns nil.
func checkNewDir(dir string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	for d := abs; ; d = filepath.Dir(d) {
		if info, err := os.Stat(filepath.Join(d, ConfigFile)); err == nil && info.Mode().IsRegular() {
			return fmt.Errorf("inside the report at %s", d)
		}
		if filepath.Dir(d) == d {
			break
		}
	}
	entries, err := os.ReadDir(abs)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		if info, statErr := os.Stat(abs); statErr == nil && !info.IsDir() {
			return errors.New("exists and is not a folder")
		}
		return err
	case len(entries) > 0:
		return errors.New("folder is not empty")
	}
	return nil
}
