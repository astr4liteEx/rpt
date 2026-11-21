package report

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/astr4liteEx/rpt/sdk"
)

// scopeHeader is the header row of a new report's scope.csv.
const scopeHeader = "id,host,port,protocol\n"

// New creates an empty report at dir: a report config naming this format
// version and the default severities and required sections, a scope.csv
// with only its header row, and empty findings and pages folders. Parent folders
// are created as needed. It refuses, changing nothing, when dir is anything
// but a missing path or an empty folder, or lies inside a report.
func New(dir string) error {
	return NewLike(dir, "", false)
}

// NewLike creates an empty report at dir as New does. With like set to
// another report, it takes that report's rpt.yaml byte for byte and its
// scope.csv header (the columns, no rows); with pages also set, it copies
// the files in like's pages/ and pages/evidence/, so page IDs are kept.
// Everything is checked before anything is written.
func NewLike(dir, like string, pages bool) error {
	if err := checkNewDir(dir); err != nil {
		return fmt.Errorf("new report %s: %w", dir, err)
	}
	var config, header []byte
	var copies []string // paths relative to like
	if like != "" {
		var err error
		if config, header, copies, err = readLike(like, pages); err != nil {
			return fmt.Errorf("new report like %s: %w", like, err)
		}
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
	if config == nil {
		config = fmt.Appendf(nil, "format: %d\nseverities: [%s]\nrequired_sections: [%s]\n",
			FormatVersion, strings.Join(sevs, ", "), strings.Join(DefaultRequiredSections, ", "))
	}
	if header == nil {
		header = []byte(scopeHeader)
	}
	for name, body := range map[string][]byte{ConfigFile: config, ScopeFile: header} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
			return fmt.Errorf("new report: %w", err)
		}
	}
	for _, rel := range copies {
		body, err := os.ReadFile(filepath.Join(like, rel))
		if err == nil {
			if err = os.MkdirAll(filepath.Dir(filepath.Join(dir, rel)), 0o755); err == nil {
				err = os.WriteFile(filepath.Join(dir, rel), body, 0o644)
			}
		}
		if err != nil {
			return fmt.Errorf("new report: copy %s: %w", rel, err)
		}
	}
	return nil
}

// readLike reads what NewLike takes from the report at like: its config,
// its scope.csv header row (nil when it has no scope.csv), and, with pages,
// the regular files in pages/ and pages/evidence/.
func readLike(like string, pages bool) (config, header []byte, copies []string, err error) {
	if info, err := os.Stat(filepath.Join(like, ConfigFile)); err != nil || !info.Mode().IsRegular() {
		return nil, nil, nil, ErrNotReport
	}
	if config, err = os.ReadFile(filepath.Join(like, ConfigFile)); err != nil {
		return nil, nil, nil, err
	}
	if f, err := os.Open(filepath.Join(like, ScopeFile)); err == nil {
		row, err := csv.NewReader(bufio.NewReader(f)).Read()
		f.Close()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("%s: header row: %w", ScopeFile, err)
		}
		var b bytes.Buffer
		w := csv.NewWriter(&b)
		w.Write(row)
		w.Flush()
		header = b.Bytes()
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil, err
	}
	if !pages {
		return config, header, nil, nil
	}
	for _, d := range []string{PagesDir, PageEvidenceDir} {
		entries, err := os.ReadDir(filepath.Join(like, d))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, nil, nil, err
		}
		for _, en := range entries {
			if en.Type().IsRegular() {
				copies = append(copies, filepath.Join(d, en.Name()))
			}
		}
	}
	return config, header, copies, nil
}

// Locate describes the report at dir as rpt ls lists it, with dir made
// absolute.
func Locate(dir string) (sdk.Location, []error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return sdk.Location{Kind: "location", Path: dir}, []error{err}
	}
	return locate(abs)
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
