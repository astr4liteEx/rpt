package report

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/astr4liteEx/rpt/sdk"
)

// New creates an empty report at dir: an rpt.yaml with this format and
// the default severities and required sections, a scope.csv with only its
// header, and empty findings and pages folders. With like, another
// report, it takes that report's rpt.yaml byte for byte and its scope.csv
// columns; with pages too, its pages and their evidence, IDs kept.
// Everything is read before anything is written, and dir must be missing
// or an empty folder outside any report.
func New(dir, like string, pages bool) error {
	if err := checkNewDir(dir); err != nil {
		return fmt.Errorf("new report %s: %w", dir, err)
	}
	files := map[string][]byte{
		ConfigFile: fmt.Appendf(nil, "format: %d\nseverities: [%s]\nrequired_sections: [%s]\n",
			FormatVersion, strings.Join(DefaultSeverities, ", "), strings.Join(DefaultRequiredSections, ", ")),
		ScopeFile: []byte("id,host,port,protocol\n"),
	}
	if like != "" {
		m, err := Load(like)
		if err != nil {
			return fmt.Errorf("new report like %s: %w", like, err)
		}
		defer m.Close()
		if files[ConfigFile], _, err = m.read(ConfigFile); err != nil {
			return err
		}
		if m.Scope.Header != nil {
			var b bytes.Buffer
			w := csv.NewWriter(&b)
			w.Write(m.Scope.Header)
			w.Flush()
			files[ScopeFile] = b.Bytes()
		}
		if pages {
			for _, d := range []string{PageKind.Dir, PageKind.EvidenceDir} {
				err := fs.WalkDir(m.root.FS(), d, func(p string, e fs.DirEntry, err error) error {
					switch {
					case errors.Is(err, fs.ErrNotExist):
						return nil
					case err != nil:
						return err
					case e.IsDir() && p != d:
						return fs.SkipDir
					case e.Type().IsRegular():
						b, err := m.root.ReadFile(p)
						files[p] = b
						return err
					}
					return nil
				})
				if err != nil {
					return fmt.Errorf("new report like %s: %w", like, err)
				}
			}
		}
	}
	for _, d := range []string{FindingKind.Dir, PageKind.Dir} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			return fmt.Errorf("new report: %w", err)
		}
	}
	for rel, b := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return fmt.Errorf("new report: %w", err)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			return fmt.Errorf("new report: %w", err)
		}
	}
	return nil
}

// checkNewDir says why dir can't hold a new report.
func checkNewDir(dir string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	for d := abs; ; d = filepath.Dir(d) {
		if isReport(d) {
			return fmt.Errorf("inside the report at %s", d)
		}
		if filepath.Dir(d) == d {
			break
		}
	}
	ents, err := os.ReadDir(abs)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		if info, serr := os.Stat(abs); serr == nil && !info.IsDir() {
			return errors.New("exists and is not a folder")
		}
		return err
	case len(ents) > 0:
		return errors.New("the folder is not empty")
	}
	return nil
}

// Locate describes the report at dir as rpt ls lists it. The problems are
// why its files don't read; the location is still given.
func Locate(dir string) (sdk.Location, []Problem) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}
	loc := sdk.Location{Kind: "location", Path: abs}
	m, err := Load(abs)
	if err != nil {
		return loc, []Problem{{Path: abs, Rule: "readable", Level: Error, Message: err.Error()}}
	}
	defer m.Close()
	var ps []Problem
	for _, p := range m.Check() {
		if p.Rule == "readable" {
			p.Path = path.Join(filepath.ToSlash(abs), p.Path)
			ps = append(ps, p)
		}
	}
	if m.Config.Err == nil {
		loc.Format = &m.Config.Format
	}
	n := 0
	for _, d := range m.docs[FindingKind] {
		if d.Err == nil {
			n++
		}
	}
	loc.Findings = &n
	return loc, ps
}
