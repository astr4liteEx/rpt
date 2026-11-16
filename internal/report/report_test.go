package report

import (
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/astr4liteEx/rpt/sdk"
)

const fixture = "../../testdata/fixture"

func openFixture(t *testing.T) *Report {
	t.Helper()
	r, err := Open(fixture)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

func TestConfig(t *testing.T) {
	cfg, err := openFixture(t).Config()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Format != 1 || cfg.Name != "Acme external test" || cfg.Client != "Acme" {
		t.Errorf("format/name/client = %d/%q/%q", cfg.Format, cfg.Name, cfg.Client)
	}
	if cfg.Period.Start != "2026-11-02" || cfg.Period.End != "2026-11-06" {
		t.Errorf("period = %+v, want 2026-11-02..2026-11-06", cfg.Period)
	}
	want := []sdk.Severity{"critical", "high", "medium", "low", "info"}
	if !slices.Equal(cfg.Severities, want) {
		t.Errorf("severities = %v, want %v", cfg.Severities, want)
	}
	if len(cfg.UnknownKeys) != 0 {
		t.Errorf("unknown keys = %v, want none", cfg.UnknownKeys)
	}
}

// copyFixture gives a test its own writable copy of the fixture report.
func copyFixture(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "report")
	if err := os.CopyFS(dir, os.DirFS(fixture)); err != nil {
		t.Fatal(err)
	}
	return dir
}

func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, rel), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestConfigDefaultsAndUnknownKeys(t *testing.T) {
	dir := copyFixture(t)
	writeFile(t, dir, "rpt.yaml", "format: 1\nname: N\nclient: C\nrenderer: typst\nlogo: acme.png\n")
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	cfg, err := r.Config()
	if err != nil {
		t.Fatal(err)
	}
	if want := []sdk.Severity{"critical", "high", "medium", "low", "info"}; !slices.Equal(cfg.Severities, want) {
		t.Errorf("severities = %v, want defaults %v", cfg.Severities, want)
	}
	if want := []string{"renderer", "logo"}; !slices.Equal(cfg.UnknownKeys, want) {
		t.Errorf("unknown keys = %v, want %v", cfg.UnknownKeys, want)
	}
}

func TestConfigBadYAMLNamesFileAndLine(t *testing.T) {
	dir := copyFixture(t)
	writeFile(t, dir, "rpt.yaml", "format: 1\nname: [unclosed\n")
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	_, err = r.Config()
	fe, ok := errors.AsType[*FileError](err)
	if !ok {
		t.Fatalf("err = %v, want a *FileError", err)
	}
	if fe.Path != "rpt.yaml" || fe.Line == 0 {
		t.Errorf("FileError = %s:%d, want rpt.yaml with a line", fe.Path, fe.Line)
	}
}

func TestConfigRequiredSectionsAndKeyLines(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want []string
	}{
		{"absent: the three fixed sections", "format: 1\n", []string{"description", "remediation", "poc"}},
		{"empty: none required", "format: 1\nrequired_sections: []\n", []string{}},
		{"custom headings keep their text", "format: 1\nrequired_sections: [description, References]\n", []string{"description", "References"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := copyFixture(t)
			writeFile(t, dir, "rpt.yaml", tt.yaml)
			r, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			cfg, err := r.Config()
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(cfg.RequiredSections, tt.want) || cfg.RequiredSections == nil {
				t.Errorf("required sections = %#v, want %#v", cfg.RequiredSections, tt.want)
			}
			if len(cfg.UnknownKeys) != 0 {
				t.Errorf("unknown keys = %v", cfg.UnknownKeys)
			}
		})
	}

	cfg, err := openFixture(t).Config()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"format": 2, "name": 3, "client": 4, "period": 5, "severities": 6}
	if !maps.Equal(cfg.KeyLines, want) {
		t.Errorf("key lines = %v, want %v", cfg.KeyLines, want)
	}
}

func TestConfigEmptySeveritiesStayEmpty(t *testing.T) {
	dir := copyFixture(t)
	writeFile(t, dir, "rpt.yaml", "format: 1\nseverities: []\n")
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	cfg, err := r.Config()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Severities) != 0 {
		t.Errorf("severities = %v; an explicit empty list must not become the defaults, so validate can report it", cfg.Severities)
	}
}
