package report

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNew(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "r")
	if err := New(dir, "", false); err != nil {
		t.Fatal(err)
	}
	m, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if ps := m.Check(); len(ps) != 0 {
		t.Errorf("a new report has problems: %v", problems(ps))
	}
	if err := New(filepath.Join(dir, "inner"), "", false); err == nil {
		t.Error("made a report inside a report")
	}
	if err := New(dir, "", false); err == nil {
		t.Error("made a report in a folder that isn't empty")
	}
}

func TestNewLike(t *testing.T) {
	src := fixture(t, map[string]string{
		"pages/P-001-a.md":     "---\nid: P-001\ntitle: A\n---\n\n![x](evidence/a.png)\n",
		"pages/evidence/a.png": "png",
	})
	dir := filepath.Join(t.TempDir(), "r")
	if err := New(dir, src.Dir, true); err != nil {
		t.Fatal(err)
	}
	cfg, _ := os.ReadFile(filepath.Join(src.Dir, ConfigFile))
	got, _ := os.ReadFile(filepath.Join(dir, ConfigFile))
	if string(got) != string(cfg) {
		t.Error("config not copied")
	}
	m, _ := Load(dir)
	if len(m.Scope.Rows) != 0 || len(m.Scope.Header) != len(src.Scope.Header) {
		t.Errorf("scope %v %d rows", m.Scope.Header, len(m.Scope.Rows))
	}
	if _, err := m.Get(PageKind, "P-001"); err != nil || !m.exists("pages/evidence/a.png") {
		t.Errorf("pages not copied: %v", err)
	}
	if len(m.Docs(FindingKind)) != 0 {
		t.Error("findings copied")
	}
}
