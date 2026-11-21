package report

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// fixture loads a copy of testdata/fixture, changed by edits: file path
// to content, "" to remove.
func fixture(t *testing.T, edits map[string]string) *Model {
	t.Helper()
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS("../../testdata/fixture")); err != nil {
		t.Fatal(err)
	}
	for rel, content := range edits {
		p := filepath.Join(dir, rel)
		if content == "" {
			os.Remove(p)
			continue
		}
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	m, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	return m
}

func TestLoadFixture(t *testing.T) {
	m := fixture(t, nil)
	if m.Config.Err != nil || m.Config.Format != 2 {
		t.Fatalf("config: %+v", m.Config)
	}
	var ids []string
	for _, d := range m.Docs(FindingKind) {
		if d.Err != nil {
			t.Fatal(d.Err)
		}
		ids = append(ids, d.ID+" "+d.Path)
	}
	want := []string{"F-003 findings/sqli-login.md", "F-002 findings/tls-weak.md", "F-001 findings/xss-search.md"}
	if !slices.Equal(ids, want) {
		t.Errorf("findings %q", ids)
	}
	f, err := m.Get(FindingKind, "f-003")
	if err != nil {
		t.Fatal(err)
	}
	if f.Title != "SQL injection in login" || f.Severity != "high" || len(f.Targets) != 2 || f.Targets[1].Scope != "S-14" || f.Targets[0].Line != 4 {
		t.Errorf("F-003: %+v", f)
	}
	if len(f.Extra) != 1 || f.Extra[0].Key.Value != "cvss" {
		t.Errorf("extra: %+v", f.Extra)
	}
	if s, ok := f.Section("description"); !ok || s.Heading != "Description" || s.Line != 10 || s.TextLine != 12 {
		t.Errorf("description: %+v", s)
	}
	if m.NextID(FindingKind) != "F-004" || m.NextID(PageKind) != "P-001" {
		t.Errorf("next IDs %s %s", m.NextID(FindingKind), m.NextID(PageKind))
	}
	if r, err := m.Scope.Row("s-20"); err != nil || r.Host != "10.0.1.0/24" || r.Extra["env"] != "staging" || r.Line != 4 {
		t.Errorf("S-20: %+v %v", r, err)
	}
}

func TestBrokenFilesAreKept(t *testing.T) {
	m := fixture(t, map[string]string{
		"findings/F-009-broken.md": "---\nid: F-009\ntitle: [\n---\n",
		"findings/reserved.md":     "---\nid: F-010\nkind: x\n---\n",
	})
	var errs []string
	for _, d := range m.Docs(FindingKind) {
		if d.Err != nil {
			errs = append(errs, d.Err.Error())
		}
	}
	if len(errs) != 2 {
		t.Fatalf("errors %q", errs)
	}
	// A broken file's number is never given out again.
	if got := m.NextID(FindingKind); got != "F-010" {
		t.Errorf("next ID %s", got)
	}
}

func TestDuplicateIDs(t *testing.T) {
	m := fixture(t, map[string]string{"findings/dup.md": "---\nid: F-003\ntitle: Dup\n---\n"})
	if _, err := m.Get(FindingKind, "F-003"); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("got %v", err)
	}
	if !m.Taken(FindingKind, "F-003") {
		t.Error("a duplicated ID is free")
	}
}

func TestScopeReading(t *testing.T) {
	m := fixture(t, map[string]string{ScopeFile: "\xef\xbb\xbf ID , Host,Port\r\nS-1,a,80\r\ns-1,b,\r\nS-2,,\r\n"})
	s := m.Scope
	if s.Err != nil {
		t.Fatal(s.Err)
	}
	if len(s.Rows) != 1 || len(s.RowErrs) != 2 {
		t.Fatalf("rows %+v errs %v", s.Rows, s.RowErrs)
	}
	if r := s.Rows[0]; r.ID != "S-1" || r.Port != 80 || string(s.src[r.Start:r.End]) != "S-1,a,80\r\n" {
		t.Errorf("row %+v", r)
	}
}

func TestPageIDsCountTheConfig(t *testing.T) {
	m := fixture(t, map[string]string{ConfigFile: "format: 2\npages: [P-004, findings]\n"})
	if got := m.NextID(PageKind); got != "P-005" {
		t.Errorf("next page ID %s", got)
	}
	if !m.Taken(PageKind, "P-004") {
		t.Error("P-004 is in the config but free")
	}
}

func TestRoot(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ConfigFile), []byte("format: 2\n"), 0o644)
	sub := filepath.Join(dir, "a", "b")
	os.MkdirAll(sub, 0o755)
	if got, err := Root(Where{Cwd: sub}); err != nil || got != dir {
		t.Errorf("got %s %v", got, err)
	}
	if got, _ := Root(Where{Flag: "x", Env: "y", Cwd: sub}); got != "x" {
		t.Errorf("flag: %s", got)
	}
	if _, err := Root(Where{Cwd: t.TempDir()}); !errors.Is(err, ErrNoReport) {
		t.Errorf("got %v", err)
	}
	found, err := Find(filepath.Dir(dir))
	if err != nil || !slices.Contains(found, dir) {
		t.Errorf("find: %v %v", found, err)
	}
}
