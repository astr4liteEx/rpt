package report

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func readDisk(t *testing.T, m *Model, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(m.Dir, rel))
	if errors.Is(err, fs.ErrNotExist) {
		return "<absent>"
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// tree lists every file in the report folder, hidden ones too.
func tree(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	return out
}

func TestSaveWritesAndRemoves(t *testing.T) {
	m := fixture(t, nil)
	if err := m.put("findings/F-004-new.md", []byte("new")); err != nil {
		t.Fatal(err)
	}
	if err := m.remove("findings/tls-weak.md"); err != nil {
		t.Fatal(err)
	}
	if err := m.Save(false); err != nil {
		t.Fatal(err)
	}
	if readDisk(t, m, "findings/F-004-new.md") != "new" || readDisk(t, m, "findings/tls-weak.md") != "<absent>" {
		t.Fatal("not saved")
	}
	for _, f := range tree(t, m.Dir) {
		if f == journalFile || filepath.Dir(f) == stagingDir {
			t.Errorf("left behind: %s", f)
		}
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	m := fixture(t, nil)
	before := tree(t, m.Dir)
	m.put("findings/F-004-new.md", []byte("new"))
	if err := m.Save(true); err != nil {
		t.Fatal(err)
	}
	if after := tree(t, m.Dir); !slices.Equal(before, after) {
		t.Errorf("dry run changed the folder: %v", after)
	}
}

func TestSaveRefusesAChangeMadeMeanwhile(t *testing.T) {
	m := fixture(t, nil)
	m.put("findings/xss-search.md", []byte("mine"))
	os.WriteFile(filepath.Join(m.Dir, "findings/xss-search.md"), []byte("theirs"), 0o644)
	var c *ConflictError
	if err := m.Save(false); !errors.As(err, &c) {
		t.Fatalf("got %v", err)
	}
	if readDisk(t, m, "findings/xss-search.md") != "theirs" {
		t.Error("overwrote someone else's change")
	}
}

func TestConcurrentAddsCantTakeTheSameID(t *testing.T) {
	a := fixture(t, nil)
	b, err := Load(a.Dir)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if a.NextID(FindingKind) != "F-004" || b.NextID(FindingKind) != "F-004" {
		t.Fatal("setup")
	}
	a.put("findings/F-004-a.md", []byte("---\nid: F-004\n---\n"))
	b.put("findings/F-004-b.md", []byte("---\nid: F-004\n---\n"))
	if err := a.Save(false); err != nil {
		t.Fatal(err)
	}
	var c *ConflictError
	if err := b.Save(false); !errors.As(err, &c) {
		t.Fatalf("second add got %v", err)
	}
}

func TestPermissionsAreKept(t *testing.T) {
	m := fixture(t, nil)
	p := filepath.Join(m.Dir, "findings/xss-search.md")
	os.Chmod(p, 0o600)
	m, _ = Load(m.Dir)
	defer m.Close()
	m.put("findings/xss-search.md", []byte("x"))
	if err := m.Save(false); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(p); info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", info.Mode().Perm())
	}
	src := filepath.Join(t.TempDir(), "shot.png")
	os.WriteFile(src, []byte("png"), 0o640)
	m.copyIn("findings/evidence/F-001-shot.png", src)
	if err := m.Save(false); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(filepath.Join(m.Dir, "findings/evidence/F-001-shot.png")); info.Mode().Perm() != 0o640 {
		t.Errorf("copy mode %v", info.Mode().Perm())
	}
}

// A rename is a new file and a removed one. Wherever a save stops, the
// next Load leaves exactly one of the two, never neither.
func TestACrashAnywhereLosesNothing(t *testing.T) {
	const oldPath, newPath = "findings/xss-search.md", "findings/F-001-renamed.md"
	for _, stop := range []string{"after staging", "after the journal", "after the first step"} {
		t.Run(stop, func(t *testing.T) {
			m := fixture(t, nil)
			content := readDisk(t, m, oldPath)
			m.put(newPath, []byte(content))
			m.remove(oldPath)
			ops, err := m.stage(m.Changed())
			if err != nil {
				t.Fatal(err)
			}
			if stop != "after staging" {
				if err := m.writeJournal(ops); err != nil {
					t.Fatal(err)
				}
			}
			if stop == "after the first step" {
				if ops[0].To != newPath {
					t.Fatalf("the new file isn't placed first: %+v", ops)
				}
				m.root.Rename(ops[0].From, ops[0].To)
			}
			m.Close()

			again, err := Load(m.Dir) // the next command
			if err != nil {
				t.Fatal(err)
			}
			defer again.Close()
			got := []string{readDisk(t, again, oldPath), readDisk(t, again, newPath)}
			switch stop {
			case "after staging": // nothing committed: as before
				if got[0] != content || got[1] != "<absent>" {
					t.Errorf("got %q", got)
				}
			default: // committed: finished
				if got[0] != "<absent>" || got[1] != content {
					t.Errorf("got %q", got)
				}
			}
			for _, f := range tree(t, again.Dir) {
				if f == journalFile || filepath.Dir(f) == stagingDir {
					t.Errorf("left behind: %s", f)
				}
			}
		})
	}
}
