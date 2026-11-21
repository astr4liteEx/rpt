package report

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAtomic(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "findings")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(sub, "a.md")
	if err := os.WriteFile(name, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	t.Run("replaces content and keeps the mode", func(t *testing.T) {
		if err := writeAtomic(root, "findings/a.md", []byte("new")); err != nil {
			t.Fatal(err)
		}
		got, _ := os.ReadFile(name)
		info, _ := os.Stat(name)
		if string(got) != "new" || info.Mode().Perm() != 0o600 {
			t.Errorf("content %q mode %v, want \"new\" 0600", got, info.Mode().Perm())
		}
		assertOnlyFile(t, sub, "a.md")
	})
	t.Run("a new file gets 0644", func(t *testing.T) {
		if err := writeAtomic(root, "findings/b.md", []byte("b")); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(filepath.Join(sub, "b.md"))
		if err != nil || info.Mode().Perm() != 0o644 {
			t.Errorf("mode %v, err %v; want 0644", info.Mode().Perm(), err)
		}
		os.Remove(filepath.Join(sub, "b.md"))
	})
	t.Run("a failed write leaves the original and no temp file", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("root ignores folder permissions")
		}
		if err := os.Chmod(sub, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(sub, 0o755) })
		if err := writeAtomic(root, "findings/a.md", []byte("lost")); err == nil {
			t.Fatal("write into a read-only folder succeeded")
		}
		got, _ := os.ReadFile(name)
		if string(got) != "new" {
			t.Errorf("original now %q, want \"new\"", got)
		}
		assertOnlyFile(t, sub, "a.md")
	})
}

func assertOnlyFile(t *testing.T, dir, want string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != want {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("folder holds %v, want only %s", names, want)
	}
}
