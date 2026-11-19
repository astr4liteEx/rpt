package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// lsTree builds a project folder holding reports in the places rpt ls must
// find, and in the places it must skip.
func lsTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	newReport := func(rel string) string {
		dir := filepath.Join(root, rel)
		if code, _, errOut := runIn(t, "", "new", dir); code != 0 {
			t.Fatalf("new %s: exit %d, stderr %q", rel, code, errOut)
		}
		return dir
	}
	newReport("acme-external")
	internal := newReport("2026/acme-internal")
	in := `{"kind":"finding","title":"A","severity":"low"}` + "\n" + `{"kind":"finding","title":"B","severity":"high"}` + "\n"
	if code, _, errOut := runIn(t, in, "findings", "add", "--report", internal); code != 0 {
		t.Fatalf("add: exit %d, stderr %q", code, errOut)
	}
	newReport(".archive/old")                                                 // hidden: skipped
	if err := os.Symlink(internal, filepath.Join(root, "link")); err != nil { // symlink: not followed
		t.Fatal(err)
	}
	broken := newReport("broken")
	if err := os.WriteFile(filepath.Join(broken, "rpt.yaml"), []byte("format: [\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "notes", "empty"), 0o755); err != nil { // no report
		t.Fatal(err)
	}
	return root
}

func TestLsVerb(t *testing.T) {
	root := lsTree(t)
	code, out, errOut := runIn(t, "", "ls", root)
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	want := "location " + filepath.Join(root, "2026/acme-internal") + " 1 2\n" +
		"location " + filepath.Join(root, "acme-external") + " 1 0\n" +
		"location " + filepath.Join(root, "broken") + "  \n"
	if got := pick(t, out, "kind", "path", "format", "findings"); got != want {
		t.Errorf("stdout\n got: %q\nwant: %q", got, want)
	}
	if !strings.Contains(errOut, "broken/rpt.yaml") {
		t.Errorf("stderr %q; want a warning naming the config that doesn't parse", errOut)
	}
}

func TestLsDefaultsToWorkingFolder(t *testing.T) {
	root := lsTree(t)
	t.Chdir(filepath.Join(root, "2026"))
	code, out, errOut := runIn(t, "", "ls")
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if got, want := pick(t, out, "path"), filepath.Join(root, "2026/acme-internal")+"\n"; got != want {
		t.Errorf("paths\n got: %q\nwant: %q", got, want)
	}
}

func TestLsInsideAReport(t *testing.T) {
	root := lsTree(t)
	code, out, _ := runIn(t, "", "ls", filepath.Join(root, "acme-external"))
	if got, want := pick(t, out, "path"), filepath.Join(root, "acme-external")+"\n"; code != 0 || got != want {
		t.Errorf("exit %d, paths %q; want only the report itself", code, got)
	}
}
