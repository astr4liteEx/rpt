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
	if code, _, errOut := runIn(t, in, "finding", "add", "--report", internal); code != 0 {
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
	want := "location " + filepath.Join(root, "2026/acme-internal") + " 2 2\n" +
		"location " + filepath.Join(root, "acme-external") + " 2 0\n" +
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

func TestLsCurrent(t *testing.T) {
	root := lsTree(t)
	internal := filepath.Join(root, "2026/acme-internal")
	external := filepath.Join(root, "acme-external")
	tests := []struct {
		name, cwd, env string
		args           []string
		want           string
	}{
		{"nearest report at or above the working folder", filepath.Join(internal, "findings"), "", nil,
			"location " + internal + " 2 2\n"},
		{"RPT_REPORT_DIR before the working folder", filepath.Join(internal, "findings"), external, nil,
			"location " + external + " 2 0\n"},
		{"--report before RPT_REPORT_DIR, made absolute", root, internal, []string{"--report", "acme-external"},
			"location " + external + " 2 0\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Chdir(tt.cwd)
			t.Setenv("RPT_REPORT_DIR", tt.env)
			code, out, errOut := runIn(t, "", append([]string{"ls", "--current"}, tt.args...)...)
			if code != 0 || errOut != "" {
				t.Fatalf("exit %d, stderr %q", code, errOut)
			}
			if got := pick(t, out, "kind", "path", "format", "findings"); got != tt.want {
				t.Errorf("stdout\n got: %q\nwant: %q", got, tt.want)
			}
		})
	}
}

func TestLsCurrentBrokenReportWarns(t *testing.T) {
	root := lsTree(t)
	t.Setenv("RPT_REPORT_DIR", "")
	code, out, errOut := runIn(t, "", "ls", "--current", "--report", filepath.Join(root, "broken"))
	if code != 0 || !strings.Contains(errOut, "rpt.yaml") {
		t.Errorf("exit %d, stderr %q; want 0 and a warning about rpt.yaml", code, errOut)
	}
	if got, want := pick(t, out, "path", "format"), filepath.Join(root, "broken")+" \n"; got != want {
		t.Errorf("stdout %q, want %q", got, want)
	}
}

func TestLsCurrentNoReport(t *testing.T) {
	root := lsTree(t)
	t.Setenv("RPT_REPORT_DIR", "")
	tests := []struct {
		name, cwd, env string
		args           []string
		wantErr        string
	}{
		{"none at or above the working folder", filepath.Join(root, "notes/empty"), "", nil, "rpt: no report"},
		{"--report names a folder without rpt.yaml", root, "", []string{"--report", "notes"},
			filepath.Join(root, "notes") + ": not a report"},
		{"RPT_REPORT_DIR names a folder without rpt.yaml", root, filepath.Join(root, "notes"), nil, "not a report"},
		{"--report names a missing folder", root, "", []string{"--report", "nope"}, "open report nope"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Chdir(tt.cwd)
			t.Setenv("RPT_REPORT_DIR", tt.env)
			code, out, errOut := runIn(t, "", append([]string{"ls", "--current"}, tt.args...)...)
			if code != 1 || out != "" || !strings.Contains(errOut, tt.wantErr) {
				t.Errorf("exit %d, stdout %q, stderr %q; want 1, nothing, and %q", code, out, errOut, tt.wantErr)
			}
		})
	}
}

func TestLsCurrentUsage(t *testing.T) {
	root := lsTree(t)
	for _, args := range [][]string{{"--current", root}, {"--report", root}, {"--report", root, root}} {
		code, out, errOut := runIn(t, "", append([]string{"ls"}, args...)...)
		if code != 2 || out != "" || !strings.Contains(errOut, "usage: rpt ls") {
			t.Errorf("%v: exit %d, stdout %q, stderr %q; want 2 and usage", args, code, out, errOut)
		}
	}
}

func TestLsCurrentJSON(t *testing.T) {
	t.Setenv("RPT_REPORT_DIR", "")
	code, out, _ := runIn(t, "", "ls", "--current", "--json", "--report", fixture)
	abs, _ := filepath.Abs(fixture)
	if want := `{"kind":"location","path":"` + abs + `","format":2,"findings":3}` + "\n"; code != 0 || out != want {
		t.Errorf("exit %d, stdout %q; want %q", code, out, want)
	}
}
