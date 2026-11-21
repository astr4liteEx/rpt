package main

import (
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewVerb(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "clients", "acme-external")

	code, out, errOut := runIn(t, "", "new", dir)
	if code != 0 || out != "" || errOut != "" {
		t.Fatalf("new: exit %d, stdout %q, stderr %q", code, out, errOut)
	}

	wantConfig := "format: 2\n" +
		"severities: [critical, high, medium, low, info]\n" +
		"required_sections: [description, remediation, poc]\n"
	if got, err := os.ReadFile(filepath.Join(dir, "rpt.yaml")); err != nil || string(got) != wantConfig {
		t.Errorf("rpt.yaml = %q, %v; want %q", got, err, wantConfig)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "scope.csv")); err != nil || string(got) != "id,host,port,protocol\n" {
		t.Errorf("scope.csv = %q, %v", got, err)
	}
	if entries, err := os.ReadDir(filepath.Join(dir, "findings")); err != nil || len(entries) != 0 {
		t.Errorf("findings/ = %v, %v; want an empty folder", entries, err)
	}

	code, out, errOut = runIn(t, "", "validate", "--report", dir)
	if code != 0 || out != "" || errOut != "" {
		t.Errorf("validate on the new report: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

func TestNewRefuses(t *testing.T) {
	tests := []struct {
		name string
		dir  func(t *testing.T) string // the path passed to rpt new
	}{
		{"a folder that isn't empty", func(t *testing.T) string {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("mine"), 0o644); err != nil {
				t.Fatal(err)
			}
			return dir
		}},
		{"a file", func(t *testing.T) string {
			p := filepath.Join(t.TempDir(), "report")
			if err := os.WriteFile(p, []byte("mine"), 0o644); err != nil {
				t.Fatal(err)
			}
			return p
		}},
		{"a folder inside a report", func(t *testing.T) string {
			return filepath.Join(reportCopy(t), "findings", "nested")
		}},
		{"the root of a report", func(t *testing.T) string {
			return reportCopy(t)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := tt.dir(t)
			parent := filepath.Dir(dir)
			before := folderState(t, parent)
			_, statErr := os.Stat(dir)

			code, out, errOut := runIn(t, "", "new", dir)
			if code != 1 || out != "" || errOut == "" {
				t.Errorf("exit %d, stdout %q, stderr %q; want exit 1 and a message", code, out, errOut)
			}
			if after := folderState(t, parent); !maps.Equal(before, after) {
				t.Errorf("rpt new changed files it refused:\nbefore %v\nafter  %v", before, after)
			}
			if _, err := os.Stat(dir); os.IsNotExist(statErr) && !os.IsNotExist(err) {
				t.Errorf("rpt new created %s, which it refused", dir)
			}
		})
	}
}

func TestNewEmptyFolder(t *testing.T) {
	dir := t.TempDir()
	if code, _, errOut := runIn(t, "", "new", dir); code != 0 || errOut != "" {
		t.Fatalf("new into an empty folder: exit %d, stderr %q", code, errOut)
	}
	if code, _, errOut := runIn(t, "", "validate", "--report", dir); code != 0 {
		t.Errorf("validate: exit %d, stderr %q", code, errOut)
	}
}

func TestNewUsage(t *testing.T) {
	for _, args := range [][]string{{"new"}, {"new", "a", "b"}} {
		if code, out, errOut := runIn(t, "", args...); code != 2 || out != "" || errOut == "" {
			t.Errorf("rpt %v: exit %d, stdout %q, stderr %q; want exit 2 and usage", args, code, out, errOut)
		}
	}
}

// likeSource builds a report to copy: a page with evidence that rpt.yaml
// requires and orders, and a scope.csv with an extra column and a row.
func likeSource(t *testing.T) string {
	t.Helper()
	src := filepath.Join(t.TempDir(), "r1")
	shot := filepath.Join(t.TempDir(), "shot.png")
	if err := os.WriteFile(shot, []byte("png"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"new", src},
		{"page", "add", "--title", "Executive summary", "--report", src},
		{"page", "set", "P-001", "body", "The test went well.", "--report", src},
		{"evidence", "add", "--report", src, "P-001", shot},
		{"config", "set", "--report", src, "required_pages", "P-001"},
		{"config", "set", "--report", src, "pages", "P-001", "findings"},
	} {
		if code, _, errOut := runIn(t, "", args...); code != 0 {
			t.Fatalf("%v: exit %d, %s", args, code, errOut)
		}
	}
	if err := os.WriteFile(filepath.Join(src, "scope.csv"), []byte("id,host,port,protocol,env\nS-001,10.0.0.1,,,prod\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return src
}

func TestNewLike(t *testing.T) {
	src := likeSource(t)
	dst := filepath.Join(t.TempDir(), "r2")
	code, out, errOut := runIn(t, "", "new", dst, "--like", src, "--with-pages", "--json")
	if code != 0 || errOut != "" {
		t.Fatalf("new --like --with-pages: exit %d, stderr %q", code, errOut)
	}
	abs, _ := filepath.Abs(dst)
	if want := `{"kind":"location","path":"` + abs + `","format":2,"findings":0}` + "\n"; out != want {
		t.Errorf("stdout %q, want %q", out, want)
	}
	for _, name := range []string{"rpt.yaml", filepath.Join("pages", "evidence", "P-001-shot.png")} {
		want, _ := os.ReadFile(filepath.Join(src, name))
		if got, err := os.ReadFile(filepath.Join(dst, name)); err != nil || string(got) != string(want) {
			t.Errorf("%s = %q, %v; want a copy, %q", name, got, err, want)
		}
	}
	if pages, _ := filepath.Glob(filepath.Join(dst, "pages", "P-001-*.md")); len(pages) != 1 {
		t.Errorf("pages: %v, want P-001 kept", pages)
	}
	if got, _ := os.ReadFile(filepath.Join(dst, "scope.csv")); string(got) != "id,host,port,protocol,env\n" {
		t.Errorf("scope.csv = %q, want the columns and no rows", got)
	}
	if code, out, errOut := runIn(t, "", "validate", "--report", dst); code != 0 {
		t.Errorf("validate the copy: exit %d, %s %s", code, out, errOut)
	}

	bare := filepath.Join(t.TempDir(), "r3")
	if code, out, errOut := runIn(t, "", "new", bare, "--like", src); code != 0 || out != "" || errOut != "" {
		t.Fatalf("new --like: exit %d, %q %q", code, out, errOut)
	}
	if entries, _ := os.ReadDir(filepath.Join(bare, "pages")); len(entries) != 0 {
		t.Errorf("pages/ without --with-pages: %v", entries)
	}
	if code, out, _ := runIn(t, "", "validate", "--report", bare); code != 1 || !strings.Contains(out, `"rule":"requiredPages"`) {
		t.Errorf("validate without the pages: exit %d, %s; want the missing required page", code, out)
	}
}

func TestNewLikeRefuses(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "r2")
	if code, _, errOut := runIn(t, "", "new", dst, "--with-pages"); code != 2 || errOut == "" {
		t.Errorf("--with-pages alone: exit %d, %q; want usage", code, errOut)
	}
	if code, _, errOut := runIn(t, "", "new", dst, "--like", t.TempDir()); code != 1 || errOut == "" {
		t.Errorf("--like a folder that isn't a report: exit %d, %q", code, errOut)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Errorf("a refused rpt new created %s", dst)
	}
}
