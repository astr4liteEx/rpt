package main

import (
	"maps"
	"os"
	"path/filepath"
	"testing"
)

func TestNewVerb(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "clients", "acme-external")

	code, out, errOut := runIn(t, "", "new", dir)
	if code != 0 || out != "" || errOut != "" {
		t.Fatalf("new: exit %d, stdout %q, stderr %q", code, out, errOut)
	}

	wantConfig := "format: 1\n" +
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
