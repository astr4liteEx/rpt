package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeleteVerb(t *testing.T) {
	dir := reportCopy(t)
	// One unknown ID: nothing is deleted.
	code, out, errOut := runIn(t, "", "finding", "remove", "--yes", "F-003", "F-404", "F-001", "--report", dir)
	if code != 1 || pick(t, out, "kind", "rule") != "problem exists\n" || !strings.Contains(errOut, "no such finding: F-404") {
		t.Errorf("exit %d, stdout %q, stderr %q; want 1 and one exists problem", code, out, errOut)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "findings", "*.md")); len(left) != 3 {
		t.Errorf("left %v, want all three", left)
	}

	code, out, errOut = runIn(t, "", "finding", "remove", "--yes", "F-003", "F-001", "--report", dir)
	if got := pick(t, out, "id", "path"); code != 0 || got != "F-003 findings/sqli-login.md\nF-001 findings/xss-search.md\n" {
		t.Errorf("exit %d, stdout %q, stderr %q; want the two deleted findings", code, got, errOut)
	}
	left, _ := filepath.Glob(filepath.Join(dir, "findings", "*.md"))
	if len(left) != 1 || filepath.Base(left[0]) != "tls-weak.md" {
		t.Errorf("left %v, want only tls-weak.md", left)
	}
}

func TestDeleteUsage(t *testing.T) {
	dir := reportCopy(t)
	code, _, errOut := runIn(t, "", "finding", "remove", "--yes", "--report", dir)
	if code != 2 || !strings.Contains(errOut, "Run 'rpt finding remove --help' for usage.") {
		t.Errorf("exit %d, stderr %q; want 2 and usage", code, errOut)
	}
	if _, err := os.Stat(filepath.Join(dir, "findings/sqli-login.md")); err != nil {
		t.Error(err)
	}
}
