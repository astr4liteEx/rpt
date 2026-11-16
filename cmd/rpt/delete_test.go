package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeleteVerb(t *testing.T) {
	dir := reportCopy(t)
	code, out, errOut := runIn(t, "", "delete", "F-003", "F-404", "F-001", "--report", dir)
	if code != 1 {
		t.Errorf("exit %d, want 1 for the unknown ID", code)
	}
	if got := pick(t, out, "id", "path"); got != "F-003 findings/sqli-login.md\nF-001 findings/xss-search.md\n" {
		t.Errorf("stdout = %q, want the two deleted findings", got)
	}
	if !strings.Contains(errOut, "no such finding: F-404") {
		t.Errorf("stderr = %q, want the unknown ID named", errOut)
	}
	left, _ := filepath.Glob(filepath.Join(dir, "findings", "*.md"))
	if len(left) != 1 || filepath.Base(left[0]) != "tls-weak.md" {
		t.Errorf("left %v, want only tls-weak.md", left)
	}
}

func TestDeleteUsage(t *testing.T) {
	dir := reportCopy(t)
	code, _, errOut := runIn(t, "", "delete", "--report", dir)
	if code != 2 || !strings.Contains(errOut, "usage: rpt delete <id>...") {
		t.Errorf("exit %d, stderr %q; want 2 and usage", code, errOut)
	}
	if _, err := os.Stat(filepath.Join(dir, "findings/sqli-login.md")); err != nil {
		t.Error(err)
	}
}
