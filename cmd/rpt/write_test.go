package main

import (
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// revOf returns the rev of the one record in jsonl.
func revOf(t *testing.T, jsonl string) string {
	t.Helper()
	rev := strings.TrimSuffix(pick(t, jsonl, "rev"), "\n")
	if len(rev) != 16 {
		t.Fatalf("no rev in %q", jsonl)
	}
	return rev
}

func TestIfRev(t *testing.T) {
	dir := reportCopy(t)
	_, out, _ := runIn(t, "", "findings", "--report", dir)
	var rev string
	for line := range strings.Lines(out) {
		if strings.Contains(line, `"id":"F-001"`) {
			rev = revOf(t, line)
		}
	}

	before := folderState(t, dir)
	code, out, errOut := runIn(t, "", "findings", "set", "F-001", "cvss", `"1.0"`, "--if-rev", "0123456789abcdef", "--report", dir)
	if code != 1 || pick(t, out, "kind", "rule") != "problem rev\n" || !strings.Contains(errOut, "changed since read") {
		t.Errorf("stale rev: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	if !maps.Equal(before, folderState(t, dir)) {
		t.Error("a stale --if-rev wrote")
	}

	code, out, errOut = runIn(t, "", "findings", "set", "F-001", "cvss", `"1.0"`, "--if-rev", "F-001="+rev, "--report", dir)
	if code != 0 || revOf(t, out) == rev {
		t.Errorf("fresh rev: exit %d, stdout %q, stderr %q; want the new rev", code, out, errOut)
	}
	// The old rev is stale now.
	if code, _, _ := runIn(t, "", "findings", "set", "F-001", "cvss", `"2.0"`, "--if-rev", rev, "--report", dir); code != 1 {
		t.Errorf("reused rev: exit %d, want 1", code)
	}
}

func TestIfRevUsage(t *testing.T) {
	for _, args := range [][]string{
		{"findings", "delete", "F-001", "F-002", "--if-rev", "0123456789abcdef"}, // which one?
		{"findings", "set", "F-001", "cvss", "1", "--if-rev", "F-002=0123456789abcdef"},
	} {
		if code, _, errOut := runIn(t, "", append(args, "--report", reportCopy(t))...); code != 2 || !strings.Contains(errOut, "--if-rev") {
			t.Errorf("rpt %v: exit %d, stderr %q; want 2", args, code, errOut)
		}
	}
}

func TestDryRun(t *testing.T) {
	dir := reportCopy(t)
	before := folderState(t, dir)
	code, dry, errOut := runIn(t, "", "findings", "set", "F-001", "cvss", `"1.0"`, "--dry-run", "--report", dir)
	if code != 0 || !strings.Contains(dry, `"cvss":"1.0"`) {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, dry, errOut)
	}
	if !maps.Equal(before, folderState(t, dir)) {
		t.Error("--dry-run wrote")
	}
	// The real write prints exactly what the dry run did, rev included.
	if _, real, _ := runIn(t, "", "findings", "set", "F-001", "cvss", `"1.0"`, "--report", dir); real != dry {
		t.Errorf("dry run printed\n%s\nthe write printed\n%s", dry, real)
	}
	// A refused write fails the same way dry.
	if code, out, _ := runIn(t, "", "findings", "set", "F-404", "cvss", "1", "--dry-run", "--report", dir); code != 1 || pick(t, out, "rule") != "exists\n" {
		t.Errorf("dry refusal: exit %d, stdout %q", code, out)
	}
}

func TestScopeDeleteIfRev(t *testing.T) {
	dir := reportCopy(t)
	_, out, _ := runIn(t, "", "scope", "S-20", "--report", dir)
	rev := revOf(t, out)
	// Adding a row leaves S-20's rev alone.
	if code, _, errOut := runIn(t, "", "scope", "add", "--host", "new.example", "--report", dir); code != 0 {
		t.Fatalf("add: exit %d, stderr %q", code, errOut)
	}
	if code, out, errOut := runIn(t, "", "scope", "delete", "S-20", "--if-rev", "S-20="+rev, "--report", dir); code != 0 || pick(t, out, "id") != "S-20\n" {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

func TestRevIsReserved(t *testing.T) {
	dir := reportCopy(t)
	if code, out, _ := runIn(t, "", "findings", "set", "F-001", "rev", "x", "--report", dir); code != 1 || pick(t, out, "rule") != "write\n" {
		t.Errorf("set rev: exit %d, stdout %q", code, out)
	}
	if err := os.WriteFile(filepath.Join(dir, "scope.csv"), []byte("id,host,rev\nS-1,a,b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := runIn(t, "", "scope", "--report", dir); code != 1 || !strings.Contains(errOut, `column "rev" is reserved`) {
		t.Errorf("rev column: exit %d, stderr %q", code, errOut)
	}
}
