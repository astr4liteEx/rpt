package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPagesAssembleAroundFindings(t *testing.T) {
	dir := reportCopy(t)
	for _, title := range []string{"Executive summary", "Conclusions"} {
		if code, _, errOut := runIn(t, "", "page", "add", "--title", title, "--report", dir); code != 0 {
			t.Fatalf("add: exit %d, stderr %q", code, errOut)
		}
	}
	if code, _, errOut := runIn(t, "We tested Acme.\n", "page", "set", "P-001", "body", "--report", dir); code != 0 {
		t.Fatalf("set body: exit %d, stderr %q", code, errOut)
	}
	if code, _, errOut := runIn(t, "", "config", "set", "pages", "P-001", "findings", "P-002", "--report", dir); code != 0 {
		t.Fatalf("config set pages: exit %d, stderr %q", code, errOut)
	}
	_, out, _ := runIn(t, "", "assemble", "--report", dir)
	if !strings.Contains(out, `"order":["P-001","findings","P-002"]`) || !strings.Contains(out, `"pages":[{"id":"P-001","title":"Executive summary","body":"We tested Acme.","assets":[]},{"id":"P-002"`) {
		t.Errorf("assemble: %s", out)
	}
}

func TestRequiredPageEmptyFailsValidate(t *testing.T) {
	dir := reportCopy(t)
	runIn(t, "", "page", "add", "--title", "Executive summary", "--report", dir)
	runIn(t, "", "config", "set", "required_pages", "P-001", "--report", dir)
	code, out, _ := runIn(t, "", "validate", "--report", dir)
	if code != 1 || !strings.Contains(out, `"path":"pages/P-001-executive-summary.md","line":5,"rule":"requiredPages"`) {
		t.Errorf("exit %d, stdout %s", code, out)
	}
}

func TestPageRemoveNeedsCleanupWhenListed(t *testing.T) {
	dir := reportCopy(t)
	runIn(t, "", "page", "add", "--title", "Summary", "--report", dir)
	runIn(t, "", "config", "set", "pages", "P-001", "findings", "--report", dir)
	if code, out, _ := runIn(t, "", "page", "remove", "P-001", "--yes", "--report", dir); code != 1 || pick(t, out, "rule") != "write\n" {
		t.Errorf("listed: exit %d, stdout %q", code, out)
	}
	code, out, errOut := runIn(t, "", "page", "remove", "p-001", "--yes", "--cleanup", "--report", dir)
	if code != 0 || pick(t, out, "kind") != "page\nconfig\n" {
		t.Errorf("--cleanup: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

func TestNewMakesPages(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "r")
	if code, _, errOut := runIn(t, "", "new", dir); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if info, err := os.Stat(filepath.Join(dir, "pages")); err != nil || !info.IsDir() {
		t.Errorf("no pages/: %v", err)
	}
}
