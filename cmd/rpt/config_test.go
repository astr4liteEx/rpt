package main

import (
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigGet(t *testing.T) {
	code, out, errOut := runIn(t, "", "config", "get", "--report", fixture)
	if code != 0 || !strings.Contains(out, `"kind":"config"`) || !strings.Contains(out, `"severities":["critical","high","medium","low","info"]`) ||
		!strings.Contains(out, `"sections":{"description":"Description","poc":"Proof of concept","remediation":"Remediation"}`) {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	// A path gives the record with only that member.
	_, out, _ = runIn(t, "", "config", "get", "sections.poc", "--report", fixture)
	if pick(t, out, "kind") != "config\n" || !strings.Contains(out, `"sections":{"poc":"Proof of concept"}`) || strings.Contains(out, "severities") {
		t.Errorf("sections.poc: %q", out)
	}
	if code, _, errOut := runIn(t, "", "config", "get", "nope", "--report", fixture); code != 1 || !strings.Contains(errOut, "no nope") {
		t.Errorf("unknown path: exit %d, stderr %q", code, errOut)
	}
	_, out, _ = runIn(t, "", "config", "get", "--lines", "--report", fixture)
	if !strings.Contains(out, `"keys":{"format":{"line":2,"column":1},"severities":{"line":3,"column":1}}`) {
		t.Errorf("--lines: %q", out)
	}
}

func TestConfigSetRenameInOneWrite(t *testing.T) {
	dir := reportCopy(t)
	code, out, errOut := runIn(t, "", "config", "set", "severities", "[critical, high, medium, low, informational]", "--rename", "info=informational", "--report", dir)
	if code != 0 || pick(t, out, "kind", "id") != "config \nfinding F-002\n" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	if code, out, _ := runIn(t, "", "validate", "--report", dir); strings.Contains(out, "knownSeverity") {
		t.Errorf("validate after the rename: exit %d\n%s", code, out)
	}
}

func TestConfigSetBadRenameIsUsage(t *testing.T) {
	dir := reportCopy(t)
	before := folderState(t, dir)
	for _, args := range [][]string{
		{"severities", "[critical, high, medium, low]", "--rename", "nope=low"},
		{"severities", "[critical, high, medium, low]", "--rename", "info"},
		{"format", "2", "--rename", "a=b"},
	} {
		code, out, errOut := runIn(t, "", append([]string{"config", "set", "--report", dir}, args...)...)
		if code != 2 || out != "" || !strings.Contains(errOut, "Run 'rpt config set --help' for usage.") {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", args, code, out, errOut)
		}
	}
	if !maps.Equal(before, folderState(t, dir)) {
		t.Error("a usage error wrote")
	}
}

func TestConfigIfRev(t *testing.T) {
	dir := reportCopy(t)
	_, out, _ := runIn(t, "", "config", "get", "--report", dir)
	rev := revOf(t, out)
	if code, _, errOut := runIn(t, "", "config", "set", "x-burp.key", "abc", "--if-rev", rev, "--report", dir); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if code, out, _ := runIn(t, "", "config", "set", "x-burp.key", "def", "--if-rev", "config="+rev, "--report", dir); code != 1 || pick(t, out, "rule") != "rev\n" {
		t.Errorf("stale rev: exit %d, stdout %q", code, out)
	}
}

func TestRuleLevelsChangeValidate(t *testing.T) {
	dir := reportCopy(t)
	if code, _, errOut := runIn(t, "", "config", "set", "rules", "{scopeIDsExist: warning}", "--report", dir); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	code, out, _ := runIn(t, "", "validate", "--report", dir)
	if code != 0 || pick(t, out, "rule", "level") != "scopeIDsExist warning\n" {
		t.Errorf("exit %d, stdout %q; want the S-99 problem as a warning, exit 0", code, out)
	}
}

func TestConfigGetMerged(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", home)
	user := filepath.Join(home, "rpt", "plugins", "burp", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(user), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(user, []byte("key: user-key\nproxy: {host: localhost, port: 8080}\nscopes: [a, b]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := reportCopy(t)
	if code, _, errOut := runIn(t, "", "config", "set", "x-burp", "{proxy: {port: 9090}, scopes: [c]}", "--report", dir); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	_, out, errOut := runIn(t, "", "config", "get", "--merged", "x-burp", "--report", dir)
	if !strings.Contains(out, `"x-burp":{"key":"user-key","proxy":{"host":"localhost","port":9090},"scopes":["c"]}`) {
		t.Errorf("stdout %q, stderr %q", out, errOut)
	}
	// With no report in reach, the user file alone.
	t.Setenv("RPT_REPORT_DIR", "")
	t.Chdir(t.TempDir())
	_, out, errOut = runIn(t, "", "config", "get", "--merged", "x-burp")
	if !strings.Contains(out, `"x-burp":{"key":"user-key","proxy":{"host":"localhost","port":8080},"scopes":["a","b"]}`) {
		t.Errorf("no report: stdout %q, stderr %q", out, errOut)
	}
}
