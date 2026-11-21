package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// complete runs rpt __complete on the fixture and returns the candidates
// (values only) and the directive line.
func complete(t *testing.T, words ...string) ([]string, string) {
	t.Helper()
	code, out, errOut := runIn(t, "", append([]string{"__complete", "--report", fixture}, words...)...)
	if code != 0 {
		t.Fatalf("%v: exit %d, stderr %q", words, code, errOut)
	}
	var vals []string
	directive := ""
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if strings.HasPrefix(line, ":") {
			directive = line
			continue
		}
		if line != "" {
			vals = append(vals, line)
		}
	}
	return vals, directive
}

func TestCompleteIDsAndValues(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	for _, tt := range []struct {
		words []string
		want  string
	}{
		{[]string{"finding", "set", "f-"}, "F-001\tReflected XSS in search|F-002\tWeak TLS configuration|F-003\tSQL injection in login"},
		{[]string{"finding", "set", "F-003", "severity", ""}, "critical|high|medium|low|info"},
		{[]string{"finding", "add", "--severity", "h"}, "high"},
		{[]string{"finding", "add", "--target", ""}, "S-12\t10.0.0.5|S-14\t10.0.0.6|S-20\t10.0.1.0/24"},
		{[]string{"finding", "unset", "F-003", "s"}, "sections.description|sections.remediation|sections.poc"},
		{[]string{"scope", "set", "S-12", ""}, "host|port|env"},
		{[]string{"evidence", "remove", "F-003", ""}, "evidence/F-003-login.png\tfrontmatter"},
		{[]string{"evidence", "set", "F-003", "evidence/F-003-login.png", ""}, "caption\tthe text of every link to it|path\tmove the file"},
		{[]string{"completion", "f"}, "fish"},
		{[]string{"help", "finding", ""}, "get|add|set|unset|remove"},
	} {
		got, d := complete(t, tt.words...)
		if strings.Join(got, "|") != tt.want || d != ":4" {
			t.Errorf("%q: %q %s, want %q", tt.words, got, d, tt.want)
		}
	}
	if got, _ := complete(t, "finding", "get", "--a"); len(got) != 1 || !strings.HasPrefix(got[0], "--assets\t") {
		t.Errorf("flags: %q", got)
	}
	if got, _ := complete(t, "validate", "-"); got[len(got)-1] != "-\tthe records on stdin" {
		t.Errorf("validate -: %q", got)
	}
	if _, d := complete(t, "new", ""); d != ":16" {
		t.Errorf("new: %s, want directories", d)
	}
}

// TestEveryCommandCompletes checks that each command and subcommand in the
// table answers __complete, and that a noun offers its actions.
func TestEveryCommandCompletes(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	for name, b := range builtins {
		_, d := complete(t, name, "")
		if d == "" {
			t.Errorf("%s: no directive", name)
		}
		if len(b.subs) > 0 {
			got, _ := complete(t, name, "")
			if len(got) != len(b.subs) {
				t.Errorf("%s: offers %q, want its %d actions", name, got, len(b.subs))
			}
		}
		for _, s := range b.subs {
			if _, d := complete(t, name, s.name, ""); d == "" {
				t.Errorf("%s %s: no directive", name, s.name)
			}
		}
	}
}

func TestCompletePlugins(t *testing.T) {
	dir := t.TempDir()
	write := func(name, script string) {
		if err := os.WriteFile(filepath.Join(dir, "rpt-"+name), []byte("#!/bin/sh\n"+script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("good", `if [ "$1" = __complete ]; then printf 'alpha\tfirst\nbeta\n:4\n'; fi`+"\n")
	write("bad", "exit 3\n")
	t.Setenv("PATH", dir)
	if got, d := complete(t, "good", "x", ""); strings.Join(got, "|") != "alpha\tfirst|beta" || d != ":4" {
		t.Errorf("good: %q %s", got, d)
	}
	if got, d := complete(t, "bad", ""); len(got) != 0 || d != ":0" {
		t.Errorf("bad: %q %s, want file completion", got, d)
	}
	if got, _ := complete(t, "go"); len(got) != 1 || !strings.HasPrefix(got[0], "good\t") {
		t.Errorf("plugin names: %q", got)
	}
}

func TestCompletionScripts(t *testing.T) {
	for _, sh := range []string{"bash", "zsh", "fish", "powershell"} {
		code, out, _ := runIn(t, "", "completion", sh)
		if code != 0 || !strings.Contains(out, "__complete") {
			t.Errorf("%s: exit %d, %d bytes", sh, code, len(out))
		}
	}
}
