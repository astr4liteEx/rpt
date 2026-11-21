package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHelpListsCommands(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // no plugins
	code, out, errOut := runIn(t, "", "help", "--json")
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	names := pick(t, out, "name")
	want := "assemble\nevidence\nfindings\nhelp\nls\nnew\nscope\nsections\nseverities\nvalidate\nversion\n"
	if names != want {
		t.Errorf("commands listed\n got: %q\nwant: %q", names, want)
	}
	for line := range strings.Lines(pick(t, out, "kind", "summary", "usage")) {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] != "command" {
			t.Errorf("record missing kind, summary or usage: %q", line)
		}
	}
	// A noun's usage lists each subcommand's after its own.
	for line := range strings.Lines(out) {
		if !strings.Contains(line, `"name":"scope","source":"builtin"`) {
			continue
		}
		for _, sub := range []string{"rpt scope [--lines] [--json] [id...] | ", " | rpt scope add ", " | rpt scope delete ", " | rpt scope match "} {
			if !strings.Contains(line, sub) {
				t.Errorf("scope's usage lacks %q:\n%s", sub, line)
			}
		}
	}
}

func TestVerbsIsGone(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if code, _, errOut := runIn(t, "", "verbs"); code != 2 || !strings.Contains(errOut, `unknown command "verbs"`) {
		t.Errorf("exit %d, stderr %q; want exit 2, unknown command", code, errOut)
	}
}

// TestHelpFlag asks every built-in and subcommand for --help and -h: each
// prints its usage line on stdout, exits 0, and does nothing else.
func TestHelpFlag(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	for _, name := range builtinNames() {
		for _, flag := range []string{"--help", "-h"} {
			dir := t.TempDir()
			t.Chdir(dir)
			args := append(strings.Fields(name), flag)
			code, out, errOut := runIn(t, "", args...)
			if code != 0 || errOut != "" || !strings.HasPrefix(out, "usage: "+usageOf(name)+"\n") {
				t.Errorf("rpt %s %s: exit %d, stdout %q, stderr %q; want exit 0 and the usage", name, flag, code, out, errOut)
			}
			if ents, _ := os.ReadDir(dir); len(ents) != 0 {
				t.Errorf("rpt %s %s created %v", name, flag, ents)
			}
		}
	}
}

func TestHelpCommandShowsUsage(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	for _, args := range [][]string{{"help", "scope", "add"}, {"scope", "add", "--help"}} {
		code, out, errOut := runIn(t, "", args...)
		if code != 0 || errOut != "" || !strings.HasPrefix(out, "usage: "+usageOf("scope add")+"\n") || !strings.Contains(out, "--host") {
			t.Errorf("rpt %v: exit %d, stdout %q, stderr %q", args, code, out, errOut)
		}
	}
	if code, _, errOut := runIn(t, "", "help", "frobnicate"); code != 2 || !strings.Contains(errOut, `unknown command "frobnicate"`) {
		t.Errorf("help frobnicate: exit %d, stderr %q", code, errOut)
	}
}

func TestNewHelpCreatesNothing(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	code, out, _ := runIn(t, "", "new", "--help")
	if code != 0 || !strings.HasPrefix(out, "usage: rpt new") {
		t.Errorf("exit %d, stdout %q", code, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "--help")); err == nil {
		t.Error("rpt new --help created a --help folder")
	}
}

func TestRootHelp(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	for _, args := range [][]string{{"--help"}, {"-h"}} {
		code, out, errOut := runIn(t, "", args...)
		if code != 0 || errOut != "" {
			t.Fatalf("rpt %v: exit %d, stderr %q", args, code, errOut)
		}
		for _, w := range []string{"rpt <command>", "findings", "validate", "--report", "--json"} {
			if !strings.Contains(out, w) {
				t.Errorf("rpt %v lacks %q:\n%s", args, w, out)
			}
		}
	}
}

func TestDidYouMean(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	code, _, errOut := runIn(t, "", "fidnings")
	if code != 2 || !strings.Contains(errOut, `unknown command "fidnings"`) || !strings.Contains(errOut, "findings") {
		t.Errorf("exit %d, stderr %q; want a suggestion of findings", code, errOut)
	}
}

func TestGlobalFlagsEitherSide(t *testing.T) {
	for _, args := range [][]string{
		{"--report", fixture, "scope", "S-20"},
		{"--report=" + fixture, "--json", "scope", "S-20"},
		{"scope", "S-20", "--report", fixture},
		{"scope", "--report", fixture, "S-20"},
	} {
		code, out, errOut := runIn(t, "", args...)
		if code != 0 || pick(t, out, "id") != "S-20\n" {
			t.Errorf("rpt %v: exit %d, stdout %q, stderr %q", args, code, out, errOut)
		}
	}
	// Every built-in takes the global flags, even one that has no use for them.
	if code, out, errOut := runIn(t, "", "--report", fixture, "version", "--json"); code != 0 || !strings.Contains(out, `"kind":"version"`) {
		t.Errorf("version with --report: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

func TestSingleDashLongFlagsAreGone(t *testing.T) {
	if code, _, _ := runIn(t, "", "scope", "-json", "--report", fixture); code != 2 {
		t.Errorf("-json: exit %d, want 2", code)
	}
}

// TestUsageMatchesTable misuses every built-in and subcommand and checks
// it answers with the usage line the command table gives it, so the two
// can't drift.
func TestUsageMatchesTable(t *testing.T) {
	misuse := map[string][][]string{
		"assemble":        {{"extra"}, {"--no-such-flag"}},
		"evidence":        {{"extra"}, {"--no-such-flag"}},
		"evidence add":    {{}, {"F-001"}, {"--no-such-flag"}},
		"evidence prune":  {{"extra"}, {"--no-such-flag"}},
		"findings":        {{"extra"}, {"--no-such-flag"}},
		"findings add":    {{"extra"}, {"--no-such-flag"}},
		"findings set":    {{}, {"--no-such-flag"}},
		"findings delete": {{}, {"--no-such-flag"}},
		"findings unset":  {{}, {"F-001"}, {"--no-such-flag"}},
		"help":            {{"--no-such-flag"}},
		"ls":              {{"a", "b"}, {"--no-such-flag"}},
		"new":             {{}, {"a", "b"}, {"--no-such-flag"}},
		"scope":           {{"--no-such-flag"}},
		"scope match":     {{"extra"}, {"--no-such-flag"}},
		"scope add":       {{"extra"}, {"--port", "1"}, {"--no-such-flag"}},
		"scope delete":    {{}, {"--no-such-flag"}},
		"sections":        {{"extra"}, {"--no-such-flag"}},
		"sections set":    {{}, {"F-001"}, {"F-001", "a", "b"}, {"--no-such-flag"}},
		"severities":      {{"extra"}, {"--no-such-flag"}},
		"validate":        {{"extra"}, {"--no-such-flag"}},
		"version":         {{"extra"}, {"--no-such-flag"}},
	}
	for _, name := range builtinNames() {
		cases, ok := misuse[name]
		if !ok {
			t.Errorf("no misuse case for built-in %q; add one", name)
			continue
		}
		want := "usage: " + usageOf(name) + "\n"
		for _, args := range cases {
			code, _, errOut := runIn(t, "", append(strings.Fields(name), args...)...)
			if code != 2 || !strings.Contains(errOut, want) {
				t.Errorf("rpt %s %v: exit %d, stderr %q; want exit 2 and %q", name, args, code, errOut, want)
			}
		}
	}
}

// builtinNames lists every built-in and "built-in sub" name.
func builtinNames() []string {
	var names []string
	for name, b := range builtins {
		names = append(names, name)
		for _, s := range b.subs {
			names = append(names, name+" "+s.name)
		}
	}
	return names
}
