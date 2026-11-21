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
	want := "assemble\ncompletion\nconfig\nevidence\nfinding\nhelp\nls\nnew\npage\nscope\nvalidate\nversion\n"
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
		for _, sub := range []string{"rpt scope <action> | ", " | rpt scope get ", " | rpt scope add ", " | rpt scope remove ", " | rpt scope match "} {
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
// prints its fang help on stdout, exits 0, and does nothing else.
func TestHelpFlag(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	for _, name := range builtinNames() {
		for _, flag := range []string{"--help", "-h"} {
			dir := t.TempDir()
			t.Chdir(dir)
			args := append(strings.Fields(name), flag)
			code, out, errOut := runIn(t, "", args...)
			if code != 0 || errOut != "" || !isHelpFor(out, name) {
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
		if code != 0 || errOut != "" || !isHelpFor(out, "scope add") || !strings.Contains(out, "--host") {
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
	if code != 0 || !isHelpFor(out, "new") {
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
		for _, w := range []string{"rpt [command]", "finding", "validate", "--report", "--json"} {
			if !strings.Contains(out, w) {
				t.Errorf("rpt %v lacks %q:\n%s", args, w, out)
			}
		}
	}
}

func TestDidYouMean(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	code, _, errOut := runIn(t, "", "fidning")
	if code != 2 || !strings.Contains(errOut, `unknown command "fidning"`) || !strings.Contains(errOut, "finding") {
		t.Errorf("exit %d, stderr %q; want a suggestion of finding", code, errOut)
	}
}

func TestGlobalFlagsEitherSide(t *testing.T) {
	for _, args := range [][]string{
		{"--report", fixture, "scope", "get", "S-20"},
		{"--report=" + fixture, "--json", "scope", "get", "S-20"},
		{"scope", "get", "S-20", "--report", fixture},
		{"scope", "get", "--report", fixture, "S-20"},
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
		"config":          {{}, {"extra"}, {"--no-such-flag"}},
		"config get":      {{"a", "b"}, {"--merged"}, {"--merged", "severities"}, {"--no-such-flag"}},
		"config set":      {{}, {"format"}, {"--rename", "x", "severities", "[a]"}, {"--no-such-flag"}},
		"config unset":    {{}, {"--no-such-flag"}},
		"evidence":        {{}, {"extra"}, {"--no-such-flag"}},
		"evidence get":    {{"--orphans", "F-001"}, {"--no-such-flag"}},
		"evidence add":    {{"F-001"}, {"--text", "x", "F-001", "a.png"}, {"--no-such-flag"}},
		"evidence set":    {{}, {"F-001", "a.png", "caption"}, {"F-001", "a.png", "size", "1"}, {"--no-such-flag"}},
		"evidence unset":  {{}, {"F-001", "a.png", "path"}, {"--no-such-flag"}},
		"evidence remove": {{}, {"F-001"}, {"--no-such-flag"}},
		"evidence prune":  {{"extra"}, {"--no-such-flag"}},
		"finding":         {{}, {"extra"}, {"--no-such-flag"}},
		"finding get":     {{"--no-such-flag"}},
		"finding add":     {{"extra"}, {"--no-such-flag"}},
		"finding set":     {{}, {"F-001", "title"}, {"--no-such-flag"}},
		"finding remove":  {{}, {"--no-such-flag"}},
		"finding unset":   {{}, {"F-001"}, {"--no-such-flag"}},
		"help":            {{"--no-such-flag"}},
		"ls":              {{"a", "b"}, {"--no-such-flag"}},
		"new":             {{}, {"a", "b"}, {"--no-such-flag"}},
		"page":            {{}, {"extra"}, {"--no-such-flag"}},
		"page get":        {{"--no-such-flag"}},
		"page add":        {{"extra"}, {"--id", "P-001"}, {"--no-such-flag"}},
		"page set":        {{}, {"P-001", "title"}, {"--no-such-flag"}},
		"page unset":      {{}, {"P-001"}, {"--no-such-flag"}},
		"page remove":     {{}, {"P-001", "--yes", "--force", "--cleanup"}, {"--no-such-flag"}},
		"scope":           {{}, {"extra"}, {"--no-such-flag"}},
		"scope match":     {{"extra"}, {"--no-such-flag"}},
		"scope add":       {{"extra"}, {"--port", "1"}, {"--no-such-flag"}},
		"scope get":       {{"--no-such-flag"}},
		"scope set":       {{}, {"S-12", "port"}, {"S-12", "port", "1", "--force", "--cleanup"}, {"--no-such-flag"}},
		"scope unset":     {{}, {"S-12"}, {"--no-such-flag"}},
		"scope remove":    {{}, {"S-12", "--yes", "--force", "--cleanup"}, {"--no-such-flag"}},
		"completion":      {{}, {"tcsh"}, {"bash", "zsh"}, {"--no-such-flag"}},
		"validate":        {{"-", "F-001"}, {"--no-such-flag"}},
		"version":         {{"extra"}, {"--no-such-flag"}},
	}
	for _, name := range builtinNames() {
		cases, ok := misuse[name]
		if !ok {
			t.Errorf("no misuse case for built-in %q; add one", name)
			continue
		}
		want := "Run 'rpt " + name + " --help' for usage.\n"
		for _, args := range cases {
			code, _, errOut := runIn(t, "", append(strings.Fields(name), args...)...)
			if code != 2 || !strings.Contains(errOut, want) {
				t.Errorf("rpt %s %v: exit %d, stderr %q; want exit 2 and %q", name, args, code, errOut, want)
			}
		}
	}
}

// builtinNames lists every built-in and "built-in sub" name.
// isHelpFor reports whether out is fang's help for the built-in name
// ("scope add"): its summary from the command table, and a usage section
// naming the command.
func isHelpFor(out, name string) bool {
	f := strings.Fields(name)
	b := builtins[f[0]]
	summary := b.desc.Summary
	for _, s := range b.subs {
		if len(f) > 1 && s.name() == f[1] {
			summary = s.summary
		}
	}
	return strings.Contains(out, summary) && strings.Contains(out, "USAGE") && strings.Contains(out, "rpt "+name)
}

func builtinNames() []string {
	var names []string
	for name, b := range builtins {
		names = append(names, name)
		for _, s := range b.subs {
			names = append(names, name+" "+s.name())
		}
	}
	return names
}

// TestUsageErrorPointsAtHelp: a bad flag names the help of the command
// it was given to, rpt itself before any command.
func TestUsageErrorPointsAtHelp(t *testing.T) {
	for args, want := range map[string]string{
		"--bogus finding get": "Run 'rpt --help' for usage.",
		"finding get --bogus": "Run 'rpt finding get --help' for usage.",
		"finding":             "Run 'rpt finding --help' for usage.",
	} {
		if code, _, errOut := runIn(t, "", strings.Fields(args)...); code != 2 || !strings.HasSuffix(errOut, want+"\n") {
			t.Errorf("rpt %s: exit %d, stderr %q; want 2 and %q", args, code, errOut, want)
		}
	}
}
