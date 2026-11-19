package main

import (
	"strings"
	"testing"
)

func TestVerbsVerb(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // no plugins
	code, out, errOut := runIn(t, "", "verbs")
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	names := pick(t, out, "name")
	want := "assemble\nevidence\nfindings\nls\nnew\nscope\nsections\nseverities\nvalidate\nverbs\nversion\n"
	if names != want {
		t.Errorf("verbs listed\n got: %q\nwant: %q", names, want)
	}
	for line := range strings.Lines(pick(t, out, "kind", "summary", "usage")) {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] != "verb" {
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

func TestVerbsUsage(t *testing.T) {
	if code, _, errOut := runIn(t, "", "verbs", "extra"); code != 2 || !strings.Contains(errOut, "usage: rpt verbs") {
		t.Errorf("exit %d, stderr %q; want exit 2 and usage", code, errOut)
	}
}

// TestVerbsPrintTableUsage misuses every built-in and subcommand and checks
// it answers with the usage line the built-ins table gives it, so the two
// can't drift.
func TestVerbsPrintTableUsage(t *testing.T) {
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
		"ls":              {{"a", "b"}, {"--no-such-flag"}},
		"new":             {{}, {"a", "b"}},
		"scope":           {{"--no-such-flag"}},
		"scope match":     {{"extra"}, {"--no-such-flag"}},
		"scope add":       {{"extra"}, {"--port", "1"}, {"--no-such-flag"}},
		"scope delete":    {{}, {"--no-such-flag"}},
		"sections":        {{"extra"}, {"--no-such-flag"}},
		"sections set":    {{}, {"F-001"}, {"F-001", "a", "b"}, {"--no-such-flag"}},
		"severities":      {{"extra"}, {"--no-such-flag"}},
		"validate":        {{"extra"}, {"--no-such-flag"}},
		"verbs":           {{"extra"}, {"--no-such-flag"}},
		"version":         {{"extra"}, {"--no-such-flag"}},
	}
	var names []string
	for name, b := range builtins {
		names = append(names, name)
		for _, s := range b.subs {
			names = append(names, name+" "+s.name)
		}
	}
	for _, name := range names {
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
