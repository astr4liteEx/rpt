package main

import (
	"strings"
	"testing"
)

func TestVerbsVerb(t *testing.T) {
	code, out, errOut := runIn(t, "", "verbs")
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	names := pick(t, out, "name")
	want := "add\nassemble\ndelete\nfindings\nls\nnew\nplugins\nscope\nsections\nset\nseverities\nvalidate\nverbs\nversion\n"
	if names != want {
		t.Errorf("verbs listed\n got: %q\nwant: %q", names, want)
	}
	for line := range strings.Lines(pick(t, out, "kind", "summary", "usage")) {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] != "verb" {
			t.Errorf("record missing kind, summary or usage: %q", line)
		}
	}
	if !strings.Contains(out, `{"kind":"verb","name":"add","summary":"Add finding records as new finding files","usage":"rpt add < records.jsonl","input":"records","output":"records"}`) {
		t.Errorf("add's record isn't as expected:\n%s", out)
	}
}

func TestVerbsUsage(t *testing.T) {
	if code, _, errOut := runIn(t, "", "verbs", "extra"); code != 2 || !strings.Contains(errOut, "usage: rpt verbs") {
		t.Errorf("exit %d, stderr %q; want exit 2 and usage", code, errOut)
	}
}

// TestVerbsPrintTableUsage misuses every built-in and checks it answers
// with the usage line rpt verbs lists for it, so the two can't drift.
func TestVerbsPrintTableUsage(t *testing.T) {
	misuse := map[string][][]string{
		"add":        {{"extra"}, {"--no-such-flag"}},
		"assemble":   {{"extra"}, {"--no-such-flag"}},
		"delete":     {{}, {"--no-such-flag"}},
		"findings":   {{"extra"}, {"--no-such-flag"}},
		"ls":         {{"a", "b"}, {"--no-such-flag"}},
		"new":        {{}, {"a", "b"}},
		"plugins":    {{"extra"}, {"--no-such-flag"}},
		"scope":      {{"extra"}, {"--no-such-flag"}, {"match", "extra"}, {"match", "--no-such-flag"}},
		"sections":   {{"extra"}, {"--no-such-flag"}},
		"set":        {{}, {"--no-such-flag"}},
		"severities": {{"extra"}, {"--no-such-flag"}},
		"validate":   {{"extra"}, {"--no-such-flag"}},
		"verbs":      {{"extra"}, {"--no-such-flag"}},
		"version":    {{"extra"}, {"--no-such-flag"}},
	}
	for name, b := range builtins {
		cases, ok := misuse[name]
		if !ok {
			t.Errorf("no misuse case for built-in %q; add one", name)
			continue
		}
		want := "usage: " + b.desc.Usage + "\n"
		for _, args := range cases {
			code, _, errOut := runIn(t, "", append([]string{name}, args...)...)
			if code != 2 || !strings.Contains(errOut, want) {
				t.Errorf("rpt %s %v: exit %d, stderr %q; want exit 2 and %q", name, args, code, errOut, want)
			}
		}
	}
}
