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
	want := "add\nassemble\ndelete\nfindings\nnew\nplugins\nscope\nsections\nset\nseverities\nvalidate\nverbs\nversion\n"
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
