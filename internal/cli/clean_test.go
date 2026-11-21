package cli

import "testing"

func TestClean(t *testing.T) {
	for in, want := range map[string]string{
		"plain\ttext\n":     "plain\ttext\n",
		"\x1b[2J title":     `\x1b[2J title`,
		"a\rb":              `a\x0db`,
		"evil\u202eexe.png": "evil\\u202eexe.png",
		"bad \xff byte":     `bad \xff byte`,
		"c1 \u009b":         `c1 \x9b`,
		"ünïcode ✓":         "ünïcode ✓",
	} {
		if got := Clean(in); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
	if got := CleanLine("a\nb\r\nc\td\x07"); got != `a b c d\x07` {
		t.Errorf("CleanLine = %q", got)
	}
}
