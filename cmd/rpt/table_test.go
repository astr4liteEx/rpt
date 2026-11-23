package main

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

// onATerminal makes rpt's stdout count as a terminal.
func onATerminal(t *testing.T) {
	t.Helper()
	old := stdoutIsTerminal
	stdoutIsTerminal = func(any) bool { return true }
	t.Cleanup(func() { stdoutIsTerminal = old })
}

const tableIn = `{"kind":"finding","id":"F-002","severity":"low","title":"Banner"}
{"kind":"note","text":"x"}
{"kind":"finding","id":"F-001","severity":"high","title":"SQLi"}
{"kind":"problem","command":"up","path":"a.md","level":"warning","rule":"r","message":"careful"}
`

func TestTablePassesRecordsOnOffATerminal(t *testing.T) {
	fixture(t)
	code, out, _ := rpt(t, tableIn, "table")
	if code != 0 || out != tableIn {
		t.Errorf("exit %d %q", code, out)
	}
	code, out, errOut := rpt(t, tableIn+"oops\n", "table")
	recs, problems := recordLines(out)
	if code != 1 || len(recs) != 3 || len(problems) != 2 || !strings.Contains(problems[1], `"line":5`) || !strings.Contains(errOut, "-:5") {
		t.Errorf("exit %d %q %q", code, out, errOut)
	}
}

func TestTableOnATerminal(t *testing.T) {
	fixture(t)
	onATerminal(t)
	code, out, errOut := rpt(t, tableIn, "table")
	out = ansi.Strip(out)
	switch {
	case code != 0:
		t.Errorf("exit %d %q", code, errOut)
	case !strings.Contains(out, "SEVERITY") || !strings.Contains(out, "SQLi"):
		t.Errorf("no findings table:\n%s", out)
	case !strings.Contains(out, "2 findings · high 1 · low 1"):
		t.Errorf("totals not in the report's order:\n%s", out)
	case !strings.HasSuffix(out, `{"kind":"note","text":"x"}`+"\n"):
		t.Errorf("a kind with no table isn't after the tables:\n%s", out)
	case strings.Contains(out, "careful") || !strings.Contains(errOut, "careful"):
		t.Errorf("a problem belongs on stderr only:\n%s\n%s", out, errOut)
	}
}

// recordsPlugin answers --describe as a plugin printing records, then
// runs body.
func recordsPlugin(body string) string {
	return `[ "$1" = --describe ] && { echo '{"summary":"s","output":"records"}'; exit 0; }
` + body
}

func TestPluginOnATerminalShowsTables(t *testing.T) {
	fixture(t)
	onATerminal(t)
	plugins(t, map[string]string{
		"imp": recordsPlugin(`echo '{"kind":"finding","id":"F-9","severity":"high","title":"From imp"}'
echo '{"kind":"x-imp-item","n":1}'
echo '{"kind":"problem","command":"imp","path":"-","level":"warning","rule":"r","message":"half"}'
echo 'imp: warning: half' >&2
exit 3`),
		"raw": `echo '{"kind":"finding","id":"F-9","severity":"high","title":"t"}'`,
	})
	code, out, errOut := rpt(t, "", "imp", "a")
	out = ansi.Strip(out)
	if code != 3 || !strings.Contains(out, "From imp") || !strings.Contains(out, `{"kind":"x-imp-item","n":1}`) ||
		strings.Contains(out, "half") || strings.Count(errOut, "half") != 1 {
		t.Errorf("exit %d\n%s\n%s", code, out, errOut)
	}
	// Without "output":"records", and with what asks for something
	// else, the plugin runs in rpt's place.
	for _, args := range [][]string{{"raw"}, {"imp", "--json"}, {"--json", "imp"}, {"imp", "--help"}, {"imp", "__complete", ""}} {
		pluginOut.Reset()
		if _, out, _ := rpt(t, "", args...); out != "" || pluginOut.Len() == 0 {
			t.Errorf("rpt %v wasn't passed through: %q", args, out)
		}
	}
}

func TestPluginTextPassesThrough(t *testing.T) {
	fixture(t)
	onATerminal(t)
	plugins(t, map[string]string{"imp": recordsPlugin(`printf '\nUsage: rpt imp\n'`)})
	if code, out, _ := rpt(t, "", "imp", "help"); code != 0 || out != "\nUsage: rpt imp\n" {
		t.Errorf("exit %d %q", code, out)
	}
}

func TestPluginBadLineOnATerminal(t *testing.T) {
	fixture(t)
	onATerminal(t)
	plugins(t, map[string]string{"imp": recordsPlugin(`echo '{"kind":"scope","id":"S-1"}'; echo 'cut off {'`)})
	code, out, errOut := rpt(t, "", "imp")
	if code != 1 || !strings.Contains(ansi.Strip(out), "S-1") || !strings.Contains(errOut, "-:2") {
		t.Errorf("exit %d\n%s\n%s", code, out, errOut)
	}
}

func TestPluginKilledOnATerminal(t *testing.T) {
	fixture(t)
	onATerminal(t)
	plugins(t, map[string]string{"imp": recordsPlugin(`echo '{"kind":"scope","id":"S-1"}'; kill -TERM $$`)})
	if code, out, _ := rpt(t, "", "imp"); code != 143 || out != "" {
		t.Errorf("exit %d %q", code, out)
	}
}
