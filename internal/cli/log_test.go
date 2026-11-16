package cli

import (
	"bytes"
	"testing"
)

func TestLoggerLines(t *testing.T) {
	var buf bytes.Buffer
	log := NewLogger(&buf)
	log.Error("mapping values are not allowed", "path", "findings/broken.md", "line", 3)
	log.Error("header has no \"host\" column", "path", "scope.csv")
	log.Warn("unknown config key", "path", "rpt.yaml", "key", "renderer")
	log.Error("no report found")
	log.Debug("not shown")
	want := "rpt: findings/broken.md:3: mapping values are not allowed\n" +
		"rpt: scope.csv: header has no \"host\" column\n" +
		"rpt: rpt.yaml: warning: unknown config key key=renderer\n" +
		"rpt: no report found\n"
	if got := buf.String(); got != want {
		t.Errorf("stderr\n got: %q\nwant: %q", got, want)
	}
}
