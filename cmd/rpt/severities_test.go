package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSeveritiesVerb(t *testing.T) {
	withConfig := func(config string) string {
		dir := reportCopy(t)
		if err := os.WriteFile(filepath.Join(dir, "rpt.yaml"), []byte(config), 0o644); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	tests := []struct {
		name   string
		report string
		want   string
	}{
		{"the fixture's levels, most severe first", fixture,
			"severity critical 1\nseverity high 2\nseverity medium 3\nseverity low 4\nseverity info 5\n"},
		{"custom levels as rpt.yaml lists them", withConfig("format: 1\nseverities: [urgent, normal]\n"),
			"severity urgent 1\nseverity normal 2\n"},
		{"no severities key gives the defaults", withConfig("format: 1\n"),
			"severity critical 1\nseverity high 2\nseverity medium 3\nseverity low 4\nseverity info 5\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, errOut := runIn(t, "", "severities", "--report", tt.report)
			if code != 0 || errOut != "" {
				t.Fatalf("exit %d, stderr %q", code, errOut)
			}
			if got := pick(t, out, "kind", "level", "rank"); got != tt.want {
				t.Errorf("stdout\n got: %q\nwant: %q", got, tt.want)
			}
		})
	}
}
