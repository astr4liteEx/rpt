package report

import (
	"strings"
	"testing"
)

func TestSetHeadingRewritesFindings(t *testing.T) {
	m := fixture(t, nil)
	ch, err := m.SetConfig("sections.remediation", []string{"Recommendation"}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Rewrote) != 3 { // every fixture finding has a Remediation section
		t.Errorf("rewrote %d", len(ch.Rewrote))
	}
	f, _ := m.Get(FindingKind, "F-001")
	if s, ok := f.Section("remediation"); !ok || s.Heading != "Recommendation" {
		t.Errorf("F-001: %+v", f.Sections)
	}
	if _, err := m.UnsetConfig(false, "sections"); err != nil {
		t.Fatal(err)
	}
	f, _ = m.Get(FindingKind, "F-001")
	if s, _ := f.Section("remediation"); s.Heading != "Remediation" {
		t.Errorf("back to the default: %+v", f.Sections)
	}
	mustSave(t, m)
	if got := readDisk(t, m, ConfigFile); strings.Contains(got, "sections") {
		t.Errorf("rpt.yaml:\n%s", got)
	}
}

func TestSeveritiesRenameAndRefuse(t *testing.T) {
	m := fixture(t, nil)
	if _, err := m.SetConfig("severities", []string{"urgent", "normal"}, nil, false); !isRefusal(err) {
		t.Fatalf("dropping used levels: %v", err)
	}
	ch, err := m.SetConfig("severities", []string{"urgent", "normal", "low"}, []Rename{{"high", "urgent"}, {"medium", "normal"}, {"info", "low"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Rewrote) != 3 {
		t.Errorf("rewrote %d", len(ch.Rewrote))
	}
	f, _ := m.Get(FindingKind, "F-003")
	if f.Severity != "urgent" {
		t.Errorf("F-003 severity %s", f.Severity)
	}
	if _, err := m.UnsetConfig(false, "severities"); !isRefusal(err) {
		t.Errorf("back to defaults with urgent in use: %v", err)
	}
}

func TestPluginConfig(t *testing.T) {
	m := fixture(t, nil)
	if _, err := m.SetConfig("x-spag.dictionary", []string{"en-GB"}, nil, false); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SetConfig("rules.textBeforeHeading", []string{"error"}, nil, false); err != nil {
		t.Fatal(err)
	}
	if m.Config.Rules["textBeforeHeading"] != "error" {
		t.Errorf("rules %v", m.Config.Rules)
	}
	if _, err := m.UnsetConfig(false, "x-spag.dictionary", "rules.textBeforeHeading"); err != nil {
		t.Fatal(err)
	}
	mustSave(t, m)
	if got := readDisk(t, m, ConfigFile); got != "# Fixture report for rpt's tests.\nformat: 2\nseverities: [critical, high, medium, low, info]\n" {
		t.Errorf("rpt.yaml:\n%s", got)
	}
	for _, bad := range [][]string{{"format", "3"}, {"rules.x", "loud"}, {"colour", "red"}} {
		if _, err := m.SetConfig(bad[0], bad[1:], nil, false); !isRefusal(err) {
			t.Errorf("%v: %v", bad, err)
		}
	}
}
