package report

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func mustSave(t *testing.T, m *Model) {
	t.Helper()
	if err := m.Save(false); err != nil {
		t.Fatal(err)
	}
}

func isRefusal(err error) bool {
	var r *Refusal
	return errors.As(err, &r)
}

func TestSetTitleTakesTextAsIs(t *testing.T) {
	m := fixture(t, nil)
	for _, title := range []string{"SQL injection: login form", "#1 issue", "- not a list", "yes"} {
		d, err := m.Set(FindingKind, "F-001", "title", title)
		if err != nil {
			t.Fatalf("%q: %v", title, err)
		}
		if d.Title != title {
			t.Errorf("%q came back as %q", title, d.Title)
		}
	}
}

func TestSetKeepsOneLineFrontmatter(t *testing.T) {
	m := fixture(t, map[string]string{"findings/flow.md": "---\n{id: F-009, title: Test, targets: [{scope: S-12}], severity: high}\n---\n\n## Description\n\nx\n"})
	d, err := m.Set(FindingKind, "F-009", "severity", "low")
	if err != nil {
		t.Fatal(err)
	}
	if d.ID != "F-009" || d.Title != "Test" || len(d.Targets) != 1 || d.Severity != "low" {
		t.Fatalf("lost keys: %+v", d)
	}
}

func TestSetRefusesAnUnknownSeverity(t *testing.T) {
	m := fixture(t, nil)
	if _, err := m.Set(FindingKind, "F-001", "severity", "urgent"); !isRefusal(err) {
		t.Fatalf("got %v", err)
	}
}

func TestSetSectionRefusesAnUnclosedFence(t *testing.T) {
	m := fixture(t, nil)
	if _, err := m.Set(FindingKind, "F-001", "sections.description", "```\ncurl x"); !isRefusal(err) {
		t.Fatalf("got %v", err)
	}
	if len(m.Changed()) != 0 {
		t.Error("a refused write changed a file")
	}
}

func TestSetAddsAMissingSection(t *testing.T) {
	m := fixture(t, nil)
	d, err := m.Set(FindingKind, "F-002", "sections.poc", "    $ curl -k https://x\n    TLSv1.0")
	if err != nil {
		t.Fatal(err)
	}
	s, ok := d.Section("poc")
	if !ok || s.Heading != "Proof of concept" || s.Text != "    $ curl -k https://x\n    TLSv1.0" {
		t.Fatalf("poc: %+v", s)
	}
}

func TestSetPluginKeysAndUnsetTheirSection(t *testing.T) {
	m := fixture(t, nil)
	if _, err := m.Set(FindingKind, "F-001", "x-foo.a", "1"); err != nil {
		t.Fatal(err)
	}
	d, err := m.Set(FindingKind, "F-001", "x-foo.b", "[x, y]")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(NodeJSON(d.src.Get("x-foo"))); got != `{"a":1,"b":["x","y"]}` {
		t.Fatalf("x-foo: %s", got)
	}
	if d, err = m.Unset(FindingKind, "F-001", "x-foo.a", "x-foo.b"); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(d.Keys(), "x-foo") {
		t.Errorf("an emptied plugin section stayed: %v", d.Keys())
	}
}

func TestUnsetRefusesWhatAFindingNeeds(t *testing.T) {
	m := fixture(t, nil)
	for _, key := range []string{"id", "title", "severity", "targets"} {
		if _, err := m.Unset(FindingKind, "F-001", key); !isRefusal(err) {
			t.Errorf("%s: got %v", key, err)
		}
	}
}

func TestAdd(t *testing.T) {
	m := fixture(t, nil)
	d, err := m.Add(FindingKind, Draft{
		Title: "Open redirect: /go", Severity: "low",
		Targets:  []Target{{Scope: "S-12", Port: 443}},
		Sections: []Section{{Key: "description", Text: "It redirects."}, {Key: "Notes", Text: "n"}},
		Extra:    []KeyValue{{"cvss", StringNode("4.3")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	mustSave(t, m)
	want := "---\nid: F-004\ntitle: 'Open redirect: /go'\ntargets:\n  - {scope: S-12, port: 443}\nseverity: low\ncvss: \"4.3\"\n---\n\n" +
		"## Description\n\nIt redirects.\n\n## Remediation\n\n## Proof of concept\n\n## Notes\n\nn\n"
	if d.Path != "findings/F-004-open-redirect-go.md" {
		t.Errorf("path %s", d.Path)
	}
	if got := readDisk(t, m, d.Path); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

func TestAddRefusesATakenOrDuplicatedID(t *testing.T) {
	m := fixture(t, map[string]string{"findings/dup.md": "---\nid: F-003\ntitle: Dup\n---\n"})
	for _, id := range []string{"F-001", "F-003", "f-003"} {
		if _, err := m.Add(FindingKind, Draft{ID: id, Title: "x", Severity: "low"}); !isRefusal(err) {
			t.Errorf("%s: got %v", id, err)
		}
	}
	if _, err := m.Add(FindingKind, Draft{Title: "x", Severity: "low", Targets: []Target{{Host: "10.0.0.5"}}}); !isRefusal(err) {
		t.Errorf("a target without scope: got %v", err)
	}
}

func TestRenameMovesAFileNamedForTheID(t *testing.T) {
	m := fixture(t, map[string]string{"findings/F-007-thing.md": "---\nid: F-007\ntitle: Thing\ntargets: []\nseverity: low\n---\n"})
	d, _ := m.Get(FindingKind, "F-007")
	nd, err := m.Rename(d, "F-010")
	if err != nil {
		t.Fatal(err)
	}
	mustSave(t, m)
	if nd.Path != "findings/F-010-thing.md" || readDisk(t, m, "findings/F-007-thing.md") != "<absent>" {
		t.Fatalf("path %s", nd.Path)
	}
	if !strings.Contains(readDisk(t, m, nd.Path), "id: F-010\n") {
		t.Error("ID not changed")
	}
	// A file not named for its ID keeps its name.
	d, _ = m.Get(FindingKind, "F-001")
	if nd, err = m.Rename(d, "F-011"); err != nil || nd.Path != "findings/xss-search.md" {
		t.Fatalf("%v %s", err, nd.Path)
	}
}

func TestPagesAndTheConfig(t *testing.T) {
	m := fixture(t, map[string]string{
		ConfigFile:                   "format: 2\npages: [P-001, findings]\nrequired_pages:\n  - P-001\n",
		"pages/P-001-summary.md":     "---\nid: P-001\ntitle: Summary\n---\n\nText.\n",
		"pages/P-002-methodology.md": "---\nid: P-002\ntitle: Methodology\n---\n",
	})
	d, _ := m.Get(PageKind, "P-001")
	if _, err := m.Rename(d, "P-005"); err != nil {
		t.Fatal(err)
	}
	if want := "format: 2\npages: [P-005, findings]\nrequired_pages:\n  - P-005\n"; string(m.files[ConfigFile].data) != want {
		t.Fatalf("config:\n%s", m.files[ConfigFile].data)
	}
	if _, _, err := m.Remove(PageKind, "P-005", RefuseCited); !isRefusal(err) {
		t.Fatalf("a cited page: got %v", err)
	}
	if _, _, err := m.Remove(PageKind, "P-005", Cleanup); err != nil {
		t.Fatal(err)
	}
	if want := "format: 2\npages: [findings]\nrequired_pages: []\n"; string(m.files[ConfigFile].data) != want {
		t.Fatalf("config:\n%s", m.files[ConfigFile].data)
	}
	p, err := m.Set(PageKind, "P-002", "body", "We tested.\n\n## Scope\n\nAll of it.")
	if err != nil {
		t.Fatal(err)
	}
	if p.Body() != "\nWe tested.\n\n## Scope\n\nAll of it.\n" {
		t.Errorf("body %q", p.Body())
	}
	mustSave(t, m)
}

func TestNodeJSON(t *testing.T) {
	for in, want := range map[string]string{
		"2024-01-01":        `"2024-01-01"`,
		".nan":              `".nan"`,
		"9.1":               `9.1`,
		"0x1F":              `31`,
		"yes":               `"yes"`,
		"true":              `true`,
		"~":                 `null`,
		"{1: a, b: [x, 2]}": `{"1":"a","b":["x",2]}`,
		"&a {k: v}":         `{"k":"v"}`,
		`"quoted: string"`:  `"quoted: string"`,
	} {
		var n yaml.Node
		if err := yaml.Unmarshal([]byte(in), &n); err != nil {
			t.Fatal(err)
		}
		if got := string(NodeJSON(&n)); got != want {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
	}
}
