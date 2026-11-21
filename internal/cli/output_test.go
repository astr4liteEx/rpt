package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

type rec map[string]any

var recs = []rec{
	{"kind": "finding", "id": "F-003", "title": "SQL injection\x1b[2J", "severity": "high", "targets": []any{map[string]any{"scope": "S-12"}, map[string]any{"scope": "S-12"}, map[string]any{"scope": "S-14"}}},
	{"kind": "scope", "id": "S-12", "host": "10.0.0.1", "port": 443},
	{"kind": "finding", "id": "F-001", "title": "XSS", "severity": "medium"},
	{"kind": "note", "text": "no columns"},
}

func render(t *testing.T, terminal, jsonFlag bool) string {
	t.Helper()
	var buf bytes.Buffer
	out := NewOutput(&buf, terminal, jsonFlag)
	out.Severities = []string{"high", "medium"}
	for _, r := range recs {
		if err := out.Write(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := out.WriteRaw([]byte(`{"kind":"raw"}`)); err != nil {
		t.Fatal(err)
	}
	if err := out.Flush(); err != nil {
		t.Fatal(err)
	}
	return ansi.Strip(buf.String())
}

func TestJSONLines(t *testing.T) {
	for _, term := range []bool{false, true} {
		got := render(t, term, term)
		lines := strings.Split(strings.TrimSpace(got), "\n")
		if len(lines) != 5 || lines[4] != `{"kind":"raw"}` || !strings.Contains(lines[0], `SQL injection\u001b[2J`) {
			t.Errorf("terminal=%v:\n%s", term, got)
		}
	}
}

func TestTablesPerKind(t *testing.T) {
	got := render(t, true, false)
	scope, finding := strings.Index(got, "HOST"), strings.Index(got, "SEVERITY")
	switch {
	case scope < 0 || finding < 0 || scope > finding:
		t.Errorf("want a scope table, then a findings table:\n%s", got)
	case !strings.Contains(got, `SQL injection\x1b[2J`):
		t.Errorf("a cell isn't cleaned:\n%s", got)
	case !strings.Contains(got, "S-12,S-14"):
		t.Errorf("scope column:\n%s", got)
	case !strings.Contains(got, "2 findings · high 1 · medium 1"):
		t.Errorf("totals:\n%s", got)
	case strings.Contains(got, "no columns") || strings.Contains(got, "raw"):
		t.Errorf("a record with no table showed:\n%s", got)
	}
}
