package plugin

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/astr4liteEx/rpt/internal/report"
)

// script writes an executable rpt-<name> shell script into dir.
func script(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, "rpt-"+name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestValidName(t *testing.T) {
	for name, ok := range map[string]bool{"tag": true, "api-export": true, "a1": true, "": false, "-x": false, "Tag": false, "../x": false, "a/b": false, "a b": false} {
		if ValidName(name) != ok {
			t.Errorf("ValidName(%q) = %v", name, !ok)
		}
	}
}

func TestDiscoverFirstOnPathWins(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	first := script(t, a, "tag", "")
	script(t, b, "tag", "")
	script(t, b, "zip", "")
	script(t, b, "Bad", "")
	os.WriteFile(filepath.Join(b, "rpt-noexec"), []byte("x"), 0o644)
	got := Discover(strings.Join([]string{"", "relative", a, b}, string(os.PathListSeparator)))
	var names []string
	for _, p := range got {
		names = append(names, p.Name)
	}
	if !slices.Equal(names, []string{"tag", "zip"}) || got[0].Path != first {
		t.Errorf("got %v", got)
	}
	if _, err := Lookup(a+string(os.PathListSeparator)+b, "../tag"); err != ErrNotFound {
		t.Error("a path was looked up")
	}
	if p, err := Lookup(b, "zip"); err != nil || p.Name != "zip" {
		t.Errorf("lookup %v %v", p, err)
	}
}

func TestEnv(t *testing.T) {
	got := Env([]string{"HOME=/h", "RPT_BIN=old", "RPT_REPORT_DIR=old"}, "", "/bin/rpt", 2)
	want := []string{"HOME=/h", "RPT_BIN=/bin/rpt", "RPT_SCHEMA_VERSION=2"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v", got)
	}
}

func TestOwner(t *testing.T) {
	names := []string{"api", "api-export"}
	for _, tt := range []struct{ noun, name, want string }{
		{"finding", "x-api-export-id", "api-export"},
		{"finding", "x-api-id", "api"},
		{"finding", "x-api", "api"},
		{"finding", "x-apis", ""},
		{"config", "x-api-export", "api-export"},
		{"config", "x-api-other", ""},
		{"finding", "title", ""},
	} {
		if got, _ := Owner(tt.noun, tt.name, names); got != tt.want {
			t.Errorf("Owner(%s, %s) = %q", tt.noun, tt.name, got)
		}
	}
}

func TestDescribeCaches(t *testing.T) {
	dir := t.TempDir()
	count := filepath.Join(dir, "count")
	p := script(t, dir, "tag", `echo x >> `+count+`; echo '{"summary":"tag"}'`)
	d := &Describer{Env: os.Environ(), CacheFile: filepath.Join(dir, "cache", "describe.json")}
	ps := []Plugin{{"tag", p}}
	for range 2 {
		a := d.Describe(ps)["tag"]
		if a.Err != nil || a.Desc.Summary != "tag" {
			t.Fatalf("answer %+v", a)
		}
	}
	if b, _ := os.ReadFile(count); string(b) != "x\n" {
		t.Errorf("asked %q times", b)
	}
	// A changed plugin is asked again.
	later := time.Now().Add(time.Hour)
	os.Chtimes(p, later, later)
	d.Describe(ps)
	if b, _ := os.ReadFile(count); string(b) != "x\nx\n" {
		t.Errorf("asked %q times", b)
	}
}

func TestDescribeTimesOut(t *testing.T) {
	p := script(t, t.TempDir(), "slow", "sleep 5")
	d := &Describer{Env: os.Environ(), Timeout: 100 * time.Millisecond}
	start := time.Now()
	a := d.Describe([]Plugin{{"slow", p}})["slow"]
	if a.Err == nil || !strings.Contains(a.Err.Error(), "timed out") || time.Since(start) > 2*time.Second {
		t.Errorf("answer %+v after %v", a, time.Since(start))
	}
}

func TestCheckSchemas(t *testing.T) {
	installed := []Plugin{{"api", "/x"}, {"api-export", "/y"}, {"gone", "/z"}}
	answers := map[string]Answer{
		"api-export": {Desc: descWith(`{"finding":{"x-api-export-id":{"type":"integer"},"x-other":{"type":"string"}},"config":{"type":"object","required":["url"]}}`)},
		"api":        {Desc: descWith(`{"finding":{"x-api":{"$ref":"other.json"}}}`)},
		"gone":       {Err: os.ErrNotExist},
	}
	names := []report.XName{
		{Noun: "finding", Name: "x-api-export-id", Path: "findings/a.md", Line: 4, Value: []byte(`"seven"`)},
		{Noun: "finding", Name: "x-api", Path: "findings/a.md", Line: 5, Value: []byte(`1`)},
		{Noun: "config", Name: "x-api-export", Path: "rpt.yaml", Line: 9, Value: []byte(`{}`)},
		{Noun: "finding", Name: "x-gone", Path: "findings/a.md", Line: 6, Value: []byte(`1`)},
		{Noun: "finding", Name: "x-unowned", Path: "findings/a.md", Line: 7, Value: []byte(`1`)},
	}
	var got []string
	for _, p := range Check(names, installed, answers) {
		got = append(got, p.Path+" "+p.Level+" "+p.Message)
	}
	want := []string{
		"findings/a.md error x-api-export-id: got string, want integer (schema from api-export)",
		". warning plugin api: the schema for x-api doesn't compile:",
		"rpt.yaml error x-api-export: missing property 'url' (schema from api-export)",
		". warning plugin gone: file does not exist; the x- names it owns are unchecked",
	}
	if len(got) != len(want) {
		t.Fatalf("got %q", got)
	}
	for i := range want {
		if !strings.HasPrefix(got[i], want[i]) {
			t.Errorf("got %q\nwant %q", got[i], want[i])
		}
	}
	if w := Wanted(names, installed); len(w) != 3 {
		t.Errorf("wanted %v", w)
	}
}
