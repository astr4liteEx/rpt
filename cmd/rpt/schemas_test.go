package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// plugins puts shell-script plugins on PATH, each answering --describe
// with the given JSON and doing nothing else.
func plugins(t *testing.T, describe map[string]string) {
	t.Helper()
	dir := t.TempDir()
	for name, d := range describe {
		script := "#!/bin/sh\nif [ \"$1\" = --describe ]; then echo '" + d + "'; fi\n"
		if err := os.WriteFile(filepath.Join(dir, "rpt-"+name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
}

// withXKey gives F-001 the frontmatter key x-foo-id with value v.
func withXKey(t *testing.T, v string) string {
	dir := reportCopy(t)
	if code, _, errOut := runIn(t, "", "finding", "set", "F-001", "x-foo-id", v, "--report", dir); code != 0 {
		t.Fatalf("set: %s", errOut)
	}
	return dir
}

func TestPluginSchemaFlagsAValue(t *testing.T) {
	plugins(t, map[string]string{"foo": `{"summary":"s","schemas":{"finding":{"x-foo-id":{"type":"string"}}}}`})
	dir := withXKey(t, "7")
	code, out, _ := runIn(t, "", "validate", "F-001", "--report", dir)
	if code != 1 || pick(t, out, "rule", "message") != "pluginSchema x-foo-id: got number, want string (schema from foo)\n" || !strings.Contains(out, `"line":`) {
		t.Errorf("exit %d, stdout %q", code, out)
	}
	if code, out, _ := runIn(t, "", "validate", "F-001", "--report", withXKey(t, "abc")); code != 0 {
		t.Errorf("a string: exit %d, stdout %q", code, out)
	}
	// rules: gives the rule another level.
	runIn(t, "", "config", "set", "rules", "{pluginSchema: warning}", "--report", dir)
	if code, out, _ := runIn(t, "", "validate", "F-001", "--report", dir); code != 0 || pick(t, out, "level") != "warning\n" {
		t.Errorf("as a warning: exit %d, stdout %q", code, out)
	}
}

func TestPluginSchemaRefusals(t *testing.T) {
	for name, tt := range map[string]struct{ describe, want string }{
		"file ref":    {`{"summary":"s","schemas":{"finding":{"x-foo-id":{"$ref":"file:///etc/passwd"}}}}`, "doesn't compile"},
		"not its own": {`{"summary":"s","schemas":{"finding":{"x-bar-id":{"type":"string"}}}}`, "isn't its own"},
		"broken":      {`not json`, "--describe did not print"},
	} {
		t.Run(name, func(t *testing.T) {
			plugins(t, map[string]string{"foo": tt.describe})
			code, out, _ := runIn(t, "", "validate", "--report", withXKey(t, "7"))
			if !strings.Contains(out, tt.want) || !strings.Contains(out, `"path":".","rule":"pluginSchema","level":"warning"`) || strings.Contains(out, `"level":"error","message":"x-foo-id`) {
				t.Errorf("exit %d, stdout %s", code, out)
			}
		})
	}
}

func TestPluginSchemaTwoClaimants(t *testing.T) {
	plugins(t, map[string]string{
		"foo":     `{"summary":"s","schemas":{"finding":{"x-foo-bar-id":{"type":"number"}}}}`,
		"foo-bar": `{"summary":"s","schemas":{"finding":{"x-foo-bar-id":{"minimum":10}}}}`,
	})
	dir := reportCopy(t)
	runIn(t, "", "finding", "set", "F-001", "x-foo-bar-id", "7", "--report", dir)
	_, out, _ := runIn(t, "", "validate", "--report", dir)
	if !strings.Contains(out, "x-foo-bar-id is declared by both foo and foo-bar") || !strings.Contains(out, "(schema from foo-bar)") || strings.Contains(out, "(schema from foo)") {
		t.Errorf("stdout %s", out)
	}
}

func TestPluginSchemaInStream(t *testing.T) {
	plugins(t, map[string]string{"foo": `{"summary":"s","schemas":{"kinds":{"x-foo-row":{"required":["n"]}}}}`})
	code, out, _ := runIn(t, `{"kind":"x-foo-row"}`+"\n", "validate", "-", "--report", reportCopy(t))
	if code != 1 || pick(t, out, "path", "line", "rule") != "- 1 pluginSchema\n" {
		t.Errorf("exit %d, stdout %q", code, out)
	}
}

func TestIncompatiblePlugin(t *testing.T) {
	plugins(t, map[string]string{"old": `{"summary":"s","requires":{"schema_version":[1]}}`, "new": `{"summary":"s","requires":{"schema_version":[2],"format":[2]}}`})
	_, out, _ := runIn(t, "", "help", "--json")
	if strings.Contains(out, `"name":"old"`) || !strings.Contains(out, `"name":"new"`) {
		t.Errorf("help: %s", out)
	}
	_, out, _ = runIn(t, "", "help", "--all", "--json")
	if !strings.Contains(out, `"name":"old"`) || !strings.Contains(out, `"incompatible":true`) {
		t.Errorf("help --all: %s", out)
	}
}

func TestRunningIncompatiblePluginWarns(t *testing.T) {
	plugins(t, map[string]string{"old": `{"summary":"s","requires":{"format":[1]}}`})
	code, _, errOut := runIn(t, "", "old")
	if code != 0 || strings.Count(errOut, "may not work with this rpt") != 1 {
		t.Errorf("exit %d, stderr %q", code, errOut)
	}
}
