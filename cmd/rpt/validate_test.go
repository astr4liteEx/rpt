package main

import (
	"strings"
	"testing"
)

func TestValidateIDs(t *testing.T) {
	code, out, _ := runIn(t, "", "validate", "F-001", "--report", fixture)
	if code != 0 || out != "" {
		t.Errorf("F-001: exit %d, stdout %q", code, out)
	}
	code, out, _ = runIn(t, "", "validate", "f-002", "--report", fixture)
	if code != 1 || pick(t, out, "path", "rule") != "findings/tls-weak.md scopeIDsExist\n" || pick(t, out, "rev") == "\n" {
		t.Errorf("F-002: exit %d, stdout %q", code, out)
	}
	if code, out, _ = runIn(t, "", "validate", "F-404", "--report", fixture); code != 1 || pick(t, out, "rule") != "exists\n" {
		t.Errorf("F-404: exit %d, stdout %q", code, out)
	}
}

const cleanStream = `{"kind":"scope","id":"S-30","host":"10.9.0.1"}
{"kind":"finding","title":"New","severity":"low","targets":[{"scope":"S-30"}],"sections":{"description":"d","remediation":"r","poc":"p"}}
{"kind":"note","x":1}
`

func TestValidateStreamPassesCleanInput(t *testing.T) {
	code, out, errOut := runIn(t, cleanStream, "validate", "-", "--report", fixture)
	if code != 0 || out != cleanStream {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

func TestValidateStreamStopsBrokenInput(t *testing.T) {
	in := `{"kind":"finding","title":"New","severity":"low","targets":[{"scope":"S-77"}],"sections":{"description":"d","remediation":"r","poc":"p"}}
{"kind":"finding","id":"F-001","title":"","severity":"low"}
{"kind":"scope","id":"S-12","host":"10.0.0.5"}
{"kind":"scope","id":"S-12","host":"10.0.0.6"}
`
	code, out, _ := runIn(t, in, "validate", "-", "--report", fixture)
	if code != 1 || pick(t, out, "path", "line", "rule") != "- 2 write\n- 4 duplicate\n- 1 scopeIDsExist\n" {
		t.Errorf("exit %d, stdout %q", code, out)
	}
	// Piped into add, nothing is added, without pipefail.
	dir := reportCopy(t)
	before := folderState(t, dir)
	code, out, _ = runIn(t, out, "finding", "add", "--report", dir)
	if code != 1 || strings.Contains(out, `"kind":"finding"`) || len(folderState(t, dir)) != len(before) {
		t.Errorf("add: exit %d, stdout %q", code, out)
	}
}

func TestValidateStreamReplacesAndChecksConfig(t *testing.T) {
	// Replacing F-002 with a fitting target clears the report's own problem;
	// a config record requiring a section F-001 lacks raises one elsewhere.
	in := `{"kind":"finding","id":"F-002","title":"Weak TLS","severity":"info","targets":[{"scope":"S-12"}],"sections":{"description":"d","remediation":"r","poc":"p"}}
{"kind":"config","format":2,"required_sections":["description","remediation","poc","impact"]}
`
	code, out, _ := runIn(t, in, "validate", "-", "--report", fixture)
	got := pick(t, out, "path", "line", "rule", "message")
	if code != 1 || !strings.Contains(got, "findings/xss-search.md") || !strings.Contains(got, "- 1 requiredSections F-002: ") || strings.Contains(got, "scopeIDsExist") {
		t.Errorf("exit %d, stdout %q", code, got)
	}
}

func TestValidateStreamPassesIncomingProblems(t *testing.T) {
	in := `{"kind":"problem","path":"x","rule":"lint","level":"error","message":"m","command":"lint"}` + "\n" + cleanStream
	code, out, errOut := runIn(t, in, "validate", "-", "--report", fixture)
	if code != 1 || pick(t, out, "command") != "lint\n" || strings.Contains(errOut, "lint") {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}
