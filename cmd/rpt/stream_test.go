package main

import (
	"bytes"
	"strings"
	"testing"
)

// runIn runs rpt with stdin and returns its exit code, stdout and stderr.
func runIn(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, strings.NewReader(stdin), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestScopeVerb(t *testing.T) {
	code, out, errOut := runIn(t, "", "scope", "--report", fixture, "--format", "{{.id}} {{.host}} {{.port}}")
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if want := "S-12 10.0.0.5 443\nS-14 10.0.0.6 8443\nS-20 10.0.1.0/24 \n"; out != want {
		t.Errorf("stdout\n got: %q\nwant: %q", out, want)
	}
}

func TestScopeMatch(t *testing.T) {
	foreign := `{"kind":"scope",  "id":"S-1","z":1,"a":2}` // odd spacing and order: must survive
	noTarget := `{"kind":"finding","title":"Weak password policy", "scope":[]}`
	in := strings.Join([]string{
		`{"kind":"finding","title":"SSH weak ciphers","target":{"host":"10.0.1.5","port":22,"protocol":"tcp"}}`, // 1: CIDR S-20
		`{"kind":"finding","title":"TLS","scope":["S-14"],"target":{"host":"10.0.0.5","port":443}}`,             // 2: merged with S-12
		foreign + "\r", // 3: CRLF
		"",             // 4: blank
		`{"kind":"finding","title":"Telnet","target":{"host":"10.9.9.9","port":23,"protocol":"tcp"}}`, // 5: out of scope
		noTarget,  // 6: nothing to match
		"garbage", // 7: malformed
		`{"kind":"finding","title":"Already","scope":["S-20"],"target":{"host":"10.0.1.9"}}`, // 8: unchanged
	}, "\n") + "\n"

	// Only the scope member changes; every other member keeps its bytes and place.
	matched1 := `{"kind":"finding","title":"SSH weak ciphers","target":{"host":"10.0.1.5","port":22,"protocol":"tcp"},"scope":["S-20"]}`
	matched2 := `{"kind":"finding","title":"TLS","scope":["S-12","S-14"],"target":{"host":"10.0.0.5","port":443}}`
	telnet := `{"kind":"finding","title":"Telnet","target":{"host":"10.9.9.9","port":23,"protocol":"tcp"}}`
	already := `{"kind":"finding","title":"Already","scope":["S-20"],"target":{"host":"10.0.1.9"}}`

	tests := []struct {
		name    string
		args    []string
		wantOut []string
		wantErr []string
	}{
		{
			name:    "matches, merges, passes through, keeps out-of-scope",
			args:    []string{"scope", "match", "--report", fixture},
			wantOut: []string{matched1, matched2, foreign, telnet, noTarget, already},
			wantErr: []string{"rpt: stdin:7: not a JSON object"},
		},
		{
			name:    "--drop-out-of-scope drops and says so",
			args:    []string{"scope", "match", "--report", fixture, "--drop-out-of-scope"},
			wantOut: []string{matched1, matched2, foreign, noTarget, already},
			wantErr: []string{
				`rpt: stdin:5: dropped "Telnet": 10.9.9.9 tcp/23 is out of scope`,
				"rpt: stdin:7: not a JSON object",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, errOut := runIn(t, in, tt.args...)
			if code != 1 {
				t.Errorf("exit %d, want 1 for the malformed line", code)
			}
			if want := strings.Join(tt.wantOut, "\n") + "\n"; out != want {
				t.Errorf("stdout\n got: %s\nwant: %s", out, want)
			}
			if want := strings.Join(tt.wantErr, "\n") + "\n"; errOut != want {
				t.Errorf("stderr\n got: %q\nwant: %q", errOut, want)
			}
		})
	}
}

// The stage's Done-when: findings piped through scope match.
func TestFindingsThroughScopeMatch(t *testing.T) {
	code, findings, errOut := runIn(t, "", "findings", "--report", fixture, "--json")
	if code != 0 {
		t.Fatalf("findings exit %d: %s", code, errOut)
	}
	big := `{"kind":"scope","id":"S-big","note":"` + strings.Repeat("x", 1<<20) + `"}`
	code, out, errOut := runIn(t, findings+big+"\n", "scope", "match", "--report", fixture, "--drop-out-of-scope")
	if code != 0 || errOut != "" {
		t.Fatalf("scope match exit %d, stderr %q", code, errOut)
	}
	// Fixture findings have no target: nothing to match, so every byte passes through.
	if want := findings + big + "\n"; out != want {
		t.Errorf("output differs from input (%d vs %d bytes)", len(out), len(want))
	}
}
