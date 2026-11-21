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
	code, out, errOut := runIn(t, "", "scope", "--report", fixture)
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if want := "S-12 10.0.0.5 443\nS-14 10.0.0.6 8443\nS-20 10.0.1.0/24 \n"; pick(t, out, "id", "host", "port") != want {
		t.Errorf("stdout\n got: %q\nwant: %q", out, want)
	}
}

func TestScopeByID(t *testing.T) {
	code, out, errOut := runIn(t, "", "scope", "--report", fixture, "S-20", "S-12")
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if got := pick(t, out, "id", "host"); got != "S-20 10.0.1.0/24\nS-12 10.0.0.5\n" {
		t.Errorf("stdout = %q, want S-20 then S-12, in the order asked", got)
	}
	code, out, errOut = runIn(t, "", "scope", "--report", fixture, "S-12", "S-99")
	if code != 1 || pick(t, out, "kind", "id") != "scope S-12\nproblem \n" || !strings.Contains(errOut, "S-99: no such scope row") {
		t.Errorf("unknown ID: exit %d, stdout %q, stderr %q; want 1, S-12 printed, S-99 named", code, out, errOut)
	}
}

func TestScopeMatch(t *testing.T) {
	foreign := `{"kind":"scope",  "id":"S-1","z":1,"a":2}` // odd spacing and order: must survive
	noTarget := `{"kind":"finding","title":"Weak password policy", "targets":[]}`
	already := `{"kind":"finding","title":"Already","targets":[{"scope":"S-20","host":"10.0.1.9"}]}`
	in := strings.Join([]string{
		`{"kind":"finding","title":"SSH weak ciphers","targets":[{"host":"10.0.1.5","port":22,"protocol":"tcp","vhost":"ssh.acme.com"}],"cvss":"5.3"}`, // 1: CIDR S-20
		`{"kind":"finding","title":"TLS","targets":[{"scope":"S-14"},{"host":"10.0.0.5","port":443}]}`,                                                 // 2: one asset S-12
		foreign + "\r", // 3: CRLF
		"",             // 4: blank
		`{"kind":"finding","title":"Telnet","targets":[{"host":"10.9.9.9","port":23,"protocol":"tcp"}]}`, // 5: out of scope
		noTarget, // 6: nothing to match
		"",       // 7: blank (a malformed line now stops the filter: problems_test.go)
		already,  // 8: unchanged
		`{"kind":"finding","title":"Mixed","targets":[{"host":"10.0.0.6","port":8443},{"host":"10.9.9.9"}]}`, // 9: half in scope
	}, "\n") + "\n"

	// Only the targets member changes; every other member keeps its bytes and place.
	ssh := `{"kind":"finding","title":"SSH weak ciphers","targets":[{"scope":"S-20","host":"10.0.1.5","port":22,"protocol":"tcp","vhost":"ssh.acme.com"}],"cvss":"5.3"}`
	tls := `{"kind":"finding","title":"TLS","targets":[{"scope":"S-14"},{"scope":"S-12","port":443}]}`
	telnet := `{"kind":"finding","title":"Telnet","targets":[{"host":"10.9.9.9","port":23,"protocol":"tcp"}]}`
	mixed := `{"kind":"finding","title":"Mixed","targets":[{"scope":"S-14","port":8443},{"host":"10.9.9.9"}]}`
	mixedDropped := `{"kind":"finding","title":"Mixed","targets":[{"scope":"S-14","port":8443}]}`

	tests := []struct {
		name    string
		args    []string
		wantOut []string
		wantErr []string
	}{
		{
			name:    "attributes, passes through, keeps out-of-scope targets",
			args:    []string{"scope", "match", "--report", fixture},
			wantOut: []string{ssh, tls, foreign, telnet, noTarget, already, mixed},
			wantErr: nil,
		},
		{
			name:    "--drop-out-of-scope drops and says so",
			args:    []string{"scope", "match", "--report", fixture, "--drop-out-of-scope"},
			wantOut: []string{ssh, tls, foreign, noTarget, already, mixedDropped},
			wantErr: []string{
				`rpt: -:5: dropped "Telnet": 10.9.9.9 tcp/23 is out of scope`,
				`rpt: -:9: dropped a target of "Mixed": 10.9.9.9 is out of scope`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, errOut := runIn(t, in, tt.args...)
			if code != 0 {
				t.Errorf("exit %d, want 0", code)
			}
			if want := strings.Join(tt.wantOut, "\n") + "\n"; out != want {
				t.Errorf("stdout\n got: %s\nwant: %s", out, want)
			}
			want := strings.Join(tt.wantErr, "\n") + "\n"
			if tt.wantErr == nil {
				want = ""
			}
			if errOut != want {
				t.Errorf("stderr\n got: %q\nwant: %q", errOut, want)
			}
		})
	}
}

// The stage's Done-when: findings piped through scope match.
func TestFindingsThroughScopeMatch(t *testing.T) {
	code, findings, errOut := runIn(t, "", "finding", "get", "--report", fixture, "--json")
	if code != 0 {
		t.Fatalf("findings exit %d: %s", code, errOut)
	}
	big := `{"kind":"scope","id":"S-big","note":"` + strings.Repeat("x", 1<<20) + `"}`
	code, out, errOut := runIn(t, findings+big+"\n", "scope", "match", "--report", fixture, "--drop-out-of-scope")
	if code != 0 || errOut != "" {
		t.Fatalf("scope match exit %d, stderr %q", code, errOut)
	}
	// Fixture findings are attributed already: nothing to match, so every byte passes through.
	if want := findings + big + "\n"; out != want {
		t.Errorf("output differs from input (%d vs %d bytes)", len(out), len(want))
	}
}
