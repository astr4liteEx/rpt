package sdk

import (
	"encoding/json/v2"
	"testing"
)

// roundTrip decodes line into a fresh T and re-encodes it the way every rpt
// writer does.
func roundTrip[T any](t *testing.T, line string) string {
	t.Helper()
	var v T
	if err := json.Unmarshal([]byte(line), &v); err != nil {
		t.Fatalf("decode %s: %v", line, err)
	}
	out, err := json.Marshal(v, json.Deterministic(true))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return string(out)
}

func TestRecordsRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T, string) string
		in   string
		want string
	}{
		{
			name: "finding keeps known and unknown fields",
			run:  roundTrip[Finding],
			in:   `{"kind":"finding","id":"F-003","title":"SQL injection in login","scope":["S-12","S-14"],"severity":"high","path":"findings/sqli-login.md","sections":{"description":"d","poc":"p"},"evidence":["evidence/F-003-login.png"],"cvss":"9.1","target":{"host":"10.0.0.5","port":443,"protocol":"tcp","vhost":"login.acme.com"},"source":{"kb":"sqli"}}`,
			want: `{"kind":"finding","id":"F-003","title":"SQL injection in login","scope":["S-12","S-14"],"severity":"high","path":"findings/sqli-login.md","sections":{"description":"d","poc":"p"},"evidence":["evidence/F-003-login.png"],"target":{"host":"10.0.0.5","port":443,"protocol":"tcp","vhost":"login.acme.com"},"cvss":"9.1","source":{"kb":"sqli"}}`,
		},
		{
			name: "scope row keeps extra CSV columns",
			run:  roundTrip[ScopeRow],
			in:   `{"kind":"scope","id":"S-12","host":"10.0.0.5","port":443,"protocol":"tcp","env":"prod"}`,
			want: `{"kind":"scope","id":"S-12","host":"10.0.0.5","port":443,"protocol":"tcp","env":"prod"}`,
		},
		{
			name: "scope row without a port omits it",
			run:  roundTrip[ScopeRow],
			in:   `{"kind":"scope","id":"S-20","host":"10.0.1.0/24"}`,
			want: `{"kind":"scope","id":"S-20","host":"10.0.1.0/24"}`,
		},
		{
			name: "problem keeps unknown fields",
			run:  roundTrip[Problem],
			in:   `{"kind":"problem","path":"findings/sqli-login.md","line":4,"rule":"knownSeverity","level":"error","message":"unknown severity \"hgih\"","hint":"use high"}`,
			want: `{"kind":"problem","path":"findings/sqli-login.md","line":4,"rule":"knownSeverity","level":"error","message":"unknown severity \"hgih\"","hint":"use high"}`,
		},
		{
			name: "problem about the whole report has no line",
			run:  roundTrip[Problem],
			in:   `{"kind":"problem","path":"scope.csv","rule":"scopeIDsExist","level":"warning","message":"m"}`,
			want: `{"kind":"problem","path":"scope.csv","rule":"scopeIDsExist","level":"warning","message":"m"}`,
		},
		{
			name: "report nests full scope rows in findings and keeps unknown fields at every level",
			run:  roundTrip[Report],
			in: `{"kind":"report","schema_version":1,` +
				`"report":{"severities":["critical","high","medium","low","info"],"renderer":"typst"},` +
				`"summary":{"high":1,"critical":0,"medium":1,"low":0,"info":2},` +
				`"scope":[{"kind":"scope","id":"S-12","host":"10.0.0.5","port":443}],` +
				`"findings":[{"id":"F-003","title":"SQL injection in login","severity":"high",` +
				`"scope":[{"kind":"scope","id":"S-12","host":"10.0.0.5","port":443,"env":"prod"}],` +
				`"sections":{"description":"d","remediation":"r","poc":"p"},` +
				`"assets":["/engagements/acme/findings/evidence/F-003-login.png"],"cvss":"9.1","target":{"host":"10.0.0.5","port":443}}],` +
				`"generator":"rpt 0.1.0"}`,
			want: `{"kind":"report","schema_version":1,` +
				`"report":{"severities":["critical","high","medium","low","info"],"renderer":"typst"},` +
				`"summary":{"critical":0,"high":1,"info":2,"low":0,"medium":1},` +
				`"scope":[{"kind":"scope","id":"S-12","host":"10.0.0.5","port":443}],` +
				`"findings":[{"id":"F-003","title":"SQL injection in login","severity":"high",` +
				`"scope":[{"kind":"scope","id":"S-12","host":"10.0.0.5","port":443,"env":"prod"}],` +
				`"sections":{"description":"d","poc":"p","remediation":"r"},` +
				`"assets":["/engagements/acme/findings/evidence/F-003-login.png"],"target":{"host":"10.0.0.5","port":443},"cvss":"9.1"}],` +
				`"generator":"rpt 0.1.0"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.run(t, tt.in); got != tt.want {
				t.Errorf("round trip\n got: %s\nwant: %s", got, tt.want)
			}
		})
	}
}
