package sdk

import (
	"bytes"
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
			in:   `{"kind":"finding","id":"F-003","title":"SQL injection in login","severity":"high","targets":[{"host":"login.acme.com","vhost":"v","scope":"S-30"},{"scope":"S-14","port":8443,"protocol":"tcp"}],"path":"findings/sqli-login.md","sections":{"description":"d","poc":"p"},"evidence":["evidence/F-003-login.png"],"cvss":"9.1","source":{"kb":"sqli"}}`,
			want: `{"kind":"finding","id":"F-003","title":"SQL injection in login","targets":[{"scope":"S-30","host":"login.acme.com","vhost":"v"},{"scope":"S-14","port":8443,"protocol":"tcp"}],"severity":"high","path":"findings/sqli-login.md","sections":{"description":"d","poc":"p"},"evidence":["evidence/F-003-login.png"],"cvss":"9.1","source":{"kb":"sqli"}}`,
		},
		{
			name: "one lines shape, positions keeping unknown members",
			run:  roundTrip[Finding],
			in:   `{"kind":"finding","title":"t","targets":[],"severity":"low","aaa":1,"lines":{"keys":{"id":{"line":2,"column":1,"end":9}},"sections":{"poc":{"heading":14,"note":"x"}},"zzz":true,"file":"/r/a.md"}}`,
			want: `{"kind":"finding","title":"t","targets":[],"severity":"low","lines":{"file":"/r/a.md","keys":{"id":{"line":2,"column":1,"end":9}},"sections":{"poc":{"heading":14,"note":"x"}},"zzz":true},"aaa":1}`,
		},
		{
			name: "evidence is an asset with an owner",
			run:  roundTrip[Evidence],
			in:   `{"kind":"evidence","finding":"F-001","ref":"e/a.png","path":"findings/e/a.png","exists":true,"image":true,"x":1}`,
			want: `{"kind":"evidence","finding":"F-001","ref":"e/a.png","path":"findings/e/a.png","image":true,"exists":true,"x":1}`,
		},
		{
			name: "a command is a description with a name",
			run:  roundTrip[Command],
			in:   `{"kind":"command","name":"tag","source":"plugin","summary":"s","requires":{"format":{"min":2}},"x":1}`,
			want: `{"kind":"command","name":"tag","source":"plugin","summary":"s","requires":{"format":{"min":2}},"x":1}`,
		},
		{
			name: "problem column",
			run:  roundTrip[Problem],
			in:   `{"kind":"problem","path":"findings/a.md","line":12,"column":7,"rule":"houseStyle","level":"warning","message":"m"}`,
			want: `{"kind":"problem","path":"findings/a.md","line":12,"column":7,"rule":"houseStyle","level":"warning","message":"m"}`,
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
			name: "a report's findings are findings, each target with its row",
			run:  roundTrip[Report],
			in: `{"kind":"report","schema_version":3,"severities":["high"],"sections":[{"key":"poc","heading":"PoC","x":1}],"order":["findings"],` +
				`"summary":{"high":1},"scope":[{"kind":"scope","id":"S-12","host":"10.0.0.5"}],` +
				`"findings":[{"kind":"finding","id":"F-003","title":"t","severity":"high","targets":[{"scope":"S-12","row":{"kind":"scope","id":"S-12","host":"10.0.0.5","env":"prod"},"note":"n"}],"cvss":"9.1"}],` +
				`"pages":[],"generator":"x"}`,
			want: `{"kind":"report","schema_version":3,"severities":["high"],"sections":[{"key":"poc","heading":"PoC","x":1}],"order":["findings"],` +
				`"summary":{"high":1},"scope":[{"kind":"scope","id":"S-12","host":"10.0.0.5"}],` +
				`"findings":[{"kind":"finding","id":"F-003","title":"t","targets":[{"scope":"S-12","row":{"kind":"scope","id":"S-12","host":"10.0.0.5","env":"prod"},"note":"n"}],"severity":"high","cvss":"9.1"}],` +
				`"pages":[],"generator":"x"}`,
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

func TestEmitSetsKind(t *testing.T) {
	var b bytes.Buffer
	if err := Emit(&b, Problem{Path: ".", Rule: "r", Level: Warning, Message: "m"}); err != nil {
		t.Fatal(err)
	}
	if got := b.String(); got != `{"kind":"problem","path":".","rule":"r","level":"warning","message":"m"}`+"\n" {
		t.Errorf("got %s", got)
	}
}
