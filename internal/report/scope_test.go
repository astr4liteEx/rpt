package report

import (
	"strings"
	"testing"
)

func TestAttribute(t *testing.T) {
	m := fixture(t, map[string]string{ScopeFile: "id,host,port,protocol\n" +
		"S-1,10.0.0.0/16,,\n" +
		"S-2,10.0.1.0/24,,\n" +
		"S-3,10.0.1.7,,\n" +
		"S-4,*.acme.com,,\n" +
		"S-5,*.api.acme.com,,\n" +
		"S-6,10.0.2.0/24,443,tcp\n" +
		"S-7,10.0.2.0/24,,\n" +
		"S-10,10.9.0.0/24,,\n" +
		"S-9,10.9.0.0/24,,\n"})
	for _, tc := range []struct {
		host string
		port int
		want string // row, then host kept or not
	}{
		{"10.0.1.7", 0, "S-3 "},
		{"10.0.1.8", 0, "S-2 10.0.1.8"},
		{"10.0.9.9", 0, "S-1 10.0.9.9"},
		{"x.api.acme.com", 0, "S-5 x.api.acme.com"},
		{"www.acme.com", 0, "S-4 www.acme.com"},
		{"10.0.2.5", 443, "S-6 10.0.2.5"},
		{"10.0.2.5", 80, "S-7 10.0.2.5"},
		{"10.9.0.1", 0, "S-9 10.9.0.1"},
		{"acme.com", 0, "none"},
	} {
		got, row, ok := m.Scope.Attribute(Target{Host: tc.host, Port: tc.port})
		s := "none"
		if ok {
			s = row.ID + " " + got.Host
		}
		if s != tc.want {
			t.Errorf("%s:%d: got %q, want %q", tc.host, tc.port, s, tc.want)
		}
	}
}

func TestFits(t *testing.T) {
	asset := &Row{ID: "S-1", Host: "10.0.0.5", Port: 443}
	rng := &Row{ID: "S-2", Host: "10.0.1.0/24"}
	for _, tc := range []struct {
		row *Row
		t   Target
		ok  bool
	}{
		{asset, Target{}, true},
		{asset, Target{Port: 443}, true},
		{asset, Target{Port: 80}, false},
		{asset, Target{Host: "10.0.0.5"}, false},
		{rng, Target{Host: "10.0.1.7"}, true},
		{rng, Target{Host: "10.0.2.7"}, false},
	} {
		if err := Fits(tc.row, tc.t); (err == nil) != tc.ok {
			t.Errorf("%+v on %s: %v", tc.t, tc.row.ID, err)
		}
	}
}

func TestScopeWrites(t *testing.T) {
	m := fixture(t, nil)
	r, err := m.AddScope(Row{Host: "10.0.0.9", Port: 22, Extra: map[string]string{"env": "prod"}})
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != "S-100" { // S-99 is cited by the fixture's planted problem
		t.Errorf("new ID %s", r.ID)
	}
	if _, err := m.AddScope(Row{ID: "s-12", Host: "x"}); !isRefusal(err) {
		t.Errorf("a duplicate ID in another case: %v", err)
	}
	if _, err := m.AddScope(Row{Host: "x", Extra: map[string]string{"owner": "me"}}); !isRefusal(err) {
		t.Errorf("a new column: %v", err)
	}

	// Renaming a row carries into its findings.
	ch, err := m.SetScope("S-14", "id", "S-15", Refuse)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Row.ID != "S-15" || len(ch.Rewrote) != 2 {
		t.Fatalf("rename: %+v", ch)
	}
	f, _ := m.Get(FindingKind, "F-001")
	if f.Targets[0].Scope != "S-15" || f.Targets[0].Port != 8443 {
		t.Errorf("F-001 targets %+v", f.Targets)
	}

	// A port that unfits a citing target is refused, or dropped.
	if _, err := m.SetScope("S-15", "port", "9443", Refuse); !isRefusal(err) {
		t.Fatalf("unfit: %v", err)
	}
	if ch, err = m.SetScope("S-15", "port", "9443", Cleanup); err != nil {
		t.Fatal(err)
	}
	if f, _ = m.Get(FindingKind, "F-001"); len(f.Targets) != 0 {
		t.Errorf("cleanup left %+v", f.Targets)
	}

	if _, err := m.RemoveScope("S-12", Refuse); !isRefusal(err) {
		t.Fatalf("cited remove: %v", err)
	}
	if _, err := m.RemoveScope("S-12", Cleanup); err != nil {
		t.Fatal(err)
	}
	mustSave(t, m)
	want := "id,host,port,env\nS-15,10.0.0.6,9443,prod\nS-20,10.0.1.0/24,,staging\nS-100,10.0.0.9,22,prod\n"
	if got := readDisk(t, m, ScopeFile); got != want {
		t.Errorf("scope.csv:\n%s", got)
	}
	if got := readDisk(t, m, "findings/sqli-login.md"); !strings.Contains(got, "targets:\n  - {scope: S-15}\n") {
		t.Errorf("F-003:\n%s", got)
	}
}
