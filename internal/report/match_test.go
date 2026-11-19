package report

import (
	"strings"
	"testing"

	"github.com/astr4liteEx/rpt/sdk"
)

func TestAttribute(t *testing.T) {
	rows := []sdk.ScopeRow{
		{ID: "S-1", Host: "10.0.0.5"},
		{ID: "S-2", Host: "10.0.0.6", Port: 443, Protocol: "tcp"},
		{ID: "S-3", Host: "10.0.1.0/24"},
		{ID: "S-4", Host: "*.acme.com"},
		{ID: "S-5", Host: "Login.Example.com", Port: 8443},
		{ID: "S-6", Host: "2001:db8::/32", Protocol: "udp"},
		{ID: "S-7", Host: "10.0.1.5", Port: 443},
		{ID: "S-8", Host: "10.0.1.0/26"},
		{ID: "S-9", Host: "*.api.acme.com"},
		{ID: "S-10", Host: "Acme iOS app"},
		{ID: "S-11", Host: "10.0.1.9"},
		{ID: "S-12", Host: "10.0.1.9", Protocol: "tcp"},
	}
	tests := []struct {
		name   string
		target sdk.Target
		want   sdk.Target // Scope empty: no row covers it
	}{
		{"one asset: its ID, host dropped", sdk.Target{Host: "10.0.0.5", Port: 22, Protocol: "tcp"}, sdk.Target{Scope: "S-1", Port: 22, Protocol: "tcp"}},
		{"port and protocol equal", sdk.Target{Host: "10.0.0.6", Port: 443, Protocol: "tcp"}, sdk.Target{Scope: "S-2", Port: 443, Protocol: "tcp"}},
		{"protocol differs", sdk.Target{Host: "10.0.0.6", Port: 443, Protocol: "udp"}, sdk.Target{}},
		{"target without protocol matches any", sdk.Target{Host: "10.0.0.6", Port: 443}, sdk.Target{Scope: "S-2", Port: 443}},
		{"port differs", sdk.Target{Host: "10.0.0.6", Port: 80}, sdk.Target{}},
		{"target without port against a port row", sdk.Target{Host: "10.0.0.6"}, sdk.Target{}},
		{"IP in a CIDR: the range's ID, host kept", sdk.Target{Host: "10.0.1.77"}, sdk.Target{Scope: "S-3", Host: "10.0.1.77"}},
		{"the narrower CIDR wins", sdk.Target{Host: "10.0.1.6", Port: 22}, sdk.Target{Scope: "S-8", Host: "10.0.1.6", Port: 22}},
		{"only the wider CIDR covers it", sdk.Target{Host: "10.0.1.100"}, sdk.Target{Scope: "S-3", Host: "10.0.1.100"}},
		{"IP outside every CIDR", sdk.Target{Host: "10.1.0.1"}, sdk.Target{}},
		{"one asset beats a CIDR", sdk.Target{Host: "10.0.1.5", Port: 443, Protocol: "tcp"}, sdk.Target{Scope: "S-7", Port: 443, Protocol: "tcp"}},
		{"a row with a protocol beats one without", sdk.Target{Host: "10.0.1.9", Protocol: "tcp"}, sdk.Target{Scope: "S-12", Protocol: "tcp"}},
		{"wildcard matches a subdomain", sdk.Target{Host: "www.acme.com"}, sdk.Target{Scope: "S-4", Host: "www.acme.com"}},
		{"the longer wildcard wins", sdk.Target{Host: "v1.api.acme.com"}, sdk.Target{Scope: "S-9", Host: "v1.api.acme.com"}},
		{"wildcard does not match the bare domain", sdk.Target{Host: "acme.com"}, sdk.Target{}},
		{"wildcard is not a suffix match", sdk.Target{Host: "notacme.com"}, sdk.Target{}},
		{"names ignore case", sdk.Target{Host: "login.example.COM", Port: 8443}, sdk.Target{Scope: "S-5", Port: 8443}},
		{"IPv6 in a CIDR with protocol", sdk.Target{Host: "2001:db8::1", Port: 53, Protocol: "udp"}, sdk.Target{Scope: "S-6", Host: "2001:db8::1", Port: 53, Protocol: "udp"}},
		{"any text is one asset", sdk.Target{Host: "acme ios APP"}, sdk.Target{Scope: "S-10"}},
		{"no DNS: a name never matches an IP row", sdk.Target{Host: "host.internal"}, sdk.Target{}},
		{"empty host matches nothing", sdk.Target{}, sdk.Target{}},
		{"already attributed: unchanged", sdk.Target{Scope: "S-99", Host: "10.0.0.5"}, sdk.Target{Scope: "S-99", Host: "10.0.0.5"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Attribute(tt.target, rows)
			if ok != (tt.want.Scope != "") {
				t.Fatalf("Attribute(%+v) ok = %v", tt.target, ok)
			}
			if !ok {
				tt.want = tt.target // an uncovered target comes back unchanged
			}
			if got.Scope != tt.want.Scope || got.Host != tt.want.Host || got.Port != tt.want.Port || got.Protocol != tt.want.Protocol {
				t.Errorf("Attribute(%+v) = %+v, want %+v", tt.target, got, tt.want)
			}
		})
	}
}

func TestTargetFits(t *testing.T) {
	asset := sdk.ScopeRow{ID: "S-1", Host: "10.0.0.5", Port: 443, Protocol: "tcp"}
	cidr := sdk.ScopeRow{ID: "S-2", Host: "10.0.1.0/24"}
	wild := sdk.ScopeRow{ID: "S-3", Host: "*.acme.com"}
	text := sdk.ScopeRow{ID: "S-4", Host: "Acme iOS app"}
	tests := []struct {
		name    string
		target  sdk.Target
		row     sdk.ScopeRow
		wantErr string
	}{
		{"bare ID", sdk.Target{Scope: "S-1"}, asset, ""},
		{"the row's own port and protocol", sdk.Target{Scope: "S-1", Port: 443, Protocol: "tcp"}, asset, ""},
		{"another port", sdk.Target{Scope: "S-1", Port: 80}, asset, "port 80 is not S-1's port 443"},
		{"another protocol", sdk.Target{Scope: "S-1", Protocol: "udp"}, asset, "protocol udp is not S-1's protocol tcp"},
		{"host on one asset", sdk.Target{Scope: "S-1", Host: "10.0.0.5"}, asset, "S-1 is one asset"},
		{"host on a text asset", sdk.Target{Scope: "S-4", Host: "x"}, text, "S-4 is one asset"},
		{"the whole range", sdk.Target{Scope: "S-2", Port: 22}, cidr, ""},
		{"host inside the range", sdk.Target{Scope: "S-2", Host: "10.0.1.5", Port: 22, Protocol: "udp"}, cidr, ""},
		{"host outside the range", sdk.Target{Scope: "S-2", Host: "10.0.2.5"}, cidr, "host 10.0.2.5 is not inside S-2"},
		{"name in a wildcard", sdk.Target{Scope: "S-3", Host: "api.acme.com"}, wild, ""},
		{"name outside a wildcard", sdk.Target{Scope: "S-3", Host: "acme.org"}, wild, "is not inside S-3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := TargetFits(tt.target, tt.row)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("TargetFits = %v, want nil", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Errorf("TargetFits = %v, want an error with %q", err, tt.wantErr)
			}
		})
	}
}
