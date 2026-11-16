package report

import (
	"slices"
	"testing"

	"github.com/astr4liteEx/rpt/sdk"
)

func TestMatchScope(t *testing.T) {
	rows := []sdk.ScopeRow{
		{ID: "S-1", Host: "10.0.0.5"},
		{ID: "S-2", Host: "10.0.0.6", Port: 443, Protocol: "tcp"},
		{ID: "S-3", Host: "10.0.1.0/24"},
		{ID: "S-4", Host: "*.acme.com"},
		{ID: "S-5", Host: "Login.Example.com", Port: 8443},
		{ID: "S-6", Host: "2001:db8::/32", Protocol: "udp"},
		{ID: "S-7", Host: "10.0.1.5", Port: 443},
	}
	tests := []struct {
		name   string
		target sdk.Target
		want   []string
	}{
		{"exact host, row without port or protocol", sdk.Target{Host: "10.0.0.5", Port: 22, Protocol: "tcp"}, []string{"S-1"}},
		{"port and protocol equal", sdk.Target{Host: "10.0.0.6", Port: 443, Protocol: "tcp"}, []string{"S-2"}},
		{"protocol differs", sdk.Target{Host: "10.0.0.6", Port: 443, Protocol: "udp"}, nil},
		{"target without protocol matches any", sdk.Target{Host: "10.0.0.6", Port: 443}, []string{"S-2"}},
		{"port differs", sdk.Target{Host: "10.0.0.6", Port: 80}, nil},
		{"target without port against a port row", sdk.Target{Host: "10.0.0.6"}, nil},
		{"IP inside a CIDR row", sdk.Target{Host: "10.0.1.77"}, []string{"S-3"}},
		{"IP outside the CIDR", sdk.Target{Host: "10.0.2.1"}, nil},
		{"wildcard matches a subdomain", sdk.Target{Host: "api.acme.com"}, []string{"S-4"}},
		{"wildcard matches deeper subdomains", sdk.Target{Host: "deep.api.acme.com"}, []string{"S-4"}},
		{"wildcard does not match the bare domain", sdk.Target{Host: "acme.com"}, nil},
		{"wildcard is not a suffix match", sdk.Target{Host: "notacme.com"}, nil},
		{"host names ignore case", sdk.Target{Host: "login.example.COM", Port: 8443}, []string{"S-5"}},
		{"IPv6 in a CIDR with protocol", sdk.Target{Host: "2001:db8::1", Port: 53, Protocol: "udp"}, []string{"S-6"}},
		{"several rows match, sorted", sdk.Target{Host: "10.0.1.5", Port: 443, Protocol: "tcp"}, []string{"S-3", "S-7"}},
		{"no DNS: a name never matches an IP row", sdk.Target{Host: "host.internal"}, nil},
		{"empty host matches nothing", sdk.Target{}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MatchScope(tt.target, rows); !slices.Equal(got, tt.want) {
				t.Errorf("MatchScope(%+v) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}
