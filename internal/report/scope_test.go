package report

import (
	"encoding/json/jsontext"
	"errors"
	"reflect"
	"testing"

	"github.com/astr4liteEx/rpt/sdk"
)

func TestScopeReadsFixture(t *testing.T) {
	got, err := openFixture(t).Scope()
	if err != nil {
		t.Fatal(err)
	}
	env := func(v string) map[string]jsontext.Value {
		return map[string]jsontext.Value{"env": jsontext.Value(`"` + v + `"`)}
	}
	want := []sdk.ScopeRow{
		{Kind: "scope", ID: "S-12", Host: "10.0.0.5", Port: 443, Extra: env("prod")},
		{Kind: "scope", ID: "S-14", Host: "10.0.0.6", Port: 8443, Extra: env("prod")},
		{Kind: "scope", ID: "S-20", Host: "10.0.1.0/24", Extra: env("staging")},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("scope\n got: %#v\nwant: %#v", got, want)
	}
}

func TestScopeErrors(t *testing.T) {
	tests := []struct {
		name     string
		csv      string
		wantRows int
		wantLine int
	}{
		{"bad port keeps other rows", "id,host,port\nS-1,a,80\nS-2,b,http\nS-3,c,\n", 2, 3},
		{"port out of range", "id,host,port\nS-1,a,70000\n", 0, 2},
		{"missing host column", "id,port\nS-1,80\n", 0, 1},
		{"bad protocol", "id,host,port,protocol\nS-1,a,53,udp\nS-2,b,80,http\n", 1, 3},
		{"row without a host", "id,host\nS-1,a\nS-2,\n", 1, 3},
		{"row without an id", "id,host\n,a\nS-2,b\n", 1, 2},
		{"repeated id keeps the first row", "id,host\nS-1,a\nS-2,b\nS-1,c\n", 2, 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := copyFixture(t)
			writeFile(t, dir, "scope.csv", tt.csv)
			r, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			rows, err := r.Scope()
			if len(rows) != tt.wantRows {
				t.Errorf("got %d rows, want %d", len(rows), tt.wantRows)
			}
			fe, ok := errors.AsType[*FileError](err)
			if !ok {
				t.Fatalf("err = %v, want a *FileError", err)
			}
			if fe.Path != "scope.csv" || fe.Line != tt.wantLine {
				t.Errorf("FileError at %s:%d, want scope.csv:%d", fe.Path, fe.Line, tt.wantLine)
			}
		})
	}
}

func TestScopeProtocolIsDeclared(t *testing.T) {
	dir := copyFixture(t)
	writeFile(t, dir, "scope.csv", "id,host,port,protocol\nS-1,10.0.0.1,53,udp\nS-2,10.0.0.2,,\n")
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	rows, err := r.Scope()
	if err != nil {
		t.Fatal(err)
	}
	want := []sdk.ScopeRow{
		{Kind: "scope", ID: "S-1", Host: "10.0.0.1", Port: 53, Protocol: "udp"},
		{Kind: "scope", ID: "S-2", Host: "10.0.0.2"},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Errorf("rows\n got: %#v\nwant: %#v", rows, want)
	}
}
