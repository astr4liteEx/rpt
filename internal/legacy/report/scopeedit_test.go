package report

import (
	"errors"
	"maps"
	"path/filepath"
	"strings"
	"testing"

	"github.com/astr4liteEx/rpt/sdk"
)

// scopeWrite runs do as one committed write on a fresh copy.
func scopeWrite(t *testing.T, do func(*Tx) (ScopeChange, error)) (ScopeChange, string, error) {
	t.Helper()
	r, dir := openCopy(t)
	tx := r.Begin()
	ch, err := do(tx)
	if err == nil {
		err = tx.Commit(false)
	}
	return ch, dir, err
}

func file(t *testing.T, dir, rel string) string {
	t.Helper()
	return string(mustReadFile(t, filepath.Join(dir, rel)))
}

func TestRenameCarriesThrough(t *testing.T) {
	ch, dir, err := scopeWrite(t, func(tx *Tx) (ScopeChange, error) { return tx.SetScope("S-14", "id", "S-015", CitedRefuse) })
	if err != nil {
		t.Fatal(err)
	}
	if ch.Row.ID != "S-015" || len(ch.Findings) != 2 {
		t.Errorf("row %s, %d findings changed; want S-015 and 2", ch.Row.ID, len(ch.Findings))
	}
	if got := file(t, dir, "scope.csv"); got != "id,host,port,env\nS-12,10.0.0.5,443,prod\nS-015,10.0.0.6,8443,prod\nS-20,10.0.1.0/24,,staging\n" {
		t.Errorf("scope.csv:\n%s", got)
	}
	if got := file(t, dir, "findings/sqli-login.md"); !strings.Contains(got, "targets: [{scope: S-12}, {scope: S-015}]   # both login front-ends\n") {
		t.Errorf("sqli-login.md:\n%s", got)
	}
	if got := file(t, dir, "findings/xss-search.md"); !strings.Contains(got, "targets: [{scope: S-015, port: 8443, protocol: tcp}]\r\n") {
		t.Errorf("xss-search.md:\n%q", got)
	}
}

func TestRenameRefusesATakenID(t *testing.T) {
	for _, to := range []string{"S-12", "S-99"} { // a row's, and one only a target cites
		r, dir := openCopy(t)
		before := snapshot(t, dir)
		if _, err := r.Begin().SetScope("S-14", "id", to, CitedRefuse); !errors.Is(err, ErrBadValue) {
			t.Errorf("%s: err = %v", to, err)
		}
		if !maps.Equal(before, snapshot(t, dir)) {
			t.Errorf("%s: folder changed", to)
		}
	}
}

func TestNarrowingIsRefusedUnlessForceOrCleanup(t *testing.T) {
	// xss-search.md targets S-14 on port 8443; moving the row to 443
	// leaves that target unfit. sqli-login.md's {scope: S-14} still fits.
	narrow := func(mode Cited) func(*Tx) (ScopeChange, error) {
		return func(tx *Tx) (ScopeChange, error) { return tx.SetScope("S-14", "port", "443", mode) }
	}
	if _, _, err := scopeWrite(t, narrow(CitedRefuse)); !errors.Is(err, ErrCited) || !strings.Contains(err.Error(), "F-001") || strings.Contains(err.Error(), "F-003") {
		t.Errorf("err = %v", err)
	}
	ch, dir, err := scopeWrite(t, narrow(CitedForce))
	if err != nil || len(ch.Left) != 1 || ch.Left[0] != "F-001" || len(ch.Findings) != 0 {
		t.Errorf("force: %+v, %v", ch, err)
	}
	if !strings.Contains(file(t, dir, "findings/xss-search.md"), "{scope: S-14, port: 8443") {
		t.Error("force changed the target")
	}
	ch, dir, err = scopeWrite(t, narrow(CitedCleanup))
	if err != nil || len(ch.Findings) != 1 {
		t.Fatalf("cleanup: %+v, %v", ch, err)
	}
	if got := file(t, dir, "findings/xss-search.md"); !strings.Contains(got, "targets: []\r\n") {
		t.Errorf("cleanup left:\n%q", got)
	}
}

func TestRemoveScopeCited(t *testing.T) {
	if _, _, err := scopeWrite(t, func(tx *Tx) (ScopeChange, error) { return tx.RemoveScope("S-12", CitedRefuse) }); !errors.Is(err, ErrCited) {
		t.Errorf("err = %v", err)
	}
	ch, dir, err := scopeWrite(t, func(tx *Tx) (ScopeChange, error) { return tx.RemoveScope("S-12", CitedCleanup) })
	if err != nil || ch.Row.ID != "S-12" || len(ch.Findings) != 1 {
		t.Fatalf("%+v, %v", ch, err)
	}
	if got := file(t, dir, "findings/sqli-login.md"); !strings.Contains(got, "targets: [{scope: S-14}]   # both login front-ends\n") {
		t.Errorf("sqli-login.md:\n%s", got)
	}
	// Removing two rows in one write drops both from the same finding.
	_, dir, err = scopeWrite(t, func(tx *Tx) (ScopeChange, error) {
		if _, err := tx.RemoveScope("S-12", CitedCleanup); err != nil {
			return ScopeChange{}, err
		}
		return tx.RemoveScope("S-14", CitedCleanup)
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := file(t, dir, "findings/sqli-login.md"); !strings.Contains(got, "targets: []") {
		t.Errorf("sqli-login.md:\n%s", got)
	}
}

func TestNextScopeIDCountsCitedIDs(t *testing.T) {
	// tls-weak.md cites S-99, which no row has: S-99 is never given out.
	_, dir, err := scopeWrite(t, func(tx *Tx) (ScopeChange, error) {
		row, err := tx.AddScope(sdk.ScopeRow{Host: "h"})
		return ScopeChange{Row: row}, err
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := file(t, dir, "scope.csv"); !strings.HasSuffix(got, "S-100,h,,\n") {
		t.Errorf("scope.csv:\n%s", got)
	}
}

func TestUnsetScope(t *testing.T) {
	ch, dir, err := scopeWrite(t, func(tx *Tx) (ScopeChange, error) { return tx.UnsetScope("s-12", "port", "env") })
	if err != nil || ch.Row.Port != 0 {
		t.Fatalf("%+v, %v", ch, err)
	}
	if got := file(t, dir, "scope.csv"); !strings.Contains(got, "\nS-12,10.0.0.5,,\n") {
		t.Errorf("scope.csv:\n%s", got)
	}
	if _, _, err := scopeWrite(t, func(tx *Tx) (ScopeChange, error) { return tx.UnsetScope("S-12", "host") }); !errors.Is(err, ErrRefusedUnset) {
		t.Errorf("unset host: %v", err)
	}
	if _, _, err := scopeWrite(t, func(tx *Tx) (ScopeChange, error) { return tx.SetScope("S-12", "owner", "x", CitedRefuse) }); !errors.Is(err, ErrBadValue) {
		t.Errorf("a missing column: %v", err)
	}
}
