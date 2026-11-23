//go:build unix

package report

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadWaitsForASaveToCommit(t *testing.T) {
	a := fixture(t, nil)
	unlock, err := a.lock()
	if err != nil {
		t.Fatal(err)
	}
	loaded := make(chan *Model, 1)
	go func() {
		b, err := Load(a.Dir)
		if err != nil {
			t.Error(err)
		}
		loaded <- b
	}()
	select {
	case <-loaded:
		unlock()
		t.Fatal("Load read the report while a save held its lock")
	case <-time.After(200 * time.Millisecond):
	}
	unlock()
	select {
	case b := <-loaded:
		if b != nil {
			b.Close()
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Load didn't go on once the save let go")
	}
}

func TestLoadsShareTheLock(t *testing.T) {
	a := fixture(t, nil)
	if err := os.WriteFile(filepath.Join(a.Dir, lockFile), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	unlock := a.readLock()
	defer unlock()
	done := make(chan error, 1)
	go func() {
		b, err := Load(a.Dir)
		if err == nil {
			b.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a read waited for another read")
	}
}

func TestAReadLeavesTheFolderAsItWas(t *testing.T) {
	a := fixture(t, nil)
	lock := filepath.Join(a.Dir, lockFile)
	os.Remove(lock)
	b, err := Load(a.Dir)
	if err != nil {
		t.Fatal(err)
	}
	b.Close()
	if _, err := os.Stat(lock); err == nil {
		t.Error("a read made the lock file")
	}
}

func TestAReadOnlyReportLoads(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes to read-only folders")
	}
	a := fixture(t, nil)
	if err := os.WriteFile(filepath.Join(a.Dir, lockFile), nil, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(a.Dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(a.Dir, 0o755) })
	b, err := Load(a.Dir)
	if err != nil {
		t.Fatal(err)
	}
	b.Close()
}
