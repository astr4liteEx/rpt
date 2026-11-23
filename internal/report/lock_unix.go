//go:build unix

package report

import (
	"fmt"
	"os"
	"syscall"
)

// lock takes the report's write lock, waiting for another rpt's save to
// finish.
func (m *Model) lock() (func(), error) {
	f, err := m.root.OpenFile(lockFile, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, fmt.Errorf("lock the report: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("lock the report: %w", err)
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

// readLock takes the report's lock shared, so no save commits while the
// report is read: every file read sees the same state. A read never
// creates the lock file, so reading leaves the folder as it was; a report
// without one (rpt new and every save make it) is read without the lock.
func (m *Model) readLock() func() {
	f, err := m.root.Open(lockFile)
	if err != nil {
		return func() {}
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH); err != nil {
		f.Close()
		return func() {}
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}
}
