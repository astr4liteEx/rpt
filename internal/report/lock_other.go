//go:build !unix

package report

import (
	"fmt"
	"os"
)

// lock takes the report's write lock. Off unix it is a lock file that
// exists while a save runs; one left by a crash must be removed by hand.
func (m *Model) lock() (func(), error) {
	f, err := m.root.OpenFile(lockFile, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return nil, fmt.Errorf("lock the report (another rpt is saving, or %s was left behind): %w", lockFile, err)
	}
	f.Close()
	return func() { m.root.Remove(lockFile) }, nil
}

// readLock is a no-op off unix: the lock file there can't be shared.
func (m *Model) readLock() func() { return func() {} }
