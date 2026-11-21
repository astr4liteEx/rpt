package report

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
)

// writeAtomic replaces the file name (relative to root) with data so that a
// crash or failure leaves either the old file or the new one, never half of
// either. It writes a uniquely named temp file in the same folder, syncs and
// closes it, renames it over name, then syncs the folder so the rename
// itself is durable. An existing file's permissions are kept; a new file
// gets 0644.
func writeAtomic(root *os.Root, name string, data []byte) (err error) {
	perm := fs.FileMode(0o644)
	if info, err := root.Stat(name); err == nil {
		perm = info.Mode().Perm()
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("write %s: %w", name, err)
	}

	dir := path.Dir(name)
	tmp := path.Join(dir, "."+path.Base(name)+"."+rand.Text()[:12]+".tmp")
	// os.Root has no CreateTemp, so O_EXCL on a random name stands in for it.
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	defer func() {
		if err != nil {
			f.Close()
			root.Remove(tmp) // best effort: the write already failed
		}
	}()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := f.Chmod(perm); err != nil { // OpenFile's perm is masked by umask
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := root.Rename(tmp, name); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	return syncDir(root, dir)
}

// syncDir flushes a folder's entries, making a rename in it durable.
func syncDir(root *os.Root, dir string) error {
	d, err := root.Open(dir)
	if err != nil {
		return fmt.Errorf("sync %s: %w", dir, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", dir, err)
	}
	return nil
}
