package report

import (
	"bytes"
	"cmp"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"slices"
)

// Rev is a file's (or a scope row's) revision: the first 16 hex
// characters of the SHA-256 of its bytes. It is opaque, compared only for
// equality, so how it is made may change.
func Rev(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

// Commit order: referring files before the things they refer to, so that
// running a half-done write again finishes it. New files that others will
// refer to (evidence copies) go first.
const (
	rankAsset   = iota // evidence files
	rankFinding        // finding files
	rankScope          // scope.csv
	rankConfig         // rpt.yaml
)

// RevError refuses a write because a thing changed since the caller read
// it: its --if-rev doesn't match, or its file changed between the check
// and the commit.
type RevError struct {
	Path string
	ID   string // the thing named; empty for a file changed during the write
	Want string // the caller's --if-rev
	Have string
}

func (e *RevError) Error() string {
	if e.ID == "" {
		return e.Path + ": changed since read; nothing was written"
	}
	return fmt.Sprintf("%s: changed since read (rev %s, --if-rev %s)", e.ID, e.Have, e.Want)
}

// NotWrittenError says a write stopped partway through its commit: the
// files in Written were written, those in NotWritten weren't. Running the
// same command again finishes it.
type NotWrittenError struct {
	Written    []string
	NotWritten []NotWritten
}

// NotWritten is one file a write didn't get to, and why.
type NotWritten struct{ Path, Reason string }

func (e *NotWrittenError) Error() string {
	return fmt.Sprintf("%d of %d files not written", len(e.NotWritten), len(e.Written)+len(e.NotWritten))
}

// A Tx is one write: every file it changes, worked out in memory, then
// written all at once by Commit (ADR 0008, "Writes that span files").
type Tx struct {
	r *Report
	// IfRev maps a thing's ID to the rev the caller last read; a write
	// touching a thing whose rev differs is refused.
	IfRev  map[string]string
	files  map[string]*change
	newIDs map[string]bool // finding IDs this write adds
	nextN  int             // the next finding number; 0 until first needed
	h      Headings        // section headings a config change in this write sets; nil if none
}

// A change is one file as the write found it and as it will leave it.
type change struct {
	path    string
	old     []byte
	existed bool
	data    []byte
	remove  bool
	rank    int
	touched bool
	tmp     string // staged copy, during Commit
	perm    fs.FileMode
}

// Begin starts a write.
func (r *Report) Begin() *Tx {
	return &Tx{r: r, IfRev: map[string]string{}, files: map[string]*change{}, newIDs: map[string]bool{}}
}

// read returns the file at p as this write sees it: its new content if the
// write already changed it, else the file as read now (remembered, so the
// commit can tell whether it changed since). exists is false for a file
// that isn't there or that this write removes.
func (tx *Tx) read(p string) (data []byte, exists bool, err error) {
	c, err := tx.entry(p)
	if err != nil {
		return nil, false, err
	}
	if c.touched {
		return c.data, !c.remove, nil
	}
	return c.old, c.existed, nil
}

func (tx *Tx) entry(p string) (*change, error) {
	if c, ok := tx.files[p]; ok {
		return c, nil
	}
	c := &change{path: p, perm: 0o644}
	b, err := tx.r.root.ReadFile(p)
	switch {
	case err == nil:
		c.old, c.existed = b, true
		if info, err := tx.r.root.Stat(p); err == nil {
			c.perm = info.Mode().Perm()
		}
	case !errors.Is(err, fs.ErrNotExist):
		return nil, &FileError{Path: p, Err: err}
	}
	tx.files[p] = c
	return c, nil
}

// put sets the new content of the file at p.
func (tx *Tx) put(p string, data []byte, rank int) error {
	c, err := tx.entry(p)
	if err != nil {
		return err
	}
	c.data, c.remove, c.rank, c.touched = data, false, rank, true
	return nil
}

// del removes the file at p.
func (tx *Tx) del(p string, rank int) error {
	c, err := tx.entry(p)
	if err != nil {
		return err
	}
	c.data, c.remove, c.rank, c.touched = nil, true, rank, true
	return nil
}

// checkRev refuses the write if the caller gave an --if-rev for id and it
// isn't rev, the thing's rev as this write read it.
func (tx *Tx) checkRev(id, p, rev string) error {
	want, ok := tx.IfRev[id]
	if !ok || want == rev {
		return nil
	}
	return &RevError{Path: p, ID: id, Want: want, Have: rev}
}

// pending lists the changes that alter a file, in commit order: by rank,
// then path. A file set to the bytes it has is no change: it keeps its
// bytes, its mtime and its rev.
func (tx *Tx) pending() []*change {
	var out []*change
	for _, c := range tx.files {
		switch {
		case !c.touched:
		case c.remove && !c.existed:
		case !c.remove && c.existed && bytes.Equal(c.data, c.old):
		default:
			out = append(out, c)
		}
	}
	slices.SortFunc(out, func(a, b *change) int {
		return cmp.Or(cmp.Compare(a.rank, b.rank), cmp.Compare(a.path, b.path))
	})
	return out
}

// Commit writes every change, or none: it stages each new file next to its
// target, reads every target again and refuses if any changed since this
// write read it, then renames the staged files into place in commit order.
// With dryRun it stops after staging and keeps nothing. A failure while
// renaming is a *NotWrittenError; there is no rollback, and the order makes
// running the same command again finish the write.
func (tx *Tx) Commit(dryRun bool) (err error) {
	cs := tx.pending()
	var made []string // folders made for staging, deepest last
	defer func() {
		for _, c := range cs {
			if c.tmp != "" {
				tx.r.root.Remove(c.tmp) // best effort: nothing to keep
				c.tmp = ""
			}
		}
		if err != nil || dryRun {
			for _, d := range slices.Backward(made) {
				tx.r.root.Remove(d) // only if still empty
			}
		}
	}()

	for _, c := range cs {
		if c.remove {
			continue
		}
		dirs, err := tx.mkdirs(path.Dir(c.path))
		made = append(made, dirs...)
		if err != nil {
			return err
		}
		if c.tmp, err = tx.stage(c); err != nil {
			return err
		}
	}
	if dryRun {
		return nil
	}

	for _, c := range cs {
		now, err := tx.r.root.ReadFile(c.path)
		exists := err == nil
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return &FileError{Path: c.path, Err: err}
		}
		if exists != c.existed || !bytes.Equal(now, c.old) {
			return &RevError{Path: c.path}
		}
	}

	nw := &NotWrittenError{}
	for i, c := range cs {
		var err error
		if c.remove {
			err = tx.r.root.Remove(c.path)
		} else {
			err = rename(tx.r.root, c.tmp, c.path)
		}
		if err != nil {
			nw.NotWritten = append(nw.NotWritten, NotWritten{c.path, err.Error()})
			for _, rest := range cs[i+1:] {
				nw.NotWritten = append(nw.NotWritten, NotWritten{rest.path, "an earlier file in this write failed"})
			}
			return nw
		}
		c.tmp = ""
		nw.Written = append(nw.Written, c.path)
	}
	synced := map[string]bool{}
	for _, c := range cs {
		if d := path.Dir(c.path); !synced[d] {
			synced[d] = true
			syncDir(tx.r.root, d) // best effort: every file is in place
		}
	}
	return nil
}

// rename is os.Root.Rename; tests replace it to fail partway through.
var rename = (*os.Root).Rename

// mkdirs makes the folder dir and any missing parents, and returns those it
// made, outermost first.
func (tx *Tx) mkdirs(dir string) ([]string, error) {
	var missing []string
	for d := dir; d != "." && d != "/"; d = path.Dir(d) {
		if _, err := tx.r.root.Stat(d); err == nil {
			break
		}
		missing = append(missing, d)
	}
	slices.Reverse(missing)
	for i, d := range missing {
		if err := tx.r.root.Mkdir(d, 0o755); err != nil {
			return missing[:i], fmt.Errorf("write %s: %w", dir, err)
		}
	}
	return missing, nil
}

// stage writes c's new content to a temporary file beside it, synced, with
// the target's permissions, and returns its name.
func (tx *Tx) stage(c *change) (tmp string, err error) {
	tmp = path.Join(path.Dir(c.path), "."+path.Base(c.path)+"."+rand.Text()[:12]+".tmp")
	f, err := tx.r.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, c.perm)
	if err != nil {
		return "", fmt.Errorf("write %s: %w", c.path, err)
	}
	defer func() {
		if err != nil {
			f.Close()
			tx.r.root.Remove(tmp)
		}
	}()
	if _, err := f.Write(c.data); err != nil {
		return "", fmt.Errorf("write %s: %w", c.path, err)
	}
	if err := f.Chmod(c.perm); err != nil { // OpenFile's perm is masked by umask
		return "", fmt.Errorf("write %s: %w", c.path, err)
	}
	if err := f.Sync(); err != nil {
		return "", fmt.Errorf("write %s: %w", c.path, err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("write %s: %w", c.path, err)
	}
	return tmp, nil
}

// one runs a single change of the report as its own write.
func one[T any](r *Report, do func(*Tx) (T, error)) (T, error) {
	tx := r.Begin()
	v, err := do(tx)
	if err != nil {
		return v, err
	}
	return v, tx.Commit(false)
}
