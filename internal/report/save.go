package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strconv"
)

// Files rpt keeps in the report root while saving. They are hidden, so
// nothing else reads them as report files.
const (
	lockFile    = ".rpt-lock"
	journalFile = ".rpt-journal"
	stagingDir  = ".rpt-staging"
)

// A ConflictError is a file someone else changed after this command read
// it. Nothing was written.
type ConflictError struct{ Path string }

func (e *ConflictError) Error() string {
	return fmt.Sprintf("%s changed while rpt was working; nothing was written, run the command again", e.Path)
}

// remove marks the file at rel for removal.
func (m *Model) remove(rel string) error {
	if _, _, err := m.read(rel); err != nil {
		return err
	}
	f := m.files[rel]
	f.data, f.remove, f.dirty = nil, true, true
	return nil
}

// copyIn sets the file at rel to a copy of the file at src, an OS path,
// taking its permissions. The copy is made when the model is saved.
func (m *Model) copyIn(rel, src string) error {
	if _, _, err := m.read(rel); err != nil {
		return err
	}
	f := m.files[rel]
	f.data, f.remove, f.dirty, f.copyFrom = nil, false, true, src
	return nil
}

// Changed lists the files the command changed, sorted.
func (m *Model) Changed() []string {
	var out []string
	for rel, f := range m.files {
		if f.dirty {
			out = append(out, rel)
		}
	}
	slices.Sort(out)
	return out
}

// An op is one step of a journal: rename a staged file into place, or
// remove a file.
type op struct {
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
	Remove string `json:"remove,omitempty"`
}

// Save writes the changes, all or none. It locks the report, checks that
// nothing the command read has changed since, stages every new file, and
// records the steps in a journal before taking them: if rpt stops partway,
// the next Load finishes the job. With dryRun it only checks.
func (m *Model) Save(dryRun bool) error {
	changed := m.Changed()
	if len(changed) == 0 {
		return nil
	}
	if dryRun {
		return m.check()
	}
	unlock, err := m.lock()
	if err != nil {
		return err
	}
	defer unlock()
	if err := m.check(); err != nil {
		return err
	}
	ops, err := m.stage(changed)
	if err != nil {
		m.root.RemoveAll(stagingDir)
		return err
	}
	if err := m.writeJournal(ops); err != nil {
		m.root.RemoveAll(stagingDir)
		return err
	}
	if err := m.replay(ops); err != nil {
		return fmt.Errorf("save stopped partway; the next rpt command finishes it: %w", err)
	}
	for _, rel := range changed {
		f := m.files[rel]
		f.old, f.existed, f.dirty = f.data, !f.remove, false
	}
	return nil
}

// check refuses when a file the command read, or a folder it listed, has
// changed since.
func (m *Model) check() error {
	for rel, f := range m.files {
		b, err := m.root.ReadFile(rel)
		exists := err == nil
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return &FileError{Path: rel, Err: err}
		}
		if exists != f.existed || exists && !bytes.Equal(b, f.old) {
			return &ConflictError{Path: rel}
		}
	}
	for dir, names := range m.listed {
		now, err := m.mdFiles(dir)
		if err != nil {
			return err
		}
		if !slices.Equal(now, names) {
			return &ConflictError{Path: dir + "/"}
		}
	}
	return nil
}

// stage writes each new file into the staging folder and returns the
// steps that put them in place.
func (m *Model) stage(changed []string) ([]op, error) {
	if err := m.root.MkdirAll(stagingDir, 0o755); err != nil {
		return nil, err
	}
	var ops []op
	for i, rel := range changed {
		f := m.files[rel]
		if f.remove {
			ops = append(ops, op{Remove: rel})
			continue
		}
		tmp := path.Join(stagingDir, strconv.Itoa(i))
		if err := m.writeStaged(tmp, rel, f); err != nil {
			return nil, fmt.Errorf("write %s: %w", rel, err)
		}
		if err := m.root.MkdirAll(path.Dir(rel), 0o755); err != nil {
			return nil, fmt.Errorf("write %s: %w", rel, err)
		}
		ops = append(ops, op{From: tmp, To: rel})
	}
	// New files go in before any file goes: a step that fails never
	// leaves a document with no file.
	slices.SortStableFunc(ops, func(a, b op) int {
		return boolInt(a.Remove != "") - boolInt(b.Remove != "")
	})
	return ops, syncDir(m, stagingDir)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// writeStaged writes the new content of the file at rel to tmp, with the
// permissions of the file it replaces or copies.
func (m *Model) writeStaged(tmp, rel string, f *file) error {
	mode := fs.FileMode(0o644)
	var src io.Reader = bytes.NewReader(f.data)
	if f.copyFrom != "" {
		in, err := os.Open(f.copyFrom)
		if err != nil {
			return err
		}
		defer in.Close()
		info, err := in.Stat()
		if err != nil {
			return err
		}
		mode, src = info.Mode().Perm(), in
	} else if f.existed {
		if info, err := m.root.Stat(rel); err == nil {
			mode = info.Mode().Perm()
		}
	}
	out, err := m.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, src); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// writeJournal records the steps durably: once it is in place, the save
// will finish even if rpt stops.
func (m *Model) writeJournal(ops []op) error {
	b, err := json.Marshal(ops)
	if err != nil {
		return err
	}
	tmp := path.Join(stagingDir, "journal")
	out, err := m.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := out.Write(b); err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := m.root.Rename(tmp, journalFile); err != nil {
		return err
	}
	return syncDir(m, ".")
}

// replay takes the journal's steps. Each is safe to take twice, so a
// replay after a crash finishes what was started.
func (m *Model) replay(ops []op) error {
	dirs := map[string]bool{}
	for _, o := range ops {
		switch {
		case o.Remove != "":
			if err := m.root.Remove(o.Remove); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			dirs[path.Dir(o.Remove)] = true
		default:
			if err := m.root.Rename(o.From, o.To); err != nil {
				if _, serr := m.root.Stat(o.From); errors.Is(serr, fs.ErrNotExist) {
					continue // taken before a crash
				}
				return err
			}
			dirs[path.Dir(o.To)] = true
		}
	}
	for d := range dirs {
		if err := syncDir(m, d); err != nil {
			return err
		}
	}
	if err := m.root.Remove(journalFile); err != nil {
		return err
	}
	return m.root.RemoveAll(stagingDir)
}

// recover finishes a save a crash interrupted, or clears one that never
// got as far as its journal.
func (m *Model) recover() error {
	b, err := m.root.ReadFile(journalFile)
	if errors.Is(err, fs.ErrNotExist) {
		if _, err := m.root.Stat(stagingDir); err == nil {
			unlock, err := m.lock()
			if err != nil {
				return err
			}
			defer unlock()
			return m.root.RemoveAll(stagingDir)
		}
		return nil
	}
	if err != nil {
		return err
	}
	unlock, err := m.lock()
	if err != nil {
		return err
	}
	defer unlock()
	var ops []op
	if err := json.Unmarshal(b, &ops); err != nil {
		return fmt.Errorf("%s is damaged: %w", journalFile, err)
	}
	if err := m.replay(ops); err != nil {
		return fmt.Errorf("finish an interrupted save: %w", err)
	}
	return nil
}

func syncDir(m *Model, dir string) error {
	d, err := m.root.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return err
	}
	return nil
}
