package report

import (
	"bytes"
	"errors"
	"io/fs"
	"maps"
	"path"
	"slices"
	"strings"
	"time"
)

// A Report reads its files through these, so a view of a write (View)
// sees the write's staged files over the folder's own.

// staged returns the staged change to p in a view, if there is one.
func (r *Report) staged(p string) (*change, bool) {
	c, ok := r.over[p]
	return c, ok && c.touched
}

func (r *Report) readFile(p string) ([]byte, error) {
	if c, ok := r.staged(p); ok {
		if c.remove {
			return nil, &fs.PathError{Op: "read", Path: p, Err: fs.ErrNotExist}
		}
		return slices.Clone(c.data), nil
	}
	return r.root.ReadFile(p)
}

func (r *Report) stat(p string) (fs.FileInfo, error) {
	if c, ok := r.staged(p); ok {
		if c.remove {
			return nil, &fs.PathError{Op: "stat", Path: p, Err: fs.ErrNotExist}
		}
		return memInfo{name: path.Base(p), size: int64(len(c.data)), mode: c.perm}, nil
	}
	info, err := r.root.Stat(p)
	if errors.Is(err, fs.ErrNotExist) && r.stagedUnder(p) {
		return memInfo{name: path.Base(p), mode: fs.ModeDir | 0o755}, nil
	}
	return info, err
}

func (r *Report) lstat(p string) (fs.FileInfo, error) {
	if _, ok := r.staged(p); ok {
		return r.stat(p)
	}
	return r.root.Lstat(p)
}

func (r *Report) open(p string) (fs.File, error) {
	if c, ok := r.staged(p); ok {
		if c.remove {
			return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrNotExist}
		}
		return &memFile{Reader: bytes.NewReader(c.data), info: memInfo{name: path.Base(p), size: int64(len(c.data)), mode: c.perm}}, nil
	}
	return r.root.Open(p)
}

// fsys is the report as an fs.FS, for reading folders.
func (r *Report) fsys() fs.FS {
	if r.over == nil {
		return r.root.FS()
	}
	return overlayFS{r}
}

// stagedUnder reports whether a view stages a file somewhere under dir.
func (r *Report) stagedUnder(dir string) bool {
	for p, c := range r.over {
		if c.touched && !c.remove && (dir == "." || strings.HasPrefix(p, dir+"/")) {
			return true
		}
	}
	return false
}

// View returns the report as it would be once tx commits: every read sees
// the staged files. It shares tx's folder, so it needs no Close, and it
// must not be written through.
func (tx *Tx) View() *Report {
	v := *tx.r
	v.over = maps.Clone(tx.files)
	v.configSrc = nil
	return &v
}

type overlayFS struct{ r *Report }

func (o overlayFS) Open(name string) (fs.File, error)          { return o.r.open(name) }
func (o overlayFS) ReadFile(name string) ([]byte, error)       { return o.r.readFile(name) }
func (o overlayFS) Stat(name string) (fs.FileInfo, error)      { return o.r.stat(name) }
func (o overlayFS) ReadDir(name string) ([]fs.DirEntry, error) { return o.r.readDir(name) }

// readDir lists a folder with the staged files laid over it.
func (r *Report) readDir(dir string) ([]fs.DirEntry, error) {
	base, err := fs.ReadDir(r.root.FS(), dir)
	if err != nil && !(errors.Is(err, fs.ErrNotExist) && r.stagedUnder(dir)) {
		return nil, err
	}
	byName := map[string]fs.DirEntry{}
	for _, e := range base {
		byName[e.Name()] = e
	}
	for p, c := range r.over {
		if !c.touched {
			continue
		}
		rest, ok := strings.CutPrefix(p, dir+"/")
		if dir == "." {
			rest, ok = p, true
		}
		if !ok {
			continue
		}
		name, deeper, _ := strings.Cut(rest, "/")
		switch {
		case deeper != "":
			if _, ok := byName[name]; !ok && !c.remove {
				byName[name] = fs.FileInfoToDirEntry(memInfo{name: name, mode: fs.ModeDir | 0o755})
			}
		case c.remove:
			delete(byName, name)
		default:
			byName[name] = fs.FileInfoToDirEntry(memInfo{name: name, size: int64(len(c.data)), mode: c.perm})
		}
	}
	out := slices.Collect(maps.Values(byName))
	slices.SortFunc(out, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	return out, nil
}

type memInfo struct {
	name string
	size int64
	mode fs.FileMode
}

func (i memInfo) Name() string       { return i.name }
func (i memInfo) Size() int64        { return i.size }
func (i memInfo) Mode() fs.FileMode  { return i.mode }
func (i memInfo) ModTime() time.Time { return time.Time{} }
func (i memInfo) IsDir() bool        { return i.mode.IsDir() }
func (i memInfo) Sys() any           { return nil }

type memFile struct {
	*bytes.Reader
	info memInfo
}

func (f *memFile) Stat() (fs.FileInfo, error) { return f.info, nil }
func (f *memFile) Close() error               { return nil }
