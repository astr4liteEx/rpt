package report

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/astr4liteEx/rpt/sdk"
)

// ErrBadAsset means an asset add was given can't be taken in: its file is
// missing, unreadable or not a regular file.
var ErrBadAsset = errors.New("bad asset")

// takeAssets brings a new finding's or page's assets into the report, as
// add does. Each asset names a ref and a file; an absolute path in
// evidence or a link with no asset is one with ref and file both that
// path. A file inside the report is pointed at where it is; any other is
// copied into dir as evidence add names copies, one copy per file. Every
// reference to a ref, in evidence and at its place in each text, is
// rewritten to the new ref, relative to the owner file at rel, and an
// asset nothing references is added to evidence. It returns the new
// evidence list.
func (tx *Tx) takeAssets(id, rel, dir string, evidence []string, texts []*string, assets []sdk.Asset) ([]string, error) {
	type taken struct{ ref, file, to string }
	var list []*taken
	byRef := map[string]*taken{}
	add := func(ref, file string) error {
		if ref == "" {
			ref = file
		}
		if ref == "" || file == "" {
			return fmt.Errorf("%w: an asset needs a file", ErrBadAsset)
		}
		if _, ok := byRef[ref]; ok {
			return nil
		}
		abs, err := filepath.Abs(file)
		if err != nil {
			return fmt.Errorf("%w: %s: %v", ErrBadAsset, file, err)
		}
		t := &taken{ref: ref, file: abs}
		byRef[ref] = t
		list = append(list, t)
		return nil
	}
	for _, a := range assets {
		if err := add(a.Ref, a.File); err != nil {
			return nil, err
		}
	}
	for _, e := range evidence {
		if path.IsAbs(e) {
			if err := add(e, e); err != nil {
				return nil, err
			}
		}
	}
	for _, t := range texts {
		for _, l := range fileLinks([]byte(*t)) {
			if path.IsAbs(l.path) && byRef[l.dest] == nil {
				if err := add(l.path, l.path); err != nil {
					return nil, err
				}
			}
		}
	}
	if len(list) == 0 {
		return evidence, nil
	}

	// Point each file at where it is in the report, or copy it in.
	copies := map[string]string{} // file -> new ref
	var outside []string
	for _, t := range list {
		if _, ok := copies[t.file]; ok || slices.Contains(outside, t.file) {
			continue
		}
		in, err := tx.inReport(t.file)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrBadAsset, t.ref, err)
		}
		if in != "" {
			to, err := filepath.Rel(filepath.FromSlash(path.Dir(rel)), filepath.FromSlash(in))
			if err != nil {
				return nil, err
			}
			copies[t.file] = filepath.ToSlash(to)
			continue
		}
		outside = append(outside, t.file)
	}
	names, err := tx.evidenceNames(dir, id, outside, "")
	if err != nil {
		return nil, err
	}
	for i, file := range outside {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBadAsset, err)
		}
		if err := tx.put(path.Join(dir, names[i]), data, rankAsset); err != nil {
			return nil, err
		}
		to, err := filepath.Rel(filepath.FromSlash(path.Dir(rel)), filepath.FromSlash(path.Join(dir, names[i])))
		if err != nil {
			return nil, err
		}
		copies[file] = filepath.ToSlash(to)
	}
	for _, t := range list {
		t.to = copies[t.file]
	}

	// Rewrite every reference.
	used := map[*taken]bool{}
	match := func(dest, p string) *taken {
		if t := byRef[dest]; t != nil {
			return t
		}
		return byRef[p]
	}
	out := slices.Clone(evidence)
	for i, e := range out {
		if t := match(e, e); t != nil {
			out[i], used[t] = t.to, true
		}
	}
	for _, s := range texts {
		*s = string(rewriteDests([]byte(*s), func(l link) (string, bool) {
			t := match(l.dest, l.path)
			if t == nil {
				return "", false
			}
			used[t] = true
			return t.to, true
		}))
		// Reference-style links are reached through their definitions.
		for _, l := range fileLinks([]byte(*s)) {
			if t := match(l.dest, l.path); t != nil {
				used[t] = true
			}
		}
	}
	for _, t := range list {
		if !used[t] && !slices.Contains(out, t.to) {
			out = append(out, t.to)
		}
	}
	return out, nil
}

// inReport checks that file is a regular file and returns its path
// relative to the report root when it lies inside the report, or "".
// A file inside the report is read through the report's root, so a
// symlink there pointing out of it is refused.
func (tx *Tx) inReport(file string) (string, error) {
	info, err := os.Stat(file)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", file)
	}
	for _, f := range []string{file, evalSymlinks(file)} {
		rel, err := filepath.Rel(tx.r.abs, f)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		rel = filepath.ToSlash(rel)
		info, err := tx.r.stat(rel)
		if err != nil {
			return "", err
		}
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("%s is not a regular file", rel)
		}
		return rel, nil
	}
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	return "", f.Close()
}

// evalSymlinks is path with its symlinks resolved, or path when they
// can't be.
func evalSymlinks(p string) string {
	if q, err := filepath.EvalSymlinks(p); err == nil {
		return q
	}
	return p
}
