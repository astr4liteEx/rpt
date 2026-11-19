package report

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/astr4liteEx/rpt/sdk"
)

// EvidenceDir is the folder, relative to the report root, that rpt
// evidence add copies files into and the only one orphans are looked for in.
const EvidenceDir = FindingsDir + "/evidence"

// ErrBadSource means a file to copy in is missing or not a regular file.
var ErrBadSource = errors.New("bad evidence source")

// Evidence lists every reference the findings make to evidence files: each
// finding's evidence list, then the links in its body, in file-name order.
// With orphans, it then lists each file under EvidenceDir that nothing
// references, by path; hidden files and folders are skipped. A finding file
// that doesn't parse is reported in the error; with orphans, the orphans
// are then left out, since that file's references are unknown.
func (r *Report) Evidence(orphans bool) ([]sdk.Evidence, error) {
	files, err := r.findingFiles()
	if err != nil {
		return nil, err
	}
	var (
		out  []sdk.Evidence
		errs []error
	)
	for _, ff := range files {
		if ff.err != nil {
			errs = append(errs, ff.err)
			continue
		}
		for _, ref := range ff.f.Evidence {
			out = append(out, r.reference(ff.f, ref, "frontmatter"))
		}
		for _, l := range relLinks(ff.body) {
			out = append(out, r.reference(ff.f, l.path, "body"))
		}
	}
	if orphans && len(errs) == 0 {
		found, err := r.orphans(out)
		if err != nil {
			return out, err
		}
		out = append(out, found...)
	}
	return out, errors.Join(errs...)
}

// reference is the record for one reference finding f makes to ref.
func (r *Report) reference(f sdk.Finding, ref, source string) sdk.Evidence {
	e := sdk.Evidence{Kind: "evidence", Finding: f.ID, Ref: ref, Source: source}
	rel, err := evidencePath(f, ref)
	if err != nil {
		return e
	}
	e.Path, e.File = rel, filepath.Join(r.abs, filepath.FromSlash(rel))
	info, err := r.root.Stat(rel)
	e.Exists = err == nil && info.Mode().IsRegular()
	return e
}

// orphans lists the files under EvidenceDir that no reference in refs
// names, sorted by path.
func (r *Report) orphans(refs []sdk.Evidence) ([]sdk.Evidence, error) {
	used := map[string]bool{}
	for _, e := range refs {
		used[e.Path] = true
	}
	var out []sdk.Evidence
	err := fs.WalkDir(r.root.FS(), EvidenceDir, func(p string, d fs.DirEntry, err error) error {
		if errors.Is(err, fs.ErrNotExist) && p == EvidenceDir {
			return fs.SkipAll
		}
		if err != nil {
			return err
		}
		if p != EvidenceDir && strings.HasPrefix(d.Name(), ".") {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() || used[p] {
			return nil
		}
		out = append(out, sdk.Evidence{Kind: "evidence", Path: p, File: filepath.Join(r.abs, filepath.FromSlash(p)), Exists: true})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", EvidenceDir, err)
	}
	slices.SortFunc(out, func(a, b sdk.Evidence) int { return strings.Compare(a.Path, b.Path) })
	return out, nil
}

// PruneEvidence removes the orphans Evidence(true) finds and returns them;
// with dryRun it only returns them. It removes nothing while any finding
// file doesn't parse, since that file may reference what looks orphaned.
func (r *Report) PruneEvidence(dryRun bool) ([]sdk.Evidence, error) {
	all, err := r.Evidence(true)
	if err != nil {
		return nil, err
	}
	var gone []sdk.Evidence
	for _, e := range all {
		if e.Finding != "" {
			continue
		}
		if !dryRun {
			if err := r.root.Remove(e.Path); err != nil {
				return gone, fmt.Errorf("prune %s: %w", e.Path, err)
			}
		}
		gone = append(gone, e)
	}
	return gone, nil
}

// AddEvidence copies the files at srcs into EvidenceDir and appends each
// copy's path to the evidence list of the finding with the given ID, then
// returns the finding as stored. Each copy is named as, which needs a
// single source and must not exist, or <id>-<slug>.<ext> with -2, -3, ...
// on a clash. Every source is checked before anything is copied, and if
// the finding can't be written the copies are removed, so a failure leaves
// the report as it was.
func (r *Report) AddEvidence(id string, srcs []string, as string) (sdk.Finding, error) {
	rel, err := r.locate(id)
	if err != nil {
		return sdk.Finding{}, err
	}
	src, err := r.root.ReadFile(rel)
	if err != nil {
		return sdk.Finding{}, &FileError{Path: rel, Err: err}
	}
	f, err := parseFinding(rel, src, r.headings())
	if err != nil {
		return sdk.Finding{}, err
	}
	for _, s := range srcs {
		info, err := os.Stat(s) // follows a symlink to the file it names
		if err != nil {
			return sdk.Finding{}, fmt.Errorf("%w: %v", ErrBadSource, err)
		}
		if !info.Mode().IsRegular() {
			return sdk.Finding{}, fmt.Errorf("%w: %s is not a regular file", ErrBadSource, s)
		}
	}
	names, err := r.evidenceNames(id, srcs, as)
	if err != nil {
		return sdk.Finding{}, err
	}

	if err := r.root.MkdirAll(EvidenceDir, 0o755); err != nil {
		return sdk.Finding{}, fmt.Errorf("evidence add: %w", err)
	}
	var copied []string
	undo := func() {
		for _, p := range copied {
			r.root.Remove(p) // best effort: the add already failed
		}
	}
	list := slices.Clone(f.Evidence)
	for i, s := range srcs {
		data, err := os.ReadFile(s)
		if err != nil {
			undo()
			return sdk.Finding{}, fmt.Errorf("%w: %v", ErrBadSource, err)
		}
		dst := path.Join(EvidenceDir, names[i])
		if err := writeAtomic(r.root, dst, data); err != nil {
			undo()
			return sdk.Finding{}, err
		}
		copied = append(copied, dst)
		if ref := "evidence/" + names[i]; !slices.Contains(list, ref) {
			list = append(list, ref)
		}
	}
	val, err := toNode(list)
	if err != nil {
		undo()
		return sdk.Finding{}, err
	}
	out, err := r.edit(rel, func(ff *findingFile) error { return ff.setEntry("evidence", val) })
	if err != nil {
		undo()
		return sdk.Finding{}, err
	}
	return out, nil
}

// evidenceNames picks the file name each source is copied to.
func (r *Report) evidenceNames(id string, srcs []string, as string) ([]string, error) {
	taken := func(name string) bool {
		_, err := r.root.Lstat(path.Join(EvidenceDir, name))
		return !errors.Is(err, fs.ErrNotExist)
	}
	if as != "" {
		if len(srcs) != 1 {
			return nil, fmt.Errorf("%w: --as names one file, not %d", ErrBadValue, len(srcs))
		}
		if as == "." || as == ".." || strings.ContainsAny(as, `/\`) {
			return nil, fmt.Errorf("%w: --as %q is not a plain file name", ErrBadValue, as)
		}
		if taken(as) {
			return nil, fmt.Errorf("%w: %s/%s already exists", ErrBadValue, EvidenceDir, as)
		}
		return []string{as}, nil
	}
	var names []string
	for _, s := range srcs {
		base := filepath.Base(s)
		ext := filepath.Ext(base)
		if ext == base { // a dotfile such as .bashrc has no extension
			ext = ""
		}
		stem := evidenceSlug(strings.TrimSuffix(base, ext), 40)
		if stem == "" {
			stem = "evidence"
		}
		if ext = evidenceSlug(ext, 40); ext != "" {
			ext = "." + ext
		}
		name := id + "-" + stem + ext
		for n := 2; taken(name) || slices.Contains(names, name); n++ {
			name = id + "-" + stem + "-" + strconv.Itoa(n) + ext
		}
		names = append(names, name)
	}
	return names, nil
}

// evidenceSlug lowercases s, turns each run of characters other than a-z
// and 0-9 into one hyphen, trims hyphens from the ends, and keeps at most
// limit characters.
func evidenceSlug(s string, limit int) string {
	var b strings.Builder
	gap := false
	for _, c := range strings.ToLower(s) {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			if gap && b.Len() > 0 {
				b.WriteByte('-')
			}
			gap = false
			b.WriteRune(c)
			continue
		}
		gap = true
	}
	out := b.String()
	if len(out) > limit {
		out = strings.TrimRight(out[:limit], "-")
	}
	return out
}
