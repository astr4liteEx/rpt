// Package report is the report folder as rpt understands it. A command
// loads the folder once into a Model, reads and changes the model, and
// saves it: every lookup is a map hit, and every read sees the changes
// made so far.
//
// It knows nothing of the command line: the caller passes in the report's
// location and gets back values and errors.
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// The files and folders a report is made of, relative to its root.
const (
	ConfigFile  = "rpt.yaml"
	ScopeFile   = "scope.csv"
	FindingsDir = "findings"
	PagesDir    = "pages"
)

// A Kind is a sort of document in the report: findings and pages are both
// markdown files with YAML frontmatter, stored and edited the same way.
type Kind struct {
	Name        string // "finding" or "page"
	Prefix      string // "F-" or "P-"
	Dir         string // the folder its files sit in
	EvidenceDir string // where rpt evidence add copies its files
	// Reserved are frontmatter keys a file may not use: rpt sets record
	// members of those names, or an older format used them.
	Reserved []string
	// Sectioned bodies are split into sections at ## headings; other
	// bodies are free text.
	Sectioned bool

	id, file *regexp.Regexp
}

// The two kinds.
var (
	FindingKind = newKind("finding", "F-", FindingsDir, true, "kind", "path", "rev", "sections", "lines", "assets", "scope", "target")
	PageKind    = newKind("page", "P-", PagesDir, false, "kind", "path", "rev", "lines", "assets", "body")
	Kinds       = []*Kind{FindingKind, PageKind}
)

func newKind(name, prefix, dir string, sectioned bool, reserved ...string) *Kind {
	return &Kind{
		Name: name, Prefix: prefix, Dir: dir, EvidenceDir: dir + "/evidence",
		Reserved: reserved, Sectioned: sectioned,
		id:   regexp.MustCompile(`^` + prefix + `([0-9]{3,})$`),
		file: regexp.MustCompile(`^` + prefix + `([0-9]{3,})(?:-.*)?\.md$`),
	}
}

// Valid reports whether id is well formed for the kind: its prefix and at
// least three digits.
func (k *Kind) Valid(id string) bool { return k.id.MatchString(id) }

func (k *Kind) number(id string) int {
	if m := k.id.FindStringSubmatch(id); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return 0
}

// KindOf is the kind an ID names by its prefix, or nil for a scope ID.
func KindOf(id string) *Kind {
	id = CanonicalID(id)
	for _, k := range Kinds {
		if strings.HasPrefix(id, k.Prefix) {
			return k
		}
	}
	return nil
}

// CanonicalID is a finding or page ID with its prefix upper-cased, so f-001
// names F-001. Other IDs are returned as they are.
func CanonicalID(id string) string {
	if len(id) > 2 && id[1] == '-' && (id[0] == 'f' || id[0] == 'p') {
		return strings.ToUpper(id[:1]) + id[1:]
	}
	return id
}

// CompareIDs orders IDs by number when both have one, else as text.
func CompareIDs(a, b string) int {
	na, errA := strconv.Atoi(a[min(2, len(a)):])
	nb, errB := strconv.Atoi(b[min(2, len(b)):])
	switch {
	case errA == nil && errB == nil && a[:2] == b[:2]:
		if na != nb {
			return na - nb
		}
	case errA == nil && errB != nil:
		return -1
	case errB == nil && errA != nil:
		return 1
	}
	return strings.Compare(a, b)
}

// Rev is a file's revision: a short hash of its bytes.
func Rev(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

// A FileError is a problem with one file of the report, at a line when
// known.
type FileError struct {
	Path string // relative to the report root, slash-separated
	Line int    // 1-based, 0 when unknown
	Err  error
}

func (e *FileError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("%s:%d: %v", e.Path, e.Line, e.Err)
	}
	return fmt.Sprintf("%s: %v", e.Path, e.Err)
}

func (e *FileError) Unwrap() error { return e.Err }

// Errors a request can make.
var (
	ErrNotFound  = errors.New("no such")
	ErrDuplicate = errors.New("is in more than one file")
)

// A Model is a report loaded into memory, with the changes a command has
// made to it.
type Model struct {
	Dir    string // the report folder, as given
	root   *os.Root
	files  map[string]*file    // every file read or changed, by path
	listed map[string][]string // every folder listed: its .md files on disk
	Config *Config
	Scope  *Scope
	docs   map[*Kind][]*Doc // in file-name order
}

// A file is one file of the report as this command saw it and as it
// will leave it.
type file struct {
	old     []byte // as read; nil when it didn't exist
	existed bool
	data    []byte // as it will be written
	remove  bool
	dirty   bool
	// copyFrom is an OS path the file is copied from when saved, in
	// place of data.
	copyFrom string
}

// Load reads the report in dir. Files that don't parse are kept, with
// their errors, for Check to report; Load itself fails only when the
// folder can't be read.
func Load(dir string) (*Model, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("open report %s: %w", dir, err)
	}
	m := &Model{Dir: dir, root: root, files: map[string]*file{}, listed: map[string][]string{}, docs: map[*Kind][]*Doc{}}
	if err := m.recover(); err != nil {
		root.Close()
		return nil, err
	}
	if err := m.load(); err != nil {
		root.Close()
		return nil, err
	}
	return m, nil
}

func (m *Model) load() error {
	src, ok, err := m.read(ConfigFile)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("open report %s: %w", m.Dir, ErrNotReport)
	}
	m.Config = parseConfig(src)
	if src, ok, err = m.read(ScopeFile); err != nil {
		return err
	}
	m.Scope = parseScope(src, ok)
	for _, k := range Kinds {
		names, err := m.list(k.Dir)
		if err != nil {
			return err
		}
		for _, name := range names {
			rel := path.Join(k.Dir, name)
			src, _, err := m.read(rel)
			if err != nil {
				m.docs[k] = append(m.docs[k], &Doc{Kind: k, Path: rel, Err: err})
				continue
			}
			m.docs[k] = append(m.docs[k], parseDoc(k, rel, src, m.Config))
		}
	}
	return nil
}

// Close releases the report folder.
func (m *Model) Close() error { return m.root.Close() }

// ErrNotReport is a folder without rpt.yaml.
var ErrNotReport = errors.New("not a report: no " + ConfigFile)

// read returns the file at rel as this command sees it, and whether it
// exists. The first read of a file is what Save checks for changes made
// meanwhile by others.
func (m *Model) read(rel string) ([]byte, bool, error) {
	if f, ok := m.files[rel]; ok {
		if f.remove {
			return nil, false, nil
		}
		return f.data, f.data != nil || f.existed, nil
	}
	b, err := m.root.ReadFile(rel)
	if errors.Is(err, fs.ErrNotExist) {
		m.files[rel] = &file{}
		return nil, false, nil
	}
	if err != nil {
		return nil, false, &FileError{Path: rel, Err: err}
	}
	m.files[rel] = &file{old: b, existed: true, data: b}
	return b, true, nil
}

// put sets the file at rel to data.
func (m *Model) put(rel string, data []byte) error {
	if _, _, err := m.read(rel); err != nil {
		return err
	}
	f := m.files[rel]
	f.data, f.remove, f.dirty = data, false, true
	return nil
}

// list names the regular .md files in dir, sorted, as this command sees
// the folder: the files on disk and the new ones it has added. Save
// checks the folder hasn't changed since.
func (m *Model) list(dir string) ([]string, error) {
	disk, ok := m.listed[dir]
	if !ok {
		var err error
		if disk, err = m.mdFiles(dir); err != nil {
			return nil, err
		}
		m.listed[dir] = disk
	}
	names := slices.Clone(disk)
	for rel, f := range m.files {
		if path.Dir(rel) == dir && path.Ext(rel) == ".md" && f.dirty && !f.remove && !f.existed {
			names = append(names, path.Base(rel))
		}
	}
	slices.Sort(names)
	return slices.Compact(names), nil
}

// mdFiles names the regular .md files in dir on disk, sorted.
func (m *Model) mdFiles(dir string) ([]string, error) {
	ents, err := fs.ReadDir(m.root.FS(), dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, &FileError{Path: dir, Err: err}
	}
	var names []string
	for _, e := range ents {
		if e.Type().IsRegular() && path.Ext(e.Name()) == ".md" {
			names = append(names, e.Name())
		}
	}
	return names, nil
}

// Docs lists the documents of a kind in file-name order, broken ones too.
func (m *Model) Docs(k *Kind) []*Doc { return m.docs[k] }

// Get returns the document with the given ID. It is ErrNotFound when no
// document has it, and ErrDuplicate when more than one does.
func (m *Model) Get(k *Kind, id string) (*Doc, error) {
	id = CanonicalID(id)
	var found []*Doc
	for _, d := range m.docs[k] {
		if d.Err == nil && d.ID == id {
			found = append(found, d)
		}
	}
	switch len(found) {
	case 0:
		return nil, fmt.Errorf("%w %s: %s", ErrNotFound, k.Name, id)
	case 1:
		return found[0], nil
	}
	var paths []string
	for _, d := range found {
		paths = append(paths, d.Path)
	}
	return nil, fmt.Errorf("%s %w: %s", id, ErrDuplicate, strings.Join(paths, ", "))
}

// Taken reports whether id is in use for the kind: by a document, or, for
// pages, by the config's page lists.
func (m *Model) Taken(k *Kind, id string) bool {
	id = CanonicalID(id)
	if slices.ContainsFunc(m.docs[k], func(d *Doc) bool { return d.ID == id }) {
		return true
	}
	return k == PageKind && m.Config.Err == nil && (slices.Contains(m.Config.Pages, id) || slices.Contains(m.Config.RequiredPages, id))
}

// NextID is the kind's next free ID: one more than the highest number in
// use, three digits at least.
func (m *Model) NextID(k *Kind) string {
	n := 0
	for _, v := range m.usedNumbers(k) {
		n = max(n, v)
	}
	return fmt.Sprintf("%s%03d", k.Prefix, n+1)
}

// usedNumbers are the numbers of every ID the kind uses: documents' IDs,
// file names (so a broken file's ID is never given out again) and, for
// pages, the config's lists (so a page --force left there isn't reused).
func (m *Model) usedNumbers(k *Kind) []int {
	var out []int
	for _, d := range m.docs[k] {
		if n := k.number(d.ID); n > 0 {
			out = append(out, n)
		}
		if mm := k.file.FindStringSubmatch(path.Base(d.Path)); mm != nil {
			n, _ := strconv.Atoi(mm[1])
			out = append(out, n)
		}
	}
	if k == PageKind && m.Config.Err == nil {
		for _, id := range slices.Concat(m.Config.Pages, m.Config.RequiredPages) {
			if n := k.number(id); n > 0 {
				out = append(out, n)
			}
		}
	}
	return out
}
