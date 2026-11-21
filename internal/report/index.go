package report

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"io/fs"
	"path"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// An Entry is a finding or page as shell completion offers it: its ID,
// title and frontmatter keys, from its frontmatter alone.
type Entry struct {
	ID, Title, Path string
	Keys            []string // top-level frontmatter keys, in file order
}

// Entries lists the findings (dir FindingsDir) or pages (PagesDir),
// reading each file only up to the end of its frontmatter, for speed. A
// file whose frontmatter doesn't parse is left out.
func (r *Report) Entries(dir string) []Entry {
	ents, err := fs.ReadDir(r.fsys(), dir)
	if err != nil {
		return nil
	}
	var out []Entry
	for _, e := range ents {
		if !e.Type().IsRegular() || path.Ext(e.Name()) != ".md" {
			continue
		}
		rel := path.Join(dir, e.Name())
		head, ok := r.frontmatter(rel)
		if !ok {
			continue
		}
		var doc yaml.Node
		if yaml.Unmarshal(head, &doc) != nil || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
			continue
		}
		en := Entry{Path: rel}
		m := doc.Content[0].Content
		for i := 0; i+1 < len(m); i += 2 {
			k := m[i].Value
			en.Keys = append(en.Keys, k)
			switch k {
			case "id":
				en.ID = CanonicalID(m[i+1].Value)
			case "title":
				en.Title = m[i+1].Value
			}
		}
		if en.ID != "" {
			out = append(out, en)
		}
	}
	slices.SortFunc(out, func(a, b Entry) int { return compareIDs(a.ID, b.ID) })
	return out
}

// frontmatter reads the file at rel up to its closing --- line and
// returns the YAML between, or false when it has none.
func (r *Report) frontmatter(rel string) ([]byte, bool) {
	f, err := r.open(rel)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	if !sc.Scan() || strings.TrimRight(sc.Text(), "\r") != "---" {
		return nil, false
	}
	var head []byte
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "---" {
			return head, true
		}
		head = append(head, line+"\n"...)
	}
	return nil, false
}

// ScopeHeader is scope.csv's header row: its column names.
func (r *Report) ScopeHeader() ([]string, error) {
	f, err := r.open(ScopeFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return csv.NewReader(f).Read()
}

// Body is the markdown after the frontmatter of the finding or page file
// at rel, as written.
func (r *Report) Body(rel string) (string, error) {
	src, err := r.readFile(rel)
	if err != nil {
		return "", err
	}
	_, body, err := splitFrontmatter(bytes.ReplaceAll(src, []byte("\r\n"), []byte("\n")))
	if err != nil {
		return "", &FileError{Path: rel, Err: err}
	}
	return string(body), nil
}
