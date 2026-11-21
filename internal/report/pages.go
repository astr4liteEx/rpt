package report

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/astr4liteEx/rpt/sdk"
)

// PagesDir holds the report's pages.
const PagesDir = "pages"

// FindingsSlot is the entry in the config's pages list that marks where
// the findings go.
const FindingsSlot = "findings"

// pageID is the form every page ID takes: P- and at least three digits.
var pageID = regexp.MustCompile(`^P-([0-9]{3,})$`)

// pageFileID matches a page file named for its ID: P-NNN.md or P-NNN-....
var pageFileID = regexp.MustCompile(`^P-([0-9]{3,})(?:-.*)?\.md$`)

// ValidPageID reports whether id is a well-formed page ID.
func ValidPageID(id string) bool { return pageID.MatchString(id) }

// ErrNoPage is an unknown page ID: a mistake in the request.
var ErrNoPage = errors.New("no such page")

// pageKeys are the frontmatter keys that map to declared Page fields.
var pageKeys = []string{"id", "title", "evidence"}

// pageRecordKeys are the page record members rpt sets itself; a
// frontmatter key with one of these names would clash with them.
var pageRecordKeys = []string{"kind", "path", "rev", "body", "lines", "assets"}

// Pages reads every page file in pages/, in file-name order, as Findings
// reads findings.
func (r *Report) Pages() ([]sdk.Page, error) {
	list, err := r.PagesWithLines()
	for i := range list {
		list[i].Lines = nil
	}
	return list, err
}

// PagesWithLines is Pages with each page's Lines set.
func (r *Report) PagesWithLines() ([]sdk.Page, error) {
	entries, err := fs.ReadDir(r.root.FS(), PagesDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", PagesDir, err)
	}
	var pages []sdk.Page
	var errs []error
	for _, e := range entries {
		if !e.Type().IsRegular() || path.Ext(e.Name()) != ".md" {
			continue
		}
		rel := path.Join(PagesDir, e.Name())
		src, err := r.root.ReadFile(rel)
		if err != nil {
			errs = append(errs, &FileError{Path: rel, Err: err})
			continue
		}
		p, err := parsePage(rel, src)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		p.Lines.File = filepath.Join(r.abs, filepath.FromSlash(rel))
		pages = append(pages, p)
	}
	return pages, errors.Join(errs...)
}

// parsePage parses one page file: YAML frontmatter, then a free markdown
// body.
func parsePage(rel string, src []byte) (sdk.Page, error) {
	n := normaliseNewlines(src)
	head, body, err := splitFrontmatter(n)
	if err != nil {
		return sdk.Page{}, &FileError{Path: rel, Line: 1, Err: err}
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(head, &doc); err != nil {
		return sdk.Page{}, yamlFileError(rel, 1, err)
	}
	var fm struct {
		ID       string `yaml:"id"`
		Title    string
		Evidence []string
	}
	if err := doc.Decode(&fm); err != nil {
		return sdk.Page{}, yamlFileError(rel, 1, err)
	}
	lines := &sdk.PageLines{Frontmatter: map[string]sdk.Position{}}
	if len(doc.Content) > 0 && doc.Content[0].Kind == yaml.MappingNode {
		m := doc.Content[0].Content
		for i := 0; i+1 < len(m); i += 2 {
			if slices.Contains(pageRecordKeys, m[i].Value) {
				return sdk.Page{}, &FileError{Path: rel, Line: m[i].Line + 1,
					Err: fmt.Errorf("frontmatter key %q is reserved: rpt sets it on page records; rename the key", m[i].Value)}
			}
			lines.Frontmatter[m[i].Value] = sdk.Position{Line: m[i].Line + 1, Column: m[i].Column}
		}
	}
	extra, err := extraFieldsBut(&doc, pageKeys)
	if err != nil {
		return sdk.Page{}, &FileError{Path: rel, Err: err}
	}
	text := pageText(body)
	first := bodyFirstLine(head)
	lines.Body = first + bytes.Count(body[:len(body)-len(bytes.TrimLeft(body, "\n"))], []byte("\n"))
	return sdk.Page{
		Kind: "page", ID: fm.ID, Title: fm.Title, Path: rel, Body: text, Evidence: fm.Evidence,
		Rev: Rev(src), Lines: lines, Extra: extra,
	}, nil
}

// pageText is a page's body as its record gives it: without the blank
// lines around it.
func pageText(body []byte) string {
	return strings.TrimRight(strings.TrimLeft(string(body), "\n"), " \t\n")
}

// pageBody is the file body for text: a blank line, the text, a newline;
// nothing for no text.
func pageBody(text string) []byte {
	text = pageText(normaliseNewlines([]byte(text)))
	if text == "" {
		return nil
	}
	return []byte("\n" + text + "\n")
}

// locatePage returns the path of the page with the given ID, as this write
// sees the folder.
func (tx *Tx) locatePage(id string) (string, error) {
	list, err := tx.r.Pages()
	if err != nil && !onlyFileErrors(err) {
		return "", err
	}
	var found []string
	for _, p := range list {
		if p.ID == id {
			if _, exists, err := tx.read(p.Path); err != nil {
				return "", err
			} else if exists {
				found = append(found, p.Path)
			}
		}
	}
	for rel, c := range tx.files { // pages this write added or renamed
		if c.touched && !c.remove && strings.HasPrefix(rel, PagesDir+"/") && !slices.Contains(found, rel) {
			if p, err := parsePage(rel, c.data); err == nil && p.ID == id {
				found = append(found, rel)
			}
		}
	}
	switch len(found) {
	case 0:
		return "", fmt.Errorf("%w: %s in %s/", ErrNoPage, id, PagesDir)
	case 1:
		return found[0], nil
	default:
		return "", fmt.Errorf("%s is in more than one file: %v", id, found)
	}
}

// nextPageID is P- and one more than the highest P- number among the
// page files, their IDs, the config's pages and required_pages, and the
// pages this write adds, padded to three digits.
func (tx *Tx) nextPageID() (string, error) {
	n := 0
	count := func(id string) {
		if m := pageID.FindStringSubmatch(id); m != nil {
			if v, err := strconv.Atoi(m[1]); err == nil && v > n {
				n = v
			}
		}
	}
	if ents, err := fs.ReadDir(tx.r.root.FS(), PagesDir); err == nil {
		for _, e := range ents {
			if m := pageFileID.FindStringSubmatch(e.Name()); m != nil {
				count("P-" + m[1])
			}
		}
	}
	list, _ := tx.r.Pages()
	for _, p := range list {
		count(p.ID)
	}
	if cfg, err := tx.r.Config(); err == nil {
		for _, id := range slices.Concat(cfg.Pages, cfg.RequiredPages) {
			count(id)
		}
	}
	for id := range tx.newIDs {
		count(id)
	}
	return fmt.Sprintf("P-%03d", n+1), nil
}

// pageTaken reports whether a page ID is in use: by a page, by the config,
// or by this write.
func (tx *Tx) pageTaken(id string) (bool, error) {
	if tx.newIDs[id] {
		return true, nil
	}
	if _, err := tx.locatePage(id); err == nil {
		return true, nil
	} else if !errors.Is(err, ErrNoPage) {
		return false, err
	}
	cfg, err := tx.r.Config()
	if err != nil {
		return false, err
	}
	return slices.Contains(cfg.Pages, id) || slices.Contains(cfg.RequiredPages, id), nil
}

// AddPage writes a new page file, pages/P-NNN-<slug>.md, taking rec's ID
// or the next free one, and returns the page as stored. It doesn't touch
// the config's pages list: an unlisted page comes last.
func (tx *Tx) AddPage(rec sdk.Page) (sdk.Page, error) {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrBadValue, fmt.Sprintf(format, a...))
	}
	if strings.TrimSpace(rec.Title) == "" {
		return sdk.Page{}, bad("title is required")
	}
	id := CanonicalID(rec.ID)
	if id == "" {
		var err error
		if id, err = tx.nextPageID(); err != nil {
			return sdk.Page{}, err
		}
	} else if !ValidPageID(id) {
		return sdk.Page{}, bad("id %q is not P- and at least three digits", id)
	} else if taken, err := tx.pageTaken(id); err != nil {
		return sdk.Page{}, err
	} else if taken {
		return sdk.Page{}, bad("id: %s is already taken", id)
	}
	rel := path.Join(PagesDir, id+"-"+slug(rec.Title)+".md")
	if _, exists, err := tx.read(rel); err != nil {
		return sdk.Page{}, err
	} else if exists {
		return sdk.Page{}, bad("%s already exists", rel)
	}
	ev, err := tx.takeAssets(id, rel, PageEvidenceDir, rec.Evidence, []*string{&rec.Body}, rec.Assets)
	if err != nil {
		return sdk.Page{}, err
	}
	rec.Evidence, rec.Assets = ev, nil
	var ff findingFile
	fields := []struct {
		key string
		val any
	}{{"id", id}, {"title", rec.Title}}
	if rec.Evidence != nil {
		fields = append(fields, struct {
			key string
			val any
		}{"evidence", rec.Evidence})
	}
	for _, k := range slices.Sorted(func(yield func(string) bool) {
		for k := range rec.Extra {
			if !yield(k) {
				return
			}
		}
	}) {
		if slices.Contains(pageRecordKeys, k) || k == "id" || k == "title" || k == "evidence" {
			continue
		}
		fields = append(fields, struct {
			key string
			val any
		}{k, rec.Extra[k]})
	}
	for _, fl := range fields {
		n, err := toNode(fl.val)
		if err != nil {
			return sdk.Page{}, bad("%s: %v", fl.key, err)
		}
		if err := ff.setEntry(fl.key, n); err != nil {
			return sdk.Page{}, bad("%s: %v", fl.key, err)
		}
	}
	ff.body = pageBody(rec.Body)
	out := ff.bytes()
	p, err := parsePage(rel, out)
	if err != nil {
		return sdk.Page{}, fmt.Errorf("add would write a broken %s: %w", rel, err)
	}
	if err := tx.put(rel, out, rankPage); err != nil {
		return sdk.Page{}, err
	}
	tx.newIDs[id] = true
	p.Lines = nil
	return p, nil
}

// editPage changes the page id's file, at rel, and returns it as stored.
func (tx *Tx) editPage(id, rel string, change func(*findingFile) error) (sdk.Page, error) {
	src, exists, err := tx.read(rel)
	if err != nil {
		return sdk.Page{}, err
	}
	if !exists {
		return sdk.Page{}, fmt.Errorf("%w: %s in %s/", ErrNoPage, id, PagesDir)
	}
	if err := tx.checkRev(id, rel, Rev(src)); err != nil {
		return sdk.Page{}, err
	}
	ff, err := splitFindingFile(src)
	if err != nil {
		return sdk.Page{}, &FileError{Path: rel, Line: 1, Err: err}
	}
	if err := change(&ff); err != nil {
		return sdk.Page{}, fmt.Errorf("%w: %s: %v", ErrBadValue, rel, err)
	}
	out := ff.bytes()
	p, err := parsePage(rel, out)
	if err != nil {
		return sdk.Page{}, fmt.Errorf("%w: the change would break %s: %v", ErrBadValue, rel, err)
	}
	if err := tx.put(rel, out, rankPage); err != nil {
		return sdk.Page{}, err
	}
	p.Lines = nil
	return p, nil
}

// PageChange is what one page write did: the page (as stored, or as it was
// for a removal), the config when the write changed it, and the config
// lists left naming a removed page (--force).
type PageChange struct {
	Page   sdk.Page
	Config *sdk.Config
	Left   []string
}

// SetPage sets one value of the page id: title, evidence (each value an
// item), body, id (renaming the page, its entries in the config, and its
// file when the name starts with the old ID), x-<plugin>.<key>, or any
// other top-level key.
func (tx *Tx) SetPage(id, p string, values ...string) (PageChange, error) {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s: %s", ErrBadValue, p, fmt.Sprintf(format, a...))
	}
	if len(values) == 0 {
		return PageChange{}, bad("give a value")
	}
	if slices.Contains([]string{"kind", "path", "rev", "lines", "assets"}, p) {
		return PageChange{}, fmt.Errorf("%w: %s: rpt sets it on page records", ErrRefusedKey, p)
	}
	if (p == "body" || p == "id" || p == "title") && len(values) != 1 {
		return PageChange{}, bad("give one value")
	}
	rel, err := tx.locatePage(id)
	if err != nil {
		return PageChange{}, err
	}
	switch p {
	case "id":
		return tx.renamePage(id, rel, CanonicalID(values[0]))
	case "body":
		pg, err := tx.editPage(id, rel, func(ff *findingFile) error { ff.body = pageBody(values[0]); return nil })
		return PageChange{Page: pg}, err
	}
	val, err := valueNode(p, values)
	if err != nil {
		return PageChange{}, bad("%v", err)
	}
	if p == "title" {
		if val.Kind != yaml.ScalarNode || strings.TrimSpace(val.Value) == "" {
			return PageChange{}, bad("must be text")
		}
	}
	if p == "evidence" {
		if err := checkValue(p, val); err != nil {
			return PageChange{}, err
		}
	}
	pg, err := tx.editPage(id, rel, func(ff *findingFile) error {
		if plugin, key, ok := pluginPath(p); ok {
			return ff.setNested(plugin, key, val)
		}
		return ff.setEntry(p, val)
	})
	return PageChange{Page: pg}, err
}

// renamePage gives the page id the ID to everywhere: its frontmatter, the
// config's lists, and its file name when that starts with the old ID.
func (tx *Tx) renamePage(id, rel, to string) (PageChange, error) {
	if !ValidPageID(to) {
		return PageChange{}, fmt.Errorf("%w: id: %q is not P- and at least three digits", ErrBadValue, to)
	}
	if to == id {
		pg, err := tx.editPage(id, rel, func(*findingFile) error { return nil })
		return PageChange{Page: pg}, err
	}
	if taken, err := tx.pageTaken(to); err != nil {
		return PageChange{}, err
	} else if taken {
		return PageChange{}, fmt.Errorf("%w: id: %s is already taken", ErrBadValue, to)
	}
	var ch PageChange
	cfg, changed, err := tx.rewritePageLists(func(e string) (string, bool) {
		if e == id {
			return to, true
		}
		return e, true
	})
	if err != nil {
		return PageChange{}, err
	}
	if changed {
		ch.Config = &cfg
	}
	val := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: to}
	pg, err := tx.editPage(id, rel, func(ff *findingFile) error { return ff.setEntry("id", val) })
	if err != nil {
		return PageChange{}, err
	}
	tx.newIDs[to] = true
	base := path.Base(rel)
	if base == id+".md" || strings.HasPrefix(base, id+"-") {
		newRel := path.Join(path.Dir(rel), to+base[len(id):])
		if _, exists, err := tx.read(newRel); err != nil {
			return PageChange{}, err
		} else if exists {
			return PageChange{}, fmt.Errorf("%w: id: %s already exists", ErrBadValue, newRel)
		}
		data, _, _ := tx.read(rel)
		if err := tx.put(newRel, data, rankPage); err != nil {
			return PageChange{}, err
		}
		if err := tx.del(rel, rankPage); err != nil {
			return PageChange{}, err
		}
		pg.Path = newRel
	}
	ch.Page = pg
	return ch, nil
}

// rewritePageLists passes every entry of the config's pages and
// required_pages through fn, dropping those it doesn't keep, and returns
// the config as now stored and whether it changed.
func (tx *Tx) rewritePageLists(fn func(string) (string, bool)) (sdk.Config, bool, error) {
	ff, err := tx.configFile()
	if err != nil {
		return sdk.Config{}, false, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(ff.head, &doc); err != nil {
		return sdk.Config{}, false, yamlFileError(ConfigFile, 0, err)
	}
	changed := false
	if len(doc.Content) > 0 {
		m := doc.Content[0].Content
		for i := 0; i+1 < len(m); i += 2 {
			if (m[i].Value != "pages" && m[i].Value != "required_pages") || m[i+1].Kind != yaml.SequenceNode {
				continue
			}
			list := clean(m[i+1])
			var items []*yaml.Node
			for _, it := range list.Content {
				v, keep := fn(it.Value)
				changed = changed || !keep || v != it.Value
				if keep {
					it.Value = v
					items = append(items, it)
				}
			}
			list.Content = items
			if err := ff.setEntry(m[i].Value, list); err != nil {
				return sdk.Config{}, false, err
			}
		}
	}
	if !changed {
		return sdk.Config{}, false, nil
	}
	if err := tx.putConfig(ff); err != nil {
		return sdk.Config{}, false, err
	}
	cfg, err := tx.configRecord()
	return cfg, true, err
}

// UnsetPage removes keys from the page id: top-level keys (a page needs
// its id and title), x-<plugin>.<key>, or body, which empties it.
func (tx *Tx) UnsetPage(id string, paths ...string) (sdk.Page, error) {
	for _, p := range paths {
		if slices.Contains([]string{"id", "title", "kind", "path", "rev", "lines", "assets"}, p) {
			return sdk.Page{}, fmt.Errorf("%w: %s: a page needs it, or rpt sets it", ErrRefusedUnset, p)
		}
	}
	rel, err := tx.locatePage(id)
	if err != nil {
		return sdk.Page{}, err
	}
	return tx.editPage(id, rel, func(ff *findingFile) error {
		for _, p := range paths {
			var err error
			switch plugin, key, ok := pluginPath(p); {
			case p == "body":
				ff.body = nil
			case ok:
				err = ff.unsetNested(plugin, key)
			default:
				err = ff.removeEntry(p)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// RemovePage removes the page id's file. A page the config's pages or
// required_pages names is refused unless mode says otherwise: --force
// leaves the entries, --cleanup drops them.
func (tx *Tx) RemovePage(id string, mode Cited) (PageChange, error) {
	rel, err := tx.locatePage(id)
	if err != nil {
		return PageChange{}, err
	}
	src, _, err := tx.read(rel)
	if err != nil {
		return PageChange{}, err
	}
	if err := tx.checkRev(id, rel, Rev(src)); err != nil {
		return PageChange{}, err
	}
	pg, err := parsePage(rel, src)
	if err != nil {
		return PageChange{}, err
	}
	pg.Lines = nil
	ch := PageChange{Page: pg}
	cfg, err := tx.r.Config()
	if err != nil {
		return PageChange{}, err
	}
	var in []string
	if slices.Contains(cfg.Pages, id) {
		in = append(in, "pages")
	}
	if slices.Contains(cfg.RequiredPages, id) {
		in = append(in, "required_pages")
	}
	if len(in) > 0 {
		switch mode {
		case CitedForce:
			ch.Left = in
		case CitedCleanup:
			c, _, err := tx.rewritePageLists(func(e string) (string, bool) { return e, e != id })
			if err != nil {
				return PageChange{}, err
			}
			ch.Config = &c
		default:
			return PageChange{}, fmt.Errorf("%w: %s is in rpt.yaml's %s; pass --force (leave it there) or --cleanup (drop it)", ErrInUse, id, strings.Join(in, " and "))
		}
	}
	return ch, tx.del(rel, rankPage)
}

// PageOrder is the report's reading order: the pages list's entries that
// exist (findings once), findings after them if the list doesn't place
// it, then every unlisted page by ID.
func PageOrder(listed []string, pages []sdk.Page) []string {
	exists := map[string]bool{}
	for _, p := range pages {
		exists[p.ID] = true
	}
	var order []string
	for _, e := range listed {
		if (e == FindingsSlot || exists[e]) && !slices.Contains(order, e) {
			order = append(order, e)
		}
	}
	if !slices.Contains(order, FindingsSlot) {
		order = append(order, FindingsSlot)
	}
	var rest []string
	for _, p := range pages {
		if !slices.Contains(order, p.ID) && !slices.Contains(rest, p.ID) {
			rest = append(rest, p.ID)
		}
	}
	slices.SortFunc(rest, compareIDs)
	return append(order, rest...)
}
