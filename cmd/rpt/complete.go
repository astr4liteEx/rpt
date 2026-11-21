package main

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/internal/report"
)

// Shell completion. Cobra's __complete finds the command; for a built-in,
// which parses its own flags, completeBuiltin offers its flags, flag
// values and arguments from the report, read fresh each time (frontmatter
// only) with nothing cached. A plugin's stub asks the plugin.

const (
	noFiles = cobra.ShellCompDirectiveNoFileComp
	files   = cobra.ShellCompDirectiveDefault
	dirs    = cobra.ShellCompDirectiveFilterDirs
)

// completer completes one built-in's arguments: name is "finding set" or
// "validate". Cobra has parsed the flags typed so far, so --report is
// known, and offers the flag names itself.
func completer(e *env, name string) cobra.CompletionFunc {
	return func(_ *cobra.Command, args []string, word string) ([]string, cobra.ShellCompDirective) {
		c := &completion{name: name, word: word, pos: args}
		if r, err := openQuiet(e.report); err == nil {
			defer r.Close()
			c.r = r
		}
		return c.args()
	}
}

// flagCompleter completes the value of one flag.
func flagCompleter(e *env, flag string) cobra.CompletionFunc {
	return func(_ *cobra.Command, _ []string, word string) ([]string, cobra.ShellCompDirective) {
		c := &completion{word: word, flag: flag}
		if r, err := openQuiet(e.report); err == nil {
			defer r.Close()
			c.r = r
		}
		return c.flagValue()
	}
}

// openQuiet opens the report completion works on, logging nothing.
func openQuiet(flag string) (*report.Report, error) {
	dir, err := report.Root(flag)
	if err != nil {
		return nil, err
	}
	return report.Open(dir)
}

// A completion is one Tab press on a built-in.
type completion struct {
	name string
	word string
	pos  []string // positional arguments before the word
	flag string   // the flag whose value the word is, if any
	r    *report.Report
}

// filter keeps the candidates starting with the word, ignoring case.
func (c *completion) filter(cands []string) []string {
	out := []string{}
	for _, cand := range cands {
		v, _, _ := strings.Cut(cand, "\t")
		if strings.HasPrefix(strings.ToLower(v), strings.ToLower(c.word)) {
			out = append(out, cand)
		}
	}
	return out
}

func (c *completion) flagValue() ([]string, cobra.ShellCompDirective) {
	switch c.flag {
	case "report", "like":
		return nil, dirs
	case "severity":
		return c.filter(c.levels()), noFiles
	case "target":
		return c.filter(c.scopeIDs()), noFiles
	case "link":
		return c.filter(append(c.sectionKeys(), "body")), noFiles
	case "rename":
		return nil, noFiles
	}
	return nil, noFiles
}

// args completes the positional argument the word is.
func (c *completion) args() ([]string, cobra.ShellCompDirective) {
	n := len(c.pos)
	at := func(i int) string {
		if i < len(c.pos) {
			return c.pos[i]
		}
		return ""
	}
	var cands []string
	dir := noFiles
	switch c.name {
	case "finding get", "finding remove":
		cands = c.findings()
	case "finding set", "finding unset":
		switch {
		case n == 0:
			cands = c.findings()
		case n == 1:
			cands = c.findingPaths(at(0), c.name == "finding unset")
		case c.name == "finding set":
			cands = c.values(at(1))
		default:
			cands = c.findingPaths(at(0), true)
		}
	case "page get", "page remove":
		cands = c.pages()
	case "page set", "page unset":
		switch {
		case n == 0:
			cands = c.pages()
		case n == 1 || c.name == "page unset":
			cands = c.pagePaths(at(0))
		}
	case "scope get", "scope remove":
		cands = c.scopeIDs()
	case "scope set", "scope unset":
		switch {
		case n == 0:
			cands = c.scopeIDs()
		case n == 1 || c.name == "scope unset":
			cands = c.scopeColumns()
		}
	case "config get", "config unset":
		cands = c.configKeys()
	case "config set":
		if n == 0 {
			cands = c.configKeys()
		} else if at(0) == "severities" || at(0) == "required_sections" {
			cands = c.configList(at(0))
		}
	case "evidence get":
		cands = append(c.findings(), c.pages()...)
	case "evidence add":
		if n == 0 {
			cands = append(c.findings(), c.pages()...)
		} else {
			dir = files
		}
	case "evidence set", "evidence unset", "evidence remove":
		switch n {
		case 0:
			cands = append(c.findings(), c.pages()...)
		case 1:
			cands = c.references(at(0))
		case 2:
			switch c.name {
			case "evidence set":
				cands = []string{"caption\tthe text of every link to it", "path\tmove the file"}
			case "evidence unset":
				cands = []string{"caption\tempty the text of every link to it"}
			}
		}
	case "validate":
		cands = append(append(append(c.findings(), c.pages()...), c.scopeIDs()...), "-\tthe records on stdin")
	case "help":
		if n == 0 {
			cands = commandNames()
		} else if b, ok := builtins[at(0)]; ok && n == 1 {
			for _, s := range b.subs {
				cands = append(cands, s.name())
			}
		}
	case "completion":
		if n == 0 {
			cands = []string{"bash", "zsh", "fish", "powershell"}
		}
	case "new", "ls":
		return nil, dirs
	}
	return c.filter(cands), dir
}

// commandNames are the built-ins, then the plugins on PATH no built-in
// hides, by name.
func commandNames() []string {
	var out []string
	for name := range builtins {
		out = append(out, name)
	}
	slices.Sort(out)
	for _, p := range findPlugins() {
		if !p.Shadowed {
			out = append(out, p.Name)
		}
	}
	return out
}

func (c *completion) findings() []string { return c.entries(report.FindingsDir) }
func (c *completion) pages() []string    { return c.entries(report.PagesDir) }

func (c *completion) entries(dir string) []string {
	if c.r == nil {
		return nil
	}
	var out []string
	for _, en := range c.r.Entries(dir) {
		out = append(out, en.ID+"\t"+en.Title)
	}
	return out
}

// entry is the finding or page id, if the report has it.
func (c *completion) entry(dir, id string) (report.Entry, bool) {
	if c.r == nil {
		return report.Entry{}, false
	}
	for _, en := range c.r.Entries(dir) {
		if strings.EqualFold(en.ID, id) {
			return en, true
		}
	}
	return report.Entry{}, false
}

// findingPaths are the paths finding set and unset take for finding id:
// its keys, its sections and the report's, and with present only what it
// has.
func (c *completion) findingPaths(id string, present bool) []string {
	en, _ := c.entry(report.FindingsDir, id)
	var out []string
	if !present {
		out = []string{"title", "severity", "targets", "evidence", "id"}
	}
	for _, k := range en.Keys {
		if !slices.Contains(out, k) && k != "id" && k != "title" && k != "severity" {
			out = append(out, k)
		}
	}
	for _, k := range c.sectionKeys() {
		out = append(out, "sections."+k)
	}
	return out
}

func (c *completion) pagePaths(id string) []string {
	en, _ := c.entry(report.PagesDir, id)
	out := []string{"title", "body", "evidence", "id"}
	for _, k := range en.Keys {
		if !slices.Contains(out, k) {
			out = append(out, k)
		}
	}
	return out
}

// values completes a finding set value for path.
func (c *completion) values(path string) []string {
	switch path {
	case "severity":
		return c.levels()
	case "targets":
		return c.scopeIDs()
	}
	return nil
}

func (c *completion) levels() []string {
	if c.r == nil {
		return nil
	}
	cfg, err := c.r.Config()
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range cfg.Severities {
		out = append(out, string(l))
	}
	return out
}

func (c *completion) sectionKeys() []string {
	if c.r == nil {
		return nil
	}
	rec, err := c.r.ConfigRecord(false)
	if err != nil {
		return slices.Clone(report.FixedSections)
	}
	out := slices.Clone(report.FixedSections)
	for _, s := range rec.RequiredSections {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func (c *completion) scopeIDs() []string {
	if c.r == nil {
		return nil
	}
	rows, _ := c.r.Scope()
	var out []string
	for _, row := range rows {
		out = append(out, row.ID+"\t"+row.Host)
	}
	return out
}

func (c *completion) scopeColumns() []string {
	if c.r == nil {
		return nil
	}
	cols, _ := c.r.ScopeHeader()
	return slices.DeleteFunc(cols, func(s string) bool { return s == "id" })
}

// configKeys are rpt.yaml's keys, the x-<plugin> sections it has, and
// sections.<key> for each fixed section.
func (c *completion) configKeys() []string {
	out := []string{"format", "severities", "required_sections", "sections", "rules", "pages", "required_pages"}
	for _, k := range report.FixedSections {
		out = append(out, "sections."+k)
	}
	if c.r != nil {
		if rec, err := c.r.ConfigRecord(false); err == nil {
			for k := range rec.Extra {
				if strings.HasPrefix(k, "x-") {
					out = append(out, k)
				}
			}
		}
	}
	return out
}

// configList offers a config list's current items, to keep or reorder.
func (c *completion) configList(key string) []string {
	if key == "severities" {
		return c.levels()
	}
	return c.sectionKeys()
}

// references are the evidence references the finding or page owner makes.
func (c *completion) references(owner string) []string {
	if c.r == nil {
		return nil
	}
	list, _ := c.r.Evidence([]string{report.CanonicalID(owner)}, false)
	var out []string
	for _, ev := range list {
		if !slices.ContainsFunc(out, func(s string) bool { return strings.HasPrefix(s, ev.Ref+"\t") || s == ev.Ref }) {
			out = append(out, ev.Ref+"\t"+cmp.Or(ev.Text, ev.Source))
		}
	}
	return out
}

// pluginCompleter forwards completion to the plugin: rpt-<name>
// __complete <args...> <word>, with no stdin and the --describe timeout.
// When the plugin fails, times out or answers in another form, the shell
// completes file names.
func pluginCompleter(bin string) cobra.CompletionFunc {
	return func(_ *cobra.Command, args []string, word string) ([]string, cobra.ShellCompDirective) {
		ctx, cancel := context.WithTimeout(context.Background(), describeTimeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, append(append([]string{"__complete"}, args...), word)...)
		cmd.Stdin = nil // /dev/null
		cmd.Env, _ = pluginEnv("")
		cmd.WaitDelay = 100 * time.Millisecond
		out, err := cmd.Output()
		if err != nil || ctx.Err() != nil {
			return nil, files
		}
		var cands []string
		sc := bufio.NewScanner(bytes.NewReader(out))
		for sc.Scan() {
			line := sc.Text()
			if d, ok := strings.CutPrefix(line, ":"); ok {
				var n int
				for _, ch := range d {
					if ch < '0' || ch > '9' {
						return nil, files
					}
					n = n*10 + int(ch-'0')
				}
				return cands, cobra.ShellCompDirective(n)
			}
			cands = append(cands, line)
		}
		return nil, files // no directive line: not cobra's form
	}
}

// completionVerb prints the completion script for a shell. The script
// calls rpt __complete on each Tab press, so it never goes stale.
func completionVerb(flags *pflag.FlagSet) runner {
	return func(e *env, args []string) int {
		if len(args) != 1 {
			return usageError(e, "needs one shell: bash, zsh, fish or powershell")
		}
		root := newRoot(e, new(int))
		var err error
		switch args[0] {
		case "bash":
			err = root.GenBashCompletionV2(e.stdout, true)
		case "zsh":
			err = root.GenZshCompletion(e.stdout)
		case "fish":
			err = root.GenFishCompletion(e.stdout, true)
		case "powershell":
			err = root.GenPowerShellCompletionWithDesc(e.stdout)
		default:
			return usageError(e, "unknown shell %q: bash, zsh, fish or powershell", args[0])
		}
		if err != nil {
			e.log.Error(err.Error())
			return cli.ExitProblems
		}
		return cli.ExitOK
	}
}
