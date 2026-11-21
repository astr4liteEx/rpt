// Package plugin finds, describes and runs rpt-<name> executables on
// PATH, and checks the x- names in a report against the schemas plugins
// declare for them.
package plugin

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// A Plugin is an rpt-<name> executable.
type Plugin struct{ Name, Path string }

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// ValidName reports whether name can name a plugin: lower-case letters,
// digits and dashes. Anything else, a / above all, is never looked up.
func ValidName(name string) bool { return nameRE.MatchString(name) }

// ErrNotFound is a plugin name with no rpt-<name> on PATH.
var ErrNotFound = errors.New("no such plugin")

// Discover lists the plugins on pathList (a PATH value), sorted by name.
// The first of a name in PATH order wins, as in a shell. Empty and
// relative PATH entries are skipped.
func Discover(pathList string) []Plugin {
	seen := map[string]bool{}
	var out []Plugin
	for _, dir := range dirs(pathList) {
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			name, ok := strings.CutPrefix(strings.TrimSuffix(e.Name(), ".exe"), "rpt-")
			if !ok || !ValidName(name) || seen[name] {
				continue
			}
			p := filepath.Join(dir, e.Name())
			if executable(p) {
				seen[name] = true
				out = append(out, Plugin{name, p})
			}
		}
	}
	slices.SortFunc(out, func(a, b Plugin) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// Lookup finds one plugin on pathList.
func Lookup(pathList, name string) (Plugin, error) {
	if !ValidName(name) {
		return Plugin{}, ErrNotFound
	}
	for _, dir := range dirs(pathList) {
		for _, file := range []string{"rpt-" + name, "rpt-" + name + ".exe"} {
			if p := filepath.Join(dir, file); executable(p) {
				return Plugin{name, p}, nil
			}
		}
	}
	return Plugin{}, ErrNotFound
}

func dirs(pathList string) []string {
	var out []string
	for _, d := range filepath.SplitList(pathList) {
		if d != "" && filepath.IsAbs(d) {
			out = append(out, d)
		}
	}
	return out
}

func executable(p string) bool {
	info, err := os.Stat(p) // follows symlinks
	return err == nil && info.Mode().IsRegular() && (info.Mode().Perm()&0o111 != 0 || filepath.Ext(p) == ".exe")
}

// Env is environ with what plugins may read set: RPT_BIN (self, so a
// plugin calls back into the same rpt), RPT_SCHEMA_VERSION and, when
// reportDir isn't empty, RPT_REPORT_DIR.
func Env(environ []string, reportDir, self string, schemaVersion int) []string {
	set := map[string]string{"RPT_SCHEMA_VERSION": strconv.Itoa(schemaVersion), "RPT_BIN": self}
	if reportDir != "" {
		if abs, err := filepath.Abs(reportDir); err == nil {
			set["RPT_REPORT_DIR"] = abs
		}
	}
	var out []string
	for _, kv := range environ {
		k, _, _ := strings.Cut(kv, "=")
		if k != "RPT_BIN" && k != "RPT_SCHEMA_VERSION" && k != "RPT_REPORT_DIR" {
			out = append(out, kv)
		}
	}
	for _, k := range []string{"RPT_BIN", "RPT_REPORT_DIR", "RPT_SCHEMA_VERSION"} {
		if v := set[k]; v != "" {
			out = append(out, k+"="+v)
		}
	}
	return out
}
