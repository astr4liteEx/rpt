package report

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"

	"go.yaml.in/yaml/v3"

	"github.com/astr4liteEx/rpt/sdk"
)

// ConfigFile is the report config's file name at the report root.
const ConfigFile = "rpt.yaml"

// DefaultSeverities is the severity order used when the report config has no
// severities list, most severe first.
var DefaultSeverities = []sdk.Severity{sdk.Critical, sdk.High, sdk.Medium, sdk.Low, sdk.Info}

// Report is an open report folder. Every file access goes through its
// os.Root, so no path can escape the folder.
type Report struct {
	root *os.Root
}

// Open opens the report folder at dir.
func Open(dir string) (*Report, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("open report %s: %w", dir, err)
	}
	return &Report{root: root}, nil
}

// Close releases the report folder.
func (r *Report) Close() error {
	return r.root.Close()
}

// FileError is a problem with one file in the report, located by path
// (relative to the report root) and, when known, a 1-based line.
type FileError struct {
	Path string
	Line int
	Err  error
}

func (e *FileError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("%s:%d: %v", e.Path, e.Line, e.Err)
	}
	return fmt.Sprintf("%s: %v", e.Path, e.Err)
}

func (e *FileError) Unwrap() error { return e.Err }

// Config is the report config read from rpt.yaml.
type Config struct {
	Format     int
	Name       string
	Client     string
	Period     sdk.Period
	Severities []sdk.Severity // most severe first; the only allowed levels

	// UnknownKeys lists top-level keys rpt doesn't define, for validate to
	// warn about. They are never copied into an assembled report.
	UnknownKeys []string
}

// Config reads the report config.
func (r *Report) Config() (Config, error) {
	src, err := r.root.ReadFile(ConfigFile)
	if err != nil {
		return Config{}, fmt.Errorf("read report config: %w", err)
	}
	var raw struct {
		Format int `yaml:"format"`
		Name   string
		Client string
		Period struct {
			Start string
			End   string
		}
		Severities []sdk.Severity
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(normaliseNewlines(src), &doc); err != nil {
		return Config{}, yamlFileError(ConfigFile, 0, err)
	}
	if err := doc.Decode(&raw); err != nil {
		return Config{}, yamlFileError(ConfigFile, 0, err)
	}
	cfg := Config{
		Format:     raw.Format,
		Name:       raw.Name,
		Client:     raw.Client,
		Period:     sdk.Period{Start: raw.Period.Start, End: raw.Period.End},
		Severities: raw.Severities,
	}
	if len(cfg.Severities) == 0 {
		cfg.Severities = slices.Clone(DefaultSeverities)
	}
	cfg.UnknownKeys = unknownKeys(&doc, "format", "name", "client", "period", "severities")
	return cfg, nil
}

// unknownKeys returns the top-level mapping keys of doc not in known.
func unknownKeys(doc *yaml.Node, known ...string) []string {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil
	}
	var unknown []string
	m := doc.Content[0].Content
	for i := 0; i+1 < len(m); i += 2 {
		if k := m[i].Value; !slices.Contains(known, k) {
			unknown = append(unknown, k)
		}
	}
	return unknown
}

// yamlLine finds the first line number in a yaml/v3 error message, which
// is the only place the library reports it.
var yamlLine = regexp.MustCompile(`line (\d+)`)

// yamlFileError wraps a yaml/v3 error with the file and, when the error
// names one, its line shifted by offset lines.
func yamlFileError(path string, offset int, err error) error {
	line := 0
	if m := yamlLine.FindStringSubmatch(err.Error()); m != nil {
		line, _ = strconv.Atoi(m[1])
		line += offset
	}
	return &FileError{Path: path, Line: line, Err: err}
}

// normaliseNewlines turns CRLF line endings into LF.
func normaliseNewlines(b []byte) []byte {
	return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
}
