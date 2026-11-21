package sdk

import "encoding/json/jsontext"

// The record kinds rpt reads and writes. A plugin's own kinds are
// x-<plugin>[-<name>].
const (
	KindFinding  = "finding"
	KindPage     = "page"
	KindScope    = "scope"
	KindConfig   = "config"
	KindEvidence = "evidence"
	KindProblem  = "problem"
	KindReport   = "report"
	KindLocation = "location"
	KindCommand  = "command"
	KindVersion  = "version"
)

// A Record is one of this package's record types; Emit sets its kind.
type Record interface{ RecordKind() string }

func (Finding) RecordKind() string     { return KindFinding }
func (Page) RecordKind() string        { return KindPage }
func (ScopeRow) RecordKind() string    { return KindScope }
func (Config) RecordKind() string      { return KindConfig }
func (Evidence) RecordKind() string    { return KindEvidence }
func (Problem) RecordKind() string     { return KindProblem }
func (Report) RecordKind() string      { return KindReport }
func (Location) RecordKind() string    { return KindLocation }
func (Command) RecordKind() string     { return KindCommand }
func (VersionInfo) RecordKind() string { return KindVersion }

// Severity is a finding's severity level. The order of levels is set by
// the report's config, not by this type.
type Severity string

// The severity levels rpt knows by default.
const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

// Finding is a "finding" record: one finding, as rpt finding get, parser
// plugins and rpt assemble give it. In an assembled report each target
// carries its scope row, links to files in the report name them by
// absolute path, and Assets is set.
type Finding struct {
	Kind     string            `json:"kind"`
	ID       string            `json:"id,omitzero"`
	Title    string            `json:"title"`
	Targets  []Target          `json:"targets"` // the scope rows it was found on
	Severity Severity          `json:"severity"`
	Path     string            `json:"path,omitzero"` // relative to the report root
	Rev      string            `json:"rev,omitzero"`  // the file's revision; pass it back as --if-rev
	Sections map[string]string `json:"sections,omitzero"`
	Evidence []string          `json:"evidence,omitzero"` // relative to the finding file's folder
	Lines    *Lines            `json:"lines,omitzero"`    // set by --lines; rpt finding add ignores it
	// Assets are the files the finding lists and links, set by --assets
	// and by rpt assemble. rpt finding add reads each one's Ref and File:
	// it copies the file in and points Ref at the copy.
	Assets []Asset `json:"assets,omitzero"`

	// Extra holds every member not named above, so records pass through
	// with fields this version of rpt doesn't know.
	Extra map[string]jsontext.Value `json:",embed"`
}

// Target is one place a finding was found on, attributed to a scope row.
// Scope names the row's ID; Host is set only when the row is a range (a
// CIDR or *.domain) and says where inside it. Port and protocol are
// optional and must fit the row's.
//
// A parser plugin, which doesn't know the report's scope, sets Host (and
// Port and Protocol) and leaves Scope empty; rpt scope match fills Scope.
// rpt finding add refuses a target without Scope.
type Target struct {
	Scope    string    `json:"scope,omitzero"` // a scope row's ID
	Row      *ScopeRow `json:"row,omitzero"`   // the row itself, in an assembled report
	Host     string    `json:"host,omitzero"`
	Port     int       `json:"port,omitzero"`
	Protocol string    `json:"protocol,omitzero"` // "tcp" or "udp"

	Extra map[string]jsontext.Value `json:",embed"`
}

// Page is a "page" record: one page of report-level prose, such as an
// executive summary.
type Page struct {
	Kind     string   `json:"kind"`
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Path     string   `json:"path,omitzero"` // relative to the report root
	Body     string   `json:"body"`          // markdown; ## headings in it are the page's own
	Evidence []string `json:"evidence,omitzero"`
	Rev      string   `json:"rev,omitzero"`
	Lines    *Lines   `json:"lines,omitzero"`
	Assets   []Asset  `json:"assets,omitzero"` // as for Finding

	Extra map[string]jsontext.Value `json:",embed"`
}

// Lines is where a record's parts sit in its file, as --lines gives them:
// 1-based lines of the file as stored, so a checker can place a problem
// without parsing the file itself. Each record sets the members that
// apply to it.
type Lines struct {
	File     string                  `json:"file,omitzero"`     // the file's absolute path, symlinks kept
	Keys     map[string]Position     `json:"keys,omitzero"`     // frontmatter or rpt.yaml top-level keys
	Sections map[string]SectionLines `json:"sections,omitzero"` // a finding's, keyed like Finding.Sections
	Body     int                     `json:"body,omitzero"`     // the line a page's body starts on
	Row      int                     `json:"row,omitzero"`      // the line a scope row starts on

	Extra map[string]jsontext.Value `json:",embed"`
}

// SectionLines is where one section sits in a finding file. Line Text+n
// is line n+1 of the section's text in Finding.Sections.
type SectionLines struct {
	Heading int `json:"heading"`
	Text    int `json:"text,omitzero"` // the text's first line; absent when the section is empty

	Extra map[string]jsontext.Value `json:",embed"`
}

// Position is a place in a file: a 1-based line, and the 1-based byte in
// that line.
type Position struct {
	Line   int `json:"line"`
	Column int `json:"column"`

	Extra map[string]jsontext.Value `json:",embed"`
}

// Config is a "config" record: rpt.yaml as in effect, defaults filled in.
// Plugin sections (x-<plugin>) are in Extra; other keys rpt doesn't
// define are left out.
type Config struct {
	Kind             string            `json:"kind"`
	Format           int               `json:"format,omitzero"`
	Severities       []Severity        `json:"severities,omitzero"`        // most severe first
	Sections         map[string]string `json:"sections,omitzero"`          // fixed section key -> its heading
	RequiredSections []string          `json:"required_sections,omitzero"` // section keys, or a custom section's heading
	Rules            map[string]Level  `json:"rules,omitzero"`             // rule name -> the level its problems take
	// Pages orders the pages: page IDs, and "findings" where the findings
	// go. Pages it doesn't list come last, by ID.
	Pages         []string `json:"pages,omitzero"`
	RequiredPages []string `json:"required_pages,omitzero"` // pages that must exist with a body
	Rev           string   `json:"rev,omitzero"`
	Lines         *Lines   `json:"lines,omitzero"`

	// Extra holds the x-<plugin> sections and any unknown members.
	Extra map[string]jsontext.Value `json:",embed"`
}

// The sources of a reference to a file.
const (
	SourceFrontmatter = "frontmatter" // the evidence list
	SourceBody        = "body"        // a link in the text
)

// Asset is one file a finding or page lists in its evidence or links in
// its text.
type Asset struct {
	Ref    string `json:"ref,omitzero"`    // as the owner writes it, relative to its file
	Path   string `json:"path,omitzero"`   // relative to the report root; absent when Ref leaves the report
	File   string `json:"file,omitzero"`   // absolute, symlinks kept: the file to open or copy
	Source string `json:"source,omitzero"` // SourceFrontmatter or SourceBody
	// MediaType is the file's type, from its extension, else its content.
	MediaType string `json:"media_type,omitzero"`
	Text      string `json:"text,omitzero"`  // a link's text, its caption
	Image     bool   `json:"image,omitzero"` // the link is an image

	Extra map[string]jsontext.Value `json:",embed"`
}

// Evidence is an "evidence" record rpt evidence get emits: one reference
// a finding or page makes to a file, or with --orphans a file in an
// evidence folder nothing references (no owner, Ref or Source).
type Evidence struct {
	Kind    string `json:"kind"`
	Finding string `json:"finding,omitzero"` // the owner, when a finding
	Page    string `json:"page,omitzero"`    // the owner, when a page
	Asset
	Exists  bool   `json:"exists"`
	Section string `json:"section,omitzero"` // the finding section a link is in
	Line    int    `json:"line,omitzero"`    // where the reference is in the owner's file
	Rev     string `json:"rev,omitzero"`     // the owner's rev
}

// ScopeRow is a "scope" record: one in-scope asset, a row of scope.csv.
type ScopeRow struct {
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	Host     string `json:"host"`
	Port     int    `json:"port,omitzero"`     // absent: every port
	Protocol string `json:"protocol,omitzero"` // "tcp" or "udp"; absent: any
	// Rev is the row's revision, over the header and the row's own text.
	Rev   string `json:"rev,omitzero"`
	Lines *Lines `json:"lines,omitzero"`

	// Extra holds the row's other columns and any unknown members.
	Extra map[string]jsontext.Value `json:",embed"`
}

// Level is how serious a Problem is.
type Level string

// The problem levels. An error makes rpt validate exit 1.
const (
	Error   Level = "error"
	Warning Level = "warning"
)

// Problem is a "problem" record: one broken rule that rpt or a checker
// plugin found.
type Problem struct {
	Kind    string `json:"kind"`
	Path    string `json:"path"`            // relative to the report root; "-" for stdin
	Line    int    `json:"line,omitzero"`   // 1-based; absent when the problem has no line
	Column  int    `json:"column,omitzero"` // 1-based byte in the line; only with Line
	Rule    string `json:"rule"`
	Level   Level  `json:"level"`
	Message string `json:"message"`
	Command string `json:"command,omitzero"` // the command that found it; never changed downstream
	// Suggestions are replacements for the text the problem is about,
	// best first; EndColumn is the 1-based byte, inclusive, it ends at.
	Suggestions []string `json:"suggestions,omitzero"`
	EndColumn   int      `json:"end_column,omitzero"`
	Rev         string   `json:"rev,omitzero"` // the rev of the file the problem is in, as read

	Extra map[string]jsontext.Value `json:",embed"`
}

// Report is the "report" record rpt assemble emits: the whole
// render-ready report, so renderers only present it.
type Report struct {
	Kind          string     `json:"kind"`
	SchemaVersion int        `json:"schema_version"`
	Severities    []Severity `json:"severities"` // most severe first
	// Sections are the finding sections in the order rpt writes them: the
	// fixed ones with this report's headings, then the custom ones it
	// requires. A finding's sections are keyed by Key.
	Sections []Section `json:"sections"`
	// Order is the report's parts in reading order: page IDs, and
	// "findings" where the findings go.
	Order    []string         `json:"order"`
	Summary  map[Severity]int `json:"summary"` // finding count per level
	Scope    []ScopeRow       `json:"scope"`
	Findings []Finding        `json:"findings"` // by severity, then ID
	Pages    []Page           `json:"pages"`    // in Order

	Extra map[string]jsontext.Value `json:",embed"`
}

// Section is one finding section: the key a finding's sections use and
// the heading this report gives it.
type Section struct {
	Key     string `json:"key"`
	Heading string `json:"heading"`

	Extra map[string]jsontext.Value `json:",embed"`
}

// Location is a "location" record rpt ls emits: a report found. Format
// and Findings are nil when its config doesn't parse.
type Location struct {
	Kind     string `json:"kind"`
	Path     string `json:"path"` // absolute
	Format   *int   `json:"format,omitzero"`
	Findings *int   `json:"findings,omitzero"` // finding files that parse

	Extra map[string]jsontext.Value `json:",embed"`
}

// Command is a "command" record rpt help emits: something rpt <name> can
// run, a built-in or a plugin, with what its --describe answer says.
type Command struct {
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Source string `json:"source"`        // "builtin" or "plugin"
	Path   string `json:"path,omitzero"` // a plugin's absolute path
	// Shadowed marks a plugin a built-in of the same name hides;
	// Incompatible one whose requires this rpt doesn't fit.
	Shadowed     bool `json:"shadowed,omitzero"`
	Incompatible bool `json:"incompatible,omitzero"`
	Description
}

// VersionInfo is the "version" record rpt version emits.
type VersionInfo struct {
	Kind          string `json:"kind"`
	Version       string `json:"version"`        // release tag, module version, or "dev"
	SchemaVersion int    `json:"schema_version"` // record schemas this rpt writes
	Format        int    `json:"format"`         // report format this rpt reads

	Extra map[string]jsontext.Value `json:",embed"`
}
