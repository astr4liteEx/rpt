package sdk

import "encoding/json/jsontext"

// Severity is a finding's severity level. The order of levels is set by the
// report's config, not by this type.
type Severity string

// The severity levels rpt knows by default.
const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

// Finding is a "finding" record: one finding in a report, as rpt findings,
// parser plugins and rpt kb emit it.
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
	Lines    *Lines            `json:"lines,omitzero"`    // set by rpt findings --lines; rpt findings add ignores it

	// Extra holds every member not named above, so records pass through
	// with fields this version of rpt doesn't know.
	Extra map[string]jsontext.Value `json:",embed"`
}

// Lines is where a finding's parts sit in its file, as rpt findings
// --lines gives them: 1-based lines of the file as stored, so a checker can
// locate a problem without parsing the file itself.
type Lines struct {
	File        string                  `json:"file,omitzero"`     // the finding file's absolute path, symlinks kept
	Frontmatter map[string]int          `json:"frontmatter"`       // top-level key -> its line
	Sections    map[string]SectionLines `json:"sections,omitzero"` // keyed like Finding.Sections

	// Extra holds any unknown members.
	Extra map[string]jsontext.Value `json:",embed"`
}

// SectionLines is where one section sits in a finding file. Line Text+n is
// line n+1 of the section's text in Finding.Sections.
type SectionLines struct {
	Heading int `json:"heading"`
	Text    int `json:"text,omitzero"` // first line of the text; absent when the section is empty

	// Extra holds any unknown members.
	Extra map[string]jsontext.Value `json:",embed"`
}

// Evidence is an "evidence" record rpt evidence emits: one reference a
// finding makes to an evidence file, or, with --orphans, a file under
// findings/evidence/ that nothing references (no Finding, Ref or Source).
type Evidence struct {
	Kind    string `json:"kind"`
	Finding string `json:"finding,omitzero"` // the referencing finding's ID
	Ref     string `json:"ref,omitzero"`     // as written in the finding, relative to its file
	Source  string `json:"source,omitzero"`  // "frontmatter" (the evidence list) or "body" (a link)
	Path    string `json:"path,omitzero"`    // relative to the report root; absent when Ref leaves the report
	File    string `json:"file,omitzero"`    // absolute, symlinks kept; absent when Ref leaves the report
	Exists  bool   `json:"exists"`
	Rev     string `json:"rev,omitzero"` // the referencing finding's rev

	// Extra holds any unknown members.
	Extra map[string]jsontext.Value `json:",embed"`
}

// ScopeRow is a "scope" record: one in-scope asset, a row of the report's
// scope.csv.
type ScopeRow struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	Host string `json:"host"`
	Port int    `json:"port,omitzero"` // absent: every port
	// Protocol is "tcp" or "udp"; absent: any protocol.
	Protocol string `json:"protocol,omitzero"`
	// Rev is the row's revision, over the header and the row's own text;
	// pass it back as --if-rev.
	Rev string `json:"rev,omitzero"`
	// Lines is where the row sits in scope.csv, set by rpt scope --lines.
	Lines *ScopeLines `json:"lines,omitzero"`

	// Extra holds the row's other CSV columns and any unknown members.
	Extra map[string]jsontext.Value `json:",embed"`
}

// ScopeLines is where a scope row sits in scope.csv.
type ScopeLines struct {
	Row  int    `json:"row"`           // 1-based line the row starts on
	File string `json:"file,omitzero"` // scope.csv's absolute path, symlinks kept

	// Extra holds any unknown members.
	Extra map[string]jsontext.Value `json:",embed"`
}

// Level is how serious a Problem is.
type Level string

// The problem levels. Any error makes rpt validate exit 1 and rpt assemble
// refuse, unless --draft turns errors into warnings.
const (
	Error   Level = "error"
	Warning Level = "warning"
)

// Problem is a "problem" record: one broken rule that rpt validate or a
// checker plugin found.
type Problem struct {
	Kind    string `json:"kind"`
	Path    string `json:"path"`            // relative to the report root
	Line    int    `json:"line,omitzero"`   // 1-based; absent when the problem has no line
	Column  int    `json:"column,omitzero"` // 1-based byte in the line; only with Line
	Rule    string `json:"rule"`
	Level   Level  `json:"level"`
	Message string `json:"message"`
	Command string `json:"command,omitzero"` // the command that found it; never changed downstream

	// Extra holds any unknown members.
	Extra map[string]jsontext.Value `json:",embed"`
}

// Report is the "report" record rpt assemble emits: the whole render-ready
// document as one record, so renderers only present it.
type Report struct {
	Kind          string           `json:"kind"`
	SchemaVersion int              `json:"schema_version"`
	Report        ReportMeta       `json:"report"`
	Summary       map[Severity]int `json:"summary"` // finding count per level
	Scope         []ScopeRow       `json:"scope"`
	Findings      []ReportFinding  `json:"findings"` // in severity order, then by ID

	// Extra holds any unknown members.
	Extra map[string]jsontext.Value `json:",embed"`
}

// ReportMeta is what the report's config tells a renderer. Engagement
// details (client, dates, title) are not part of a report: renderers take
// them from their own input.
type ReportMeta struct {
	// Severities are the report's levels, most severe first, so renderers
	// can order the summary and the findings without guessing.
	Severities []Severity `json:"severities"`

	// Sections are the report's sections in the order rpt writes them:
	// the fixed ones with this report's headings, then the custom ones it
	// requires, as rpt sections gives them. A finding's sections are keyed
	// by Key; Heading is what a reader sees.
	Sections []ReportSection `json:"sections"`

	// Extra holds unknown members of the record. rpt never copies unknown
	// config keys here.
	Extra map[string]jsontext.Value `json:",embed"`
}

// ReportSection is one section in ReportMeta: the key a finding's sections
// use and the heading this report gives it.
type ReportSection struct {
	Key     string `json:"key"`
	Heading string `json:"heading"`

	// Extra holds any unknown members.
	Extra map[string]jsontext.Value `json:",embed"`
}

// ReportFinding is a finding inside a Report: each target's scope ID is
// replaced by the full scope row and its evidence paths are made absolute,
// so renderers never read scope.csv or resolve paths.
type ReportFinding struct {
	ID       string            `json:"id"`
	Title    string            `json:"title"`
	Severity Severity          `json:"severity"`
	Targets  []ReportTarget    `json:"targets"`
	Sections map[string]string `json:"sections"` // markdown, keyed description, remediation, poc
	Assets   []string          `json:"assets"`   // absolute paths

	// Extra holds the finding's unknown members.
	Extra map[string]jsontext.Value `json:",embed"`
}

// ReportTarget is a Target inside a Report, with the full scope row in
// place of its ID.
type ReportTarget struct {
	Scope    ScopeRow `json:"scope"`
	Host     string   `json:"host,omitzero"`
	Port     int      `json:"port,omitzero"`
	Protocol string   `json:"protocol,omitzero"`

	// Extra holds any unknown members.
	Extra map[string]jsontext.Value `json:",embed"`
}

// Target is one place a finding was found on, attributed to a scope row.
// In a report every target names its row's ID in Scope. Host is set only
// when the row is a range (a CIDR or *.domain) and says where inside it;
// a row that is one asset (an address, a name or any other text) needs no
// host. Port and protocol are optional and must fit the row's.
//
// A parser plugin, which doesn't know the report's scope, sets Host (and
// Port and Protocol) and leaves Scope empty; rpt scope match fills Scope
// from the most specific matching row and drops a Host the row makes
// redundant. rpt findings add refuses a target without Scope.
type Target struct {
	Scope    string `json:"scope,omitzero"` // a scope row's ID
	Host     string `json:"host,omitzero"`
	Port     int    `json:"port,omitzero"`
	Protocol string `json:"protocol,omitzero"` // "tcp" or "udp"

	// Extra holds any unknown members.
	Extra map[string]jsontext.Value `json:",embed"`
}

// Location is one "location" record rpt ls emits: a report found under the
// folder searched. Format and Findings are nil when its config doesn't
// parse.
type Location struct {
	Kind     string `json:"kind"`
	Path     string `json:"path"` // absolute path of the report root
	Format   *int   `json:"format,omitzero"`
	Findings *int   `json:"findings,omitzero"` // finding files that parse

	// Extra holds any unknown members.
	Extra map[string]jsontext.Value `json:",embed"`
}

// Command is one "command" record rpt help emits: something rpt <name> can
// run, a built-in or a plugin, described with the members a --describe
// answer uses. A plugin's describe members come from its answer, unknown
// ones in Extra, and are empty when it gave none in time.
type Command struct {
	Kind     string   `json:"kind"`
	Name     string   `json:"name"`
	Source   string   `json:"source"`           // "builtin" or "plugin"
	Path     string   `json:"path,omitzero"`    // a plugin's absolute path
	Summary  string   `json:"summary,omitzero"` // always set for a built-in
	Usage    string   `json:"usage,omitzero"`
	Version  string   `json:"version,omitzero"` // a plugin's own version
	Input    string   `json:"input,omitzero"`
	Output   string   `json:"output,omitzero"`
	Roles    []string `json:"roles,omitzero"`
	Shadowed bool     `json:"shadowed,omitzero"` // a plugin a built-in of the same name hides

	// Extra holds any unknown members.
	Extra map[string]jsontext.Value `json:",embed"`
}

// VersionInfo is the "version" record rpt version emits.
type VersionInfo struct {
	Kind          string `json:"kind"`
	Version       string `json:"version"`        // release tag, module version, or "dev"
	SchemaVersion int    `json:"schema_version"` // record schemas this rpt writes
	Format        int    `json:"format"`         // report format this rpt reads

	// Extra holds any unknown members.
	Extra map[string]jsontext.Value `json:",embed"`
}

// Section is one "section" record rpt sections emits: a section of the
// report's findings, as the report config maps it. Key is the fixed key
// (description, remediation, poc) or, for a custom section, its heading.
type Section struct {
	Kind     string `json:"kind"`
	Key      string `json:"key"`
	Heading  string `json:"heading"`
	Fixed    bool   `json:"fixed"`
	Required bool   `json:"required"`

	// Extra holds any unknown members.
	Extra map[string]jsontext.Value `json:",embed"`
}

// SeverityLevel is one "severity" record rpt severities emits: a level the
// report allows, with its rank (1 is the most severe).
type SeverityLevel struct {
	Kind  string   `json:"kind"`
	Level Severity `json:"level"`
	Rank  int      `json:"rank"`

	// Extra holds any unknown members.
	Extra map[string]jsontext.Value `json:",embed"`
}
