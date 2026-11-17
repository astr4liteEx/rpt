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
	Scope    []string          `json:"scope"` // scope IDs
	Severity Severity          `json:"severity"`
	Path     string            `json:"path,omitzero"` // relative to the report root
	Sections map[string]string `json:"sections,omitzero"`
	Evidence []string          `json:"evidence,omitzero"` // relative to the finding file's folder
	Target   *Target           `json:"target,omitzero"`   // what was hit; set by parser plugins

	// Extra holds every member not named above, so records pass through
	// with fields this version of rpt doesn't know.
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

	// Extra holds the row's other CSV columns and any unknown members.
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

// Problem is a "problem" record: one broken rule that rpt validate found.
type Problem struct {
	Kind    string `json:"kind"`
	Path    string `json:"path"`          // relative to the report root
	Line    int    `json:"line,omitzero"` // 1-based; absent when the problem has no line
	Rule    string `json:"rule"`
	Level   Level  `json:"level"`
	Message string `json:"message"`

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

	// Extra holds unknown members of the record. rpt never copies unknown
	// config keys here.
	Extra map[string]jsontext.Value `json:",embed"`
}

// ReportFinding is a finding inside a Report: its scope IDs are replaced by
// the full scope rows and its evidence paths are made absolute, so renderers
// never read scope.csv or resolve paths.
type ReportFinding struct {
	ID       string            `json:"id"`
	Title    string            `json:"title"`
	Severity Severity          `json:"severity"`
	Scope    []ScopeRow        `json:"scope"`
	Sections map[string]string `json:"sections"` // markdown, keyed description, remediation, poc
	Assets   []string          `json:"assets"`   // absolute paths
	Target   *Target           `json:"target,omitzero"`

	// Extra holds the finding's unknown members.
	Extra map[string]jsontext.Value `json:",embed"`
}

// Target is the host, port and protocol a finding was actually found on.
// rpt scope match reads it to assign scope IDs and never rewrites it.
type Target struct {
	Host     string `json:"host"`
	Port     int    `json:"port,omitzero"`
	Protocol string `json:"protocol,omitzero"` // "tcp" or "udp"

	// Extra holds any unknown members.
	Extra map[string]jsontext.Value `json:",embed"`
}

// PluginInfo is a "plugin" record: one plugin rpt plugins found. Every
// member but Kind, Name and Path comes from the plugin's --describe answer,
// unknown ones in Extra, and is empty when it gave none in time.
type PluginInfo struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"` // the verb: the file name without "rpt-"
	Path    string `json:"path"` // absolute path of the program
	Summary string `json:"summary,omitzero"`
	Usage   string `json:"usage,omitzero"`
	Version string `json:"version,omitzero"`
	Input   string `json:"input,omitzero"`
	Output  string `json:"output,omitzero"`

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
