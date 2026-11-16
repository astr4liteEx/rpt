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
	Port int    `json:"port,omitzero"` // absent for a host or range without a port

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

// ReportMeta describes the engagement, from the report's config.
type ReportMeta struct {
	Name   string `json:"name"`
	Client string `json:"client"`
	Period Period `json:"period"`

	// Extra holds any other config keys.
	Extra map[string]jsontext.Value `json:",embed"`
}

// Period is the engagement's date range, as ISO 8601 dates.
type Period struct {
	Start string `json:"start"`
	End   string `json:"end"`

	// Extra holds any unknown members.
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

	// Extra holds the finding's unknown members.
	Extra map[string]jsontext.Value `json:",embed"`
}
