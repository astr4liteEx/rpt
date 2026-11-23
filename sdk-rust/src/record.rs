//! The record wire types. Each matches its schema in rpt's `schema/` folder: members the type
//! doesn't name ride in `extra`, so records pass through with fields this version doesn't
//! know. Decoding is lenient, as rpt's own is: a missing member takes its empty value.
//! Encoding leaves out empty optional members, always writes required ones, and writes the
//! record's kind when `kind` is empty, so `Finding { title, ..Default::default() }` is a whole
//! finding record.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::plugin::Description;

/// The record kinds rpt reads and writes. A plugin's own kinds are `x-<plugin>[-<name>]`.
pub mod kind {
    pub const FINDING: &str = "finding";
    pub const PAGE: &str = "page";
    pub const SCOPE: &str = "scope";
    pub const CONFIG: &str = "config";
    pub const EVIDENCE: &str = "evidence";
    pub const PROBLEM: &str = "problem";
    pub const REPORT: &str = "report";
    pub const LOCATION: &str = "location";
    pub const COMMAND: &str = "command";
    pub const VERSION: &str = "version";
}

/// The severity levels rpt knows by default. The order of levels is set by the report's
/// config.
pub mod severity {
    pub const CRITICAL: &str = "critical";
    pub const HIGH: &str = "high";
    pub const MEDIUM: &str = "medium";
    pub const LOW: &str = "low";
    pub const INFO: &str = "info";
}

/// The problem levels. An error makes `rpt validate` exit 1.
pub mod level {
    pub const ERROR: &str = "error";
    pub const WARNING: &str = "warning";
}

/// The sources of a reference to a file, [`Asset::source`].
pub mod source {
    /// The evidence list.
    pub const FRONTMATTER: &str = "frontmatter";
    /// A link in the text.
    pub const BODY: &str = "body";
}

/// One of this crate's record types.
pub trait Record {
    /// The kind it writes when its `kind` is empty.
    const KIND: &'static str;
}

fn write_kind<T: Record, S: Serializer>(k: &str, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(if k.is_empty() { T::KIND } else { k })
}

fn is_zero_u32(n: &u32) -> bool {
    *n == 0
}
fn is_zero_i64(n: &i64) -> bool {
    *n == 0
}
fn is_false(b: &bool) -> bool {
    !*b
}

/// A `finding` record: one finding, as `rpt finding get`, parser plugins and `rpt assemble`
/// give it. In an assembled report each target carries its scope row, links to files in the
/// report name them by absolute path, and `assets` is set.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Finding {
    #[serde(serialize_with = "write_kind::<Finding, _>")]
    pub kind: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub id: String,
    pub title: String,
    /// The scope rows it was found on.
    pub targets: Vec<Target>,
    pub severity: String,
    /// Relative to the report root.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub path: String,
    /// The file's revision; pass it back as `--if-rev`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub rev: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub sections: BTreeMap<String, String>,
    /// Relative to the finding file's folder.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    /// Set by `--lines`; `rpt finding add` ignores it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lines: Option<Lines>,
    /// The files the finding lists and links, set by `--assets` and by `rpt assemble`.
    /// `rpt finding add` reads each one's `ref` and `file`: it copies the file in and points
    /// `ref` at the copy.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub assets: Vec<Asset>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Record for Finding {
    const KIND: &'static str = kind::FINDING;
}

/// One place a finding was found on, attributed to a scope row. `scope` names the row's ID;
/// `host` is set only when the row is a range (a CIDR or `*.domain`) and says where inside it.
///
/// A parser plugin, which doesn't know the report's scope, sets `host` (and `port` and
/// `protocol`) and leaves `scope` empty; `rpt scope match` fills it. `rpt finding add` refuses
/// a target without one.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Target {
    /// A scope row's ID.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub scope: String,
    /// The row itself, in an assembled report.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub row: Option<Box<ScopeRow>>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub host: String,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub port: i64,
    /// `tcp` or `udp`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub protocol: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A `page` record: one page of report-level prose, such as an executive summary.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Page {
    #[serde(serialize_with = "write_kind::<Page, _>")]
    pub kind: String,
    pub id: String,
    pub title: String,
    /// Relative to the report root.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub path: String,
    /// Markdown; `##` headings in it are the page's own.
    pub body: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub rev: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lines: Option<Lines>,
    /// As for [`Finding::assets`].
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub assets: Vec<Asset>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Record for Page {
    const KIND: &'static str = kind::PAGE;
}

/// Where a record's parts sit in its file, as `--lines` gives them: 1-based lines of the file
/// as stored, so a checker can place a problem without parsing the file itself. Each record
/// sets the members that apply to it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Lines {
    /// The file's absolute path, symlinks kept.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub file: String,
    /// Frontmatter or `rpt.yaml` top-level keys.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub keys: BTreeMap<String, Position>,
    /// A finding's sections, keyed like [`Finding::sections`].
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub sections: BTreeMap<String, SectionLines>,
    /// The line a page's body starts on.
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub body: u32,
    /// The line a scope row starts on.
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub row: u32,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Where one section sits in a finding file. Line `text + n` is line n+1 of the section's text.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SectionLines {
    pub heading: u32,
    /// The text's first line; absent when the section is empty.
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub text: u32,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A place in a file: a 1-based line, and the 1-based byte in that line.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Position {
    pub line: u32,
    pub column: u32,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A `config` record: `rpt.yaml` as in effect, defaults filled in. Plugin sections
/// (`x-<plugin>`) are in `extra`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    #[serde(serialize_with = "write_kind::<Config, _>")]
    pub kind: String,
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub format: u32,
    /// Most severe first.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub severities: Vec<String>,
    /// Fixed section key to its heading.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub sections: BTreeMap<String, String>,
    /// Section keys, or a custom section's heading.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub required_sections: Vec<String>,
    /// Rule name to the level its problems take.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub rules: BTreeMap<String, String>,
    /// The pages' order: page IDs, and `findings` where the findings go. Pages it doesn't list
    /// come last, by ID.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pages: Vec<String>,
    /// Pages that must exist with a body.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub required_pages: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub rev: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lines: Option<Lines>,
    /// The `x-<plugin>` sections and any unknown members.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Record for Config {
    const KIND: &'static str = kind::CONFIG;
}

/// One file a finding or page lists in its evidence or links in its text.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Asset {
    /// As the owner writes it, relative to its file.
    #[serde(rename = "ref", skip_serializing_if = "String::is_empty")]
    pub reference: String,
    /// Relative to the report root; absent when `ref` leaves the report.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub path: String,
    /// Absolute, symlinks kept: the file to open or copy.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub file: String,
    /// [`source::FRONTMATTER`] or [`source::BODY`].
    #[serde(skip_serializing_if = "String::is_empty")]
    pub source: String,
    /// The file's type, from its extension, else its content.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub media_type: String,
    /// A link's text, its caption.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub text: String,
    /// The link is an image.
    #[serde(skip_serializing_if = "is_false")]
    pub image: bool,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// An `evidence` record `rpt evidence get` emits: one reference a finding or page makes to a
/// file, or with `--orphans` a file in an evidence folder nothing references (no owner, `ref`
/// or `source`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Evidence {
    #[serde(serialize_with = "write_kind::<Evidence, _>")]
    pub kind: String,
    /// The owner, when a finding.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub finding: String,
    /// The owner, when a page.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub page: String,
    pub exists: bool,
    /// The finding section a link is in.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub section: String,
    /// Where the reference is in the owner's file.
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub line: u32,
    /// The owner's rev.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub rev: String,
    /// The file referenced; its `extra` holds the record's unknown members.
    #[serde(flatten)]
    pub asset: Asset,
}

impl Record for Evidence {
    const KIND: &'static str = kind::EVIDENCE;
}

/// A `scope` record: one in-scope asset, a row of `scope.csv`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ScopeRow {
    #[serde(serialize_with = "write_kind::<ScopeRow, _>")]
    pub kind: String,
    pub id: String,
    pub host: String,
    /// Zero: every port.
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub port: i64,
    /// `tcp` or `udp`; empty: any.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub protocol: String,
    /// The row's revision, over the header and the row's own text.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub rev: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lines: Option<Lines>,
    /// The row's other columns and any unknown members.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Record for ScopeRow {
    const KIND: &'static str = kind::SCOPE;
}

/// A `problem` record: one broken rule that rpt or a checker plugin found.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Problem {
    #[serde(serialize_with = "write_kind::<Problem, _>")]
    pub kind: String,
    /// Relative to the report root; `-` for stdin.
    pub path: String,
    /// 1-based; zero when the problem has no line.
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub line: u32,
    /// 1-based byte in the line; only with `line`.
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub column: u32,
    pub rule: String,
    /// [`level::ERROR`] or [`level::WARNING`].
    pub level: String,
    pub message: String,
    /// The command that found it; never changed downstream.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub command: String,
    /// Replacements for the text the problem is about, best first.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub suggestions: Vec<String>,
    /// The 1-based byte, inclusive, the text the suggestions replace ends at.
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub end_column: u32,
    /// The rev of the file the problem is in, as read.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub rev: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Record for Problem {
    const KIND: &'static str = kind::PROBLEM;
}

impl Problem {
    /// Whether it is error-level: a writer or renderer reading it stops.
    pub fn is_error(&self) -> bool {
        self.level == level::ERROR
    }
}

/// The `report` record `rpt assemble` emits: the whole render-ready report, so renderers only
/// present it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Report {
    #[serde(serialize_with = "write_kind::<Report, _>")]
    pub kind: String,
    pub schema_version: u32,
    /// Most severe first.
    pub severities: Vec<String>,
    /// The finding sections in the order rpt writes them: the fixed ones with this report's
    /// headings, then the custom ones it requires. A finding's sections are keyed by `key`.
    pub sections: Vec<Section>,
    /// The report's parts in reading order: page IDs, and `findings` where the findings go.
    pub order: Vec<String>,
    /// Finding count per level.
    pub summary: BTreeMap<String, i64>,
    pub scope: Vec<ScopeRow>,
    /// By severity, then ID.
    pub findings: Vec<Finding>,
    /// In `order`.
    pub pages: Vec<Page>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Record for Report {
    const KIND: &'static str = kind::REPORT;
}

/// One finding section: the key a finding's sections use and the heading this report gives it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Section {
    pub key: String,
    pub heading: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A `location` record `rpt ls` emits: a report found. `format` and `findings` are `None`
/// when its config doesn't parse.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Location {
    #[serde(serialize_with = "write_kind::<Location, _>")]
    pub kind: String,
    /// Absolute.
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<u32>,
    /// Finding files that parse.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub findings: Option<u32>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Record for Location {
    const KIND: &'static str = kind::LOCATION;
}

/// A `command` record `rpt help` emits: something `rpt <name>` can run, a built-in or a plugin,
/// with what its `--describe` answer says.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Command {
    #[serde(serialize_with = "write_kind::<Command, _>")]
    pub kind: String,
    pub name: String,
    /// `builtin` or `plugin`.
    pub source: String,
    /// A plugin's absolute path.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub path: String,
    /// A plugin a built-in of the same name hides.
    #[serde(skip_serializing_if = "is_false")]
    pub shadowed: bool,
    /// A plugin whose `requires` this rpt doesn't fit.
    #[serde(skip_serializing_if = "is_false")]
    pub incompatible: bool,
    /// What its `--describe` says; its `extra` holds the record's unknown members.
    #[serde(flatten)]
    pub description: Description,
}

impl Record for Command {
    const KIND: &'static str = kind::COMMAND;
}

/// The `version` record `rpt version` emits.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Version {
    #[serde(serialize_with = "write_kind::<Version, _>")]
    pub kind: String,
    /// Release tag, module version, or `dev`.
    pub version: String,
    /// Record schemas this rpt writes.
    pub schema_version: u32,
    /// Report format this rpt reads.
    pub format: u32,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Record for Version {
    const KIND: &'static str = kind::VERSION;
}
