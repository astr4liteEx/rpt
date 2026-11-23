//! The plugin entry points and the `--describe` answer.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{self, BufRead, Write};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// What a plugin prints for `--describe`: one JSON object on one line. `rpt help` shows it;
/// the plugin's name comes from its file name (`rpt-parse-nuclei` is the command
/// `parse-nuclei`), not from here. Every built-in answers `--describe` the same way.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Description {
    /// One line: what the plugin does.
    pub summary: String,
    /// One line, e.g. `rpt parse-nuclei < results.jsonl`; name the plugin's flags.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub usage: String,
    /// The plugin's own version.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version: String,
    /// The data the plugin takes: `records` for an rpt JSON Lines stream, otherwise
    /// `<format>` or `<format>/<tool>`, such as `xml/nessus`. Empty is "not said".
    #[serde(skip_serializing_if = "String::is_empty")]
    pub input: String,
    /// The data the plugin gives, named as for `input`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub output: String,
    /// What the plugin is, from [`role`], so a tool on top of rpt can find, say, every
    /// checker. A plugin can hold several; empty is "not said".
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    /// JSON Schemas (draft 2020-12) for the `x-` names the plugin owns, which `rpt validate`
    /// checks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schemas: Option<Schemas>,
    /// Which rpt the plugin works with.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires: Option<Requires>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The JSON Schemas a plugin declares for what it owns, by noun. A plugin named `<command>`
/// owns `x-<command>` (its config section) and the names starting `x-<command>-` (keys,
/// columns and record kinds); a schema for any other name is ignored. A `$ref` may point inside
/// the schema or at one of rpt's schemas by its `$id`, nowhere else.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Schemas {
    /// Each frontmatter key the plugin owns, to a schema for its value.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub finding: BTreeMap<String, Value>,
    /// As for `finding`, for pages.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub page: BTreeMap<String, Value>,
    /// Each scope column the plugin owns; a scope value is the CSV text.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub scope: BTreeMap<String, Value>,
    /// The schema for the plugin's whole `x-<command>` section of `rpt.yaml`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<Value>,
    /// Each `x-` record kind, to a schema for the whole record.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub kinds: BTreeMap<String, Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The rpt versions a plugin works with, each as a range. A range left out fits any version.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Requires {
    /// Record schemas, [`crate::Version::schema_version`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<Range>,
    /// Report format, [`crate::Version::format`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<Range>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Requires {
    /// Whether a plugin requiring this works with an rpt writing `schema_version` and reading
    /// `format`.
    pub fn fits(&self, schema_version: u32, format: u32) -> bool {
        self.schema_version.as_ref().is_none_or(|r| r.has(schema_version))
            && self.format.as_ref().is_none_or(|r| r.has(format))
    }
}

/// The versions from `min` to `max`, both included. A bound left zero is open, so
/// `Range { min: 2, ..Default::default() }` fits 2 and every later version.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Range {
    #[serde(skip_serializing_if = "is_zero")]
    pub min: u32,
    #[serde(skip_serializing_if = "is_zero")]
    pub max: u32,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

impl Range {
    /// Whether `v` is in the range.
    pub fn has(&self, v: u32) -> bool {
        (self.min == 0 || v >= self.min) && (self.max == 0 || v <= self.max)
    }
}

impl fmt::Display for Range {
    /// The range for people: `2`, `2 to 3`, `2 or later`, `up to 1`, or `any`.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match (self.min, self.max) {
            (0, 0) => f.write_str("any"),
            (min, 0) => write!(f, "{min} or later"),
            (0, max) => write!(f, "up to {max}"),
            (min, max) if min == max => write!(f, "{min}"),
            (min, max) => write!(f, "{min} to {max}"),
        }
    }
}

/// The roles a plugin can declare in [`Description::roles`]. Each is a promise the protocol's
/// `--describe` section spells out.
pub mod role {
    /// Emits problem records about the report, exits 1 only when one is an error, and never
    /// changes the report.
    pub const CHECKER: &str = "checker";
    /// Reads records on stdin and writes records on stdout.
    pub const FILTER: &str = "filter";
    /// Changes the report, only through `$RPT_BIN` write commands.
    pub const WRITER: &str = "writer";
    /// Reads a report record and writes a document to a place it's given (a file or folder
    /// flag); never changes the report and writes no records to stdout.
    pub const RENDERER: &str = "renderer";
}

type RunFn = dyn Fn(&[OsString], &mut dyn BufRead, &mut dyn Write, &mut dyn Write) -> i32;
type CompleteFn = dyn Fn(&[String], &str) -> Vec<String>;

/// A plugin program: its description and the function that does its work.
pub struct Plugin {
    pub description: Description,
    run: Box<RunFn>,
    complete: Option<Box<CompleteFn>>,
}

impl Plugin {
    /// A plugin whose work is `run`. It gets the arguments after the command, byte for byte,
    /// and its streams, and returns the exit code: 0 success, 1 problems in the input, 2 usage,
    /// 3 the plugin couldn't do its work.
    pub fn new(
        description: Description,
        run: impl Fn(&[OsString], &mut dyn BufRead, &mut dyn Write, &mut dyn Write) -> i32 + 'static,
    ) -> Self {
        Plugin { description, run: Box::new(run), complete: None }
    }

    /// Gives shell completion its candidates: `complete(args, word)` returns the candidates
    /// for `word`, the word being typed after `args`, each `value` or `value\tdescription`.
    /// Without it, the shell completes file names.
    pub fn complete(mut self, complete: impl Fn(&[String], &str) -> Vec<String> + 'static) -> Self {
        self.complete = Some(Box::new(complete));
        self
    }
}

/// Shell completion directives, as cobra's `__complete` protocol ends its answer with
/// `:<directive>`.
const COMPLETE_DEFAULT: u8 = 0; // the shell may fall back to file names
const COMPLETE_NO_FILES: u8 = 4; // only the candidates given

/// Runs a plugin. It answers these itself, doing no work:
/// - a lone `--describe`: the description, one JSON line;
/// - a lone `--help` or `-h`: the usage and summary;
/// - `__complete <args...> <word>`: shell completion, from [`Plugin::complete`].
///
/// Anything else goes to the plugin's own function. It never exits and never touches the
/// process's streams, so plugin tests call it directly.
pub fn run(
    p: &Plugin,
    args: &[OsString],
    stdin: &mut dyn BufRead,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let alone = |flag: &str| args.len() == 1 && args[0] == OsStr::new(flag);
    if alone("--help") || alone("-h") {
        let d = &p.description;
        let _ = if d.usage.is_empty() {
            writeln!(stdout, "{}", d.summary)
        } else {
            writeln!(stdout, "Usage: {}\n\n{}", d.usage, d.summary)
        };
        let _ = stdout.flush();
        return 0;
    }
    if let Some(first) = args.first().filter(|a| *a == "__complete" || *a == "__completeNoDesc") {
        let mut rest: Vec<String> = args[1..].iter().map(|a| a.to_string_lossy().into_owned()).collect();
        let word = rest.pop().unwrap_or_default();
        let mut out = String::new();
        let mut directive = COMPLETE_DEFAULT;
        if let Some(complete) = &p.complete {
            for c in complete(&rest, &word) {
                let c = if first == "__completeNoDesc" { c.split('\t').next().unwrap_or("") } else { &c };
                out.push_str(c);
                out.push('\n');
            }
            directive = COMPLETE_NO_FILES;
        }
        let _ = writeln!(stdout, "{out}:{directive}").and_then(|_| stdout.flush());
        return 0;
    }
    if alone("--describe") {
        let written = serde_json::to_vec(&p.description)
            .map_err(io::Error::from)
            .and_then(|mut line| {
                line.push(b'\n');
                stdout.write_all(&line)
            })
            .and_then(|_| stdout.flush());
        if let Err(e) = written {
            let _ = writeln!(stderr, "describe: {e}");
            return 1;
        }
        return 0;
    }
    (p.run)(args, stdin, stdout, stderr)
}

/// The whole of a plugin's `main` function:
///
/// ```no_run
/// # let plugin = rpt_sdk::Plugin::new(Default::default(), |_, _, _, _| 0);
/// rpt_sdk::main(plugin)
/// ```
///
/// It calls [`run`] with the process's arguments and streams, flushes stdout, and exits with
/// the code it returns. Exiting skips destructors still on `main`'s stack, so do cleanup in the
/// plugin's own function.
pub fn main(p: Plugin) -> ! {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    let mut code = run(&p, &args, &mut stdin, &mut stdout, &mut stderr);
    if stdout.flush().is_err() && code == 0 {
        code = 1;
    }
    std::process::exit(code)
}

/// The rpt to call back into: `$RPT_BIN` when rpt started the plugin, so it gets the same rpt
/// version, otherwise `rpt` from `PATH`. A plugin never requires being started by rpt.
pub fn bin() -> OsString {
    match std::env::var_os("RPT_BIN") {
        Some(b) if !b.is_empty() => b,
        _ => OsString::from("rpt"),
    }
}
