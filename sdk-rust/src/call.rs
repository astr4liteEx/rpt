//! Calling back into rpt, reading settings, and writing records.

use std::ffi::OsString;
use std::fmt;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::plugin::bin;
use crate::record::Problem;
use crate::stream::{Rec, records};

/// What goes wrong outside reading a stream.
#[derive(Debug)]
pub enum Error {
    /// rpt couldn't be started, or a stream couldn't be read or written.
    Io(io::Error),
    /// A value couldn't be encoded or decoded.
    Json(serde_json::Error),
    /// Input that isn't what it must be, such as `set_member` given something other than one
    /// JSON object.
    Invalid(String),
    /// rpt printed something that isn't records.
    BadOutput { command: String, reason: String },
    /// rpt ran longer than its [`Call::timeout`] and was killed.
    TimedOut { command: String },
    /// The plugin's settings couldn't be read.
    Settings(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Io(e) => e.fmt(f),
            Error::Json(e) => e.fmt(f),
            Error::Invalid(m) => f.write_str(m),
            Error::BadOutput { command, reason } => write!(f, "rpt {command}: {reason}"),
            Error::TimedOut { command } => write!(f, "rpt {command}: took too long and was stopped"),
            Error::Settings(m) => write!(f, "settings: {m}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Json(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e)
    }
}

/// Writes `v` as one record: one JSON line. This crate's record types write their kind when
/// `kind` is empty.
pub fn emit<W: Write + ?Sized, T: Serialize + ?Sized>(w: &mut W, v: &T) -> Result<(), Error> {
    let mut line = serde_json::to_vec(v)?;
    line.push(b'\n');
    w.write_all(&line)?;
    Ok(())
}

/// What one rpt command printed and how it exited.
#[derive(Debug, Clone, Default)]
pub struct Output {
    /// stdout, record by record.
    pub records: Vec<Rec>,
    /// The exit code: 0 ok, 1 problems, 2 usage, 3 couldn't do its work; -1 for a signal. From
    /// one of rpt's own write commands, 3 means a file changed while it wrote and nothing was
    /// written, so running it again is safe; from a plugin, 3 means its work failed, perhaps
    /// partway, so it isn't. [`Call`] never retries: only the caller knows which it ran.
    pub code: i32,
    /// The text rpt wrote for people.
    pub stderr: String,
}

impl Output {
    /// The problem records among the records.
    pub fn problems(&self) -> Vec<Problem> {
        self.records.iter().filter(|r| r.kind == "problem").filter_map(|r| serde_json::from_str(&r.raw).ok()).collect()
    }

    /// Whether a write was refused because something changed since it was read (rule `rev`):
    /// read again and decide again. rpt never retries on its own.
    pub fn stale(&self) -> bool {
        self.problems().iter().any(|p| p.rule == "rev")
    }
}

/// How long [`Call`] keeps reading rpt's output after rpt has exited, while something rpt
/// started holds the pipes open.
const WAIT_DELAY: Duration = Duration::from_secs(1);

/// One rpt command to run, through [`bin`]:
///
/// ```no_run
/// let out = rpt_sdk::Call::new(["finding", "get", "F-001"]).run()?;
/// # Ok::<(), rpt_sdk::Error>(())
/// ```
///
/// A command that runs and exits non-zero is an [`Output`] with that code, not an error: the
/// error is for an rpt that couldn't be started, one that ran past its timeout, or output that
/// isn't records.
///
/// A program that runs rpt itself rather than being started by it (an editor, a TUI, CI
/// tooling) says how with [`bin`](Call::bin), [`current_dir`](Call::current_dir),
/// [`env`](Call::env), [`env_remove`](Call::env_remove) and
/// [`process_group`](Call::process_group):
///
/// ```no_run
/// # use std::time::Duration;
/// let out = rpt_sdk::Call::new(["validate", "--records"])
///     .bin("/usr/local/bin/rpt")
///     .current_dir("/work/acme-report")
///     .env_remove("RPT_REPORT_DIR")
///     .process_group()
///     .timeout(Duration::from_secs(30))
///     .run()?;
/// # Ok::<(), rpt_sdk::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct Call {
    args: Vec<OsString>,
    stdin: Option<Vec<u8>>,
    timeout: Option<Duration>,
    bin: Option<OsString>,
    dir: Option<PathBuf>,
    env: Vec<(OsString, Option<OsString>)>,
    group: bool,
}

impl Call {
    pub fn new<I, S>(args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        Call {
            args: args.into_iter().map(Into::into).collect(),
            stdin: None,
            timeout: None,
            bin: None,
            dir: None,
            env: vec![],
            group: false,
        }
    }

    /// What rpt reads on stdin, such as records for `finding add`. Without it, stdin is empty.
    pub fn stdin(mut self, input: impl Into<Vec<u8>>) -> Self {
        self.stdin = Some(input.into());
        self
    }

    /// Kills rpt if it runs longer than `timeout`, so a plugin's waits end on their own. Without
    /// [`process_group`](Call::process_group) it kills rpt alone.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// The rpt to run. Without it, [`bin`](crate::bin).
    pub fn bin(mut self, bin: impl Into<OsString>) -> Self {
        self.bin = Some(bin.into());
        self
    }

    /// The folder to run rpt in. Without it, this process's.
    pub fn current_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.dir = Some(dir.into());
        self
    }

    /// Sets a variable in rpt's environment, which is otherwise this process's.
    pub fn env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.env.push((key.into(), Some(value.into())));
        self
    }

    /// Takes a variable out of rpt's environment.
    pub fn env_remove(mut self, key: impl Into<OsString>) -> Self {
        self.env.push((key.into(), None));
        self
    }

    /// Starts rpt in a process group of its own, and at the timeout kills the whole group: rpt,
    /// the plugin it became, and what that started, which would otherwise outlive the call. The
    /// group is out of the terminal's reach, so Ctrl-C no longer stops it: use it in a program
    /// that handles keys itself, not in a plugin, whose rpt must stop when the user stops the
    /// pipeline. Unix only; elsewhere it does nothing.
    pub fn process_group(mut self) -> Self {
        self.group = true;
        self
    }

    pub fn run(self) -> Result<Output, Error> {
        let command = self.args.iter().map(|a| a.to_string_lossy()).collect::<Vec<_>>().join(" ");
        let mut cmd = Command::new(self.bin.unwrap_or_else(bin));
        cmd.args(&self.args)
            .stdin(if self.stdin.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(dir) = &self.dir {
            cmd.current_dir(dir);
        }
        for (key, value) in &self.env {
            match value {
                Some(v) => cmd.env(key, v),
                None => cmd.env_remove(key),
            };
        }
        if self.group {
            group::start(&mut cmd);
        }
        let mut child = cmd.spawn()?;
        if let (Some(input), Some(mut pipe)) = (self.stdin, child.stdin.take()) {
            // A broken pipe means rpt stopped reading; its exit code says why.
            thread::spawn(move || pipe.write_all(&input));
        }
        let stdout = read_chunks(child.stdout.take());
        let stderr = read_chunks(child.stderr.take());
        let deadline = self.timeout.map(|t| Instant::now() + t);
        let group = self.group;
        let timed_out = |child: &mut Child| {
            if group {
                group::kill(child);
            } else {
                let _ = child.kill();
            }
            let _ = child.wait();
            Error::TimedOut { command: command.clone() }
        };
        let status = match deadline {
            None => child.wait()?,
            Some(deadline) => loop {
                match child.try_wait()? {
                    Some(status) => break status,
                    None if Instant::now() >= deadline => return Err(timed_out(&mut child)),
                    None => thread::sleep(Duration::from_millis(5)),
                }
            },
        };
        // Something rpt started may hold the pipes open after rpt exits. Read until they close,
        // for WAIT_DELAY at most, or until the deadline when that comes first.
        let delay = Instant::now() + WAIT_DELAY;
        let limit = deadline.map_or(delay, |d| d.min(delay));
        let (out, out_closed) = collect(&stdout, limit);
        let (err, err_closed) = collect(&stderr, limit);
        if !(out_closed && err_closed) && deadline.is_some_and(|d| d <= limit) {
            return Err(timed_out(&mut child));
        }
        let mut output =
            Output { records: vec![], code: status.code().unwrap_or(-1), stderr: String::from_utf8_lossy(&err).into() };
        for rec in records(&out[..]) {
            match rec {
                Ok(rec) => output.records.push(rec),
                Err(e) => return Err(Error::BadOutput { command, reason: e.to_string() }),
            }
        }
        Ok(output)
    }
}

/// Reads a pipe on a thread, sending what it reads as it comes; the channel closes at the end.
fn read_chunks(pipe: Option<impl Read + Send + 'static>) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    if let Some(mut pipe) = pipe {
        thread::spawn(move || {
            let mut buf = vec![0; 64 << 10];
            loop {
                match pipe.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if tx.send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
        });
    }
    rx
}

/// What a pipe gave until it closed or `limit` came, and whether it closed.
fn collect(rx: &mpsc::Receiver<Vec<u8>>, limit: Instant) -> (Vec<u8>, bool) {
    let mut out = vec![];
    loop {
        match rx.recv_timeout(limit.saturating_duration_since(Instant::now())) {
            Ok(chunk) => out.extend(chunk),
            Err(mpsc::RecvTimeoutError::Disconnected) => return (out, true),
            Err(mpsc::RecvTimeoutError::Timeout) => return (out, false),
        }
    }
}

/// rpt in a process group of its own, on Unix.
#[cfg(unix)]
mod group {
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command};

    pub(super) fn start(cmd: &mut Command) {
        cmd.process_group(0);
    }

    /// Kills the whole group, which outlives rpt itself while anything in it runs.
    pub(super) fn kill(child: &mut Child) {
        if let Ok(pgid) = i32::try_from(child.id()) {
            // SAFETY: killpg only sends a signal; the group is the one rpt leads.
            unsafe { libc::killpg(pgid, libc::SIGKILL) };
        }
    }
}

#[cfg(not(unix))]
mod group {
    use std::process::{Child, Command};

    pub(super) fn start(_: &mut Command) {}

    pub(super) fn kill(child: &mut Child) {
        let _ = child.kill();
    }
}

/// The plugin's settings over `defaults`: the user's `~/.config/rpt/plugins/<plugin>/config.yaml`
/// with the report's `x-<plugin>` section of `rpt.yaml` laid over it, as `rpt config get
/// --merged` gives them, laid over `defaults` the same way (objects merge member by member;
/// lists and plain values are replaced). Members neither sets keep their defaults; parse flags
/// after, so they win. `plugin` is the command name, as in `rpt <plugin>`.
pub fn settings<T: Serialize + DeserializeOwned>(plugin: &str, defaults: T) -> Result<T, Error> {
    let member = format!("x-{plugin}");
    let out = Call::new(["config", "get", "--merged", "--json", &member]).run()?;
    if out.code != 0 {
        let why = match out.problems().into_iter().next() {
            Some(p) => p.message,
            None => format!("rpt config get exited {}: {}", out.code, out.stderr.trim()),
        };
        return Err(Error::Settings(why));
    }
    let Some(config) = out.records.iter().find(|r| r.kind == "config") else {
        return Ok(defaults);
    };
    let mut config: serde_json::Map<String, Value> = serde_json::from_str(&config.raw)?;
    match config.remove(&member) {
        None | Some(Value::Null) => Ok(defaults), // nothing set: the defaults stand
        Some(set) => {
            let mut merged = serde_json::to_value(defaults)?;
            merge(&mut merged, set);
            serde_json::from_value(merged).map_err(|e| Error::Settings(format!("{member}: {e}")))
        }
    }
}

/// Lays `over` on `base`: objects merge member by member, anything else is replaced.
fn merge(base: &mut Value, over: Value) {
    match (base, over) {
        (Value::Object(base), Value::Object(over)) => {
            for (k, v) in over {
                match base.get_mut(&k) {
                    Some(b) => merge(b, v),
                    None => {
                        base.insert(k, v);
                    }
                }
            }
        }
        (base, over) => *base = over,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn merge_lays_objects_over_and_replaces_the_rest() {
        let mut base = json!({"label": "triaged", "words": ["a"], "deep": {"x": 1, "y": 2}});
        merge(&mut base, json!({"words": ["b"], "deep": {"y": 3}, "new": true}));
        assert_eq!(base, json!({"label": "triaged", "words": ["b"], "deep": {"x": 1, "y": 3}, "new": true}));
    }
}
