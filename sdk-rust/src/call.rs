//! Calling back into rpt, reading settings, and writing records.

use std::ffi::OsString;
use std::fmt;
use std::io::{self, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::plugin::bin;
use crate::record::Problem;
use crate::stream::{ReadError, Rec, records};

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
    /// The exit code: 0 ok, 1 problems, 2 usage, 3 couldn't do its work; -1 for a signal.
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
#[derive(Debug, Clone)]
pub struct Call {
    args: Vec<OsString>,
    stdin: Option<Vec<u8>>,
    timeout: Option<Duration>,
}

impl Call {
    pub fn new<I, S>(args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        Call { args: args.into_iter().map(Into::into).collect(), stdin: None, timeout: None }
    }

    /// What rpt reads on stdin, such as records for `finding add`. Without it, stdin is empty.
    pub fn stdin(mut self, input: impl Into<Vec<u8>>) -> Self {
        self.stdin = Some(input.into());
        self
    }

    /// Kills rpt if it runs longer than `timeout`, so a plugin's waits end on their own.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn run(self) -> Result<Output, Error> {
        let command = self.args.iter().map(|a| a.to_string_lossy()).collect::<Vec<_>>().join(" ");
        let mut child = Command::new(bin())
            .args(&self.args)
            .stdin(if self.stdin.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let (Some(input), Some(mut pipe)) = (self.stdin, child.stdin.take()) {
            // A broken pipe means rpt stopped reading; its exit code says why.
            thread::spawn(move || pipe.write_all(&input));
        }
        let stdout = read_all(child.stdout.take());
        let stderr = read_all(child.stderr.take());
        let deadline = self.timeout.map(|t| Instant::now() + t);
        let timed_out = |child: &mut Child| {
            let _ = child.kill();
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
        // Something rpt started may hold a pipe open after it exits; the deadline covers that.
        let recv = |rx: mpsc::Receiver<io::Result<Vec<u8>>>| match deadline {
            None => rx.recv().unwrap_or_else(|_| Ok(vec![])),
            Some(d) => rx
                .recv_timeout(d.saturating_duration_since(Instant::now()))
                .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "output still open at the deadline"))),
        };
        let out = recv(stdout).map_err(|_| Error::TimedOut { command: command.clone() })?;
        let err = recv(stderr).map_err(|_| Error::TimedOut { command: command.clone() })?;
        let mut output =
            Output { records: vec![], code: status.code().unwrap_or(-1), stderr: String::from_utf8_lossy(&err).into() };
        for rec in records(&out[..]) {
            match rec {
                Ok(rec) => output.records.push(rec),
                Err(ReadError::Line(e)) => return Err(Error::BadOutput { command, reason: e.to_string() }),
                Err(e) => return Err(Error::BadOutput { command, reason: e.to_string() }),
            }
        }
        Ok(output)
    }
}

fn read_all(pipe: Option<impl Read + Send + 'static>) -> mpsc::Receiver<io::Result<Vec<u8>>> {
    let (tx, rx) = mpsc::channel();
    if let Some(mut pipe) = pipe {
        thread::spawn(move || {
            let mut buf = vec![];
            let _ = tx.send(pipe.read_to_end(&mut buf).map(|_| buf));
        });
    }
    rx
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
