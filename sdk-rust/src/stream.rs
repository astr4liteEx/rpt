//! Reading a JSON Lines stream of records.

use std::fmt;
use std::io::{self, BufRead};

use crate::json::{Head, check_object};

/// The longest JSON Lines record rpt reads, in bytes.
pub const MAX_LINE: usize = 16 << 20;

/// One record read from a JSON Lines stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rec {
    /// The record's `kind`, or `""` when it has none.
    pub kind: String,
    /// The line exactly as received, without its line ending.
    pub raw: String,
    /// 1-based line number in the stream.
    pub line: usize,
}

/// A line that is not a record: invalid JSON, JSON that is not an object, or a line longer
/// than [`MAX_LINE`]. [`Records`] keeps reading after one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineError {
    pub line: usize,
    /// What is wrong, e.g. `not a record: null`.
    pub reason: String,
}

impl fmt::Display for LineError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.reason)
    }
}

impl std::error::Error for LineError {}

/// What [`Records`] yields instead of a record.
#[derive(Debug)]
pub enum ReadError {
    /// A line that is not a record; reading goes on.
    Line(LineError),
    /// The error-level problem record reading stopped at, given [`Records::stop_at_error`].
    /// Nothing comes after it: pass it on, write nothing of your own, and exit 1.
    Stopped(Rec),
    /// The stream couldn't be read; nothing comes after it.
    Io(io::Error),
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ReadError::Line(e) => e.fmt(f),
            ReadError::Stopped(rec) => write!(f, "line {}: stopped at an error-level problem", rec.line),
            ReadError::Io(e) => write!(f, "read records: {e}"),
        }
    }
}

impl std::error::Error for ReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ReadError::Line(e) => Some(e),
            ReadError::Io(e) => Some(e),
            ReadError::Stopped(_) => None,
        }
    }
}

/// Reads a JSON Lines stream. It yields each record with its original text, so filters can
/// pass through records they don't own byte for byte. Blank lines are skipped; lines may end
/// in `\n` or `\r\n`, and the last line needs no newline. A line that isn't a record yields
/// [`ReadError::Line`] and reading continues; a read error is yielded last.
pub fn records<R: BufRead>(reader: R) -> Records<R> {
    Records { reader, line: 0, stop: false, done: false, buf: Vec::new() }
}

/// The iterator [`records`] returns.
pub struct Records<R> {
    reader: R,
    line: usize,
    stop: bool,
    done: bool,
    buf: Vec<u8>,
}

impl<R> Records<R> {
    /// Stops at the first error-level problem record: it comes as [`ReadError::Stopped`], and
    /// nothing after it. A writer or renderer reads this way, since it must not act on a
    /// stream an earlier stage found broken. Filters and checkers read on and pass problems
    /// through.
    pub fn stop_at_error(mut self) -> Self {
        self.stop = true;
        self
    }
}

enum Line {
    /// A line, in the buffer, its ending removed; `last` when the stream ended after it.
    Text {
        last: bool,
    },
    TooLong {
        last: bool,
    },
    End,
}

impl<R: BufRead> Records<R> {
    /// Reads the next line into `buf`. A line over [`MAX_LINE`] is discarded up to its newline.
    fn read_line(&mut self) -> io::Result<Line> {
        self.buf.clear();
        let mut too_long = false;
        let mut any = false;
        loop {
            let chunk = match self.reader.fill_buf() {
                Ok(c) => c,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            if chunk.is_empty() {
                if !any {
                    return Ok(Line::End);
                }
                return Ok(self.finish(too_long, true));
            }
            any = true;
            let (part, newline) = match chunk.iter().position(|&b| b == b'\n') {
                Some(i) => (&chunk[..=i], true),
                None => (chunk, false),
            };
            let n = part.len();
            if !too_long {
                if self.buf.len() + n > MAX_LINE + 2 {
                    // +2 for a \r\n ending
                    too_long = true;
                    self.buf = Vec::new();
                } else {
                    self.buf.extend_from_slice(part);
                }
            }
            self.reader.consume(n);
            if newline {
                return Ok(self.finish(too_long, false));
            }
        }
    }

    fn finish(&mut self, too_long: bool, last: bool) -> Line {
        if too_long {
            return Line::TooLong { last };
        }
        if self.buf.last() == Some(&b'\n') {
            self.buf.pop();
        }
        if self.buf.last() == Some(&b'\r') {
            self.buf.pop();
        }
        if self.buf.len() > MAX_LINE { Line::TooLong { last } } else { Line::Text { last } }
    }
}

impl<R: BufRead> Iterator for Records<R> {
    type Item = Result<Rec, ReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.done {
            self.line += 1;
            let line = self.line;
            let read = match self.read_line() {
                Ok(r) => r,
                Err(e) => {
                    self.done = true;
                    return Some(Err(ReadError::Io(e)));
                }
            };
            match read {
                Line::End => self.done = true,
                Line::TooLong { last } => {
                    self.done = last;
                    let reason = format!("line longer than {MAX_LINE} bytes");
                    return Some(Err(ReadError::Line(LineError { line, reason })));
                }
                Line::Text { last } => {
                    self.done = last;
                    if self.buf.iter().all(u8::is_ascii_whitespace) {
                        continue;
                    }
                    let rec = match parse(&self.buf, line) {
                        Ok((rec, true)) if self.stop => {
                            self.done = true;
                            return Some(Err(ReadError::Stopped(rec)));
                        }
                        Ok((rec, _)) => Ok(rec),
                        Err(e) => Err(ReadError::Line(e)),
                    };
                    return Some(rec);
                }
            }
        }
        None
    }
}

/// Checks that a line is a JSON object and reads its kind; true when it is an error-level
/// problem.
fn parse(bytes: &[u8], line: usize) -> Result<(Rec, bool), LineError> {
    let bad = |reason: String| LineError { line, reason: format!("not a record: {reason}") };
    let text = std::str::from_utf8(bytes).map_err(|e| bad(e.to_string()))?;
    check_object(text).map_err(bad)?;
    let head: Head = serde_json::from_str(text).map_err(|e| bad(e.to_string()))?;
    let error = head.kind() == "problem" && head.level() == "error";
    Ok((Rec { kind: head.kind().to_string(), raw: text.to_string(), line }, error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_lines() {
        let mib = format!(r#"{{"kind":"finding","title":"{}"}}"#, "a".repeat(1 << 20));
        let huge = format!(r#"{{"kind":"finding","title":"{}"}}"#, "b".repeat(MAX_LINE));
        let input = format!("{mib}\n{huge}\n{{\"kind\":\"scope\"}}\n{huge}");
        let got: Vec<_> = records(input.as_bytes()).collect();
        assert_eq!(got.len(), 4);
        assert!(matches!(&got[0], Ok(r) if r.kind == "finding" && r.raw.len() == mib.len()));
        assert!(matches!(&got[1], Err(ReadError::Line(e)) if e.line == 2 && e.reason.starts_with("line longer")));
        assert!(matches!(&got[2], Ok(r) if r.kind == "scope" && r.line == 3));
        assert!(matches!(&got[3], Err(ReadError::Line(e)) if e.line == 4));
    }

    #[test]
    fn a_line_of_exactly_max_line_is_read() {
        let pad = MAX_LINE - r#"{"t":""}"#.len();
        let line = format!(r#"{{"t":"{}"}}"#, "c".repeat(pad));
        assert_eq!(line.len(), MAX_LINE);
        let got: Vec<_> = records(format!("{line}\r\n").as_bytes()).collect();
        assert!(matches!(&got[..], [Ok(r)] if r.raw.len() == MAX_LINE));
    }

    #[test]
    fn line_errors_say_what_is_wrong() {
        for (input, want) in [("null", "not a record: null"), ("[1]", "not a record: not a JSON object")] {
            match records(input.as_bytes()).next() {
                Some(Err(ReadError::Line(e))) => assert_eq!(e.reason, want),
                other => panic!("{input}: {other:?}"),
            }
        }
        match records(&b"{\"a\":\xff}"[..]).next() {
            Some(Err(ReadError::Line(e))) => assert!(e.reason.starts_with("not a record: invalid utf-8"), "{e}"),
            other => panic!("{other:?}"),
        }
    }

    struct Failing;
    impl io::Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("boom"))
        }
    }

    #[test]
    fn a_read_error_comes_last() {
        let got: Vec<_> = records(io::BufReader::new(Failing)).collect();
        assert!(matches!(&got[..], [Err(ReadError::Io(_))]));
    }
}
