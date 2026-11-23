//! Changing one member of a record without re-encoding the rest.

use serde::Serialize;

use crate::call::Error;
use crate::json::check_object;

/// Returns the JSON object `raw` with its member `name` set to `value`. Every other member
/// keeps its original text and position; an existing member is replaced where it stands, a
/// new one is appended. Filters use it to change one field of a record without re-encoding
/// the rest.
///
/// ```
/// let got = rpt_sdk::set_member(r#"{"kind":"finding", "id":"F-001"}"#, "x-tag-label", &"triaged").unwrap();
/// assert_eq!(got, r#"{"kind":"finding","id":"F-001","x-tag-label":"triaged"}"#);
/// ```
pub fn set_member<T: Serialize + ?Sized>(raw: &str, name: &str, value: &T) -> Result<String, Error> {
    let invalid = |reason: String| Error::Invalid(format!("set {name:?}: {reason}"));
    check_object(raw).map_err(invalid)?;
    let member = format!("{}:{}", serde_json::to_string(name)?, serde_json::to_string(value)?);

    let mut scan = Scanner { s: raw.as_bytes(), pos: 0 };
    scan.ws();
    scan.pos += 1; // the {
    let mut members: Vec<String> = vec![];
    let mut found = false;
    loop {
        scan.ws();
        if scan.peek() == b'}' {
            break;
        }
        let key = scan.string();
        scan.ws();
        scan.pos += 1; // the :
        scan.ws();
        let val = scan.value();
        let decoded: String = serde_json::from_str(&raw[key.clone()])?;
        if decoded == name && !found {
            found = true;
            members.push(member.clone());
        } else {
            members.push(format!("{}:{}", &raw[key], &raw[val]));
        }
        scan.ws();
        if scan.peek() == b',' {
            scan.pos += 1;
        }
    }
    if !found {
        members.push(member);
    }
    Ok(format!("{{{}}}", members.join(",")))
}

/// Walks JSON already checked to be valid, returning the spans of strings and values.
struct Scanner<'a> {
    s: &'a [u8],
    pos: usize,
}

impl Scanner<'_> {
    fn peek(&self) -> u8 {
        self.s[self.pos]
    }

    fn ws(&mut self) {
        while self.pos < self.s.len() && matches!(self.s[self.pos], b' ' | b'\t' | b'\n' | b'\r') {
            self.pos += 1;
        }
    }

    /// The string starting here, quotes included.
    fn string(&mut self) -> std::ops::Range<usize> {
        let start = self.pos;
        self.pos += 1;
        loop {
            match self.s[self.pos] {
                b'\\' => self.pos += 2,
                b'"' => {
                    self.pos += 1;
                    return start..self.pos;
                }
                _ => self.pos += 1,
            }
        }
    }

    /// The value starting here.
    fn value(&mut self) -> std::ops::Range<usize> {
        let start = self.pos;
        match self.peek() {
            b'"' => {
                self.string();
            }
            b'{' | b'[' => {
                let mut depth = 0usize;
                loop {
                    match self.peek() {
                        b'"' => {
                            self.string();
                            continue;
                        }
                        b'{' | b'[' => depth += 1,
                        b'}' | b']' => depth -= 1,
                        _ => {}
                    }
                    self.pos += 1;
                    if depth == 0 {
                        break;
                    }
                }
            }
            _ => {
                while !matches!(self.peek(), b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r') {
                    self.pos += 1;
                }
            }
        }
        start..self.pos
    }
}
