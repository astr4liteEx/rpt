//! The conformance cases in ../testdata/sdk, shared by every SDK; see the README there.

use std::cell::RefCell;
use std::ffi::OsString;
use std::path::Path;
use std::rc::Rc;

use rpt_sdk::*;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

/// The cases in `file`, or `None` outside the rpt repository.
fn cases(file: &str) -> Option<Value> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/sdk").join(file);
    match std::fs::read_to_string(&path) {
        Ok(text) => Some(serde_json::from_str(&text).unwrap_or_else(|e| panic!("{file}: {e}"))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipped: needs the rpt repository's testdata/sdk folder");
            None
        }
        Err(e) => panic!("{file}: {e}"),
    }
}

fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or_else(|| panic!("{key} in {v}"))
}

fn rec_json(r: &Rec) -> Value {
    json!({"kind": r.kind, "raw": r.raw, "line": r.line})
}

#[test]
fn stream() {
    let Some(cases) = cases("stream.json") else { return };
    for c in cases.as_array().unwrap() {
        let mut reader = records(str_of(c, "input").as_bytes());
        if c["stop_at_error"] == true {
            reader = reader.stop_at_error();
        }
        let got: Vec<Value> = reader
            .map(|item| match item {
                Ok(r) => rec_json(&r),
                Err(ReadError::Line(e)) => json!({"error_line": e.line}),
                Err(ReadError::Stopped(r)) => json!({"stopped": rec_json(&r)}),
                Err(ReadError::Io(e)) => panic!("{e}"),
            })
            .collect();
        assert_eq!(Value::Array(got), c["want"], "{}", str_of(c, "name"));
    }
}

#[test]
fn set_member_cases() {
    let Some(cases) = cases("set_member.json") else { return };
    for c in cases.as_array().unwrap() {
        let name = str_of(c, "name");
        let got = set_member(str_of(c, "in"), str_of(c, "member"), &c["value"]);
        if c["error"] == true {
            assert!(got.is_err(), "{name}: got {got:?}, want an error");
        } else {
            assert_eq!(got.unwrap_or_else(|e| panic!("{name}: {e}")), str_of(c, "want"), "{name}");
        }
    }
}

fn round_trip<T: DeserializeOwned + Serialize>(input: &Value) -> String {
    let v: T = serde_json::from_value(input.clone()).unwrap_or_else(|e| panic!("decode {input}: {e}"));
    let mut out = vec![];
    emit(&mut out, &v).unwrap();
    String::from_utf8(out).unwrap()
}

#[test]
fn round_trips() {
    let Some(cases) = cases("round_trip.json") else { return };
    for c in cases.as_array().unwrap() {
        let name = str_of(c, "name");
        let input = &c["in"];
        let got = match str_of(c, "type") {
            "finding" => round_trip::<Finding>(input),
            "page" => round_trip::<Page>(input),
            "scope" => round_trip::<ScopeRow>(input),
            "config" => round_trip::<Config>(input),
            "evidence" => round_trip::<Evidence>(input),
            "problem" => round_trip::<Problem>(input),
            "report" => round_trip::<Report>(input),
            "location" => round_trip::<Location>(input),
            "command" => round_trip::<Command>(input),
            "version" => round_trip::<Version>(input),
            "description" => round_trip::<Description>(input),
            other => panic!("{name}: unknown type {other}"),
        };
        assert!(got.ends_with('\n') && got.matches('\n').count() == 1, "{name}: {got:?} is not one line");
        let got: Value = serde_json::from_str(&got).unwrap();
        let want = if c["want"].is_null() { input } else { &c["want"] };
        assert_eq!(&got, want, "{name}");
    }
}

/// What the completion function got: the arguments and the word.
type Completed = (Vec<String>, String);

#[test]
fn run_cases() {
    let Some(suite) = cases("run.json") else { return };
    let plugin = &suite["plugin"];
    let candidates: Vec<String> = serde_json::from_value(plugin["complete"].clone()).unwrap();
    for c in suite["cases"].as_array().unwrap() {
        let name = str_of(c, "name");
        let mut description: Description = serde_json::from_value(plugin["description"].clone()).unwrap();
        if c["no_usage"] == true {
            description.usage.clear();
        }
        let ran_with: Rc<RefCell<Option<Vec<OsString>>>> = Rc::default();
        let ran = ran_with.clone();
        let mut p = Plugin::new(description, move |args, _, _, _| {
            *ran.borrow_mut() = Some(args.to_vec());
            7
        });
        let completed: Rc<RefCell<Option<Completed>>> = Rc::default();
        if c["no_complete"] != true {
            let completed = completed.clone();
            let candidates = candidates.clone();
            p = p.complete(move |args, word| {
                *completed.borrow_mut() = Some((args.to_vec(), word.to_string()));
                candidates.clone()
            });
        }
        let args: Vec<String> = serde_json::from_value(c["args"].clone()).unwrap();
        let args: Vec<OsString> = args.into_iter().map(OsString::from).collect();
        let mut out = vec![];
        let code = run(&p, &args, &mut &b""[..], &mut out, &mut std::io::sink());
        let out = String::from_utf8(out).unwrap();
        if c["runs"] == true {
            assert_eq!((code, ran_with.borrow().as_ref()), (7, Some(&args)), "{name}");
            continue;
        }
        assert_eq!((code, ran_with.borrow().is_none()), (0, true), "{name}: exit, didn't run");
        if c["describe"] == true {
            assert!(out.ends_with('\n') && out.matches('\n').count() == 1, "{name}: {out:?}");
            assert_eq!(serde_json::from_str::<Value>(&out).unwrap(), plugin["description"], "{name}");
        } else if let Some(want) = c["stdout"].as_str() {
            assert_eq!(out, want, "{name}");
        }
        if let Some(word) = c["complete_word"].as_str() {
            let want: Vec<String> = serde_json::from_value(c["complete_args"].clone()).unwrap();
            assert_eq!(completed.borrow().clone(), Some((want, word.to_string())), "{name}");
        }
    }
}
