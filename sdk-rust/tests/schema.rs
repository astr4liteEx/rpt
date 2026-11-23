//! Checks that each published JSON Schema in ../schema names exactly the members the Rust type
//! knows, and requires exactly the ones it always writes, so the two can't drift apart.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use rpt_sdk::*;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};

fn schema_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../schema")
}

fn load(file: &str) -> Value {
    let text = std::fs::read_to_string(schema_dir().join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
    serde_json::from_str(&text).unwrap()
}

/// The object schema at `path` in `file`.
fn object_schema(file: &str, path: &[&str]) -> Value {
    let mut node = load(file);
    for key in path {
        node = node[key].clone();
    }
    node
}

/// A value the schema `s` (in `file`) accepts, non-empty so a type writes it back.
fn sample(file: &str, s: &Value) -> Value {
    if let Some(r) = s["$ref"].as_str() {
        let (target_file, pointer) = match r.split_once('#') {
            Some(("", p)) => (file.to_string(), p.to_string()),
            Some((f, p)) => (f.rsplit('/').next().unwrap().to_string(), p.to_string()),
            None => (r.rsplit('/').next().unwrap().to_string(), String::new()),
        };
        let root = load(&target_file);
        let target = root.pointer(&pointer).unwrap_or_else(|| panic!("{r}")).clone();
        return sample(&target_file, &target);
    }
    if let Some(c) = s.get("const") {
        return c.clone();
    }
    if let Some(e) = s["enum"].as_array() {
        return e[0].clone();
    }
    for key in ["oneOf", "anyOf"] {
        if let Some(alts) = s[key].as_array() {
            return sample(file, &alts[0]);
        }
    }
    let types: Vec<&str> = match &s["type"] {
        Value::String(t) => vec![t.as_str()],
        Value::Array(ts) => ts.iter().filter_map(Value::as_str).collect(),
        _ => vec![],
    };
    match types.iter().find(|t| **t != "null").copied() {
        Some("string") => json!("x"),
        Some("integer" | "number") => json!(1),
        Some("boolean") => json!(true),
        Some("array") => json!([sample(file, &s["items"])]),
        Some("object") if s["properties"].is_object() => {
            let required: Vec<String> = serde_json::from_value(s["required"].clone()).unwrap_or_default();
            let props = s["properties"].as_object().unwrap();
            let mut m = Map::new();
            for name in required {
                m.insert(name.clone(), sample(file, &props[&name]));
            }
            if m.is_empty() {
                m.insert("k".into(), json!("x"));
            }
            Value::Object(m)
        }
        Some("object") => match &s["additionalProperties"] {
            ap @ Value::Object(_) => json!({"k": sample(file, ap)}),
            _ => json!({"k": "x"}),
        },
        _ => json!({"k": "x"}),
    }
}

fn keys(v: &Value) -> BTreeSet<String> {
    v.as_object().unwrap().keys().cloned().collect()
}

/// Checks type `T` against the object schema at `path` in `file`; `extra` gives the members it
/// didn't know.
fn check<T: DeserializeOwned + Serialize + Default>(file: &str, path: &[&str], extra: fn(&T) -> &Map<String, Value>) {
    let what = format!("{file} {path:?}");
    let schema = object_schema(file, path);
    assert_eq!(schema["additionalProperties"], true, "{what}: records pass through unknown members");
    let props = keys(&schema["properties"]);
    let required: BTreeSet<String> = serde_json::from_value(schema["required"].clone()).unwrap_or_default();

    // Every property is a member the type knows, and writes back.
    let full: Map<String, Value> = props.iter().map(|p| (p.clone(), sample(file, &schema["properties"][p]))).collect();
    let v: T = serde_json::from_value(Value::Object(full.clone())).unwrap_or_else(|e| panic!("{what}: {e}"));
    assert!(extra(&v).is_empty(), "{what}: members the type doesn't know: {:?}", extra(&v).keys());
    let written = serde_json::to_value(&v).unwrap();
    assert_eq!(keys(&written), props, "{what}: members written from a full record");

    // An empty value writes exactly the required members.
    let empty = serde_json::to_value(T::default()).unwrap();
    assert_eq!(keys(&empty), required, "{what}: members an empty value writes");
}

#[test]
fn schemas_match_types() {
    if !schema_dir().exists() {
        eprintln!("skipped: needs the rpt repository's schema folder");
        return;
    }
    check::<Finding>("finding.schema.json", &[], |v| &v.extra);
    check::<Target>("finding.schema.json", &["$defs", "target"], |v| &v.extra);
    check::<Lines>("finding.schema.json", &["$defs", "lines"], |v| &v.extra);
    check::<SectionLines>("finding.schema.json", &["$defs", "sectionLines"], |v| &v.extra);
    check::<Position>("finding.schema.json", &["$defs", "position"], |v| &v.extra);
    check::<Asset>("finding.schema.json", &["$defs", "asset"], |v| &v.extra);
    check::<Page>("page.schema.json", &[], |v| &v.extra);
    check::<ScopeRow>("scope.schema.json", &[], |v| &v.extra);
    check::<Config>("config.schema.json", &[], |v| &v.extra);
    check::<Evidence>("evidence.schema.json", &[], |v| &v.asset.extra);
    check::<Problem>("problem.schema.json", &[], |v| &v.extra);
    check::<Report>("report.schema.json", &[], |v| &v.extra);
    check::<Section>("report.schema.json", &["$defs", "section"], |v| &v.extra);
    check::<Location>("location.schema.json", &[], |v| &v.extra);
    check::<Version>("version.schema.json", &[], |v| &v.extra);
    check::<Command>("command.schema.json", &[], |v| &v.description.extra);
    check::<Description>("command.schema.json", &["$defs", "description"], |v| &v.extra);
    check::<Requires>("command.schema.json", &["$defs", "requires"], |v| &v.extra);
    check::<Range>("command.schema.json", &["$defs", "range"], |v| &v.extra);
    check::<Schemas>("command.schema.json", &["$defs", "schemas"], |v| &v.extra);
}
