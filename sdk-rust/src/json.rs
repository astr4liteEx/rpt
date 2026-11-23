//! Strict JSON checks shared by the stream reader and `set_member`: rpt refuses what
//! `serde_json` alone accepts, a member name given twice in one object.

use std::collections::HashSet;
use std::fmt;

use serde::Deserialize;
use serde::de::{self, MapAccess, SeqAccess, Visitor};

/// Checks that `text` is one JSON object, nothing after it but whitespace, with no member
/// name repeated in any object. The error says what is wrong.
pub(crate) fn check_object(text: &str) -> Result<(), String> {
    match serde_json::from_str::<Strict>(text) {
        Ok(Strict { object: true }) => Ok(()),
        Ok(_) if text.trim() == "null" => Err("null".into()),
        Ok(_) => Err("not a JSON object".into()),
        Err(e) => Err(e.to_string()),
    }
}

/// A JSON value checked for repeated member names; `object` says whether it was an object.
struct Strict {
    object: bool,
}

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Strict;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Strict, E> {
        Ok(Strict { object: false })
    }
    fn visit_i64<E>(self, _: i64) -> Result<Strict, E> {
        Ok(Strict { object: false })
    }
    fn visit_u64<E>(self, _: u64) -> Result<Strict, E> {
        Ok(Strict { object: false })
    }
    fn visit_f64<E>(self, _: f64) -> Result<Strict, E> {
        Ok(Strict { object: false })
    }
    fn visit_str<E>(self, _: &str) -> Result<Strict, E> {
        Ok(Strict { object: false })
    }
    fn visit_unit<E>(self) -> Result<Strict, E> {
        Ok(Strict { object: false })
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
        while seq.next_element::<Strict>()?.is_some() {}
        Ok(Strict { object: false })
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Strict, A::Error> {
        let mut seen = HashSet::new();
        while let Some(name) = map.next_key::<String>()? {
            if !seen.insert(name.clone()) {
                return Err(de::Error::custom(format!("duplicate object member name {name:?}")));
            }
            map.next_value::<Strict>()?;
        }
        Ok(Strict { object: true })
    }
}

/// The members of a record the reader looks at: its kind and, for a problem, its level.
/// A member of another type counts as absent.
#[derive(Deserialize)]
pub(crate) struct Head {
    #[serde(default)]
    kind: Option<serde_json::Value>,
    #[serde(default)]
    level: Option<serde_json::Value>,
}

impl Head {
    pub(crate) fn kind(&self) -> &str {
        self.kind.as_ref().and_then(|k| k.as_str()).unwrap_or("")
    }

    pub(crate) fn level(&self) -> &str {
        self.level.as_ref().and_then(|l| l.as_str()).unwrap_or("")
    }
}
