//! The one way a configuration file changes (spec §4.2): standard parse,
//! byte-exact round trip through the concrete-syntax editor, the edits,
//! then the semantic check against the standard parse.

mod json;
mod toml;
mod yaml;

use serde_json::Value;

use crate::model::Refusal;
use crate::node::{Edit, Format, lower};

/// `text` with `edits` applied, or why it cannot be done safely.
pub fn edit_text(format: Format, text: &str, edits: &[Edit]) -> Result<String, Refusal> {
    let old = parse_standard(format, text)?;
    let ops = lower(edits, &old)?;
    let new_text = match format {
        Format::Json | Format::Json5 => json::apply(text, &ops)?,
        Format::Toml => toml::apply(text, &ops)?,
        Format::Yaml => yaml::apply(text, &ops)?,
    };
    verify(format, &old, edits, &new_text)?;
    Ok(new_text)
}

/// The semantic postcondition (spec §4.2): `new_text` parses under the
/// standard parser to exactly `old` with `edits` applied. Public so the
/// guard can be tested against a tampered text.
pub fn verify(format: Format, old: &Value, edits: &[Edit], new_text: &str) -> Result<(), Refusal> {
    let mut expected = old.clone();
    for e in edits {
        e.apply_to(&mut expected)?;
    }
    let got = parse_standard(format, new_text).map_err(|_| Refusal::SemanticDiff)?;
    if got == expected {
        Ok(())
    } else {
        Err(Refusal::SemanticDiff)
    }
}

/// A JSON5 or TOML value whose numbers are all finite. `Infinity`/`Infinity`
/// and `nan`/`inf`/`-inf` would collapse to `null` in `serde_json::Value`,
/// and the semantic check would then not see a change to them, so they
/// refuse.
struct Finite(Value);

impl<'de> serde::Deserialize<'de> for Finite {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(FiniteVisitor).map(Finite)
    }
}

struct FiniteVisitor;

impl<'de> serde::de::Visitor<'de> for FiniteVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON5 value with finite numbers")
    }
    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite number"))
    }
    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_string()))
    }
    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_some<D: serde::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(FiniteVisitor)
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
        let mut v = Vec::new();
        while let Some(Finite(x)) = a.next_element()? {
            v.push(x);
        }
        Ok(Value::Array(v))
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
        let mut m = serde_json::Map::new();
        while let Some((k, Finite(x))) = a.next_entry::<String, Finite>()? {
            m.insert(k, x);
        }
        Ok(Value::Object(m))
    }
}

/// The file's value under the standard parser for its format.
pub fn parse_standard(format: Format, text: &str) -> Result<Value, Refusal> {
    let v = match format {
        Format::Json => serde_json::from_str::<Value>(text).map_err(|_| Refusal::Syntax)?,
        Format::Json5 => {
            json5::from_str::<Finite>(text)
                .map_err(|_| Refusal::Syntax)?
                .0
        }
        // Through the same `Finite` visitor as JSON5 (review I1): TOML's
        // `nan`/`inf`/`-inf` would otherwise collapse to `null` through
        // `serde_json::to_value(toml::Table)`, and the semantic guard would
        // then not see a change to them. A TOML datetime deserializes as a
        // one-entry map (`FiniteVisitor::visit_map`), which is fine here:
        // `parse_standard` only needs a value stable enough to compare
        // before and after, not a JSON-native datetime representation.
        Format::Toml => {
            ::toml::from_str::<Finite>(text)
                .map_err(|_| Refusal::Syntax)?
                .0
        }
        Format::Yaml if text.trim().is_empty() => Value::Object(Default::default()),
        Format::Yaml => serde_yaml_ng::from_str::<Value>(text).map_err(|_| Refusal::Syntax)?,
    };
    if v.is_object() {
        Ok(v)
    } else {
        Err(Refusal::NotAnObject)
    }
}

/// The text the app shows when a file cannot be edited safely: one line per
/// edit with its key path and JSON value. It contains the gateway token,
/// so it is shown to the user only, never logged.
pub fn snippet(edits: &[Edit]) -> String {
    let mut out = String::new();
    for e in edits {
        let path = e.path().join(" → ");
        let line = match e {
            Edit::Set { value, .. } => format!("set {path} to {}", value.to_json()),
            Edit::Remove { .. } => format!("remove {path}"),
            Edit::Push { value, .. } => format!("add {} to the list {path}", value.to_json()),
            Edit::Pull { value, .. } => format!("remove {} from the list {path}", value.to_json()),
            Edit::PullMatching { marker, .. } => {
                format!("remove the entries containing {marker} from the list {path}")
            }
        };
        out.push_str(&line);
        out.push('\n');
    }
    out
}
