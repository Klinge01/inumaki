//! JSON (spec §5.2): an order-preserving parse (no `preserve_order`
//! feature: it would unify across the workspace), keys, strings, and
//! numbers as blocks, numbers kept as their source text (lossless beyond
//! `u64` and `f64`), a two-space pretty print with the source's line
//! endings, JSON Lines with each line's own terminator, and one
//! verification block per object: its scalar members plus the keys of its
//! nested members as `"k":{}` or `"k":[]`, so a key is never checked out of
//! its siblings' context. Arrays go beyond spec §5.2 (recall first): one
//! block per array holding any scalar, so a value split across elements
//! (`["Zyxwuria","Quolnath"]`, tabular rows) is checked side by side.

use std::fmt::Write as _;

use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};

use super::{Doc, Shape};

#[derive(Clone)]
enum J {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

struct V;

impl<'de> Visitor<'de> for V {
    type Value = J;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JSON")
    }
    fn visit_unit<E>(self) -> Result<J, E> {
        Ok(J::Null)
    }
    fn visit_bool<E>(self, b: bool) -> Result<J, E> {
        Ok(J::Bool(b))
    }
    // Number text is replaced by the source literal in `parse`.
    fn visit_i64<E>(self, _: i64) -> Result<J, E> {
        Ok(J::Num(String::new()))
    }
    fn visit_u64<E>(self, _: u64) -> Result<J, E> {
        Ok(J::Num(String::new()))
    }
    fn visit_f64<E>(self, _: f64) -> Result<J, E> {
        Ok(J::Num(String::new()))
    }
    fn visit_str<E: de::Error>(self, s: &str) -> Result<J, E> {
        Ok(J::Str(s.to_owned()))
    }
    fn visit_string<E>(self, s: String) -> Result<J, E> {
        Ok(J::Str(s))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<J, A::Error> {
        let mut v = Vec::new();
        while let Some(x) = a.next_element_seed(Seed)? {
            v.push(x);
        }
        Ok(J::Arr(v))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<J, A::Error> {
        let mut v = Vec::new();
        while let Some(k) = a.next_key::<String>()? {
            v.push((k, a.next_value_seed(Seed)?));
        }
        Ok(J::Obj(v))
    }
}

struct Seed;

impl<'de> de::DeserializeSeed<'de> for Seed {
    type Value = J;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<J, D::Error> {
        d.deserialize_any(V)
    }
}

/// Number literals of a valid JSON text in document order (strings are
/// skipped, escapes honoured). The visitor meets numbers in the same order,
/// so the i-th `J::Num` takes the i-th literal and no digit is lost to `f64`.
fn number_literals(s: &str) -> Vec<String> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'"' => {
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    if b[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
                i += 1;
            }
            b'-' | b'0'..=b'9' => {
                let start = i;
                while i < b.len() && matches!(b[i], b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
                {
                    i += 1;
                }
                out.push(s[start..i].to_string());
            }
            _ => i += 1,
        }
    }
    out
}

fn fill_numbers(j: &mut J, lits: &mut std::vec::IntoIter<String>) -> Option<()> {
    match j {
        J::Num(n) => *n = lits.next()?,
        J::Arr(v) => {
            for x in v {
                fill_numbers(x, lits)?;
            }
        }
        J::Obj(m) => {
            for (_, x) in m {
                fill_numbers(x, lits)?;
            }
        }
        J::Null | J::Bool(_) | J::Str(_) => {}
    }
    Some(())
}

fn parse(s: &str) -> Option<J> {
    let mut de = serde_json::Deserializer::from_str(s);
    let mut j = de::DeserializeSeed::deserialize(Seed, &mut de).ok()?;
    de.end().ok()?;
    let mut lits = number_literals(s).into_iter();
    fill_numbers(&mut j, &mut lits)?;
    lits.next().is_none().then_some(j)
}

/// One source line of JSON Lines: a document with its terminator, or a
/// blank line kept as it was.
#[derive(Clone)]
enum Line {
    Doc(usize, String),
    Blank(String),
}

/// Documents (one, or one per line) and the source text.
#[derive(Clone)]
pub struct JsonShape {
    docs: Vec<J>,
    /// `None`: one document; `Some`: JSON Lines, every source line.
    lines: Option<Vec<Line>>,
    /// The source's line ending for the pretty print.
    nl: &'static str,
    source: String,
}

pub(super) fn source(s: &JsonShape) -> String {
    s.source.clone()
}

fn collect(j: &J, out: &mut Vec<String>) {
    match j {
        J::Num(n) => out.push(n.clone()),
        J::Str(s) => out.push(s.clone()),
        J::Arr(v) => v.iter().for_each(|x| collect(x, out)),
        J::Obj(m) => {
            for (k, v) in m {
                out.push(k.clone());
                collect(v, out);
            }
        }
        J::Null | J::Bool(_) => {}
    }
}

pub(super) fn doc(s: &str) -> Option<Doc> {
    let j = parse(s)?;
    let mut blocks = Vec::new();
    collect(&j, &mut blocks);
    let nl = if s.contains("\r\n") { "\r\n" } else { "\n" };
    Some(Doc {
        blocks,
        shape: Shape::Json(JsonShape {
            docs: vec![j],
            lines: None,
            nl,
            source: s.to_string(),
        }),
    })
}

pub(super) fn lines_doc(s: &str) -> Option<Doc> {
    let mut docs = Vec::new();
    let mut lines = Vec::new();
    for raw in s.split_inclusive('\n') {
        let body = raw.trim_end_matches(['\r', '\n']);
        if body.trim().is_empty() {
            lines.push(Line::Blank(raw.to_string()));
        } else {
            docs.push(parse(body)?);
            lines.push(Line::Doc(docs.len() - 1, raw[body.len()..].to_string()));
        }
    }
    let mut blocks = Vec::new();
    docs.iter().for_each(|d| collect(d, &mut blocks));
    Some(Doc {
        blocks,
        shape: Shape::Json(JsonShape {
            docs,
            lines: Some(lines),
            nl: "\n",
            source: s.to_string(),
        }),
    })
}

/// Replace in order; `None` when two distinct keys of one object became equal.
fn rebuild(j: &J, out: &mut std::slice::Iter<'_, String>, verify: &mut Vec<String>) -> Option<J> {
    Some(match j {
        J::Num(n) => {
            let s = out.next()?.clone();
            if &s == n { J::Num(s) } else { J::Str(s) }
        }
        J::Str(_) => J::Str(out.next()?.clone()),
        J::Arr(v) => {
            let items: Vec<J> = v
                .iter()
                .map(|x| rebuild(x, out, verify))
                .collect::<Option<_>>()?;
            // Scalars side by side, so a value split across elements is
            // verified in context; nested containers are placeholders.
            if items.iter().any(|x| !matches!(x, J::Arr(_) | J::Obj(_))) {
                let ctx: Vec<String> = items.iter().map(placeholder).collect();
                verify.push(format!("[{}]", ctx.join(",")));
            }
            J::Arr(items)
        }
        J::Obj(m) => {
            let mut members: Vec<(String, J)> = Vec::with_capacity(m.len());
            let mut sources: Vec<&str> = Vec::with_capacity(m.len());
            for (k, v) in m {
                let nk = out.next()?.clone();
                // Two different source keys that sanitize to one token
                // (alias groups) would merge members: redo as text.
                let merged = members
                    .iter()
                    .zip(&sources)
                    .any(|((x, _), src)| *x == nk && *src != k.as_str());
                if merged {
                    return None;
                }
                sources.push(k);
                members.push((nk, rebuild(v, out, verify)?));
            }
            // Every member's key, with its scalar value or an empty
            // container, so keys are verified in their siblings' context.
            let mut ctx = String::from("{");
            for (k, v) in &members {
                if ctx.len() > 1 {
                    ctx.push(',');
                }
                let _ = write!(ctx, "{}:{}", quote(k), placeholder(v));
            }
            ctx.push('}');
            if !members.is_empty() {
                verify.push(ctx);
            }
            J::Obj(members)
        }
        other => other.clone(),
    })
}

/// A scalar as JSON, a container as `{}` or `[]`.
fn placeholder(j: &J) -> String {
    match j {
        J::Obj(_) => "{}".into(),
        J::Arr(_) => "[]".into(),
        scalar => compact(scalar),
    }
}

/// A JSON string literal, escaped as serde_json does (infallible).
fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn compact(j: &J) -> String {
    match j {
        J::Null => "null".into(),
        J::Bool(b) => b.to_string(),
        J::Num(n) => n.clone(),
        J::Str(s) => quote(s),
        J::Arr(_) | J::Obj(_) => String::new(),
    }
}

fn pretty(j: &J, indent: usize, nl: &str, out: &mut String) {
    let pad = "  ".repeat(indent + 1);
    match j {
        J::Arr(v) if !v.is_empty() => {
            out.push('[');
            out.push_str(nl);
            for (i, x) in v.iter().enumerate() {
                out.push_str(&pad);
                pretty(x, indent + 1, nl, out);
                if i + 1 < v.len() {
                    out.push(',');
                }
                out.push_str(nl);
            }
            out.push_str(&"  ".repeat(indent));
            out.push(']');
        }
        J::Obj(m) if !m.is_empty() => {
            out.push('{');
            out.push_str(nl);
            for (i, (k, v)) in m.iter().enumerate() {
                out.push_str(&pad);
                out.push_str(&quote(k));
                out.push_str(": ");
                pretty(v, indent + 1, nl, out);
                if i + 1 < m.len() {
                    out.push(',');
                }
                out.push_str(nl);
            }
            out.push_str(&"  ".repeat(indent));
            out.push('}');
        }
        J::Arr(_) => out.push_str("[]"),
        J::Obj(_) => out.push_str("{}"),
        s => out.push_str(&compact(s)),
    }
}

pub(super) fn assemble(s: &JsonShape, out: &[String]) -> Option<super::Assembled> {
    let mut it = out.iter();
    let mut verify = Vec::new();
    let mut rebuilt = Vec::with_capacity(s.docs.len());
    for d in &s.docs {
        rebuilt.push(rebuild(d, &mut it, &mut verify)?);
    }
    let mut text = String::new();
    match &s.lines {
        None => {
            for j in &rebuilt {
                pretty(j, 0, s.nl, &mut text);
                text.push_str(s.nl);
            }
        }
        Some(lines) => {
            for l in lines {
                match l {
                    Line::Doc(i, terminator) => {
                        compact_doc(&rebuilt[*i], &mut text);
                        text.push_str(terminator);
                    }
                    Line::Blank(raw) => text.push_str(raw),
                }
            }
        }
    }
    Some(super::Assembled { text, verify })
}

/// One line of JSON Lines, member order kept.
fn compact_doc(j: &J, out: &mut String) {
    match j {
        J::Arr(v) => {
            out.push('[');
            for (i, x) in v.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                compact_doc(x, out);
            }
            out.push(']');
        }
        J::Obj(m) => {
            out.push('{');
            for (i, (k, v)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&quote(k));
                out.push(':');
                compact_doc(v, out);
            }
            out.push('}');
        }
        s => out.push_str(&compact(s)),
    }
}
