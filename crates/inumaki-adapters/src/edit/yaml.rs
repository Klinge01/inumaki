//! YAML through `yaml-edit` (lossless). Only block-style mappings on an
//! edit's path are edited. A flow-style mapping or sequence on an edit's
//! path refuses, and so does an anchor, an alias, or a merge key anywhere in
//! the file, because an edit could change what an alias expands to.
//!
//! The file is parsed with [`YamlFile`], not `Document`: `Document::from_str`
//! rejects a comment before the first key, which every real Hermes
//! `config.yaml` has (docs/harness-adapters.md, editor decision). A mapping
//! value, or a missing parent, is inserted as an empty *pending block* node
//! and filled in place: a `BTreeMap` or a copied mapping handed to
//! `Mapping::set` prints mis-indented YAML.

use std::str::FromStr;

use yaml_edit::{Mapping, ScalarValue, Sequence, YamlFile};

use crate::model::Refusal;
use crate::node::{Node, Op};

pub(super) fn apply(text: &str, ops: &[Op]) -> Result<String, Refusal> {
    if has_anchor_or_alias(text) {
        return Err(Refusal::Anchor);
    }
    let file = YamlFile::from_str(text).map_err(|_| Refusal::Syntax)?;
    if file.to_string() != text {
        return Err(Refusal::RoundTrip);
    }
    let root = file
        .document()
        .and_then(|d| d.as_mapping())
        .ok_or(Refusal::NotAnObject)?;
    if root.is_flow_style() {
        return Err(Refusal::FlowStyle);
    }
    for op in ops {
        apply_op(&root, op)?;
    }
    Ok(file.to_string())
}

/// The deepest existing block mapping along `parents`, and the keys below it
/// that do not exist yet.
fn deepest<'p>(root: &Mapping, parents: &'p [String]) -> Result<(Mapping, &'p [String]), Refusal> {
    let mut cur = root.clone();
    for (i, k) in parents.iter().enumerate() {
        match cur.get_mapping(k.as_str()) {
            Some(m) if m.is_flow_style() => return Err(Refusal::FlowStyle),
            Some(m) => cur = m,
            None if cur.contains_key(k.as_str()) => return Err(Refusal::TypeConflict),
            None => return Ok((cur, &parents[i..])),
        }
    }
    Ok((cur, &[]))
}

/// Set `key` in `m` to `value`. A collection is inserted as a pending block
/// node and filled in place: `Mapping::set` of a copied mapping, or of a
/// `BTreeMap`, loses the indentation of nested levels.
fn set_value(m: &Mapping, key: &str, value: &Node) -> Result<(), Refusal> {
    match value {
        Node::Null => m.set(key, ScalarValue::null()),
        Node::Bool(b) => m.set(key, *b),
        Node::Int(i) => m.set(key, *i),
        Node::Num(n) => match (n.as_i64(), n.as_f64()) {
            (Some(i), _) => m.set(key, i),
            (None, Some(f)) if n.is_f64() && f.is_finite() => m.set(key, f),
            _ => return Err(Refusal::Unrepresentable),
        },
        Node::Str(s) => m.set(key, s.as_str()),
        // An empty collection would print as flow (`{}`, `[]`).
        Node::Obj(kv) if !kv.is_empty() => {
            m.set(key, Mapping::new_pending_block());
            let child = m.get_mapping(key).ok_or(Refusal::Internal)?;
            for (k, v) in kv {
                set_value(&child, k, v)?;
            }
        }
        Node::Arr(items) if !items.is_empty() => {
            m.set(key, Sequence::new_pending_block());
            let seq = m.get_sequence(key).ok_or(Refusal::Internal)?;
            for item in items {
                push_scalar(&seq, item)?;
            }
        }
        Node::Obj(_) | Node::Arr(_) => return Err(Refusal::Unrepresentable),
    }
    Ok(())
}

/// Append a scalar element; a collection element is not needed by any adapter.
fn push_scalar(seq: &Sequence, v: &Node) -> Result<(), Refusal> {
    match v {
        Node::Str(s) => seq.push(s.as_str()),
        Node::Bool(b) => seq.push(*b),
        Node::Int(i) => seq.push(*i),
        _ => return Err(Refusal::Unrepresentable),
    }
    Ok(())
}

/// Set `last` under `parents`, building missing parents as one nested
/// block value (never an empty mapping that could print as flow `{}`).
fn set_nested(root: &Mapping, parents: &[String], last: &str, value: &Node) -> Result<(), Refusal> {
    let (m, missing) = deepest(root, parents)?;
    match missing.split_first() {
        None => set_value(&m, last, value),
        Some((first, rest)) => {
            let mut v = Node::Obj(vec![(last.to_string(), value.clone())]);
            for k in rest.iter().rev() {
                v = Node::Obj(vec![(k.clone(), v)]);
            }
            set_value(&m, first, &v)
        }
    }
}

fn apply_op(root: &Mapping, op: &Op) -> Result<(), Refusal> {
    match op {
        Op::Set(path, v) => {
            let (last, parents) = path.split_last().ok_or(Refusal::Internal)?;
            set_nested(root, parents, last, v)?;
        }
        Op::Remove(path) => {
            let (last, parents) = path.split_last().ok_or(Refusal::Internal)?;
            let (m, missing) = deepest(root, parents)?;
            if missing.is_empty() {
                m.remove(last.as_str());
            }
        }
        Op::Append(path, v) => {
            let (last, parents) = path.split_last().ok_or(Refusal::Internal)?;
            let (m, missing) = deepest(root, parents)?;
            match (missing.is_empty(), m.get_sequence(last.as_str())) {
                (true, Some(seq)) if seq.is_flow_style() => return Err(Refusal::FlowStyle),
                (true, Some(seq)) => push_scalar(&seq, v)?,
                (true, None) if m.contains_key(last.as_str()) => return Err(Refusal::TypeConflict),
                _ => set_nested(root, parents, last, &Node::Arr(vec![v.clone()]))?,
            }
        }
        Op::RemoveAt(path, i) => {
            let (last, parents) = path.split_last().ok_or(Refusal::Internal)?;
            let (m, missing) = deepest(root, parents)?;
            if !missing.is_empty() {
                return Err(Refusal::Internal);
            }
            let seq = m.get_sequence(last.as_str()).ok_or(Refusal::Internal)?;
            seq.remove(*i).ok_or(Refusal::Internal)?;
        }
    }
    Ok(())
}

/// An anchor (`&a`), alias (`*a`), or merge key (`<<:`) outside a comment.
/// It errs toward refusing: a plain scalar that merely starts with `&` or
/// `*` followed by name characters also refuses.
fn has_anchor_or_alias(text: &str) -> bool {
    text.lines().any(|line| {
        let code = line.split(" #").next().unwrap_or("");
        code.contains("<<:")
            || code
                .split(|c: char| c.is_whitespace() || matches!(c, '[' | '{' | ','))
                .any(|w| {
                    (w.starts_with('&') || w.starts_with('*'))
                        && w.len() > 1
                        && w[1..]
                            .chars()
                            .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
                })
    })
}
