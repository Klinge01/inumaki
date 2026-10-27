//! JSON and JSON5 through the `jsonc-parser` CST: comments, trailing
//! commas, key order, and quoting are kept.

use jsonc_parser::ParseOptions;
use jsonc_parser::cst::{CstInputValue, CstObject, CstRootNode};

use crate::model::Refusal;
use crate::node::{Node, Op};

pub(super) fn apply(text: &str, ops: &[Op]) -> Result<String, Refusal> {
    let root = CstRootNode::parse(text, &ParseOptions::default()).map_err(|_| Refusal::Syntax)?;
    if root.to_string() != text {
        return Err(Refusal::RoundTrip);
    }
    let obj = root.object_value().ok_or(Refusal::NotAnObject)?;
    for op in ops {
        apply_op(&obj, op)?;
    }
    Ok(root.to_string())
}

fn object_at(
    root: &CstObject,
    keys: &[String],
    create: bool,
) -> Result<Option<CstObject>, Refusal> {
    let mut cur = root.clone();
    for k in keys {
        cur = match cur.get(k) {
            Some(prop) => prop.object_value().ok_or(Refusal::TypeConflict)?,
            None if create => cur.object_value_or_set(k),
            None => return Ok(None),
        };
    }
    Ok(Some(cur))
}

fn apply_op(root: &CstObject, op: &Op) -> Result<(), Refusal> {
    match op {
        Op::Set(path, v) => {
            let (last, parents) = path.split_last().ok_or(Refusal::Internal)?;
            let o = object_at(root, parents, true)?.ok_or(Refusal::Internal)?;
            match o.get(last) {
                Some(p) => p.set_value(cst(v)),
                None => {
                    o.append(last, cst(v));
                }
            }
        }
        Op::Remove(path) => {
            let (last, parents) = path.split_last().ok_or(Refusal::Internal)?;
            if let Some(p) = object_at(root, parents, false)?.and_then(|o| o.get(last)) {
                p.remove();
            }
        }
        Op::Append(path, v) => {
            let (last, parents) = path.split_last().ok_or(Refusal::Internal)?;
            let o = object_at(root, parents, true)?.ok_or(Refusal::Internal)?;
            let arr = match o.get(last) {
                Some(p) => p.array_value().ok_or(Refusal::TypeConflict)?,
                None => o.array_value_or_set(last),
            };
            arr.append(cst(v));
        }
        Op::RemoveAt(path, i) => {
            let (last, parents) = path.split_last().ok_or(Refusal::Internal)?;
            let o = object_at(root, parents, false)?.ok_or(Refusal::Internal)?;
            let arr = o
                .get(last)
                .and_then(|p| p.array_value())
                .ok_or(Refusal::Internal)?;
            let el = arr.elements().get(*i).cloned().ok_or(Refusal::Internal)?;
            el.remove();
        }
    }
    Ok(())
}

fn cst(n: &Node) -> CstInputValue {
    match n {
        Node::Null => CstInputValue::Null,
        Node::Bool(b) => CstInputValue::Bool(*b),
        Node::Int(i) => CstInputValue::Number(i.to_string()),
        Node::Num(n) => CstInputValue::Number(n.to_string()),
        Node::Str(s) => CstInputValue::String(s.clone()),
        Node::Arr(v) => CstInputValue::Array(v.iter().map(cst).collect()),
        Node::Obj(kv) => {
            CstInputValue::Object(kv.iter().map(|(k, v)| (k.clone(), cst(v))).collect())
        }
    }
}
