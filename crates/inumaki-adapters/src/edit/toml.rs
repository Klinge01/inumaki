//! TOML through `toml_edit`: comments, key order, and table layout are
//! kept. A new object at a key becomes a `[table]`, and objects inside it
//! become inline tables.

use toml_edit::{Array, DocumentMut, InlineTable, Item, Table, TableLike, Value};

use crate::model::Refusal;
use crate::node::{Node, Op};

pub(super) fn apply(text: &str, ops: &[Op]) -> Result<String, Refusal> {
    let mut doc: DocumentMut = text.parse().map_err(|_| Refusal::Syntax)?;
    let printed = doc.to_string();
    // `toml_edit` always prints a trailing newline (0.25.15), so a file
    // saved without a final "\n" (common with "insert final newline" off)
    // would otherwise always refuse with RoundTrip. Accept that one-byte
    // difference and strip it back off the edited output (review I2); the
    // semantic guard still runs on the result either way.
    let strip_final_newline = !text.ends_with('\n') && printed == format!("{text}\n");
    if printed != text && !strip_final_newline {
        return Err(Refusal::RoundTrip);
    }
    for op in ops {
        apply_op(doc.as_table_mut(), op)?;
    }
    let mut out = doc.to_string();
    if strip_final_newline && out.ends_with('\n') {
        out.pop();
    }
    Ok(out)
}

fn table_at<'a>(
    root: &'a mut Table,
    keys: &[String],
    create: bool,
) -> Result<Option<&'a mut dyn TableLike>, Refusal> {
    let mut cur: &mut dyn TableLike = root;
    for k in keys {
        if !cur.contains_key(k) {
            if !create {
                return Ok(None);
            }
            let mut t = Table::new();
            t.set_implicit(true);
            cur.insert(k, Item::Table(t));
        }
        cur = match cur.get_mut(k).and_then(Item::as_table_like_mut) {
            Some(t) => t,
            None => return Err(Refusal::TypeConflict),
        };
    }
    Ok(Some(cur))
}

fn apply_op(root: &mut Table, op: &Op) -> Result<(), Refusal> {
    match op {
        Op::Set(path, v) => {
            let (last, parents) = path.split_last().ok_or(Refusal::Internal)?;
            let t = table_at(root, parents, true)?.ok_or(Refusal::Internal)?;
            let mut item = to_item(v)?;
            // A replaced table keeps its place in the document and the
            // comments above its header.
            if let (Some(Item::Table(old)), Item::Table(new)) = (t.get(last), &mut item) {
                new.set_position(old.position());
                *new.decor_mut() = old.decor().clone();
            }
            t.insert(last, item);
        }
        Op::Remove(path) => {
            let (last, parents) = path.split_last().ok_or(Refusal::Internal)?;
            if let Some(t) = table_at(root, parents, false)? {
                t.remove(last);
            }
        }
        Op::Append(path, v) => {
            let (last, parents) = path.split_last().ok_or(Refusal::Internal)?;
            let t = table_at(root, parents, true)?.ok_or(Refusal::Internal)?;
            if !t.contains_key(last) {
                t.insert(last, Item::Value(Value::Array(Array::new())));
            }
            let arr = t
                .get_mut(last)
                .and_then(Item::as_array_mut)
                .ok_or(Refusal::TypeConflict)?;
            arr.push(to_value(v)?);
        }
        Op::RemoveAt(path, i) => {
            let (last, parents) = path.split_last().ok_or(Refusal::Internal)?;
            let t = table_at(root, parents, false)?.ok_or(Refusal::Internal)?;
            let arr = t
                .get_mut(last)
                .and_then(Item::as_array_mut)
                .ok_or(Refusal::Internal)?;
            if *i >= arr.len() {
                return Err(Refusal::Internal);
            }
            arr.remove(*i);
        }
    }
    Ok(())
}

fn to_item(n: &Node) -> Result<Item, Refusal> {
    match n {
        Node::Obj(kv) => {
            let mut t = Table::new();
            for (k, v) in kv {
                t.insert(k, Item::Value(to_value(v)?));
            }
            Ok(Item::Table(t))
        }
        other => Ok(Item::Value(to_value(other)?)),
    }
}

fn to_value(n: &Node) -> Result<Value, Refusal> {
    Ok(match n {
        Node::Null => return Err(Refusal::Unrepresentable),
        Node::Bool(b) => Value::from(*b),
        Node::Int(i) => Value::from(*i),
        Node::Num(n) => match (n.as_i64(), n.as_f64()) {
            (Some(i), _) => Value::from(i),
            (None, Some(f)) if n.is_f64() => Value::from(f),
            _ => return Err(Refusal::Unrepresentable),
        },
        Node::Str(s) => Value::from(s.as_str()),
        Node::Arr(v) => {
            let mut a = Array::new();
            for x in v {
                a.push(to_value(x)?);
            }
            Value::Array(a)
        }
        Node::Obj(kv) => {
            let mut t = InlineTable::new();
            for (k, v) in kv {
                t.insert(k, to_value(v)?);
            }
            Value::InlineTable(t)
        }
    })
}
