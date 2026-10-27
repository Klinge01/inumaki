//! The texts of a tool output, in one fixed walk order: object entries in
//! `serde_json`'s key order, each key before its value, and arrays in order.
//! Every key, string, and number is a text (review C4: an identifier can be
//! a key or a number). On the way back only string values that are not
//! discriminators may change; anything else would change the shape, and
//! the harness would then fall back to the original.

use serde_json::Value;

/// Keys whose string value names the output's shape: never rewritten. The
/// spec's four (`type`, `mimeType`, `role`, `kind`) plus the enum-typed keys
/// Task 1 found in the hooked tools' output schemas (docs/harness-adapters.md
/// §5): a rewritten enum value fails Claude Code's schema check, and the
/// original output would be used.
pub const DISCRIMINATORS: &[&str] = &[
    "type",
    "mimeType",
    "mediaType",
    "role",
    "kind",
    "mode",
    "status",
    "action",
    "source",
];

/// Every key, string, and number of `v`, as text.
pub fn texts(v: &Value) -> Vec<String> {
    let mut out = Vec::new();
    collect(v, &mut out);
    out
}

fn collect(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Number(n) => out.push(n.to_string()),
        Value::Array(a) => a.iter().for_each(|x| collect(x, out)),
        Value::Object(m) => {
            for (k, x) in m {
                out.push(k.clone());
                collect(x, out);
            }
        }
        Value::Bool(_) | Value::Null => {}
    }
}

/// Write `new` (same order as [`texts`]) back into `v`. `false` when the
/// lengths differ or a key, a number, or a discriminator value would
/// change: the caller blocks, and `v` must then not be used.
pub fn write_back(v: &mut Value, new: &[String]) -> bool {
    let mut it = new.iter();
    put(v, false, &mut it) && it.next().is_none()
}

fn put(v: &mut Value, disc: bool, it: &mut std::slice::Iter<'_, String>) -> bool {
    match v {
        Value::String(s) => match it.next() {
            None => false,
            Some(n) if disc => *n == *s,
            Some(n) => {
                s.clone_from(n);
                true
            }
        },
        Value::Number(x) => it.next().is_some_and(|n| *n == x.to_string()),
        Value::Array(a) => a.iter_mut().all(|x| put(x, false, it)),
        Value::Object(m) => m.iter_mut().all(|(k, x)| {
            it.next().is_some_and(|n| n == k) && put(x, DISCRIMINATORS.contains(&k.as_str()), it)
        }),
        Value::Bool(_) | Value::Null => true,
    }
}
