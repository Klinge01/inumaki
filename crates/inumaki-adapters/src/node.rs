//! A format-neutral value with ordered object keys, the edits adapters make,
//! and their meaning on a parsed value (the semantic check, spec §4.2).

use serde_json::{Map, Value};

use crate::model::Refusal;

/// Syntax of a configuration file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    /// Strict JSON (Claude Code, Codex `hooks.json`).
    Json,
    /// JSON5 (OpenClaw).
    Json5,
    /// TOML (Codex).
    Toml,
    /// YAML (Hermes).
    Yaml,
}

impl Format {
    /// The text a missing file starts from; `None`: the file must exist.
    pub fn empty_document(self) -> Option<&'static str> {
        match self {
            Format::Json | Format::Json5 => Some("{}\n"),
            Format::Toml => Some(""),
            Format::Yaml => None,
        }
    }
}

/// A value an adapter writes. Object keys keep their order. `Debug`
/// prints the shape only (values can be bearer tokens).
#[derive(Clone, PartialEq)]
pub enum Node {
    /// `null` (JSON only).
    Null,
    /// Boolean.
    Bool(bool),
    /// Integer.
    Int(i64),
    /// Any other JSON number (a float, or an integer beyond `i64`), kept exact.
    Num(serde_json::Number),
    /// String.
    Str(String),
    /// Array.
    Arr(Vec<Node>),
    /// Object with ordered keys.
    Obj(Vec<(String, Node)>),
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Node::Null => f.write_str("Null"),
            Node::Bool(_) => f.write_str("Bool"),
            Node::Int(_) => f.write_str("Int"),
            Node::Num(_) => f.write_str("Num"),
            Node::Str(s) => write!(f, "Str({} bytes)", s.len()),
            Node::Arr(v) => write!(f, "Arr({})", v.len()),
            Node::Obj(v) => write!(f, "Obj({})", v.len()),
        }
    }
}

impl Node {
    /// A string.
    pub fn s(v: impl Into<String>) -> Node {
        Node::Str(v.into())
    }

    /// An object from ordered pairs.
    pub fn obj<'a>(pairs: impl IntoIterator<Item = (&'a str, Node)>) -> Node {
        Node::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    /// The JSON value (object keys sorted, as `serde_json` compares them).
    pub fn to_json(&self) -> Value {
        match self {
            Node::Null => Value::Null,
            Node::Bool(b) => Value::Bool(*b),
            Node::Int(i) => Value::from(*i),
            Node::Num(n) => Value::Number(n.clone()),
            Node::Str(s) => Value::String(s.clone()),
            Node::Arr(v) => Value::Array(v.iter().map(Node::to_json).collect()),
            Node::Obj(kv) => Value::Object(
                kv.iter()
                    .map(|(k, v)| (k.clone(), v.to_json()))
                    .collect::<Map<_, _>>(),
            ),
        }
    }
}

/// One edit. Paths are object keys from the document root.
///
/// `Debug` (ruling F1, privacy) prints the variant and the key-path depth
/// only: a path can hold a server name or a project directory, so it never
/// appears, not even one segment of it.
#[derive(Clone, PartialEq)]
pub enum Edit {
    /// Set the value at the path, creating parent objects.
    Set {
        /// Key path.
        path: Vec<String>,
        /// Value.
        value: Node,
    },
    /// Remove the key at the path; nothing when absent.
    Remove {
        /// Key path.
        path: Vec<String>,
    },
    /// Append to the array at the path unless an equal element exists
    /// (creating the array and its parents).
    Push {
        /// Array path.
        path: Vec<String>,
        /// Element.
        value: Node,
    },
    /// Remove every element equal to `value` from the array at the path.
    Pull {
        /// Array path.
        path: Vec<String>,
        /// Element.
        value: Node,
    },
    /// Remove every element whose JSON text contains `marker` (our own
    /// earlier hook entries; the marker is `inumaki-hook`).
    PullMatching {
        /// Array path.
        path: Vec<String>,
        /// Marker substring.
        marker: String,
    },
}

impl std::fmt::Debug for Edit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (variant, depth) = match self {
            Edit::Set { path, .. } => ("Set", path.len()),
            Edit::Remove { path } => ("Remove", path.len()),
            Edit::Push { path, .. } => ("Push", path.len()),
            Edit::Pull { path, .. } => ("Pull", path.len()),
            Edit::PullMatching { path, .. } => ("PullMatching", path.len()),
        };
        write!(f, "Edit::{variant}(path_depth={depth})")
    }
}

impl Edit {
    /// The key path this edit owns.
    pub fn path(&self) -> &[String] {
        match self {
            Edit::Set { path, .. }
            | Edit::Remove { path }
            | Edit::Push { path, .. }
            | Edit::Pull { path, .. }
            | Edit::PullMatching { path, .. } => path,
        }
    }

    /// Apply this edit to a parsed value: what the edited file must parse to.
    pub fn apply_to(&self, root: &mut Value) -> Result<(), Refusal> {
        match self {
            Edit::Set { path, value } => {
                let (last, parents) = path.split_last().ok_or(Refusal::Internal)?;
                parent_mut(root, parents, true)?
                    .ok_or(Refusal::Internal)?
                    .insert(last.clone(), value.to_json());
            }
            Edit::Remove { path } => {
                let (last, parents) = path.split_last().ok_or(Refusal::Internal)?;
                if let Some(p) = parent_mut(root, parents, false)? {
                    p.remove(last);
                }
            }
            Edit::Push { path, value } => {
                let (last, parents) = path.split_last().ok_or(Refusal::Internal)?;
                let p = parent_mut(root, parents, true)?.ok_or(Refusal::Internal)?;
                let arr = p
                    .entry(last.clone())
                    .or_insert_with(|| Value::Array(Vec::new()));
                let arr = arr.as_array_mut().ok_or(Refusal::TypeConflict)?;
                let v = value.to_json();
                if !arr.contains(&v) {
                    arr.push(v);
                }
            }
            Edit::Pull { path, value } => {
                if let Some(arr) = array_mut(root, path)? {
                    let v = value.to_json();
                    arr.retain(|x| *x != v);
                }
            }
            Edit::PullMatching { path, marker } => {
                if let Some(arr) = array_mut(root, path)? {
                    arr.retain(|x| !x.to_string().contains(marker.as_str()));
                }
            }
        }
        Ok(())
    }
}

fn parent_mut<'a>(
    root: &'a mut Value,
    keys: &[String],
    create: bool,
) -> Result<Option<&'a mut Map<String, Value>>, Refusal> {
    let mut cur = root.as_object_mut().ok_or(Refusal::NotAnObject)?;
    for k in keys {
        if !cur.contains_key(k) {
            if !create {
                return Ok(None);
            }
            cur.insert(k.clone(), Value::Object(Map::new()));
        }
        cur = match cur.get_mut(k) {
            Some(Value::Object(m)) => m,
            _ => return Err(Refusal::TypeConflict),
        };
    }
    Ok(Some(cur))
}

fn array_mut<'a>(
    root: &'a mut Value,
    path: &[String],
) -> Result<Option<&'a mut Vec<Value>>, Refusal> {
    let (last, parents) = path.split_last().ok_or(Refusal::Internal)?;
    match parent_mut(root, parents, false)? {
        None => Ok(None),
        Some(p) => match p.get_mut(last) {
            None => Ok(None),
            Some(Value::Array(a)) => Ok(Some(a)),
            Some(_) => Err(Refusal::TypeConflict),
        },
    }
}

/// The value at `path`, if every key exists.
pub fn value_at<'a>(root: &'a Value, path: &[String]) -> Option<&'a Value> {
    path.iter().try_fold(root, |v, k| v.as_object()?.get(k))
}

/// What a concrete-syntax editor performs: array edits are resolved to
/// indexes on the parsed value first, so editors never compare elements.
///
/// `Debug` (ruling F1, privacy) prints the variant and the key-path depth
/// only, for the same reason as [`Edit`].
#[derive(Clone)]
pub enum Op {
    /// Set a key (creating parents).
    Set(Vec<String>, Node),
    /// Remove a key.
    Remove(Vec<String>),
    /// Append an element (creating the array).
    Append(Vec<String>, Node),
    /// Remove the element at an index.
    RemoveAt(Vec<String>, usize),
}

impl std::fmt::Debug for Op {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (variant, depth) = match self {
            Op::Set(path, _) => ("Set", path.len()),
            Op::Remove(path) => ("Remove", path.len()),
            Op::Append(path, _) => ("Append", path.len()),
            Op::RemoveAt(path, _) => ("RemoveAt", path.len()),
        };
        write!(f, "Op::{variant}(path_depth={depth})")
    }
}

/// Resolve `edits` against the parsed file `old`. The array edits are
/// simulated in order on a copy, so a later edit sees the earlier ones.
pub fn lower(edits: &[Edit], old: &Value) -> Result<Vec<Op>, Refusal> {
    let mut sim = old.clone();
    let mut ops = Vec::new();
    for e in edits {
        match e {
            Edit::Set { path, value } => ops.push(Op::Set(path.clone(), value.clone())),
            Edit::Remove { path } => {
                if value_at(&sim, path).is_some() {
                    ops.push(Op::Remove(path.clone()));
                }
            }
            Edit::Push { path, value } => {
                let v = value.to_json();
                let present = match value_at(&sim, path) {
                    None => false,
                    Some(Value::Array(a)) => a.contains(&v),
                    Some(_) => return Err(Refusal::TypeConflict),
                };
                if !present {
                    ops.push(Op::Append(path.clone(), value.clone()));
                }
            }
            Edit::Pull { .. } | Edit::PullMatching { .. } => {
                if let Some(Value::Array(a)) = value_at(&sim, e.path()) {
                    let hit = |x: &Value| match e {
                        Edit::Pull { value, .. } => *x == value.to_json(),
                        Edit::PullMatching { marker, .. } => {
                            x.to_string().contains(marker.as_str())
                        }
                        _ => false,
                    };
                    let idx: Vec<usize> = a
                        .iter()
                        .enumerate()
                        .filter(|(_, x)| hit(x))
                        .map(|(i, _)| i)
                        .collect();
                    for i in idx.into_iter().rev() {
                        ops.push(Op::RemoveAt(e.path().to_vec(), i));
                    }
                }
            }
        }
        e.apply_to(&mut sim)?;
    }
    Ok(ops)
}
