//! Apply and revert over several files of one harness, with the backup
//! written before the first file changes (spec §4.2).

use serde_json::Value;

use crate::backup::{Backup, BackupStore, EditRecord, FileRecord, RevertReport};
use crate::edit::{edit_text, parse_standard};
use crate::fsio::{self, Snapshot, WriteError};
use crate::model::{AdapterError, ConfigFile, DriftItem, FileRole, HarnessId, Refusal};
use crate::node::{Edit, Format, value_at};

/// Attempts before [`AdapterError::Changed`].
pub const ATTEMPTS: u32 = 3;

fn text_of(
    snap: &Snapshot,
    format: Format,
    role: FileRole,
    edits: &[Edit],
) -> Result<String, AdapterError> {
    match &snap.bytes {
        Some(b) => String::from_utf8(b.clone())
            .map_err(|_| AdapterError::cannot(role, Refusal::Syntax, edits)),
        None => format
            .empty_document()
            .map(str::to_string)
            .ok_or_else(|| AdapterError::cannot(role, Refusal::NotAnObject, edits)),
    }
}

/// The parsed current value of `file` (an empty object when missing).
pub fn current_value(file: &ConfigFile) -> Result<Value, AdapterError> {
    let snap = fsio::read(&file.path).map_err(|e| AdapterError::Io {
        role: file.role,
        kind: e.kind(),
    })?;
    let text = text_of(&snap, file.format, file.role, &[])?;
    parse_standard(file.format, &text).map_err(|r| AdapterError::cannot(file.role, r, &[]))
}

fn records_for(edits: &[Edit], old: &Value) -> Result<Vec<EditRecord>, Refusal> {
    let mut sim = old.clone();
    let mut out = Vec::new();
    for e in edits {
        let rec = match e {
            Edit::Set { path, value } => EditRecord::Set {
                path: path.clone(),
                before: value_at(&sim, path).cloned(),
                after: value.to_json(),
                created_parents: created_parents(&sim, path),
            },
            Edit::Remove { path } => EditRecord::Remove {
                path: path.clone(),
                before: value_at(&sim, path).cloned(),
            },
            Edit::Push { path, value } => {
                let v = value.to_json();
                let was_present = value_at(&sim, path)
                    .and_then(Value::as_array)
                    .is_some_and(|a| a.contains(&v));
                EditRecord::Push {
                    path: path.clone(),
                    value: v,
                    was_present,
                    created_array: value_at(&sim, path).is_none(),
                    created_parents: created_parents(&sim, path),
                }
            }
            Edit::Pull { path, .. } | Edit::PullMatching { path, .. } => {
                EditRecord::Pull { path: path.clone() }
            }
        };
        e.apply_to(&mut sim)?;
        out.push(rec);
    }
    Ok(out)
}

fn matches(pattern: &[&str], path: &[String]) -> bool {
    pattern.len() == path.len() && pattern.iter().zip(path).all(|(p, k)| *p == "*" || p == k)
}

/// Every edit's path matches one of `owned`'s patterns for its file (`*`
/// matches one segment). Checked before anything is read or written.
pub fn check_owned(
    owned: &[(FileRole, &[&str])],
    files: &[(ConfigFile, Vec<Edit>)],
) -> Result<(), AdapterError> {
    for (f, edits) in files {
        for e in edits {
            if !owned
                .iter()
                .any(|(r, pat)| *r == f.role && matches(pat, e.path()))
            {
                return Err(AdapterError::cannot(f.role, Refusal::Internal, edits));
            }
        }
    }
    Ok(())
}

/// Apply `edits` to each file. Two phases: every file is read and edited in
/// memory first, and one refusal writes nothing at all; then the files are
/// written in order. The backup chains onto the active backup of `h` if
/// there is one. Returns the new active backup.
pub fn apply_files(
    store: &BackupStore,
    h: HarnessId,
    owned: &[(FileRole, &[&str])],
    files: Vec<(ConfigFile, Vec<Edit>)>,
) -> Result<Backup, AdapterError> {
    apply_files_with(store, h, owned, files, &|_, _| {})
}

/// [`apply_files`] with a callback before each compare (tests).
pub(crate) fn apply_files_with(
    store: &BackupStore,
    h: HarnessId,
    owned: &[(FileRole, &[&str])],
    files: Vec<(ConfigFile, Vec<Edit>)>,
    race: &dyn Fn(FileRole, u32),
) -> Result<Backup, AdapterError> {
    check_owned(owned, &files)?;
    let files: Vec<(ConfigFile, Vec<Edit>)> =
        files.into_iter().filter(|(_, e)| !e.is_empty()).collect();
    // Phase 1: a dry run over every file before the first write.
    for (file, edits) in &files {
        let snap = fsio::read(&file.path).map_err(|e| AdapterError::Io {
            role: file.role,
            kind: e.kind(),
        })?;
        let text = text_of(&snap, file.format, file.role, edits)?;
        edit_text(file.format, &text, edits)
            .map_err(|r| AdapterError::cannot(file.role, r, edits))?;
    }
    let prev = store.active(h);
    if files.is_empty() {
        if let Some(p) = prev {
            return Ok(p);
        }
    }
    let mut b = store.create(h)?;
    if let Some(p) = &prev {
        // Final review T3-M2: a failed chain copy must not leave the new
        // directory behind. It has no manifest, so no list, prune, or revert
        // would ever see it, yet it can hold a plaintext copy.
        let chained = p.files.iter().filter(|f| f.full_copy).try_for_each(|f| {
            let bytes = std::fs::read(p.copy_path(f.role)).map_err(|_| AdapterError::Backup)?;
            b.save_copy(f.role, &bytes)
        });
        if let Err(e) = chained {
            let _ = store.delete(&b);
            return Err(e);
        }
        b.files = p.files.clone();
    }
    // Phase 2: the writes.
    let mut written = 0usize;
    let result = apply_each(&mut b, &files, race, &mut written);
    if let Err(e) = result {
        // Nothing written: the new backup is dropped and the previous one
        // stays active. Something written: the new backup is how those files
        // are reverted, so it becomes the active one.
        if written == 0 {
            let _ = store.delete(&b);
        } else {
            b.save()?;
            supersede(prev)?;
            store.prune(h);
        }
        return Err(e);
    }
    b.save()?;
    supersede(prev)?;
    store.prune(h);
    Ok(b)
}

fn supersede(prev: Option<Backup>) -> Result<(), AdapterError> {
    if let Some(mut p) = prev {
        p.superseded = true;
        p.save()?;
    }
    Ok(())
}

/// Undo what one failed attempt staged (review C1): a record it created
/// goes, with its full copy; a chained record gets its records and hash
/// back. The backup then describes only bytes that were actually edited.
fn drop_attempt(b: &mut Backup, idx: usize, created: bool, base: usize, sha_after: String) {
    if created {
        let role = b.files[idx].role;
        let _ = std::fs::remove_file(b.copy_path(role));
        b.files.remove(idx);
    } else {
        b.files[idx].records.truncate(base);
        b.files[idx].sha_after = sha_after;
    }
}

fn apply_each(
    b: &mut Backup,
    files: &[(ConfigFile, Vec<Edit>)],
    race: &dyn Fn(FileRole, u32),
    written: &mut usize,
) -> Result<(), AdapterError> {
    for (file, edits) in files {
        let mut done = false;
        for attempt in 0..ATTEMPTS {
            let snap = fsio::read(&file.path).map_err(|e| AdapterError::Io {
                role: file.role,
                kind: e.kind(),
            })?;
            let text = text_of(&snap, file.format, file.role, edits)?;
            let old = parse_standard(file.format, &text)
                .map_err(|r| AdapterError::cannot(file.role, r, edits))?;
            let new_text = edit_text(file.format, &text, edits)
                .map_err(|r| AdapterError::cannot(file.role, r, edits))?;
            let records =
                records_for(edits, &old).map_err(|r| AdapterError::cannot(file.role, r, edits))?;
            // Stage the backup before the file changes.
            let (idx, created) = match b.files.iter().position(|f| f.role == file.role) {
                Some(i) => {
                    // Chained onto an earlier apply: if the file changed since
                    // then, restoring the pre-inumaki bytes would lose that
                    // change, so revert must go key by key.
                    if snap.sha.as_deref() != Some(b.files[i].sha_after.as_str()) {
                        b.files[i].byte_exact_ok = false;
                    }
                    (i, false)
                }
                None => {
                    // Never a copy of `~/.claude.json`, whatever the adapter asks
                    // for (spec §4.2): it holds account state and MCP secrets.
                    let full_copy =
                        file.full_copy && file.role != FileRole::ClaudeJson && snap.bytes.is_some();
                    if full_copy {
                        b.save_copy(file.role, snap.bytes.as_deref().unwrap_or_default())?;
                    }
                    b.files.push(FileRecord {
                        role: file.role,
                        path: snap.target.clone(),
                        format: file.format,
                        existed: snap.bytes.is_some(),
                        sha_before: snap.sha.clone(),
                        sha_after: String::new(),
                        mode: snap.mode,
                        full_copy,
                        byte_exact_ok: true,
                        records: Vec::new(),
                    });
                    (b.files.len() - 1, true)
                }
            };
            let base = b.files[idx].records.len();
            let old_sha_after = b.files[idx].sha_after.clone();
            b.files[idx].records.extend(records);
            b.files[idx].sha_after = fsio::sha256_hex(new_text.as_bytes());
            b.save()?;
            race(file.role, attempt);
            match fsio::write_if_unchanged(&snap, new_text.as_bytes()) {
                Ok(()) => {
                    *written += 1;
                    done = true;
                    break;
                }
                Err(WriteError::Changed) => {
                    drop_attempt(b, idx, created, base, old_sha_after);
                    b.save()?;
                    continue;
                }
                Err(WriteError::Io(kind)) => {
                    drop_attempt(b, idx, created, base, old_sha_after);
                    b.save()?;
                    return Err(AdapterError::Io {
                        role: file.role,
                        kind,
                    });
                }
            }
        }
        if !done {
            return Err(AdapterError::Changed { role: file.role });
        }
    }
    Ok(())
}

/// `a` and `b` are the same value at `path` of `role`, apart from the
/// user-owned sub-keys there ([`crate::harness::user_subkeys`]: Codex's
/// `default_tools_approval_mode` on a gateway entry), which the user may
/// add, change, or remove without that counting as drift or a conflict.
fn same_owned(role: FileRole, path: &[String], a: Option<&Value>, b: Option<&Value>) -> bool {
    let user = crate::harness::user_subkeys(role, path);
    if user.is_empty() || a == b {
        return a == b;
    }
    let strip = |v: Option<&Value>| {
        v.cloned().map(|mut v| {
            if let Some(m) = v.as_object_mut() {
                for k in user {
                    m.remove(*k);
                }
            }
            v
        })
    };
    strip(a) == strip(b)
}

/// Owned keys whose current value is not what the backup's latest apply wrote.
pub fn drift(b: &Backup) -> Vec<DriftItem> {
    let mut out = Vec::new();
    for f in &b.files {
        let file = ConfigFile {
            role: f.role,
            path: f.path.clone(),
            format: f.format,
            full_copy: f.full_copy,
        };
        let Ok(cur) = current_value(&file) else {
            out.push(DriftItem {
                role: f.role,
                path: Vec::new(),
            });
            continue;
        };
        let mut last: std::collections::BTreeMap<Vec<String>, &EditRecord> = Default::default();
        for r in &f.records {
            match r {
                EditRecord::Set { path, .. } | EditRecord::Remove { path, .. } => {
                    last.insert(path.clone(), r);
                }
                EditRecord::Push { .. } | EditRecord::Pull { .. } => {}
            }
        }
        for (path, r) in last {
            let now = value_at(&cur, &path);
            let ok = match r {
                EditRecord::Set { after, .. } => same_owned(f.role, &path, now, Some(after)),
                EditRecord::Remove { .. } => now.is_none(),
                _ => true,
            };
            if !ok {
                out.push(DriftItem { role: f.role, path });
            }
        }
        for (i, r) in f.records.iter().enumerate() {
            if let EditRecord::Push { path, value, .. } = r {
                // A later pull on the same array removed our own element on
                // purpose (a re-applied hook entry): not drift (review I5).
                if f.records[i + 1..]
                    .iter()
                    .any(|later| matches!(later, EditRecord::Pull { path: p } if p == path))
                {
                    continue;
                }
                let present = value_at(&cur, path)
                    .and_then(Value::as_array)
                    .is_some_and(|a| a.contains(value));
                if !present {
                    out.push(DriftItem {
                        role: f.role,
                        path: path.clone(),
                    });
                }
            }
        }
    }
    out
}

/// How many of the innermost parent tables of `path` do not exist in `v`:
/// a `Set` at `path` creates exactly these.
fn created_parents(v: &Value, path: &[String]) -> usize {
    let parents = path.len().saturating_sub(1);
    let existing = (1..=parents)
        .take_while(|&n| value_at(v, &path[..n]).is_some_and(Value::is_object))
        .count();
    parents - existing
}

/// Revert edits computed against `cur`, newest record first: a key still
/// holding what inumaki wrote gets its previous value back; any other
/// value is a conflict and stays.
fn revert_edits(f: &FileRecord, cur: &Value) -> Result<(Vec<Edit>, Vec<DriftItem>), Refusal> {
    let mut sim = cur.clone();
    let mut edits = Vec::new();
    let mut conflicts = Vec::new();
    for r in f.records.iter().rev() {
        // Set when the edit removes a key that created its parent tables.
        let mut emptied = None;
        // Set when the edit pulls an element out of an array it created.
        let mut drains = None;
        let e = match r {
            EditRecord::Set {
                path,
                before,
                after,
                created_parents,
            } => {
                let now = value_at(&sim, path).cloned();
                if same_owned(f.role, path, now.as_ref(), Some(after)) {
                    Some(match before {
                        Some(v) => Edit::Set {
                            path: path.clone(),
                            value: json_node(v),
                        },
                        None => {
                            emptied = Some((path.as_slice(), *created_parents));
                            Edit::Remove { path: path.clone() }
                        }
                    })
                } else if !same_owned(f.role, path, now.as_ref(), before.as_ref()) {
                    conflicts.push(DriftItem {
                        role: f.role,
                        path: path.clone(),
                    });
                    None
                } else {
                    None
                }
            }
            EditRecord::Remove { path, before } => match (value_at(&sim, path), before) {
                (None, Some(v)) => Some(Edit::Set {
                    path: path.clone(),
                    value: json_node(v),
                }),
                (Some(_), Some(_)) => {
                    conflicts.push(DriftItem {
                        role: f.role,
                        path: path.clone(),
                    });
                    None
                }
                _ => None,
            },
            EditRecord::Push {
                path,
                value,
                was_present,
                created_array,
                created_parents,
            } => (!was_present).then(|| {
                if *created_array {
                    drains = Some((path.as_slice(), *created_parents));
                }
                Edit::Pull {
                    path: path.clone(),
                    value: json_node(value),
                }
            }),
            EditRecord::Pull { .. } => None,
        };
        if let Some(e) = e {
            e.apply_to(&mut sim)?;
            edits.push(e);
            if let Some((path, created)) = emptied {
                remove_emptied_parents(&mut sim, &mut edits, path, created)?;
            }
            // An array we created and now emptied goes like a key we set
            // with no previous value, with the tables that held it.
            if let Some((path, created)) = drains
                && value_at(&sim, path)
                    .and_then(Value::as_array)
                    .is_some_and(Vec::is_empty)
            {
                let remove = Edit::Remove {
                    path: path.to_vec(),
                };
                remove.apply_to(&mut sim)?;
                edits.push(remove);
                remove_emptied_parents(&mut sim, &mut edits, path, created)?;
            }
        }
    }
    Ok((edits, conflicts))
}

/// After removing a key that created its parent tables: remove each of those
/// tables (innermost first) that is now empty, so the file does not keep a
/// table that did not exist before Connect (the TOML editor drops an empty
/// implicit table, and the semantic check would see `{}` against nothing).
/// A table that existed before, or holds any other key, stays.
fn remove_emptied_parents(
    sim: &mut Value,
    edits: &mut Vec<Edit>,
    path: &[String],
    created: usize,
) -> Result<(), Refusal> {
    for n in 0..created.min(path.len().saturating_sub(1)) {
        let parent = &path[..path.len() - 1 - n];
        if !value_at(sim, parent)
            .and_then(Value::as_object)
            .is_some_and(|o| o.is_empty())
        {
            break;
        }
        let remove = Edit::Remove {
            path: parent.to_vec(),
        };
        remove.apply_to(sim)?;
        edits.push(remove);
    }
    Ok(())
}

/// A JSON value as a `Node` (object keys in `serde_json`'s order).
pub(crate) fn json_node(v: &Value) -> crate::node::Node {
    use crate::node::Node;
    match v {
        Value::Null => Node::Null,
        Value::Bool(b) => Node::Bool(*b),
        Value::Number(n) => n.as_i64().map_or_else(|| Node::Num(n.clone()), Node::Int),
        Value::String(s) => Node::Str(s.clone()),
        Value::Array(a) => Node::Arr(a.iter().map(json_node).collect()),
        Value::Object(m) => Node::Obj(m.iter().map(|(k, v)| (k.clone(), json_node(v))).collect()),
    }
}

/// Revert `b` (spec §4.2): byte for byte where the file is unchanged since
/// apply and a copy exists (or inumaki created it), key by key otherwise.
/// Deletes the backup afterwards unless `keep_after_revert`.
pub fn revert(store: &BackupStore, b: &Backup) -> Result<RevertReport, AdapterError> {
    let mut report = RevertReport::default();
    for f in &b.files {
        for _attempt in 0..ATTEMPTS {
            let snap = fsio::read(&f.path).map_err(|e| AdapterError::Io {
                role: f.role,
                kind: e.kind(),
            })?;
            let unchanged = snap.sha.as_deref() == Some(f.sha_after.as_str());
            let res = if snap.bytes.is_none() {
                // Deleted since apply (or already removed by an earlier,
                // interrupted revert): revert never creates a file. Keys
                // that held something before inumaki are reported.
                let empty = Value::Object(Default::default());
                let (_, conflicts) =
                    revert_edits(f, &empty).map_err(|r| AdapterError::cannot(f.role, r, &[]))?;
                report.key_level.push(f.role);
                report.conflicts.extend(conflicts);
                Ok(())
            } else if unchanged && f.existed && f.full_copy && f.byte_exact_ok {
                let bytes = std::fs::read(b.copy_path(f.role)).map_err(|_| AdapterError::Backup)?;
                fsio::write_if_unchanged(&snap, &bytes).map(|()| report.byte_exact.push(f.role))
            } else if unchanged && !f.existed && f.byte_exact_ok {
                fsio::remove_if_unchanged(&snap).map(|()| report.byte_exact.push(f.role))
            } else {
                let text = text_of(&snap, f.format, f.role, &[])?;
                let cur = parse_standard(f.format, &text)
                    .map_err(|r| AdapterError::cannot(f.role, r, &[]))?;
                let (edits, conflicts) =
                    revert_edits(f, &cur).map_err(|r| AdapterError::cannot(f.role, r, &[]))?;
                let new_text = edit_text(f.format, &text, &edits)
                    .map_err(|r| AdapterError::cannot(f.role, r, &edits))?;
                fsio::write_if_unchanged(&snap, new_text.as_bytes()).map(|()| {
                    report.key_level.push(f.role);
                    report.conflicts.extend(conflicts);
                })
            };
            match res {
                Ok(()) => break,
                Err(WriteError::Changed) => continue,
                Err(WriteError::Io(kind)) => return Err(AdapterError::Io { role: f.role, kind }),
            }
        }
    }
    let done = report.byte_exact.len() + report.key_level.len();
    if done != b.files.len() {
        let role = b
            .files
            .iter()
            .map(|f| f.role)
            .find(|r| !report.byte_exact.contains(r) && !report.key_level.contains(r));
        return Err(AdapterError::Changed {
            role: role.unwrap_or(FileRole::ClaudeJson),
        });
    }
    if b.keep_after_revert {
        let mut kept = b.clone();
        kept.reverted = true;
        kept.save()?;
        report.kept = true;
    } else {
        store.delete(b)?;
    }
    Ok(report)
}

/// Rewrite owned keys of one file outside an apply (an adapter's own step
/// of a revert). `plan` computes the edits from the current value on every
/// attempt; the owned-key check and the semantic guard run as in an apply,
/// and the write is compare-and-rename with [`ATTEMPTS`] tries. No backup
/// is made. A missing file is never created. `Ok(false)`: nothing to change.
pub fn rewrite_owned(
    owned: &[(FileRole, &[&str])],
    file: &ConfigFile,
    plan: &dyn Fn(&Value) -> Vec<Edit>,
) -> Result<bool, AdapterError> {
    for _ in 0..ATTEMPTS {
        let snap = fsio::read(&file.path).map_err(|e| AdapterError::Io {
            role: file.role,
            kind: e.kind(),
        })?;
        if snap.bytes.is_none() {
            return Ok(false);
        }
        let text = text_of(&snap, file.format, file.role, &[])?;
        let cur = parse_standard(file.format, &text)
            .map_err(|r| AdapterError::cannot(file.role, r, &[]))?;
        let edits = plan(&cur);
        if edits.is_empty() {
            return Ok(false);
        }
        check_owned(owned, &[(file.clone(), edits.clone())])?;
        let new_text = edit_text(file.format, &text, &edits)
            .map_err(|r| AdapterError::cannot(file.role, r, &edits))?;
        match fsio::write_if_unchanged(&snap, new_text.as_bytes()) {
            Ok(()) => return Ok(true),
            Err(WriteError::Changed) => continue,
            Err(WriteError::Io(kind)) => {
                return Err(AdapterError::Io {
                    role: file.role,
                    kind,
                });
            }
        }
    }
    Err(AdapterError::Changed { role: file.role })
}

/// Unprotect one entry (spec §4.5): restore the value at `path` of `role`
/// from the backup if it still holds what inumaki wrote, and drop those
/// records. `false`: someone else changed it; nothing was written.
pub fn restore_key(b: &mut Backup, role: FileRole, path: &[String]) -> Result<bool, AdapterError> {
    let Some(i) = b.files.iter().position(|f| f.role == role) else {
        return Ok(false);
    };
    let mut only = b.files[i].clone();
    only.records.retain(|r| matches!(r, EditRecord::Set { path: p, .. } | EditRecord::Remove { path: p, .. } if p.as_slice() == path));
    let file = ConfigFile {
        role,
        path: only.path.clone(),
        format: only.format,
        full_copy: only.full_copy,
    };
    for _ in 0..ATTEMPTS {
        let snap = fsio::read(&file.path).map_err(|e| AdapterError::Io {
            role,
            kind: e.kind(),
        })?;
        let text = text_of(&snap, file.format, role, &[])?;
        let cur =
            parse_standard(file.format, &text).map_err(|r| AdapterError::cannot(role, r, &[]))?;
        let (edits, conflicts) =
            revert_edits(&only, &cur).map_err(|r| AdapterError::cannot(role, r, &[]))?;
        if !conflicts.is_empty() {
            return Ok(false);
        }
        let new_text = edit_text(file.format, &text, &edits)
            .map_err(|r| AdapterError::cannot(role, r, &edits))?;
        match fsio::write_if_unchanged(&snap, new_text.as_bytes()) {
            Ok(()) => {
                b.files[i].records.retain(|r| !matches!(r, EditRecord::Set { path: p, .. } | EditRecord::Remove { path: p, .. } if p.as_slice() == path));
                b.files[i].sha_after = fsio::sha256_hex(new_text.as_bytes());
                b.save()?;
                return Ok(true);
            }
            Err(WriteError::Changed) => continue,
            Err(WriteError::Io(kind)) => return Err(AdapterError::Io { role, kind }),
        }
    }
    Err(AdapterError::Changed { role })
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use crate::node::Node;

    fn file(dir: &std::path::Path) -> ConfigFile {
        ConfigFile {
            role: FileRole::ClaudeSettings,
            path: dir.join("settings.json"),
            format: Format::Json,
            full_copy: true,
        }
    }

    fn set(k: &str) -> Vec<Edit> {
        vec![Edit::Set {
            path: vec!["env".into(), k.into()],
            value: Node::s("http://127.0.0.1:8787/anthropic"),
        }]
    }

    const OWNED: &[(FileRole, &[&str])] = &[(FileRole::ClaudeSettings, &["env", "*"])];

    /// Review Focus 1.
    #[test]
    fn a_concurrent_write_is_retried_then_given_up_without_writing() {
        let d = tempfile::tempdir().unwrap();
        let store = BackupStore::new(&d.path().join("data"));
        let f = file(d.path());
        std::fs::write(&f.path, "{\"a\": 1}\n").unwrap();
        // Once: the harness writes between our read and our compare; we retry
        // on its bytes and keep its change.
        let n = Cell::new(0);
        let race = |_: FileRole, _: u32| {
            if n.get() == 0 {
                std::fs::write(&f.path, "{\"a\": 2}\n").unwrap();
            }
            n.set(n.get() + 1);
        };
        let b = apply_files_with(
            &store,
            HarnessId::ClaudeCode,
            OWNED,
            vec![(f.clone(), set("ANTHROPIC_BASE_URL"))],
            &race,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&f.path).unwrap()).unwrap();
        assert_eq!(v["a"], 2, "the harness's write survives");
        assert_eq!(
            v["env"]["ANTHROPIC_BASE_URL"],
            "http://127.0.0.1:8787/anthropic"
        );
        // Review C1: the backup holds the bytes actually edited, so a revert
        // returns to the harness's version, not to the pre-race bytes.
        revert(&store, &b).unwrap();
        assert_eq!(std::fs::read_to_string(&f.path).unwrap(), "{\"a\": 2}\n");
        // Always: give up after ATTEMPTS, file untouched.
        std::fs::write(&f.path, "{\"b\": 0}\n").unwrap();
        let k = Cell::new(0);
        let always = |_: FileRole, _: u32| {
            k.set(k.get() + 1);
            std::fs::write(&f.path, format!("{{\"b\": {}}}\n", k.get())).unwrap();
        };
        let e = apply_files_with(
            &store,
            HarnessId::ClaudeCode,
            OWNED,
            vec![(f.clone(), set("X"))],
            &always,
        )
        .unwrap_err();
        assert!(matches!(e, AdapterError::Changed { .. }), "{e}");
        assert_eq!(
            std::fs::read_to_string(&f.path).unwrap(),
            format!("{{\"b\": {ATTEMPTS}}}\n")
        );
        assert!(
            store.list(HarnessId::ClaudeCode).is_empty(),
            "the failed apply left no backup behind"
        );
    }

    /// The file at `path` with `key` set to `v`, as a harness would write it.
    fn harness_writes(path: &std::path::Path, key: &str, v: i64) {
        let mut j: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        j[key] = v.into();
        std::fs::write(path, serde_json::to_string_pretty(&j).unwrap()).unwrap();
    }

    /// Review Focus 1, connected case: a race on a chained apply stages
    /// only the bytes actually edited, and a failed chained apply never
    /// touches the previous backup.
    #[test]
    fn a_race_on_a_chained_apply_keeps_the_previous_backup_and_the_harness_change() {
        let d = tempfile::tempdir().unwrap();
        let f = file(d.path());
        let none = |_: FileRole, _: u32| {};
        let read = || -> Value {
            serde_json::from_str(&std::fs::read_to_string(&f.path).unwrap()).unwrap()
        };

        // (1) + (2): A, then B racing once.
        let store = BackupStore::new(&d.path().join("data"));
        std::fs::write(&f.path, "{\"a\": 1}\n").unwrap();
        let a = apply_files_with(
            &store,
            HarnessId::ClaudeCode,
            OWNED,
            vec![(f.clone(), set("K1"))],
            &none,
        )
        .unwrap();
        let race_once = |_: FileRole, attempt: u32| {
            if attempt == 0 {
                harness_writes(&f.path, "h", 1);
            }
        };
        let b = apply_files_with(
            &store,
            HarnessId::ClaudeCode,
            OWNED,
            vec![(f.clone(), set("K2"))],
            &race_once,
        )
        .unwrap();
        let v = read();
        assert_eq!(v["h"], 1, "the harness's write survives");
        assert_eq!(v["env"]["K1"], "http://127.0.0.1:8787/anthropic");
        assert_eq!(v["env"]["K2"], "http://127.0.0.1:8787/anthropic");
        let rec = b.file(FileRole::ClaudeSettings).unwrap();
        assert_eq!(
            rec.records.len(),
            2,
            "one record per apply: the failed attempt's record was dropped"
        );
        assert_eq!(
            rec.sha_after,
            fsio::sha256_hex(&std::fs::read(&f.path).unwrap())
        );
        assert!(!rec.byte_exact_ok, "the file changed between the applies");
        assert_eq!(store.active(HarnessId::ClaudeCode).unwrap().id, b.id);
        assert!(store.load(HarnessId::ClaudeCode, &a.id).unwrap().superseded);
        revert(&store, &b).unwrap();
        let v = read();
        assert_eq!(v["h"], 1, "revert keeps the harness's change");
        assert_eq!(v["a"], 1);
        assert!(
            v.get("env").and_then(|e| e.get("K1")).is_none() && v["env"].get("K2").is_none(),
            "our keys are gone"
        );

        // (3): a fresh store with A active, then an always-racing apply.
        let store = BackupStore::new(&d.path().join("data2"));
        std::fs::write(&f.path, "{\"a\": 1}\n").unwrap();
        let a = apply_files_with(
            &store,
            HarnessId::ClaudeCode,
            OWNED,
            vec![(f.clone(), set("K1"))],
            &none,
        )
        .unwrap();
        let manifest = std::fs::read(a.dir.join("manifest.json")).unwrap();
        let k = Cell::new(0);
        let always = |_: FileRole, _: u32| {
            k.set(k.get() + 1);
            harness_writes(&f.path, "h", k.get());
        };
        let e = apply_files_with(
            &store,
            HarnessId::ClaudeCode,
            OWNED,
            vec![(f.clone(), set("K2"))],
            &always,
        )
        .unwrap_err();
        assert!(matches!(e, AdapterError::Changed { .. }), "{e}");
        let active = store.active(HarnessId::ClaudeCode).unwrap();
        assert_eq!(active.id, a.id, "the previous backup stays active");
        assert!(!active.superseded);
        assert_eq!(
            store.list(HarnessId::ClaudeCode),
            vec![a.id.clone()],
            "the failed apply left no backup behind"
        );
        assert_eq!(
            std::fs::read(a.dir.join("manifest.json")).unwrap(),
            manifest,
            "A's manifest is untouched"
        );
        assert_eq!(
            std::fs::read(a.copy_path(FileRole::ClaudeSettings)).unwrap(),
            b"{\"a\": 1}\n",
            "A's copy is intact"
        );
        let v = read();
        assert!(
            v["env"].get("K2").is_none(),
            "the failed apply wrote nothing"
        );
        revert(&store, &active).unwrap();
        let v = read();
        assert_eq!(v["h"], ATTEMPTS, "revert keeps the harness's change");
        assert!(v["env"].get("K1").is_none(), "A's key is reverted");
    }
}
