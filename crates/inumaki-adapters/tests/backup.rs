//! Backup safety and revert (spec §4.2, §11).

use std::os::unix::fs::PermissionsExt;

use inumaki_adapters::engine::{apply_files, drift, revert};
use inumaki_adapters::{BackupStore, ConfigFile, Edit, FileRole, Format, HarnessId, Node};

fn p(keys: &[&str]) -> Vec<String> {
    keys.iter().map(|k| k.to_string()).collect()
}

const OWNED: &[(FileRole, &[&str])] = &[
    (FileRole::ClaudeSettings, &["env", "*"]),
    (
        FileRole::ClaudeSettings,
        &["permissions", "additionalDirectories"],
    ),
    (FileRole::ClaudeJson, &["mcpServers", "*"]),
];

const SETTINGS: &str = "{\n  // not strict: refused\n}\n";
const SETTINGS_OK: &str = "{\n  \"permissions\": {\"allow\": [\"Bash(ls)\"]},\n  \"env\": {}\n}\n";
const CLAUDE_JSON: &str = "{\"numStartups\": 7, \"mcpServers\": {\"crm\": {\"command\": \"/bin/crm\", \"env\": {\"CRM_TOKEN\": \"s3cret-qwxzvk\"}}}}\n";

fn files(dir: &std::path::Path) -> (ConfigFile, ConfigFile) {
    (
        ConfigFile {
            role: FileRole::ClaudeSettings,
            path: dir.join("settings.json"),
            format: Format::Json,
            full_copy: true,
        },
        ConfigFile {
            role: FileRole::ClaudeJson,
            path: dir.join("claude.json"),
            format: Format::Json,
            full_copy: false,
        },
    )
}

fn gw() -> Node {
    Node::obj([
        ("type", Node::s("http")),
        ("url", Node::s("http://127.0.0.1:8789/mcp/mcp-crm")),
        (
            "headers",
            Node::obj([("Authorization", Node::s("Bearer t"))]),
        ),
    ])
}

#[test]
fn backups_are_private_and_claude_json_is_never_copied() {
    let d = tempfile::tempdir().unwrap();
    let (s, c) = files(d.path());
    std::fs::write(&s.path, SETTINGS_OK).unwrap();
    std::fs::write(&c.path, CLAUDE_JSON).unwrap();
    let store = BackupStore::new(&d.path().join("data"));
    let b = apply_files(
        &store,
        HarnessId::ClaudeCode,
        OWNED,
        vec![
            (
                s.clone(),
                vec![Edit::Push {
                    path: p(&["permissions", "additionalDirectories"]),
                    value: Node::s("/m"),
                }],
            ),
            (
                c.clone(),
                vec![Edit::Set {
                    path: p(&["mcpServers", "crm"]),
                    value: gw(),
                }],
            ),
        ],
    )
    .unwrap();
    assert_eq!(
        std::fs::metadata(&b.dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for e in std::fs::read_dir(&b.dir).unwrap().flatten() {
        assert_eq!(
            e.metadata().unwrap().permissions().mode() & 0o777,
            0o600,
            "{:?}",
            e.file_name()
        );
    }
    assert!(b.copy_path(FileRole::ClaudeSettings).exists());
    assert!(
        !b.copy_path(FileRole::ClaudeJson).exists(),
        "no plaintext copy of ~/.claude.json"
    );
    assert!(!format!("{b:?}").contains("qwxzvk"));
}

#[test]
fn revert_is_byte_exact_when_unchanged_and_key_level_after_an_external_edit() {
    let d = tempfile::tempdir().unwrap();
    let (s, c) = files(d.path());
    std::fs::write(&s.path, SETTINGS_OK).unwrap();
    std::fs::write(&c.path, CLAUDE_JSON).unwrap();
    let store = BackupStore::new(&d.path().join("data"));
    let plan = || {
        vec![
            (
                s.clone(),
                vec![Edit::Set {
                    path: p(&["env", "ANTHROPIC_BASE_URL"]),
                    value: Node::s("http://127.0.0.1:8787/anthropic"),
                }],
            ),
            (
                c.clone(),
                vec![Edit::Set {
                    path: p(&["mcpServers", "crm"]),
                    value: gw(),
                }],
            ),
        ]
    };
    // Unchanged since apply: settings byte-exact, claude.json key-level
    // (no copy), and both end byte-identical to the input.
    let b = apply_files(&store, HarnessId::ClaudeCode, OWNED, plan()).unwrap();
    let r = revert(&store, &b).unwrap();
    assert_eq!(r.byte_exact, vec![FileRole::ClaudeSettings]);
    assert_eq!(std::fs::read_to_string(&s.path).unwrap(), SETTINGS_OK);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&std::fs::read_to_string(&c.path).unwrap())
            .unwrap(),
        serde_json::from_str::<serde_json::Value>(CLAUDE_JSON).unwrap()
    );
    assert!(!b.dir.exists(), "deleted after a successful revert");
    // External edits since apply: the user's key survives, the conflict is reported.
    let b = apply_files(&store, HarnessId::ClaudeCode, OWNED, plan()).unwrap();
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&s.path).unwrap()).unwrap();
    v["env"]["USER_KEY"] = "kept".into();
    v["env"]["ANTHROPIC_BASE_URL"] = "https://elsewhere.example".into();
    std::fs::write(&s.path, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    assert_eq!(drift(&b).len(), 1);
    let r = revert(&store, &b).unwrap();
    assert_eq!(r.conflicts.len(), 1);
    let after: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&s.path).unwrap()).unwrap();
    assert_eq!(after["env"]["USER_KEY"], "kept");
    assert_eq!(
        after["env"]["ANTHROPIC_BASE_URL"], "https://elsewhere.example",
        "a key someone else changed is left alone"
    );
}

#[test]
fn a_second_apply_chains_and_revert_returns_to_before_inumaki() {
    let d = tempfile::tempdir().unwrap();
    let (s, _) = files(d.path());
    std::fs::write(&s.path, SETTINGS_OK).unwrap();
    let store = BackupStore::new(&d.path().join("data"));
    let set = |u: &str| {
        vec![(
            s.clone(),
            vec![Edit::Set {
                path: p(&["env", "ANTHROPIC_BASE_URL"]),
                value: Node::s(u),
            }],
        )]
    };
    apply_files(&store, HarnessId::ClaudeCode, OWNED, set("http://a")).unwrap();
    let b2 = apply_files(&store, HarnessId::ClaudeCode, OWNED, set("http://b")).unwrap();
    assert_eq!(store.active(HarnessId::ClaudeCode).unwrap().id, b2.id);
    revert(&store, &b2).unwrap();
    assert_eq!(std::fs::read_to_string(&s.path).unwrap(), SETTINGS_OK);
}

#[test]
fn a_symlinked_file_is_edited_at_its_target() {
    let d = tempfile::tempdir().unwrap();
    let target = d.path().join("dotfiles-settings.json");
    std::fs::write(&target, SETTINGS_OK).unwrap();
    let link = d.path().join("settings.json");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let store = BackupStore::new(&d.path().join("data"));
    let f = ConfigFile {
        role: FileRole::ClaudeSettings,
        path: link.clone(),
        format: Format::Json,
        full_copy: true,
    };
    let b = apply_files(
        &store,
        HarnessId::ClaudeCode,
        OWNED,
        vec![(
            f,
            vec![Edit::Set {
                path: p(&["env", "K"]),
                value: Node::s("v"),
            }],
        )],
    )
    .unwrap();
    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink(),
        "the symlink stays"
    );
    assert!(std::fs::read_to_string(&target).unwrap().contains("\"K\""));
    revert(&store, &b).unwrap();
    assert_eq!(std::fs::read_to_string(&target).unwrap(), SETTINGS_OK);
}

#[test]
fn a_file_that_cannot_be_edited_is_not_written_and_gets_a_snippet() {
    let d = tempfile::tempdir().unwrap();
    let (s, _) = files(d.path());
    std::fs::write(&s.path, SETTINGS).unwrap();
    let store = BackupStore::new(&d.path().join("data"));
    let e = apply_files(
        &store,
        HarnessId::ClaudeCode,
        OWNED,
        vec![(
            s.clone(),
            vec![Edit::Set {
                path: p(&["env", "K"]),
                value: Node::s("v"),
            }],
        )],
    )
    .unwrap_err();
    assert!(e.snippet().unwrap().contains("env → K"));
    assert_eq!(std::fs::read_to_string(&s.path).unwrap(), SETTINGS);
}

#[test]
fn retention_keeps_five_and_never_the_active_one() {
    let d = tempfile::tempdir().unwrap();
    let (s, _) = files(d.path());
    std::fs::write(&s.path, SETTINGS_OK).unwrap();
    let store = BackupStore::new(&d.path().join("data"));
    for i in 0..8 {
        apply_files(
            &store,
            HarnessId::ClaudeCode,
            OWNED,
            vec![(
                s.clone(),
                vec![Edit::Set {
                    path: p(&["env", "K"]),
                    value: Node::Int(i),
                }],
            )],
        )
        .unwrap();
    }
    assert_eq!(
        store.list(HarnessId::ClaudeCode).len(),
        inumaki_adapters::backup::RETENTION
    );
    assert!(store.active(HarnessId::ClaudeCode).is_some());
}

/// Review C1 (chained applies).
#[test]
fn a_user_edit_between_two_applies_survives_revert() {
    let d = tempfile::tempdir().unwrap();
    let (s, _) = files(d.path());
    std::fs::write(&s.path, SETTINGS_OK).unwrap();
    let store = BackupStore::new(&d.path().join("data"));
    let set = |u: &str| {
        vec![(
            s.clone(),
            vec![Edit::Set {
                path: p(&["env", "ANTHROPIC_BASE_URL"]),
                value: Node::s(u),
            }],
        )]
    };
    apply_files(&store, HarnessId::ClaudeCode, OWNED, set("http://a")).unwrap();
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&s.path).unwrap()).unwrap();
    v["env"]["USER_KEY"] = "kept".into();
    std::fs::write(&s.path, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    let b2 = apply_files(&store, HarnessId::ClaudeCode, OWNED, set("http://b")).unwrap();
    revert(&store, &b2).unwrap();
    let after: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&s.path).unwrap()).unwrap();
    assert_eq!(
        after["env"]["USER_KEY"], "kept",
        "the edit made between the applies survives"
    );
    assert!(after["env"].get("ANTHROPIC_BASE_URL").is_none());
}

/// Review I1 and I3.
#[test]
fn unowned_keys_and_any_refusal_write_no_file() {
    let d = tempfile::tempdir().unwrap();
    let (s, c) = files(d.path());
    std::fs::write(&s.path, SETTINGS_OK).unwrap();
    std::fs::write(&c.path, CLAUDE_JSON).unwrap();
    let store = BackupStore::new(&d.path().join("data"));
    // A key outside OWNED.
    let e = apply_files(
        &store,
        HarnessId::ClaudeCode,
        OWNED,
        vec![(
            c.clone(),
            vec![Edit::Set {
                path: p(&["numStartups"]),
                value: Node::Int(0),
            }],
        )],
    )
    .unwrap_err();
    assert!(
        matches!(
            e,
            inumaki_adapters::AdapterError::CannotEditSafely {
                reason: inumaki_adapters::Refusal::Internal,
                ..
            }
        ),
        "{e}"
    );
    // The second file refuses (a comment in strict JSON): the first is not written either.
    std::fs::write(&s.path, SETTINGS).unwrap();
    let e = apply_files(
        &store,
        HarnessId::ClaudeCode,
        OWNED,
        vec![
            (
                c.clone(),
                vec![Edit::Set {
                    path: p(&["mcpServers", "crm"]),
                    value: gw(),
                }],
            ),
            (
                s.clone(),
                vec![Edit::Set {
                    path: p(&["env", "K"]),
                    value: Node::s("v"),
                }],
            ),
        ],
    )
    .unwrap_err();
    assert!(e.snippet().is_some());
    assert_eq!(std::fs::read_to_string(&c.path).unwrap(), CLAUDE_JSON);
    assert!(store.list(HarnessId::ClaudeCode).is_empty());
}

/// Revert never creates a file: one deleted since apply stays deleted, and
/// a key that held something before inumaki is reported as a conflict.
#[test]
fn revert_does_not_recreate_a_file_deleted_since_apply() {
    let d = tempfile::tempdir().unwrap();
    let (s, c) = files(d.path());
    std::fs::write(&c.path, CLAUDE_JSON).unwrap();
    let store = BackupStore::new(&d.path().join("data"));
    let b = apply_files(
        &store,
        HarnessId::ClaudeCode,
        OWNED,
        vec![
            (
                s.clone(),
                vec![Edit::Set {
                    path: p(&["env", "K"]),
                    value: Node::s("v"),
                }],
            ),
            (
                c.clone(),
                vec![Edit::Set {
                    path: p(&["mcpServers", "crm"]),
                    value: gw(),
                }],
            ),
        ],
    )
    .unwrap();
    assert!(s.path.exists(), "inumaki created settings.json");
    std::fs::remove_file(&s.path).unwrap();
    std::fs::remove_file(&c.path).unwrap();
    let r = revert(&store, &b).unwrap();
    assert!(
        !s.path.exists() && !c.path.exists(),
        "revert creates no file"
    );
    assert_eq!(
        r.conflicts.len(),
        1,
        "mcpServers.crm held the user's entry before inumaki"
    );
}

/// Review I1: the engine never copies `~/.claude.json`, even when the
/// adapter asks for a full copy.
#[test]
fn claude_json_is_never_copied_even_when_asked() {
    let d = tempfile::tempdir().unwrap();
    let (_, mut c) = files(d.path());
    c.full_copy = true;
    std::fs::write(&c.path, CLAUDE_JSON).unwrap();
    let store = BackupStore::new(&d.path().join("data"));
    let b = apply_files(
        &store,
        HarnessId::ClaudeCode,
        OWNED,
        vec![(
            c.clone(),
            vec![Edit::Set {
                path: p(&["mcpServers", "crm"]),
                value: gw(),
            }],
        )],
    )
    .unwrap();
    assert!(!b.copy_path(FileRole::ClaudeJson).exists());
    assert!(!b.file(FileRole::ClaudeJson).unwrap().full_copy);
    for e in std::fs::read_dir(&b.dir).unwrap().flatten() {
        assert!(
            !e.file_name().to_string_lossy().ends_with(".orig"),
            "no full copy in the backup"
        );
    }
    revert(&store, &b).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&std::fs::read_to_string(&c.path).unwrap())
            .unwrap(),
        serde_json::from_str::<serde_json::Value>(CLAUDE_JSON).unwrap()
    );
}

/// Final review T3-M2: when the previous backup's copy cannot be read, the
/// chained apply fails and leaves no new backup directory behind.
#[test]
fn a_failed_chain_copy_leaves_no_stray_backup_directory() {
    let d = tempfile::tempdir().unwrap();
    let (s, _) = files(d.path());
    std::fs::write(&s.path, SETTINGS_OK).unwrap();
    let store = BackupStore::new(&d.path().join("data"));
    let set = |u: &str| {
        vec![(
            s.clone(),
            vec![Edit::Set {
                path: p(&["env", "ANTHROPIC_BASE_URL"]),
                value: Node::s(u),
            }],
        )]
    };
    let b1 = apply_files(&store, HarnessId::ClaudeCode, OWNED, set("http://a")).unwrap();
    std::fs::remove_file(b1.copy_path(FileRole::ClaudeSettings)).unwrap();
    let written = std::fs::read(&s.path).unwrap();
    assert!(apply_files(&store, HarnessId::ClaudeCode, OWNED, set("http://b")).is_err());
    let dirs: Vec<_> = std::fs::read_dir(store.dir(HarnessId::ClaudeCode))
        .unwrap()
        .flatten()
        .map(|e| e.file_name())
        .collect();
    assert_eq!(
        dirs,
        vec![std::ffi::OsString::from(&b1.id)],
        "only the first backup is left"
    );
    assert_eq!(std::fs::read(&s.path).unwrap(), written, "nothing written");
}
