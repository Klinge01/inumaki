//! The contract fixtures (M6 spec §9.8), one per response shape, and the
//! round-trip checks that the daemon's endpoint tests use. Lanes L1 and L2
//! call `assert_value_round_trip` on their new endpoints' live bodies; the
//! M6-0 test calls `assert_bytes_round_trip` on the struct-serialized
//! bodies that are already on `main`.

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

/// Every fixture, by name.
pub const FIXTURES: &[(&str, &str)] = &[
    ("status", include_str!("../fixtures/contract/status.json")),
    (
        "datasets",
        include_str!("../fixtures/contract/datasets.json"),
    ),
    ("dataset", include_str!("../fixtures/contract/dataset.json")),
    ("rotate", include_str!("../fixtures/contract/rotate.json")),
    (
        "upstreams",
        include_str!("../fixtures/contract/upstreams.json"),
    ),
    (
        "upstream",
        include_str!("../fixtures/contract/upstream.json"),
    ),
    ("tokens", include_str!("../fixtures/contract/tokens.json")),
    (
        "token_created",
        include_str!("../fixtures/contract/token_created.json"),
    ),
    (
        "activity",
        include_str!("../fixtures/contract/activity.json"),
    ),
    (
        "activity_verify",
        include_str!("../fixtures/contract/activity_verify.json"),
    ),
    ("inspect", include_str!("../fixtures/contract/inspect.json")),
    (
        "sanitize",
        include_str!("../fixtures/contract/sanitize.json"),
    ),
    (
        "rehydrate",
        include_str!("../fixtures/contract/rehydrate.json"),
    ),
    ("doctor", include_str!("../fixtures/contract/doctor.json")),
    (
        "shutdown",
        include_str!("../fixtures/contract/shutdown.json"),
    ),
    (
        "error_privacy_block",
        include_str!("../fixtures/contract/error_privacy_block.json"),
    ),
    (
        "error_unresolved",
        include_str!("../fixtures/contract/error_unresolved.json"),
    ),
    (
        "error_not_found",
        include_str!("../fixtures/contract/error_not_found.json"),
    ),
    ("journal", include_str!("../fixtures/contract/journal.json")),
    (
        "journal_record",
        include_str!("../fixtures/contract/journal_record.json"),
    ),
    (
        "entities",
        include_str!("../fixtures/contract/entities.json"),
    ),
    ("forget", include_str!("../fixtures/contract/forget.json")),
    ("mailbox", include_str!("../fixtures/contract/mailbox.json")),
    (
        "mailbox_check",
        include_str!("../fixtures/contract/mailbox_check.json"),
    ),
    ("folder", include_str!("../fixtures/contract/folder.json")),
    (
        "folder_rescan",
        include_str!("../fixtures/contract/folder_rescan.json"),
    ),
    ("folders", include_str!("../fixtures/contract/folders.json")),
    ("proxy", include_str!("../fixtures/contract/proxy.json")),
    ("service", include_str!("../fixtures/contract/service.json")),
    (
        "models_job",
        include_str!("../fixtures/contract/models_job.json"),
    ),
    (
        "hook_pass",
        include_str!("../fixtures/contract/hook_pass.json"),
    ),
    (
        "hook_replace",
        include_str!("../fixtures/contract/hook_replace.json"),
    ),
    (
        "check_created",
        include_str!("../fixtures/contract/check_created.json"),
    ),
    (
        "check_report",
        include_str!("../fixtures/contract/check_report.json"),
    ),
];

/// The fixture `name`; panics on an unknown name (a test typo).
pub fn fixture(name: &str) -> &'static str {
    FIXTURES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, j)| *j)
        .unwrap_or_else(|| panic!("no contract fixture {name}"))
}

/// Decode `bytes` into `T` and encode it again: the result must equal
/// `bytes` exactly. For bodies the daemon serializes from a struct, where
/// field order is part of the contract.
pub fn assert_bytes_round_trip<T: Serialize + DeserializeOwned>(bytes: &[u8]) {
    let name = std::any::type_name::<T>();
    let t: T = serde_json::from_slice(bytes)
        .unwrap_or_else(|e| panic!("{name}: the daemon's body does not decode: {e}"));
    let again = serde_json::to_vec(&t).expect("client types serialize");
    assert!(
        again == bytes,
        "{name}: re-encoded bytes differ\n daemon: {}\n client: {}",
        String::from_utf8_lossy(bytes),
        String::from_utf8_lossy(&again)
    );
}

/// Decode `v` into `T` and encode it again: the result must equal `v` as a
/// JSON value (key order ignored). For bodies built with `json!` and for
/// the fixtures. A key that `T` does not know is dropped on the way and
/// fails the comparison, and so does a `null` the fixture forgot.
pub fn assert_value_round_trip<T: Serialize + DeserializeOwned>(v: &Value) {
    let name = std::any::type_name::<T>();
    let t: T = serde_json::from_value(v.clone())
        .unwrap_or_else(|e| panic!("{name}: the body does not decode: {e}"));
    let again = serde_json::to_value(&t).expect("client types serialize");
    assert!(
        &again == v,
        "{name}: re-encoded value differs\n body:   {v}\n client: {again}"
    );
}
