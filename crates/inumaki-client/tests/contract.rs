//! Every fixture decodes into its type and re-encodes to the same JSON
//! value, and its `Debug` never shows the marker that every sensitive
//! fixture field carries (M6 spec §6.6, §9.8).

use std::collections::BTreeSet;

use inumaki_client::contract::{FIXTURES, assert_value_round_trip, fixture};
use inumaki_client::*;
use serde::Serialize;
use serde::de::DeserializeOwned;

const MARKER: &str = "qwxzvk";

fn check<T: Serialize + DeserializeOwned + std::fmt::Debug>(
    name: &'static str,
    seen: &mut BTreeSet<&'static str>,
) {
    let v: serde_json::Value = serde_json::from_str(fixture(name)).expect("fixture is JSON");
    assert_value_round_trip::<T>(&v);
    let t: T = serde_json::from_value(v).unwrap();
    let d = format!("{t:?}");
    assert!(
        !d.to_lowercase().contains(MARKER),
        "{name}: Debug shows a value: {d}"
    );
    assert!(seen.insert(name), "{name} checked twice");
}

#[test]
fn every_fixture_round_trips_and_debug_prints_no_value() {
    let mut seen = BTreeSet::new();
    // §9.2
    check::<StatusBody>("status", &mut seen);
    check::<Vec<DatasetBody>>("datasets", &mut seen);
    check::<DatasetBody>("dataset", &mut seen);
    check::<RotateBody>("rotate", &mut seen);
    check::<Vec<UpstreamBody>>("upstreams", &mut seen);
    check::<UpstreamBody>("upstream", &mut seen);
    check::<Vec<TokenBody>>("tokens", &mut seen);
    check::<TokenCreated>("token_created", &mut seen);
    check::<ActivityList>("activity", &mut seen);
    check::<ActivityVerify>("activity_verify", &mut seen);
    check::<InspectBody>("inspect", &mut seen);
    check::<SanitizeResponse>("sanitize", &mut seen);
    check::<RehydrateResponse>("rehydrate", &mut seen);
    check::<DoctorBody>("doctor", &mut seen);
    check::<ShutdownBody>("shutdown", &mut seen);
    check::<ErrorBody>("error_privacy_block", &mut seen);
    check::<ErrorBody>("error_unresolved", &mut seen);
    check::<ErrorBody>("error_not_found", &mut seen);
    // §9.3
    check::<JournalList>("journal", &mut seen);
    check::<JournalRecord>("journal_record", &mut seen);
    check::<EntityList>("entities", &mut seen);
    check::<ForgetBody>("forget", &mut seen);
    // §9.4
    check::<MailboxBody>("mailbox", &mut seen);
    check::<MailboxCheck>("mailbox_check", &mut seen);
    // §9.5
    check::<FolderBody>("folder", &mut seen);
    check::<RescanBody>("folder_rescan", &mut seen);
    check::<FoldersBody>("folders", &mut seen);
    // §9.6
    check::<ProxyBody>("proxy", &mut seen);
    // §9.7
    check::<ServiceBody>("service", &mut seen);
    check::<ModelsJob>("models_job", &mut seen);
    check::<HookResponse>("hook_pass", &mut seen);
    check::<HookResponse>("hook_replace", &mut seen);
    check::<CheckCreated>("check_created", &mut seen);
    check::<CheckReport>("check_report", &mut seen);
    let all: BTreeSet<&str> = FIXTURES.iter().map(|(n, _)| *n).collect();
    assert_eq!(all, seen, "every fixture has exactly one type check");
}

#[test]
fn request_debug_prints_no_value() {
    let mut up = UpstreamCreate::stdio("qwxzvk-crm", "/opt/qwxzvk/bin/crm");
    up.secret_env.insert("QWXZVK_TOKEN", "s3cret-qwxzvk");
    up.env.insert("TENANT".into(), "qwxzvk".into());
    let mut inspect = InspectRequest::new("qwxzvk-kunde", "Hallo Qwxzvk Zyxwuria");
    inspect.show_values = true;
    let shown = [
        format!("{:?}", CreateDataset::new("qwxzvk-kunde", "Qwxzvk Kunde")),
        format!("{up:?}"),
        format!(
            "{:?}",
            SanitizeRequest::dataset("qwxzvk-kunde", "Qwxzvk Zyxwuria")
        ),
        format!(
            "{:?}",
            RehydrateRequest::dataset("qwxzvk-kunde", "Qwxzvk Zyxwuria")
        ),
        format!("{inspect:?}"),
        format!(
            "{:?}",
            TokenCreate {
                label: "qwxzvk-laptop".into()
            }
        ),
        format!("{:?}", Secret::new("qwxzvk-password")),
        format!(
            "{:?}",
            MailboxCreate::preset(
                MailboxPreset::Generic,
                "office@qwxzvk.example",
                Secret::new("pw-qwxzvk")
            )
        ),
        format!(
            "{:?}",
            FolderCreate {
                source: "/Users/qwxzvk/Akten".into(),
                outbox_destination: None
            }
        ),
        format!(
            "{:?}",
            ForgetRequest {
                value: Secret::new("Qwxzvk Zyxwuria")
            }
        ),
        format!(
            "{:?}",
            HookRequest {
                harness: HookHarness::ClaudeCode,
                tool: HookTool::Read,
                cwd: "/Users/qwxzvk/src".into(),
                paths: vec!["/Users/qwxzvk/Akten/a.txt".into()],
                texts: vec!["Qwxzvk Zyxwuria".into()]
            }
        ),
        format!(
            "{:?}",
            CheckHarnessRequest {
                harness: HarnessId::Codex,
                output: "Qwxzvk Zyxwuria".into(),
                exit_code: 0
            }
        ),
    ];
    for d in shown {
        assert!(!d.to_lowercase().contains(MARKER), "{d}");
    }
}

fn closed<E>(pairs: &[(E, &str)])
where
    E: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
{
    for (e, s) in pairs {
        assert_eq!(
            serde_json::to_value(e).unwrap(),
            serde_json::json!(s),
            "{e:?}"
        );
        assert_eq!(
            &serde_json::from_value::<E>(serde_json::json!(s)).unwrap(),
            e
        );
    }
    assert!(serde_json::from_value::<E>(serde_json::json!("not-a-member")).is_err());
}

#[test]
fn closed_sets_use_the_spec_strings_and_refuse_others() {
    closed(&[
        (DatasetKind::Generic, "generic"),
        (DatasetKind::Mailbox, "mailbox"),
        (DatasetKind::Folder, "folder"),
        (DatasetKind::Chat, "chat"),
    ]);
    closed(&[
        (ContractState::Ready, "ready"),
        (ContractState::None, "none"),
        (ContractState::Invalid, "invalid"),
        (ContractState::Drift, "drift"),
    ]);
    closed(&[
        (FrontDoor::Gateway, "gateway"),
        (FrontDoor::Control, "control"),
        (FrontDoor::Proxy, "proxy"),
        (FrontDoor::Mirror, "mirror"),
        (FrontDoor::Hook, "hook"),
    ]);
    closed(&[
        (CheckLabel::Leak, "Leak"),
        (CheckLabel::DetectorError, "DetectorError"),
        (CheckLabel::ClearValue, "ClearValue"),
    ]);
    closed(&[
        (JournalLabel::Tokens, JOURNAL_TOKENS_LABEL),
        (JournalLabel::Values, JOURNAL_VALUES_LABEL),
    ]);
    closed(&[
        (MailboxPreset::Gmail, "gmail"),
        (MailboxPreset::Outlook, "outlook"),
        (MailboxPreset::Generic, "generic"),
    ]);
    closed(&[
        (FolderState::Scanning, "scanning"),
        (FolderState::Watching, "watching"),
        (FolderState::Stopped, "stopped"),
        (FolderState::Failed, "failed"),
        (FolderState::Pending, "pending"),
    ]);
    closed(&[
        (FolderError::SourceMissing, "source_missing"),
        (FolderError::SourceNotPermitted, "source_not_permitted"),
        (FolderError::SourceUnreadable, "source_unreadable"),
        (FolderError::MirrorUnwritable, "mirror_unwritable"),
        (FolderError::WatchFailed, "watch_failed"),
        (FolderError::VaultUnavailable, "vault_unavailable"),
        (FolderError::ModelUnavailable, "model_unavailable"),
        (FolderError::OutboxUnwritable, "outbox_unwritable"),
        (FolderError::Internal, "internal"),
    ]);
    closed(&[
        (ProxyState::Running, "running"),
        (ProxyState::Disabled, "disabled"),
        (ProxyState::BindFailed, "bind_failed"),
    ]);
    closed(&[
        (RoutePrefix::Anthropic, "/anthropic"),
        (RoutePrefix::Openai, "/openai"),
        (RoutePrefix::Codex, "/codex"),
    ]);
    closed(&[
        (ProxyUpstream::Anthropic, "anthropic"),
        (ProxyUpstream::Openai, "openai"),
        (ProxyUpstream::OpenaiCodex, "openai-codex"),
    ]);
    closed(&[
        (RouteState::Ok, "ok"),
        (RouteState::Idle, "idle"),
        (RouteState::Failing, "failing"),
    ]);
    closed(&[
        (ProxyError::UpstreamUnreachable, "upstream_unreachable"),
        (ProxyError::UpstreamAuth, "upstream_auth"),
        (ProxyError::UpstreamRateLimited, "upstream_rate_limited"),
        (ProxyError::Upstream5xx, "upstream_5xx"),
        (ProxyError::PrivacyBlock, "privacy_block"),
        (ProxyError::ResourceLimit, "resource_limit"),
        (ProxyError::StreamAborted, "stream_aborted"),
        (ProxyError::BadRequest, "bad_request"),
        (ProxyError::Internal, "internal"),
    ]);
    closed(&[
        (ClientKind::ClaudeCode, "claude_code"),
        (ClientKind::Codex, "codex"),
        (ClientKind::Hermes, "hermes"),
        (ClientKind::Openclaw, "openclaw"),
        (ClientKind::Other, "other"),
    ]);
    closed(&[
        (ManagedBy::App, "app"),
        (ManagedBy::Homebrew, "homebrew"),
        (ManagedBy::Deb, "deb"),
        (ManagedBy::Manual, "manual"),
    ]);
    closed(&[
        (JobState::Idle, "idle"),
        (JobState::Running, "running"),
        (JobState::Done, "done"),
        (JobState::Failed, "failed"),
    ]);
    closed(&[
        (JobError::Network, "network"),
        (JobError::HashMismatch, "hash_mismatch"),
        (JobError::Disk, "disk"),
        (JobError::Manifest, "manifest"),
    ]);
    closed(&[
        (HookHarness::ClaudeCode, "claude-code"),
        (HookHarness::Codex, "codex"),
    ]);
    closed(&[
        (HookTool::Bash, "bash"),
        (HookTool::Read, "read"),
        (HookTool::Grep, "grep"),
        (HookTool::Glob, "glob"),
        (HookTool::Edit, "edit"),
        (HookTool::WebFetch, "web_fetch"),
        (HookTool::Mcp, "mcp"),
        (HookTool::Other, "other"),
    ]);
    closed(&[
        (HarnessId::ClaudeCode, "claude-code"),
        (HarnessId::Codex, "codex"),
        (HarnessId::Hermes, "hermes"),
        (HarnessId::Openclaw, "openclaw"),
    ]);
    closed(&[
        (CheckPath::Gateway, "gateway"),
        (CheckPath::Mirror, "mirror"),
        (CheckPath::Proxy, "proxy"),
    ]);
    closed(&[
        (AvailReason::MirrorUnavailable, "mirror_unavailable"),
        (AvailReason::ProxyUnavailable, "proxy_unavailable"),
    ]);
    closed(&[
        (PathStatus::Passed, "passed"),
        (PathStatus::Failed, "failed"),
        (PathStatus::NotChecked, "not_checked"),
    ]);
    closed(&[
        (PathReason::MirrorUnavailable, "mirror_unavailable"),
        (PathReason::ProxyUnavailable, "proxy_unavailable"),
        (PathReason::ChatNotRouted, "chat_not_routed"),
        (PathReason::CanaryInUpstream, "canary_in_upstream"),
        (PathReason::NoTokens, "no_tokens"),
        (PathReason::NotRehydrated, "not_rehydrated"),
        (PathReason::Timeout, "timeout"),
        (PathReason::HarnessFailed, "harness_failed"),
    ]);
}

/// M6 spec §9.7 amendment 2026-10-10: `mirror.source_dir` is optional, so a
/// daemon from before the amendment still decodes (and re-encodes to the
/// same bytes); `Debug` prints neither path.
#[test]
fn check_mirror_source_dir_is_optional_and_never_printed() {
    let old = r#"{"path":"/Users/qwxzvk/Inumaki/check-0123456789ab-f/canary.txt"}"#;
    let m: CheckMirror = serde_json::from_str(old).unwrap();
    assert!(m.source_dir.is_none());
    assert_eq!(serde_json::to_string(&m).unwrap(), old);
    let new = r#"{"path":"/Users/qwxzvk/Inumaki/check-0123456789ab-f/canary.txt","source_dir":"/tmp/inumaki-check-qwxzvk-x/source"}"#;
    let m: CheckMirror = serde_json::from_str(new).unwrap();
    assert_eq!(
        m.source_dir.as_deref(),
        Some("/tmp/inumaki-check-qwxzvk-x/source")
    );
    assert_eq!(serde_json::to_string(&m).unwrap(), new);
    let d = format!("{m:?}");
    assert!(!d.contains("qwxzvk") && !d.contains('/'), "{d}");
}

/// A daemon from before `outbox_destination` omits it from a folders entry:
/// it decodes to the empty string (the app treats that as unknown), and the
/// entry's other fields are unaffected.
#[test]
fn folders_entry_without_outbox_destination_decodes_to_empty() {
    use inumaki_client::contract::fixture;
    let mut v: serde_json::Value = serde_json::from_str(fixture("folders")).unwrap();
    for f in v["folders"].as_array_mut().unwrap() {
        f.as_object_mut().unwrap().remove("outbox_destination");
    }
    let body: FoldersBody = serde_json::from_value(v).unwrap();
    assert!(!body.folders.is_empty());
    for f in &body.folders {
        assert_eq!(f.outbox_destination, "");
    }
    assert_eq!(body.folders[0].dataset, "qwxzvk-akten");
}
