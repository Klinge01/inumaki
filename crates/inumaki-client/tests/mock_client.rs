#![cfg(feature = "mock")]
//! The typed client against the mock daemon: every route is reached by its
//! method, errors keep their status and never their message, parameters
//! are encoded, and a hung daemon times out (M6-0 Review Focus 2–5).

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use inumaki_client::mock::{Canned, MockDaemon, ROUTES};
use inumaki_client::*;
use serde_json::json;

const DS: &str = "qwxzvk-kunde";
const CHECK: &str = "0123456789abcdef0123456789abcdef";

fn hook_req() -> HookRequest {
    HookRequest {
        harness: HookHarness::ClaudeCode,
        tool: HookTool::Read,
        cwd: "/tmp".into(),
        paths: vec!["/tmp/a.txt".into()],
        texts: vec!["hello".into()],
    }
}

#[tokio::test]
async fn every_route_is_reached_by_its_typed_method() {
    let m = MockDaemon::start().await;
    let c = m.client();
    c.status().await.unwrap();
    c.datasets().await.unwrap();
    c.create_dataset(&CreateDataset::new(DS, "Qwxzvk Kunde"))
        .await
        .unwrap();
    c.delete_dataset(DS).await.unwrap();
    c.rotate_dataset(DS).await.unwrap();
    c.upstreams(DS).await.unwrap();
    c.create_upstream(DS, &UpstreamCreate::stdio("qwxzvk-crm", "/bin/echo"))
        .await
        .unwrap();
    c.delete_upstream(DS, "qwxzvk-crm").await.unwrap();
    c.accept_schema(DS, "qwxzvk-crm", None).await.unwrap();
    c.tokens().await.unwrap();
    c.create_token("app:codex").await.unwrap();
    c.revoke_token(3).await.unwrap();
    c.activity(&ActivityQuery {
        dataset: Some(DS.into()),
        since: Some(0),
        limit: Some(10),
    })
    .await
    .unwrap();
    c.verify_activity().await.unwrap();
    c.inspect(&InspectRequest::new(DS, "Hallo")).await.unwrap();
    c.sanitize(&SanitizeRequest::dataset(DS, "Hallo"))
        .await
        .unwrap();
    c.rehydrate(&RehydrateRequest::dataset(DS, "Hallo"))
        .await
        .unwrap();
    c.doctor().await.unwrap();
    c.shutdown().await.unwrap();
    c.journal(DS, None, Some(5)).await.unwrap();
    c.journal_record(DS, CHECK, true).await.unwrap();
    c.entities(DS, false, None).await.unwrap();
    c.forget_token(DS, "<PERSON_a7f2>").await.unwrap();
    c.forget_value(DS, &Secret::new("Qwxzvk Zyxwuria"))
        .await
        .unwrap();
    c.set_mailbox(
        DS,
        &MailboxCreate::preset(MailboxPreset::Gmail, "u@example.invalid", Secret::new("pw")),
    )
    .await
    .unwrap();
    c.mailbox(DS).await.unwrap();
    c.delete_mailbox(DS).await.unwrap();
    c.check_mailbox(DS).await.unwrap();
    c.set_folder(
        DS,
        &FolderCreate {
            source: "/tmp/x".into(),
            outbox_destination: None,
        },
    )
    .await
    .unwrap();
    c.folder(DS).await.unwrap();
    c.delete_folder(DS).await.unwrap();
    c.rescan_folder(DS).await.unwrap();
    c.folders().await.unwrap();
    c.proxy().await.unwrap();
    c.service().await.unwrap();
    c.start_models_pull(&ModelsPull::default()).await.unwrap();
    c.models_pull().await.unwrap();
    c.hook(&hook_req()).await.unwrap();
    let created = c.create_check(&CheckCreate::default()).await.unwrap();
    // §9.7 amendment 2026-10-10: the mirror carries the check's source dir.
    assert!(
        created
            .mirror
            .and_then(|m| m.source_dir)
            .is_some_and(|d| d.ends_with("/source"))
    );
    c.check_direct(CHECK).await.unwrap();
    c.check_harness(
        CHECK,
        &CheckHarnessRequest {
            harness: HarnessId::ClaudeCode,
            output: "x".into(),
            exit_code: 0,
        },
    )
    .await
    .unwrap();
    c.check_report(CHECK).await.unwrap();
    c.delete_check(CHECK).await.unwrap();
    let hit: Vec<(String, &str)> = m
        .requests()
        .into_iter()
        .map(|r| (r.method, r.route))
        .collect();
    let expected: Vec<(&str, &str)> = vec![
        ("GET", "/v1/status"),
        ("GET", "/v1/datasets"),
        ("POST", "/v1/datasets"),
        ("DELETE", "/v1/datasets/{id}"),
        ("POST", "/v1/datasets/{id}/rotate"),
        ("GET", "/v1/datasets/{id}/upstreams"),
        ("POST", "/v1/datasets/{id}/upstreams"),
        ("DELETE", "/v1/datasets/{id}/upstreams/{name}"),
        ("POST", "/v1/datasets/{id}/upstreams/{name}/accept-schema"),
        ("GET", "/v1/gateway/tokens"),
        ("POST", "/v1/gateway/tokens"),
        ("DELETE", "/v1/gateway/tokens/{id}"),
        ("GET", "/v1/activity"),
        ("GET", "/v1/activity/verify"),
        ("POST", "/v1/inspect"),
        ("POST", "/v1/sanitize"),
        ("POST", "/v1/rehydrate"),
        ("GET", "/v1/doctor"),
        ("POST", "/v1/shutdown"),
        ("GET", "/v1/datasets/{id}/journal"),
        ("GET", "/v1/datasets/{id}/journal/{record}"),
        ("GET", "/v1/datasets/{id}/entities"),
        ("DELETE", "/v1/datasets/{id}/entities/{token}"),
        ("POST", "/v1/datasets/{id}/entities/forget"),
        ("POST", "/v1/datasets/{id}/mailbox"),
        ("GET", "/v1/datasets/{id}/mailbox"),
        ("DELETE", "/v1/datasets/{id}/mailbox"),
        ("POST", "/v1/datasets/{id}/mailbox/check"),
        ("POST", "/v1/datasets/{id}/folder"),
        ("GET", "/v1/datasets/{id}/folder"),
        ("DELETE", "/v1/datasets/{id}/folder"),
        ("POST", "/v1/datasets/{id}/folder/rescan"),
        ("GET", "/v1/folders"),
        ("GET", "/v1/proxy"),
        ("GET", "/v1/service"),
        ("POST", "/v1/models/pull"),
        ("GET", "/v1/models/pull"),
        ("POST", "/v1/hook"),
        ("POST", "/v1/check"),
        ("POST", "/v1/check/{id}/direct"),
        ("POST", "/v1/check/{id}/harness"),
        ("GET", "/v1/check/{id}"),
        ("DELETE", "/v1/check/{id}"),
    ];
    let expected: Vec<(String, &str)> = expected
        .into_iter()
        .map(|(method, route)| (method.to_string(), route))
        .collect();
    assert_eq!(
        hit, expected,
        "each call reached exactly its intended route, in order"
    );
    let hit_set: BTreeSet<_> = hit.iter().cloned().collect();
    let all_set: BTreeSet<(String, &str)> = ROUTES
        .iter()
        .map(|r| (r.method.to_string(), r.path))
        .collect();
    assert_eq!(
        hit_set, all_set,
        "every route is reached by at least one typed method"
    );
    m.stop().await;
}

#[tokio::test]
async fn errors_map_to_status_without_leaking_the_message() {
    let m = MockDaemon::start().await;
    let c = m.client();
    m.set(
        "POST",
        "/v1/hook",
        Canned::error(
            451,
            "privacy_block",
            "the sanitized text did not pass verification; nothing was sent",
            &["PERSON"],
        ),
    );
    let e = c.hook(&hook_req()).await.unwrap_err();
    match &e {
        ClientError::Status {
            status: 451,
            error: Some(d),
        } => {
            assert_eq!(d.kind, "privacy_block");
            assert_eq!(d.kinds, ["PERSON"]);
        }
        other => panic!("{other:?}"),
    }
    m.set(
        "GET",
        "/v1/datasets/{id}/mailbox",
        Canned::error(404, "not_found", "dataset qwxzvk-kunde not found", &[]),
    );
    let e = c.mailbox(DS).await.unwrap_err();
    assert_eq!(e.status(), Some(404));
    assert_eq!(
        e.detail().unwrap().message,
        "dataset qwxzvk-kunde not found"
    );
    let shown = format!("{e} {e:?}");
    assert!(!shown.contains("qwxzvk"), "{shown}");
    // Review Focus 2: non-JSON and empty error bodies keep their status.
    m.set(
        "POST",
        "/v1/hook",
        Canned::raw(413, "length limit exceeded"),
    );
    assert!(matches!(
        c.hook(&hook_req()).await.unwrap_err(),
        ClientError::Status {
            status: 413,
            error: None
        }
    ));
    m.set("GET", "/v1/proxy", Canned::empty(502));
    assert!(matches!(
        c.proxy().await.unwrap_err(),
        ClientError::Status {
            status: 502,
            error: None
        }
    ));
    // A 2xx body of the wrong shape is `Decode`, never a default value.
    m.set(
        "GET",
        "/v1/service",
        Canned::json(200, json!({ "version": 1 })),
    );
    assert!(matches!(
        c.service().await.unwrap_err(),
        ClientError::Decode
    ));
    m.stop().await;
}

#[tokio::test]
async fn path_parameters_and_query_values_are_percent_encoded() {
    let m = MockDaemon::start().await;
    let c = m.client();
    c.forget_token(DS, "<PERSON_a7f2>").await.unwrap();
    c.delete_dataset("a/b c%").await.unwrap();
    c.activity(&ActivityQuery {
        dataset: Some("x&since=1".into()),
        ..Default::default()
    })
    .await
    .unwrap();
    let r = m.requests();
    assert_eq!(r[0].route, "/v1/datasets/{id}/entities/{token}");
    assert_eq!(
        r[0].path,
        "/v1/datasets/qwxzvk-kunde/entities/%3CPERSON_a7f2%3E"
    );
    assert_eq!(r[1].route, "/v1/datasets/{id}");
    assert_eq!(r[1].path, "/v1/datasets/a%2Fb%20c%25");
    assert_eq!(r[2].route, "/v1/activity");
    assert_eq!(r[2].query.as_deref(), Some("dataset=x%26since%3D1"));
    m.stop().await;
}

#[tokio::test]
async fn a_hung_daemon_times_out_and_a_missing_one_is_connect() {
    let m = MockDaemon::start().await;
    m.set(
        "POST",
        "/v1/hook",
        Canned::fixture(200, "hook_pass").delayed(Duration::from_secs(5)),
    );
    let c = m.client().with_timeout(Duration::from_millis(200));
    let t = Instant::now();
    assert!(matches!(
        c.hook(&hook_req()).await.unwrap_err(),
        ClientError::Timeout
    ));
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    drop(m);
    let gone =
        Client::new(std::env::temp_dir().join(format!("inumaki-none-{}.sock", std::process::id())));
    assert!(matches!(
        gone.status().await.unwrap_err(),
        ClientError::Connect(_)
    ));
}

/// Each default mint is distinct, a revoke removes it, and the list shows
/// what is live (tests that count live tokens rely on this).
#[tokio::test]
async fn default_mints_are_distinct_and_revoke_removes_them() {
    let m = MockDaemon::start().await;
    let c = m.client();
    let a = c.create_token("app:codex").await.unwrap();
    let b = c.create_token("app:codex").await.unwrap();
    assert_ne!(a.id, b.id);
    assert_ne!(a.token.expose(), b.token.expose());
    assert_eq!(m.live_tokens(), [a.id, b.id]);
    c.revoke_token(a.id).await.unwrap();
    assert_eq!(m.live_tokens(), [b.id]);
    let listed = c.tokens().await.unwrap();
    assert!(listed.iter().any(|t| t.id == b.id) && !listed.iter().any(|t| t.id == a.id));
}

#[tokio::test]
async fn an_unconfigured_folder_answers_404_not_found() {
    let m = MockDaemon::start().await;
    let c = m.client();
    for method in [Method::GET, Method::DELETE] {
        let path = format!(
            "/v1/datasets/{}/folder",
            inumaki_client::mock::UNCONFIGURED_FOLDER
        );
        let r = c.raw(method, &path, Vec::new()).await.unwrap();
        assert_eq!(r.status, 404);
        let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(v["error"]["type"], "not_found");
        assert_eq!(v["error"]["message"], "folder not configured");
    }
}

/// TCC spike finding 2: a folder whose first open waits on a macOS prompt
/// reads `pending`, and the client decodes it.
#[tokio::test]
async fn a_pending_folder_decodes() {
    let m = MockDaemon::start().await;
    let c = m.client();
    let mut body: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/contract/folders.json")).unwrap();
    body["folders"][1]["state"] = json!("pending");
    body["folders"][1]["error"] = json!(null);
    m.set("GET", "/v1/folders", Canned::json(200, body));
    let f = c.folders().await.unwrap();
    assert_eq!(f.folders[1].state, inumaki_client::FolderState::Pending);
    assert_eq!(f.folders[1].error, None);
    m.stop().await;
}
