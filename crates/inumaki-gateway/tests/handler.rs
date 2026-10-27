//! The per-dataset handler against in-process scripted upstreams and a
//! fake engine: contracts are checked against the dataset's profile on
//! every rebuild (carry 9), a down upstream keeps its names through its
//! last-known lists at its current index (carry 2, 8b), and a new
//! upstream set swaps the catalog with it (carry 8c); a handle lookup never
//! waits for a sanitization (review I2), and an oversized result costs no
//! engine work (Review Focus 4). Final review: a session that never reads
//! does not hold up rebuilds (finding 3), a transient listing failure is
//! retried (finding 4), and a map-rule key trips the tripwire (finding 5).

// `fetch_update` is deprecated for `try_update` since Rust 1.99, which is newer
// than the workspace's `rust-version`.
#![allow(deprecated)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use inumaki_core::policy::{Action, EntityPolicy, Profile, VerifierSettings};
use inumaki_gateway::scripted::{IDENTITY, ScriptedUpstream};
use inumaki_gateway::upstream::{
    BoxFut, BuiltinUpstreams, ResolvedUpstream, Running, ServerGuard, Supervision, UpstreamClient,
    UpstreamError, UpstreamHandle, connect_in_process,
};
use inumaki_gateway::{
    ActivitySink, BlockOutcome, BlockResult, Blocks, BlocksError, ContractState, DatasetHandler,
    FieldHint, GatewayConfig, TextBlock, TripwireMode, UpstreamContract,
};
use inumaki_vault::{DatasetSpec, KeySource, UpstreamKind, Vault, VaultOptions};
use rmcp::model::{
    CallToolRequestParams, ClientCapabilities, GetPromptRequestParams, Implementation,
    InitializeRequestParams, ReadResourceRequestParams,
};
use rmcp::service::RunningService;
use rmcp::{RoleClient, ServiceExt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const POLICY: &str = include_str!("../../../docs/examples/scripted-upstream.policy.json");

/// Passes text through, types identifiers; its profile blocks
/// `CUSTOMER_ID` while `block_ids` is set. The clear-value scan finds the
/// canary name as a known entity.
struct Engine {
    block_ids: AtomicBool,
    /// Sanitization batches run.
    batches: AtomicUsize,
    /// Batches still to fail with `ModelUnavailable`.
    fail_next: AtomicUsize,
    /// Profile reads still to fail with `VaultUnavailable`.
    fail_profile: AtomicUsize,
    /// Profile reads (one per rebuild).
    profiles: AtomicUsize,
    /// When armed, the next batch reports it started and waits for release.
    gate: Mutex<Option<(std_mpsc::Sender<()>, std_mpsc::Receiver<()>)>>,
}

impl Blocks for Engine {
    fn sanitize_blocks(
        &self,
        _dataset: &str,
        blocks: Vec<TextBlock>,
    ) -> Result<Vec<BlockResult>, BlocksError> {
        self.batches.fetch_add(1, Ordering::SeqCst);
        if self
            .fail_next
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(BlocksError::ModelUnavailable);
        }
        let gate = self.gate.lock().unwrap().take();
        if let Some((started, release)) = gate {
            let _ = started.send(());
            let _ = release.recv_timeout(Duration::from_secs(10));
        }
        Ok(blocks
            .into_iter()
            .map(|b| BlockResult {
                outcome: BlockOutcome::Pass,
                text: match b.hint {
                    FieldHint::Identifier(k) => format!("<{}_cccccc>", k.label()),
                    FieldHint::FreeText | FieldHint::Metadata | FieldHint::Handle => b.text,
                },
                replacements: 0,
                kinds: vec![],
                reasons: vec![],
                cached: false,
            })
            .collect())
    }

    fn rehydrate_strict(
        &self,
        _dataset: &str,
        blocks: Vec<String>,
    ) -> Result<Vec<String>, BlocksError> {
        Ok(blocks)
    }

    fn profile(&self, _dataset: &str) -> Result<Arc<Profile>, BlocksError> {
        self.profiles.fetch_add(1, Ordering::SeqCst);
        if self
            .fail_profile
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(BlocksError::VaultUnavailable);
        }
        let action = if self.block_ids.load(Ordering::SeqCst) {
            Action::Block
        } else {
            Action::Tokenize
        };
        let mut entities = std::collections::HashMap::new();
        entities.insert(
            "CUSTOMER_ID".to_string(),
            EntityPolicy {
                action,
                min_confidence: 0.5,
            },
        );
        Ok(Arc::new(Profile {
            name: "p".into(),
            language: None,
            entities,
            default: EntityPolicy {
                action: Action::Tokenize,
                min_confidence: 0.5,
            },
            escalate_below: 0.3,
            verifier: VerifierSettings::default(),
            ner_sanitizer: None,
            ner_verifier: None,
        }))
    }

    fn scan_clear(
        &self,
        _dataset: &str,
        texts: &[String],
    ) -> Result<Vec<(String, u32)>, BlocksError> {
        let n = texts
            .iter()
            .filter(|t| t.to_lowercase().contains(&IDENTITY.to_lowercase()))
            .count();
        Ok(if n == 0 {
            Vec::new()
        } else {
            vec![("PERSON".to_string(), n as u32)]
        })
    }
}

/// Every built-in is the scripted server, in process.
struct Scripted;

impl BuiltinUpstreams for Scripted {
    fn connect(
        &self,
        _dataset: &str,
        _upstream: &str,
        client: UpstreamClient,
    ) -> BoxFut<Result<(Running, ServerGuard), UpstreamError>> {
        Box::pin(async move {
            let ct = CancellationToken::new();
            connect_in_process(
                ScriptedUpstream::default().with_stop(ct.clone()),
                client,
                ct,
            )
            .await
        })
    }
}

fn resolved(name: &str) -> ResolvedUpstream {
    ResolvedUpstream {
        name: name.into(),
        kind: UpstreamKind::Mail,
        command: None,
        args: vec![],
        cwd: None,
        url: None,
        env: BTreeMap::new(),
        headers: BTreeMap::new(),
    }
}

async fn running(name: &str) -> Arc<UpstreamHandle> {
    let (tx, rx) = mpsc::unbounded_channel();
    // The test drives rebuilds itself; events are kept but unread.
    std::mem::forget(rx);
    let h = UpstreamHandle::spawn(
        "label".into(),
        "crm".into(),
        resolved(name),
        tx,
        Arc::new(Scripted),
        Supervision {
            max_backoff: Duration::from_millis(50),
            handshake_timeout: Duration::from_secs(5),
            max_message: usize::MAX,
        },
    );
    for _ in 0..500 {
        if h.peer().is_some() {
            return h;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("upstream {name} did not start");
}

fn setup() -> (tempfile::TempDir, Vault, Arc<Engine>) {
    let dir = tempfile::tempdir().unwrap();
    let vault =
        Vault::open(VaultOptions::in_dir(dir.path()).with_key_source(KeySource::File)).unwrap();
    vault
        .create_dataset(&DatasetSpec::new("crm", "Kunde", "p"))
        .unwrap();
    let engine = Arc::new(Engine {
        block_ids: AtomicBool::new(true),
        batches: AtomicUsize::new(0),
        fail_next: AtomicUsize::new(0),
        fail_profile: AtomicUsize::new(0),
        profiles: AtomicUsize::new(0),
        gate: Mutex::new(None),
    });
    (dir, vault, engine)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn contracts_are_checked_against_the_profile_on_every_rebuild() {
    let (_dir, vault, engine) = setup();
    let handler = DatasetHandler::new(
        "crm",
        "label",
        vault,
        Arc::clone(&engine) as Arc<dyn Blocks>,
        GatewayConfig::default(),
        ActivitySink::disabled(),
    );
    let a = running("a").await;
    handler.set_upstreams(vec![(
        Arc::clone(&a),
        UpstreamContract::from_row(POLICY, None),
    )]);
    handler.rebuild().await;
    let st = handler.status();
    assert_eq!(st.upstreams[0].contract, ContractState::Invalid.as_str());
    assert!(
        handler.catalog().tools().is_empty(),
        "a refused contract exposes nothing"
    );
    // The profile changes: the next rebuild binds and exposes the upstream.
    engine.block_ids.store(false, Ordering::SeqCst);
    handler.rebuild().await;
    assert_eq!(handler.status().upstreams[0].contract, "ready");
    assert!(handler.catalog().route_tool("lookup").is_some());
    // And back: hidden again, whatever it listed before.
    engine.block_ids.store(true, Ordering::SeqCst);
    handler.rebuild().await;
    assert_eq!(handler.status().upstreams[0].contract, "invalid");
    assert!(handler.catalog().route_tool("lookup").is_none());
    a.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_down_upstream_keeps_its_names_and_a_new_set_swaps_the_catalog() {
    let (_dir, vault, engine) = setup();
    engine.block_ids.store(false, Ordering::SeqCst);
    let handler = DatasetHandler::new(
        "crm",
        "label",
        vault,
        Arc::clone(&engine) as Arc<dyn Blocks>,
        GatewayConfig::default(),
        ActivitySink::disabled(),
    );
    let a = running("a").await;
    let b = running("b").await;
    handler.set_upstreams(vec![
        (Arc::clone(&a), UpstreamContract::from_row(POLICY, None)),
        (Arc::clone(&b), UpstreamContract::from_row(POLICY, None)),
    ]);
    handler.rebuild().await;
    assert_eq!(handler.catalog().route_tool("echo").map(|r| r.0), Some(0));
    assert_eq!(
        handler.catalog().route_tool("b__echo").map(|r| r.0),
        Some(1)
    );
    // `a` goes down: its names stay with it (calls answer upstream_unavailable),
    // they never move to `b`.
    a.stop().await;
    handler.rebuild().await;
    assert_eq!(handler.catalog().route_tool("echo").map(|r| r.0), Some(0));
    assert_eq!(
        handler.catalog().route_tool("b__echo").map(|r| r.0),
        Some(1)
    );
    // A new set where `b` is first: its last-known lists are re-indexed,
    // and nothing routes by an index into the old set meanwhile.
    handler.set_upstreams(vec![(
        Arc::clone(&b),
        UpstreamContract::from_row(POLICY, None),
    )]);
    assert!(
        handler.catalog().tools().is_empty(),
        "swapped with the upstream set"
    );
    b.stop().await;
    handler.rebuild().await;
    assert_eq!(
        handler.catalog().route_tool("echo").map(|r| r.0),
        Some(0),
        "b's last-known lists at its current index"
    );
}

/// Serve `handler` in process and connect an rmcp client to it.
async fn agent(handler: DatasetHandler) -> RunningService<RoleClient, InitializeRequestParams> {
    let (a, b) = tokio::io::duplex(1 << 20);
    let (a_rd, a_wr) = tokio::io::split(a);
    let (b_rd, b_wr) = tokio::io::split(b);
    let server = tokio::spawn(async move {
        let s = rmcp::serve_server(handler, (a_rd, a_wr)).await.unwrap();
        let _ = s.waiting().await;
    });
    std::mem::forget(server);
    InitializeRequestParams::new(ClientCapabilities::default(), Implementation::new("t", "0"))
        .serve((b_rd, b_wr))
        .await
        .unwrap()
}

async fn ready_handler(
    config: GatewayConfig,
) -> (
    tempfile::TempDir,
    Arc<Engine>,
    DatasetHandler,
    Arc<UpstreamHandle>,
) {
    ready_handler_with(config, POLICY).await
}

async fn ready_handler_with(
    config: GatewayConfig,
    policy: &str,
) -> (
    tempfile::TempDir,
    Arc<Engine>,
    DatasetHandler,
    Arc<UpstreamHandle>,
) {
    let (dir, vault, engine) = setup();
    engine.block_ids.store(false, Ordering::SeqCst);
    let handler = DatasetHandler::new(
        "crm",
        "label",
        vault,
        Arc::clone(&engine) as Arc<dyn Blocks>,
        config,
        ActivitySink::disabled(),
    );
    let a = running("a").await;
    handler.set_upstreams(vec![(
        Arc::clone(&a),
        UpstreamContract::from_row(policy, None),
    )]);
    handler.rebuild().await;
    assert_eq!(handler.status().upstreams[0].contract, "ready");
    (dir, engine, handler, a)
}

/// Review I2: the handle store is never held across an engine batch, so a
/// handle lookup (here: an unknown resource) answers while another call of
/// the same dataset is mid-sanitization.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn handle_lookups_do_not_wait_for_a_sanitization() {
    let (_dir, engine, handler, a) = ready_handler(GatewayConfig::default()).await;
    let c = agent(handler).await;
    let (started_tx, started_rx) = std_mpsc::channel();
    let (release_tx, release_rx) = std_mpsc::channel();
    *engine.gate.lock().unwrap() = Some((started_tx, release_rx));
    let peer = c.peer().clone();
    let call =
        tokio::spawn(async move { peer.call_tool(CallToolRequestParams::new("linked")).await });
    tokio::task::spawn_blocking(move || started_rx.recv_timeout(Duration::from_secs(5)))
        .await
        .unwrap()
        .expect("the call reached the engine");
    let peer = c.peer().clone();
    let read = tokio::spawn(async move {
        peer.read_resource(ReadResourceRequestParams::new(
            "inumaki://res/0123456789abcdef",
        ))
        .await
    });
    let answered = tokio::time::timeout(Duration::from_secs(2), read).await;
    release_tx.send(()).unwrap();
    let e = match answered
        .expect("the lookup waited for the sanitization")
        .unwrap()
    {
        Err(rmcp::ServiceError::McpError(e)) => e,
        other => panic!("{other:?}"),
    };
    assert_eq!(e.message, "unknown_resource");
    let r = call.await.unwrap().unwrap();
    assert_eq!(r.content.len(), 2, "the call finished after the release");
    c.cancel().await.ok();
    a.stop().await;
}

/// Review Focus 4 ordering: an oversized result is refused before any
/// engine work.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_oversized_result_costs_no_engine_work() {
    let config = GatewayConfig {
        max_response_bytes: 1_000,
        ..GatewayConfig::default()
    };
    let (_dir, engine, handler, a) = ready_handler(config).await;
    let c = agent(handler).await;
    let before = engine.batches.load(Ordering::SeqCst);
    let e = match c
        .peer()
        .call_tool(
            CallToolRequestParams::new("long").with_arguments(
                serde_json::json!({ "bytes": 50_000 })
                    .as_object()
                    .cloned()
                    .unwrap(),
            ),
        )
        .await
    {
        Err(rmcp::ServiceError::McpError(e)) => e,
        other => panic!("{other:?}"),
    };
    assert_eq!(e.message, "resource_limit");
    assert_eq!(
        engine.batches.load(Ordering::SeqCst),
        before,
        "no batch ran"
    );
    c.cancel().await.ok();
    a.stop().await;
}

/// M4 spec §16.4: prompts and reads leave records too (the daemon tests
/// cover tools). A record names the dataset and the upstream by opaque
/// label only; a released one carries its size and keyed digest.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prompts_and_reads_leave_activity_records() {
    let (_dir, vault, engine) = setup();
    engine.block_ids.store(false, Ordering::SeqCst);
    let handler = DatasetHandler::new(
        "crm",
        "label",
        vault.clone(),
        Arc::clone(&engine) as Arc<dyn Blocks>,
        GatewayConfig::default(),
        ActivitySink::spawn(vault.clone(), true),
    );
    let a = running("a").await;
    handler.set_upstreams(vec![(
        Arc::clone(&a),
        UpstreamContract::from_row(POLICY, None),
    )]);
    handler.rebuild().await;
    let c = agent(handler).await;
    let mut p = GetPromptRequestParams::new("greet");
    p.arguments = serde_json::json!({ "name": "Ann" }).as_object().cloned();
    c.peer().get_prompt(p).await.unwrap();
    let resources = c.peer().list_all_resources().await.unwrap();
    let customer = resources.iter().find(|r| r.name != "logo").unwrap();
    c.peer()
        .read_resource(ReadResourceRequestParams::new(customer.uri.clone()))
        .await
        .unwrap();
    let logo = resources.iter().find(|r| r.name == "logo").unwrap();
    let e = match c
        .peer()
        .read_resource(ReadResourceRequestParams::new(logo.uri.clone()))
        .await
    {
        Err(rmcp::ServiceError::McpError(e)) => e,
        other => panic!("{other:?}"),
    };
    assert_eq!(e.message, "unsupported_content");
    let all = inumaki_vault::ActivityFilter {
        dataset: Some(vault.opaque_ref("crm")),
        since: None,
        limit: 10,
    };
    let mut recs = Vec::new();
    for _ in 0..200 {
        recs = vault.activity(&all).unwrap();
        if recs.len() >= 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    use inumaki_vault::{Direction, FrontDoor, Verdict};
    let verdicts: Vec<Verdict> = recs.iter().map(|r| r.verdict).collect();
    assert_eq!(
        verdicts,
        [Verdict::Unsupported, Verdict::Released, Verdict::Released],
        "newest first"
    );
    for r in &recs {
        assert_eq!(r.front_door, FrontDoor::Gateway);
        assert_eq!(r.direction, Direction::Result);
        assert_eq!(r.upstream, Some(vault.opaque_upstream("crm", "a")));
    }
    assert!(recs[0].released.is_none() && recs[0].bytes == 0);
    assert!(recs[1].released.is_some() && recs[1].bytes > 0);
    assert!(recs[2].released.is_some() && recs[2].bytes > 0);
    c.cancel().await.ok();
    a.stop().await;
}

/// Final review, finding 3: list-change notifications are sent after the
/// rebuild lock is released and never wait on a session for long. A session
/// that stops reading (a client with an open, unread stream) fills its
/// transport; before, the next rebuild waited on it while holding the
/// rebuild lock, and so did every rebuild after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_that_never_reads_does_not_block_rebuilds() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let (_dir, engine, handler, a) = ready_handler(GatewayConfig::default()).await;
    // A raw client over a tiny pipe: it initializes, then never reads again.
    let (client_io, server_io) = tokio::io::duplex(256);
    let served = handler.clone();
    tokio::spawn(async move {
        if let Ok(s) = rmcp::serve_server(served, server_io).await {
            let _ = s.waiting().await;
        }
    });
    let (rd, mut wr) = tokio::io::split(client_io);
    wr.write_all(
        concat!(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#,
            "\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut lines = BufReader::new(rd).lines();
    let init = tokio::time::timeout(Duration::from_secs(5), lines.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(init.contains("\"result\""), "{init}");
    wr.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    // Every rebuild changes the catalog (the contract is refused, then
    // accepted again), so each one notifies; the pipe is full after two.
    for i in 0..8 {
        engine.block_ids.store(i % 2 == 0, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(5), handler.rebuild())
            .await
            .unwrap_or_else(|_| panic!("rebuild {i} waited on a session that does not read"));
    }
    drop(wr);
    drop(lines);
    a.stop().await;
}

/// Final review, finding 4: a listing that failed for a transient reason
/// (models or vault unavailable, the profile unreadable) is retried with
/// backoff, so the catalog comes back without an upstream restart or a row
/// change. A content failure is not retried.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_transient_listing_failure_is_retried() {
    async fn comes_back(handler: &DatasetHandler) -> bool {
        for _ in 0..100 {
            if handler.catalog().route_tool("lookup").is_some() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }
    for (models, profile) in [(1, 0), (0, 1)] {
        let (_dir, vault, engine) = setup();
        engine.block_ids.store(false, Ordering::SeqCst);
        engine.fail_next.store(models, Ordering::SeqCst);
        engine.fail_profile.store(profile, Ordering::SeqCst);
        let handler = DatasetHandler::new(
            "crm",
            "label",
            vault,
            Arc::clone(&engine) as Arc<dyn Blocks>,
            GatewayConfig::default(),
            ActivitySink::disabled(),
        );
        let a = running("a").await;
        handler.set_upstreams(vec![(
            Arc::clone(&a),
            UpstreamContract::from_row(POLICY, None),
        )]);
        handler.rebuild().await;
        assert!(
            handler.catalog().tools().is_empty(),
            "the first listing failed"
        );
        assert!(
            comes_back(&handler).await,
            "not retried (models {models}, profile {profile})"
        );
        a.stop().await;
    }
    // A refused contract (content, not availability) stays refused.
    let (_dir, vault, engine) = setup();
    let handler = DatasetHandler::new(
        "crm",
        "label",
        vault,
        Arc::clone(&engine) as Arc<dyn Blocks>,
        GatewayConfig::default(),
        ActivitySink::disabled(),
    );
    let a = running("a").await;
    handler.set_upstreams(vec![(
        Arc::clone(&a),
        UpstreamContract::from_row(POLICY, None),
    )]);
    handler.rebuild().await;
    assert_eq!(handler.status().upstreams[0].contract, "invalid");
    let before = engine.profiles.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    assert_eq!(
        engine.profiles.load(Ordering::SeqCst),
        before,
        "no rebuild again for a non-transient refusal"
    );
    a.stop().await;
}

/// Final review, finding 5: the tripwire scans what gets rehydrated,
/// including a dynamic key under a `map` rule (the key is data there).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_map_rule_key_trips_the_tripwire() {
    let mut policy: serde_json::Value = serde_json::from_str(POLICY).unwrap();
    policy["tools"]["nested"]["arguments"] =
        serde_json::json!({ "/filter": { "map": "free_text" } });
    let config = GatewayConfig {
        tripwire: TripwireMode::Block,
        ..GatewayConfig::default()
    };
    let (_dir, _engine, handler, a) = ready_handler_with(config, &policy.to_string()).await;
    let c = agent(handler.clone()).await;
    let mut filter = serde_json::Map::new();
    filter.insert(IDENTITY.to_string(), serde_json::json!("x"));
    let e = match c
        .peer()
        .call_tool(
            CallToolRequestParams::new("nested").with_arguments(
                serde_json::json!({ "filter": filter })
                    .as_object()
                    .cloned()
                    .unwrap(),
            ),
        )
        .await
    {
        Err(rmcp::ServiceError::McpError(e)) => e,
        other => panic!("{other:?}"),
    };
    assert_eq!(e.message, "privacy_block");
    assert_eq!(e.data.unwrap()["checks"], serde_json::json!(["ClearValue"]));
    assert_eq!(handler.status().clear_value_hits, 1);
    c.cancel().await.ok();
    a.stop().await;
}
