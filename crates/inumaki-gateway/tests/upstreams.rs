//! M4 spec §5.2: upstream connections (in-process, HTTP), the supervisor's
//! backoff and restart, the catalog's static names, collision prefixes and
//! routing, opaque handles, and list-changed notifications.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use inumaki_gateway::aggregate::RawLists;
use inumaki_gateway::aggregate::{
    Catalog, TemplateRoute, UpstreamLists, fetch_lists, prefixed, valid_static_name,
};
use inumaki_gateway::handles::{HandleStore, Owner, expand_template, template_params};
use inumaki_gateway::scripted::{IDENTITY, ScriptedUpstream, serve_scripted_http};
use inumaki_gateway::upstream::{
    BoxFut, BuiltinUpstreams, ResolvedUpstream, Running, STABLE_UPTIME, ServerGuard, Supervision,
    UpstreamClient, UpstreamError, UpstreamEvent, UpstreamHandle, UpstreamState, backoff,
    connect_http, connect_in_process, connect_stdio,
};
use inumaki_vault::UpstreamKind;
use rmcp::model::{CallToolRequestParams, Prompt, Resource, ResourceTemplate, Tool};
use serde_json::json;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

async fn scripted_in_process(c: UpstreamClient) -> (Running, ServerGuard) {
    let ct = CancellationToken::new();
    connect_in_process(ScriptedUpstream::default().with_stop(ct.clone()), c, ct)
        .await
        .unwrap()
}

fn client(name: &str) -> (UpstreamClient, mpsc::UnboundedReceiver<UpstreamEvent>) {
    let (tx, rx) = mpsc::unbounded_channel();
    (
        UpstreamClient {
            name: name.into(),
            events: tx,
        },
        rx,
    )
}

fn args(v: serde_json::Value) -> rmcp::model::JsonObject {
    v.as_object().cloned().unwrap()
}

fn text_of(r: &rmcp::model::CallToolResult) -> String {
    r.content
        .iter()
        .filter_map(|c| c.as_text().map(|t| t.text.clone()))
        .collect::<Vec<_>>()
        .join("\n")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_process_upstream_lists_and_calls() {
    let (c, _rx) = client("mail");
    let (running, _guard) = scripted_in_process(c).await;
    let tools = running.peer().list_all_tools().await.unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    assert!(
        names.contains(&"echo") && names.contains(&"record") && names.contains(&"lookup"),
        "{names:?}"
    );
    let r = running
        .peer()
        .call_tool(
            CallToolRequestParams::new("echo").with_arguments(args(json!({ "query": "hi" }))),
        )
        .await
        .unwrap();
    assert_eq!(text_of(&r), "echo: hi");
    assert_eq!(r.structured_content.as_ref().unwrap()["received"], "hi");
    let raw = fetch_lists(running.peer(), std::time::Duration::from_secs(5))
        .await
        .unwrap();
    assert!(raw.tools.len() >= 12);
    assert_eq!(raw.prompts.len(), 1);
    assert_eq!(raw.resources.len(), 2);
    assert_eq!(raw.templates.len(), 1);
    assert!(
        raw.resources[0].uri.contains("Zyxwuria"),
        "the raw uri carries the identity; the catalog must never expose it"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_upstream_connects_with_stored_headers() {
    let (addr, ct) = serve_scripted_http(ScriptedUpstream::default()).await;
    let mut headers = BTreeMap::new();
    headers.insert("X-Test".to_string(), "abc".to_string());
    let u = ResolvedUpstream {
        name: "wiki".into(),
        kind: UpstreamKind::Http,
        command: None,
        args: vec![],
        cwd: None,
        url: Some(format!("http://{addr}/mcp")),
        env: BTreeMap::new(),
        headers,
    };
    let (c, _rx) = client("wiki");
    let running = connect_http(&u, c, usize::MAX).await.unwrap();
    let r = running
        .peer()
        .call_tool(
            CallToolRequestParams::new("headers").with_arguments(args(json!({ "name": "x-test" }))),
        )
        .await
        .unwrap();
    assert_eq!(text_of(&r), "abc");
    let mut bad = u.clone();
    bad.headers
        .insert("Authorization".into(), "Basic abc".into());
    let (c, _rx) = client("wiki");
    assert!(matches!(
        connect_http(&bad, c, usize::MAX).await,
        Err(UpstreamError::Config("authorization"))
    ));
    let mut none = u.clone();
    none.url = None;
    let (c, _rx) = client("wiki");
    assert!(matches!(
        connect_http(&none, c, usize::MAX).await,
        Err(UpstreamError::Config("url"))
    ));
    ct.cancel();
}

#[test]
fn backoff_doubles_and_caps() {
    let max = Duration::from_secs(30);
    let seq: Vec<u64> = (0..7).map(|a| backoff(a, max).as_secs()).collect();
    assert_eq!(seq, [1, 2, 4, 8, 16, 30, 30]);
    assert_eq!(backoff(40, max), max, "no overflow");
    assert_eq!(
        backoff(3, Duration::from_millis(50)),
        Duration::from_millis(50)
    );
}

fn tool(name: &str) -> Tool {
    Tool::new(
        name.to_string(),
        format!("tool {name}"),
        serde_json::Map::new(),
    )
}

fn res(uri: &str, name: &str) -> Resource {
    Resource::new(uri, name)
}

fn lists(name: &str, index: usize, tools: &[&str]) -> UpstreamLists {
    UpstreamLists {
        name: name.into(),
        index,
        tools: tools.iter().map(|t| tool(t)).collect(),
        prompts: vec![],
        resources: vec![],
        templates: vec![],
    }
}

#[test]
fn static_names_are_checked() {
    for ok in ["echo", "get_user", "crm.search", "a-b", &"x".repeat(64)] {
        assert!(valid_static_name(ok), "{ok}");
    }
    for bad in [
        "",
        " echo",
        "Zyxwuria Quolnath",
        "ä",
        "a/b",
        &"x".repeat(65),
    ] {
        assert!(!valid_static_name(bad), "{bad:?}");
    }
}

#[test]
fn catalog_prefixes_collisions_and_routes_by_exposed_name() {
    let mut a = lists("crm", 0, &["search", "get"]);
    let mut b = lists("wiki", 1, &["search", "page"]);
    a.prompts.push(Prompt::new("summarize", Some("s"), None));
    b.prompts.push(Prompt::new("summarize", Some("s"), None));
    a.resources.push((
        res("inumaki://res/aaaaaaaaaaaaaaaa", "customers"),
        "crm://customers".into(),
    ));
    let tpl = ResourceTemplate::new("inumaki://tpl/bbbbbbbbbbbbbbbb/{id}", "page");
    b.templates.push((
        tpl,
        TemplateRoute {
            original: "wiki://page/{id}".into(),
            params: vec!["id".into()],
        },
    ));
    let c = Catalog::build(&[a, b]);
    let names: Vec<&str> = c.tools().iter().map(|t| t.name.as_ref()).collect();
    assert_eq!(names, ["search", "get", "wiki__search", "page"]);
    assert_eq!(prefixed("wiki", "search"), "wiki__search");
    assert_eq!(c.route_tool("search"), Some((0, "search")));
    assert_eq!(c.route_tool("wiki__search"), Some((1, "search")));
    assert_eq!(c.route_tool("nope"), None);
    let prompts: Vec<&str> = c.prompts().iter().map(|p| p.name.as_str()).collect();
    assert_eq!(prompts, ["summarize", "wiki__summarize"]);
    assert_eq!(c.route_prompt("wiki__summarize"), Some((1, "summarize")));
    assert_eq!(
        c.route_resource("inumaki://res/aaaaaaaaaaaaaaaa"),
        Some((0, "crm://customers"))
    );
    assert_eq!(
        c.route_resource("crm://customers"),
        None,
        "raw uris are never routable"
    );
    let (i, route, values) = c
        .route_template("inumaki://tpl/bbbbbbbbbbbbbbbb/42")
        .unwrap();
    assert_eq!(
        (i, route.original.as_str(), values),
        (1, "wiki://page/{id}", vec!["42".to_string()])
    );
    assert!(
        c.route_template("inumaki://tpl/bbbbbbbbbbbbbbbb").is_none(),
        "missing value"
    );
    assert!(
        c.route_template("inumaki://tpl/cccccccccccccccc/42")
            .is_none()
    );
    assert_eq!(c.offers(), (true, true, true));
    assert_eq!(c.upstream_name(1), "wiki");
    assert!(Catalog::empty().tools().is_empty());

    // `wiki` lists `wiki__search` before `search`: the prefixed form is
    // taken, so the second is dropped rather than shadowing the first.
    let a = lists("crm", 0, &["search"]);
    let b = lists("wiki", 1, &["wiki__search", "search"]);
    let c = Catalog::build(&[a, b]);
    let names: Vec<&str> = c.tools().iter().map(|t| t.name.as_ref()).collect();
    assert_eq!(names, ["search", "wiki__search"]);
    assert_eq!(c.route_tool("wiki__search"), Some((1, "wiki__search")));
}

/// Review Focus 5.
#[test]
fn handles_hide_uris_and_go_stale_with_their_upstream() {
    let (crm, wiki) = (Owner::new("crm", 1), Owner::new("wiki", 2));
    let mut h = HandleStore::new();
    let a = h.resource(&crm, &format!("crm://customer/{IDENTITY}"));
    assert!(
        a.starts_with("inumaki://res/") && a.len() == "inumaki://res/".len() + 16,
        "{a}"
    );
    assert!(!a.contains("Zyxwuria"));
    assert_eq!(
        h.resource(&crm, &format!("crm://customer/{IDENTITY}")),
        a,
        "stable for the same uri"
    );
    assert_ne!(
        h.resource(&wiki, &format!("crm://customer/{IDENTITY}")),
        a,
        "per upstream"
    );
    assert_eq!(
        h.resolve_resource(&a),
        Some((&crm, format!("crm://customer/{IDENTITY}").as_str()))
    );
    let t = h.template(&wiki, "wiki://page/{id}");
    assert!(t.starts_with("inumaki://tpl/"));
    assert_eq!(
        h.resolve_template(&format!("{t}/42")),
        Some((&wiki, "wiki://page/{id}", "42"))
    );
    assert_eq!(
        h.resolve_template(&t),
        Some((&wiki, "wiki://page/{id}", ""))
    );
    // `crm` removed and re-added under the same name: a new generation.
    let crm_again = Owner::new("crm", 3);
    let b = h.resource(&crm_again, &format!("crm://customer/{IDENTITY}"));
    assert_ne!(b, a, "a re-added upstream never inherits the old handle");
    h.retain(&[wiki.clone(), crm_again.clone()]);
    assert_eq!(h.resolve_resource(&b).map(|(o, _)| o), Some(&crm_again));
    assert_eq!(
        h.resolve_resource(&a),
        None,
        "stale after its upstream went away"
    );
    assert!(h.resolve_template(&format!("{t}/1")).is_some());
    assert_eq!(template_params("mem://note/{id}/v/{ver}"), ["id", "ver"]);
    assert_eq!(
        expand_template("mem://note/{id}", &["id".into()], &["a%2Fb".into()]).as_deref(),
        Some("mem://note/a%2Fb")
    );
    assert_eq!(
        expand_template(
            "mem://note/{id}/{v}",
            &["id".into(), "v".into()],
            &["1".into()]
        ),
        None
    );
    let (p2, v2): (Vec<String>, Vec<String>) = (
        vec!["id".into(), "v".into()],
        vec!["{v}".into(), "2".into()],
    );
    assert_eq!(
        expand_template("mem://note/{id}/{v}", &p2, &v2).as_deref(),
        Some("mem://note/{v}/2"),
        "values are not re-expanded"
    );
    assert_eq!(
        expand_template("mem://note/{other}", &["id".into()], &["1".into()]),
        None,
        "unknown parameter"
    );
}

struct Flaky {
    fail_times: u32,
    attempts: Arc<AtomicU32>,
}

impl BuiltinUpstreams for Flaky {
    fn connect(
        &self,
        _dataset: &str,
        _upstream: &str,
        client: UpstreamClient,
    ) -> BoxFut<Result<(Running, ServerGuard), UpstreamError>> {
        let n = self.attempts.fetch_add(1, Ordering::SeqCst);
        let fail = n < self.fail_times;
        Box::pin(async move {
            if fail {
                return Err(UpstreamError::Builtin("simulated"));
            }
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

/// Connects once, then refuses: an upstream that went down and stays down.
struct OnceThenDown {
    attempts: Arc<AtomicU32>,
}

impl BuiltinUpstreams for OnceThenDown {
    fn connect(
        &self,
        _dataset: &str,
        _upstream: &str,
        client: UpstreamClient,
    ) -> BoxFut<Result<(Running, ServerGuard), UpstreamError>> {
        let first = self.attempts.fetch_add(1, Ordering::SeqCst) == 0;
        Box::pin(async move {
            if !first {
                return Err(UpstreamError::Builtin("down"));
            }
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

/// Connects every time; the n-th connection crashes after `uptimes[n]`
/// (the ones past the list stay up). Records when each connect started.
struct CrashAfter {
    uptimes: Vec<Duration>,
    connects: Arc<std::sync::Mutex<Vec<tokio::time::Instant>>>,
}

impl BuiltinUpstreams for CrashAfter {
    fn connect(
        &self,
        _dataset: &str,
        _upstream: &str,
        client: UpstreamClient,
    ) -> BoxFut<Result<(Running, ServerGuard), UpstreamError>> {
        let mut connects = self.connects.lock().unwrap();
        let uptime = self.uptimes.get(connects.len()).copied();
        connects.push(tokio::time::Instant::now());
        Box::pin(async move {
            let ct = CancellationToken::new();
            let r = connect_in_process(
                ScriptedUpstream::default().with_stop(ct.clone()),
                client,
                ct.clone(),
            )
            .await;
            if let Some(up) = uptime {
                tokio::spawn(async move {
                    tokio::time::sleep(up).await;
                    ct.cancel();
                });
            }
            r
        })
    }
}

/// Never finishes its handshake.
struct Hangs {
    attempts: Arc<AtomicU32>,
}

impl BuiltinUpstreams for Hangs {
    fn connect(
        &self,
        _dataset: &str,
        _upstream: &str,
        _client: UpstreamClient,
    ) -> BoxFut<Result<(Running, ServerGuard), UpstreamError>> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        Box::pin(std::future::pending())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hanging_handshake_times_out_and_is_retried() {
    let attempts = Arc::new(AtomicU32::new(0));
    let builtin: Arc<dyn BuiltinUpstreams> = Arc::new(Hangs {
        attempts: Arc::clone(&attempts),
    });
    let (tx, _rx) = mpsc::unbounded_channel();
    let h = UpstreamHandle::spawn(
        "ds-label".into(),
        "mail-work".into(),
        resolved_mail(),
        tx,
        builtin,
        Supervision {
            max_backoff: Duration::from_millis(40),
            handshake_timeout: Duration::from_millis(100),
            max_message: usize::MAX,
        },
    );
    wait_state(&h, UpstreamState::Failed("init"), Duration::from_secs(5)).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while attempts.load(Ordering::SeqCst) < 2 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "retried after the timeout"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    h.stop().await;
    assert_eq!(h.state(), UpstreamState::Stopped);
}

async fn wait_state(h: &UpstreamHandle, want: UpstreamState, within: Duration) {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        if h.state() == want {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "state is {} not {want}",
            h.state()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn resolved_mail() -> ResolvedUpstream {
    ResolvedUpstream {
        name: "mail".into(),
        kind: UpstreamKind::Mail,
        command: None,
        args: vec![],
        cwd: None,
        url: None,
        env: BTreeMap::new(),
        headers: BTreeMap::new(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supervisor_retries_with_backoff_and_reports_state() {
    let attempts = Arc::new(AtomicU32::new(0));
    let builtin: Arc<dyn BuiltinUpstreams> = Arc::new(Flaky {
        fail_times: 2,
        attempts: Arc::clone(&attempts),
    });
    let (tx, mut rx) = mpsc::unbounded_channel();
    let h = UpstreamHandle::spawn(
        "ds-label".into(),
        "mail-work".into(),
        resolved_mail(),
        tx,
        builtin,
        Supervision {
            max_backoff: Duration::from_millis(40),
            handshake_timeout: Duration::from_secs(5),
            max_message: usize::MAX,
        },
    );
    wait_state(&h, UpstreamState::Running, Duration::from_secs(5)).await;
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        3,
        "two failures, then success"
    );
    assert_eq!(
        rx.recv().await.unwrap(),
        UpstreamEvent::ListChanged {
            upstream: "mail".into()
        }
    );
    let st = h.status(inumaki_gateway::ContractState::None);
    assert_eq!(
        (
            st.name.as_str(),
            st.kind.as_str(),
            st.state.as_str(),
            st.contract.as_str()
        ),
        ("mail", "mail", "running", "none")
    );
    assert_eq!(st.restarts, 0, "failed starts are not restarts");
    assert!(h.peer().is_some());
    h.stop().await;
    assert_eq!(h.state(), UpstreamState::Stopped);
    assert!(h.peer().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supervisor_restarts_after_the_upstream_exits() {
    let attempts = Arc::new(AtomicU32::new(0));
    let builtin: Arc<dyn BuiltinUpstreams> = Arc::new(Flaky {
        fail_times: 0,
        attempts: Arc::clone(&attempts),
    });
    let (tx, mut rx) = mpsc::unbounded_channel();
    let h = UpstreamHandle::spawn(
        "ds-label".into(),
        "mail-work".into(),
        resolved_mail(),
        tx,
        builtin,
        Supervision {
            max_backoff: Duration::from_millis(40),
            handshake_timeout: Duration::from_secs(5),
            max_message: usize::MAX,
        },
    );
    wait_state(&h, UpstreamState::Running, Duration::from_secs(5)).await;
    assert_eq!(
        rx.recv().await.unwrap(),
        UpstreamEvent::ListChanged {
            upstream: "mail".into()
        }
    );
    let peer = h.peer().unwrap();
    let _ = peer.call_tool(CallToolRequestParams::new("crash")).await;
    assert_eq!(
        rx.recv().await.unwrap(),
        UpstreamEvent::Exited {
            upstream: "mail".into()
        }
    );
    wait_state(&h, UpstreamState::Running, Duration::from_secs(5)).await;
    assert_eq!(h.status(inumaki_gateway::ContractState::None).restarts, 1);
    assert_eq!(
        rx.recv().await.unwrap(),
        UpstreamEvent::ListChanged {
            upstream: "mail".into()
        }
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    h.stop().await;
}

/// An upstream that crashes right after its handshake keeps climbing the
/// backoff; only one that stayed up for `STABLE_UPTIME` starts over at 1 s.
#[tokio::test(start_paused = true)]
async fn quick_crashes_keep_backing_off_until_the_upstream_stays_up() {
    let zero = Duration::ZERO;
    let long = STABLE_UPTIME + Duration::from_secs(10);
    let uptimes = vec![zero, zero, zero, zero, long, zero];
    let connects = Arc::new(std::sync::Mutex::new(Vec::new()));
    let builtin: Arc<dyn BuiltinUpstreams> = Arc::new(CrashAfter {
        uptimes: uptimes.clone(),
        connects: Arc::clone(&connects),
    });
    let (tx, _rx) = mpsc::unbounded_channel();
    let h = UpstreamHandle::spawn(
        "ds-label".into(),
        "mail-work".into(),
        resolved_mail(),
        tx,
        builtin,
        Supervision {
            max_backoff: Duration::from_secs(30),
            handshake_timeout: Duration::from_secs(5),
            max_message: usize::MAX,
        },
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(600);
    while connects.lock().unwrap().len() < uptimes.len() + 1 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "only {} connects",
            connects.lock().unwrap().len()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let c = connects.lock().unwrap().clone();
    let delays: Vec<u64> = (0..uptimes.len())
        .map(|i| (c[i + 1] - c[i] - uptimes[i]).as_millis() as u64)
        .collect();
    let expected = [1000u64, 2000, 4000, 8000, 1000, 2000];
    for (got, want) in delays.iter().zip(expected) {
        assert!(
            *got >= want && *got < want + 100,
            "restart delays {delays:?}, want about {expected:?}"
        );
    }
    h.stop().await;
}

/// M4 spec §5: a colliding name keeps its owner while the owner is down.
/// Built the way a rebuild does it: every configured upstream in creation
/// order, a down one with its last-known lists.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_down_upstream_keeps_its_names() {
    let attempts = Arc::new(AtomicU32::new(0));
    let builtin: Arc<dyn BuiltinUpstreams> = Arc::new(OnceThenDown {
        attempts: Arc::clone(&attempts),
    });
    let (tx, mut rx) = mpsc::unbounded_channel();
    let crm = UpstreamHandle::spawn(
        "ds-label".into(),
        "ds".into(),
        ResolvedUpstream {
            name: "crm".into(),
            ..resolved_mail()
        },
        tx,
        builtin,
        Supervision {
            max_backoff: Duration::from_millis(40),
            handshake_timeout: Duration::from_secs(5),
            max_message: usize::MAX,
        },
    );
    wait_state(&crm, UpstreamState::Running, Duration::from_secs(5)).await;
    assert_eq!(
        crm.last_lists().map(|l| l.tools.len()),
        None,
        "nothing listed yet"
    );
    crm.set_last_lists(lists("crm", 0, &["search", "get"]));
    let wiki = lists("wiki", 1, &["search", "page"]);
    let configured = |crm_lists: Option<UpstreamLists>| -> Vec<UpstreamLists> {
        crm_lists.into_iter().chain([wiki.clone()]).collect()
    };

    let up = Catalog::build(&configured(crm.last_lists()));
    assert_eq!(up.route_tool("search"), Some((0, "search")));
    assert_eq!(up.route_tool("wiki__search"), Some((1, "search")));

    let _ = crm
        .peer()
        .unwrap()
        .call_tool(CallToolRequestParams::new("crash"))
        .await;
    assert_eq!(
        rx.recv().await.unwrap(),
        UpstreamEvent::ListChanged {
            upstream: "crm".into()
        }
    );
    assert_eq!(
        rx.recv().await.unwrap(),
        UpstreamEvent::Exited {
            upstream: "crm".into()
        }
    );
    wait_state(&crm, UpstreamState::Failed("down"), Duration::from_secs(5)).await;
    assert!(crm.peer().is_none());

    let down = Catalog::build(&configured(crm.last_lists()));
    let names: Vec<&str> = down.tools().iter().map(|t| t.name.as_ref()).collect();
    assert_eq!(
        names,
        ["search", "get", "wiki__search", "page"],
        "same exposure as while it was up"
    );
    assert_eq!(
        down.route_tool("search"),
        Some((0, "search")),
        "still the owner; the call answers upstream_unavailable"
    );
    assert_eq!(down.route_tool("wiki__search"), Some((1, "search")));
    crm.stop().await;
}

/// A dataset that forgets `stop` must not leak a running upstream: the
/// supervisor holds no reference to its handle, so dropping the handle ends it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_the_handle_stops_the_supervisor() {
    let attempts = Arc::new(AtomicU32::new(0));
    let builtin: Arc<dyn BuiltinUpstreams> = Arc::new(Flaky {
        fail_times: 0,
        attempts: Arc::clone(&attempts),
    });
    let (tx, _rx) = mpsc::unbounded_channel();
    let h = UpstreamHandle::spawn(
        "ds-label".into(),
        "mail-work".into(),
        resolved_mail(),
        tx,
        builtin,
        Supervision {
            max_backoff: Duration::from_millis(40),
            handshake_timeout: Duration::from_secs(5),
            max_message: usize::MAX,
        },
    );
    wait_state(&h, UpstreamState::Running, Duration::from_secs(5)).await;
    let peer = h.peer().unwrap();
    assert!(peer.list_all_tools().await.is_ok());
    drop(h);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while peer.list_all_tools().await.is_ok() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the connection outlived its handle"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "no reconnect after the drop"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_changed_notifications_reach_the_events_channel() {
    let (c, mut rx) = client("mail");
    let (running, _guard) = scripted_in_process(c).await;
    let before = running.peer().list_all_tools().await.unwrap().len();
    running
        .peer()
        .call_tool(CallToolRequestParams::new("change_tools"))
        .await
        .unwrap();
    let ev = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        ev,
        UpstreamEvent::ListChanged {
            upstream: "mail".into()
        }
    );
    assert_eq!(
        running.peer().list_all_tools().await.unwrap().len(),
        before + 1
    );
}

#[test]
fn upstream_debug_impls_print_no_values() {
    let mut u = ResolvedUpstream {
        name: "crm".into(),
        kind: UpstreamKind::Stdio,
        command: Some(IDENTITY.into()),
        args: vec![IDENTITY.into()],
        cwd: Some("/tmp".into()),
        url: None,
        env: BTreeMap::new(),
        headers: BTreeMap::new(),
    };
    u.env.insert("TOKEN".into(), "hunter2-canary".into());
    u.headers
        .insert("Authorization".into(), "Bearer hunter2-canary".into());
    let (c, _rx) = client("crm");
    let d = format!("{u:?} {c:?} {:?}", UpstreamError::Builtin("class"));
    assert!(!d.contains("hunter2") && !d.contains("Zyxwuria"), "{d}");

    // Handles, routes, lists, and the catalog hold raw upstream URIs and
    // unsanitized upstream data; their `Debug` prints counts only.
    let owner = Owner::new("crm", 1);
    let uri = format!("crm://customer/{IDENTITY}");
    let template = format!("crm://{IDENTITY}/{{id}}");
    let mut store = HandleStore::new();
    let res_handle = store.resource(&owner, &uri);
    let tpl_handle = store.template(&owner, &template);
    let route = TemplateRoute {
        original: template.clone(),
        params: vec!["id".into()],
    };
    let mut ul = lists("crm", 0, &["search"]);
    ul.resources
        .push((Resource::new(res_handle, IDENTITY), uri.clone()));
    ul.templates.push((
        ResourceTemplate::new(format!("{tpl_handle}/{{id}}"), IDENTITY),
        route.clone(),
    ));
    let raw = RawLists {
        tools: vec![tool(IDENTITY)],
        prompts: vec![Prompt::new(IDENTITY, Some(IDENTITY), None)],
        resources: vec![Resource::new(uri.clone(), IDENTITY)],
        templates: vec![ResourceTemplate::new(template.clone(), IDENTITY)],
    };
    let catalog = Catalog::build(std::slice::from_ref(&ul));
    assert_eq!(
        catalog.resources().len(),
        1,
        "the fixture must be exposed to be meaningful"
    );
    let d = format!("{store:?} {route:?} {ul:?} {raw:?} {catalog:?}");
    assert!(!d.contains("Zyxwuria") && !d.contains("crm://"), "{d}");
}

/// The catalog fails closed item by item: raw or malformed handles,
/// duplicate handles, and names that are not static after prefixing are
/// never exposed.
#[test]
fn catalog_drops_malformed_and_duplicate_items() {
    let long = "x".repeat(60);
    let mut a = lists("crm", 0, &[long.as_str()]);
    let b = lists("wiki", 1, &[long.as_str()]);
    let good = "inumaki://res/aaaaaaaaaaaaaaaa";
    for (uri, original) in [
        (format!("crm://customer/{IDENTITY}"), "crm://raw"),
        (good.to_string(), "crm://first"),
        (good.to_string(), "crm://second"),
        ("inumaki://res/AAAAAAAAAAAAAAAA".to_string(), "crm://upper"),
        ("inumaki://res/aaaaaaaaaaaaaaa".to_string(), "crm://short"),
        (format!("{good}/x"), "crm://suffix"),
    ] {
        a.resources.push((Resource::new(uri, "r"), original.into()));
    }
    let route = TemplateRoute {
        original: "crm://page/{id}".into(),
        params: vec!["id".into()],
    };
    for t in [
        "crm://page/{id}",
        "inumaki://tpl/bbbbbbbbbbbbbbbb/{id}",
        "inumaki://tpl/bbbbbbbbbbbbbbbb/{id}",
        "inumaki://tpl/bbbb/{id}",
    ] {
        a.templates
            .push((ResourceTemplate::new(t, "t"), route.clone()));
    }
    let c = Catalog::build(&[a, b]);
    let names: Vec<&str> = c.tools().iter().map(|t| t.name.as_ref()).collect();
    assert_eq!(
        names,
        [long.as_str()],
        "wiki__xxx… exceeds 64 bytes and is dropped"
    );
    assert_eq!(c.resources().len(), 1);
    assert_eq!(
        c.route_resource(good),
        Some((0, "crm://first")),
        "a duplicate never overwrites"
    );
    assert_eq!(
        c.route_resource(&format!("crm://customer/{IDENTITY}")),
        None
    );
    assert_eq!(c.templates().len(), 1);
    assert!(
        c.route_template("inumaki://tpl/bbbbbbbbbbbbbbbb/7")
            .is_some()
    );
    assert!(c.route_template("inumaki://tpl/bbbb/7").is_none());
}

/// A child that answers the handshake and one tool call, each time writing
/// a notification rmcp ignores and the response in one write.
const IGNORED_THEN_RESPONSE: &str = r#"
ignored='{"jsonrpc":"2.0","method":"$/custom","params":5}'
read -r line
id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
ver=$(printf '%s' "$line" | sed -n 's/.*"protocolVersion":"\([^"]*\)".*/\1/p')
printf '%s\n%s\n' "$ignored" "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"protocolVersion\":\"$ver\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"s\",\"version\":\"0\"}}}"
while read -r line; do
  case "$line" in
    *'"tools/call"'*)
      id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
      printf '%s\n%s\n' "$ignored" "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"ok\"}]}}"
      ;;
  esac
done
"#;

/// Review round 2 (N1): a line the codec ignores must not hold back the
/// response buffered right behind it, neither during the handshake nor on a
/// call (the child writes nothing more until it gets another request).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ignored_line_does_not_stall_the_message_behind_it() {
    let u = ResolvedUpstream {
        name: "sh".into(),
        kind: UpstreamKind::Stdio,
        command: Some("/bin/sh".into()),
        args: vec!["-c".into(), IGNORED_THEN_RESPONSE.into()],
        cwd: None,
        url: None,
        env: BTreeMap::new(),
        headers: BTreeMap::new(),
    };
    let (c, _rx) = client("sh");
    let running = tokio::time::timeout(
        Duration::from_secs(5),
        connect_stdio(
            &u,
            c,
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
            1 << 20,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        ),
    )
    .await
    .expect("the handshake completed")
    .unwrap();
    let r = tokio::time::timeout(
        Duration::from_secs(2),
        running.peer().call_tool(CallToolRequestParams::new("x")),
    )
    .await
    .expect("the call completed")
    .unwrap();
    assert_eq!(text_of(&r), "ok");
    running.cancel().await.ok();
}
