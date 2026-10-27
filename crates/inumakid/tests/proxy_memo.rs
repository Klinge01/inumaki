//! The daemon's side of the static-prompt NER memo (M8 spec §20, amendment
//! 2026-10-12; plan Task 3): `DaemonHost`'s dictionary contract, its two
//! engines (ruling L2-40), and, with real models (`models-tests`), a hit
//! across two sessions through a proxy over the daemon's host.

mod common;

use std::sync::Arc;
use std::time::Duration;

use hyper::Method;
use inumaki_core::span::EntityKind;
use inumaki_core::token::TokenStore;
use inumaki_proxy::host::ProxyHost;

fn host(d: &common::TestDaemon) -> inumakid::proxy_host::DaemonHost {
    inumakid::proxy_host::DaemonHost::new(Arc::downgrade(&d.state)).expect("the host builds")
}

/// The host contract (M8 spec §20, amendment 2026-10-12): `dictionary()`
/// returns the same `Arc` until its content changes, so the memo is not
/// cleared on every request; rotating a user dataset is a change and gives
/// a new `Arc`, for a dataset with entities and for an empty one. (The
/// namespace's refresh also rebuilds the detector on a new epoch, so the
/// generation moves too; the epoch id in the key does not rely on that.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_dictionary_is_one_arc_until_a_user_dataset_rotates() {
    let d = common::start_with("", "", Duration::from_secs(3600), None).await;
    d.dataset("kunden").await;
    d.dataset("leer").await;
    {
        let ns = d.state.namespace("kunden").unwrap();
        let mut n = ns.lock().unwrap();
        n.token_for(&EntityKind::Person, "Quirin Zablowski")
            .unwrap();
        n.rebuild_detector_now().unwrap();
    }
    let h = host(&d);
    let a = h.dictionary().unwrap();
    let b = h.dictionary().unwrap();
    assert!(Arc::ptr_eq(&a, &b), "no change, the same Arc");

    for id in ["kunden", "leer"] {
        let before = h.dictionary().unwrap();
        let (code, body) = d
            .call(Method::POST, &format!("/v1/datasets/{id}/rotate"), None)
            .await;
        assert_eq!(code, 200, "{body}");
        let after = h.dictionary().unwrap();
        assert!(
            !Arc::ptr_eq(&before, &after),
            "{id}: a rotation is a change"
        );
        assert!(
            Arc::ptr_eq(&after, &h.dictionary().unwrap()),
            "{id}: stable again after the rotation"
        );
    }
    d.stop().await;
}

/// Ruling L2-40 at the host: `engine_unmemoized()` is the unwrapped engine
/// the gateway, the mirror and the hook share (`Engines::engine` with no
/// dataset, the same `Arc`), and `engine()` is the separate proxy engine
/// wrapped by the host's memo (`Engines::proxy_engine`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_unmemoized_is_the_shared_engine_and_engine_is_the_memo_engine() {
    let d = common::start_with("", "", Duration::from_secs(3600), None).await;
    let h = host(&d);
    let memo = h.ner_memo().expect("a host over a state has a memo");
    let shared = d.state.engines.engine("offline", None).unwrap();
    let plain = h.engine_unmemoized("offline").unwrap();
    assert!(Arc::ptr_eq(&plain, &shared), "the shared, unwrapped engine");
    let wrapped = h.engine("offline").unwrap();
    assert!(!Arc::ptr_eq(&wrapped, &shared), "never the shared engine");
    assert!(Arc::ptr_eq(
        &wrapped,
        &d.state.engines.proxy_engine("offline", &memo).unwrap()
    ));
    d.stop().await;
}

/// With real models (P4): two sessions with the same system text and the
/// client header, through the daemon's own proxy (its host, its memo, a
/// scripted upstream): session 2's system leaf is served by the memo, which
/// `GET /v1/proxy` reports as `static_cache.hits >= 1`, and the two
/// forwarded bodies are equal after canonical token renaming. The status
/// also carries a timing window of 2 samples and the enabled flag. (L2-40
/// is covered by the test above and the unit tests in `engines.rs` and
/// `proxy_host.rs`.) Needs `INUMAKI_MODELS_DIR`.
#[cfg(feature = "models-tests")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_sessions_hit_the_static_prompt_memo_through_the_daemon_host() {
    use axum::body::Body;
    use inumaki_proxy::{Script, Step};
    use tower::ServiceExt;

    let models = std::path::PathBuf::from(
        std::env::var("INUMAKI_MODELS_DIR").expect("set INUMAKI_MODELS_DIR"),
    );
    inumaki_proxy::forward::ensure_crypto_provider();
    let (addr, up) = inumaki_proxy::scripted::spawn_http(Script(vec![Step::EchoUserText])).await;
    let config = format!(
        "{}\n[daemon]\ndefault_profile = \"support-email\"\n[vault]\nkey_source = \"file\"\n[gateway]\nlisten = \"127.0.0.1:0\"\n[proxy]\nlisten = \"127.0.0.1:0\"\n[proxy.upstreams.anthropic]\nbase_url = \"http://{addr}\"\n",
        common::BASE_CONFIG
    );
    let d = common::start_with_config(config, Some(models), Duration::from_secs(3600), None).await;
    assert!(d.state.cfg.proxy.static_cache, "on by default");
    let (_, status) = d.call(Method::GET, "/v1/proxy", None).await;
    assert_eq!(status["static_cache"]["enabled"], true);
    assert_eq!(status["static_cache"]["hits"], 0);
    assert_eq!(status["timing"]["window"], 0);
    let client = status["client_header"]["value"]
        .as_str()
        .unwrap()
        .to_string();
    let proxy = d.state.proxy.get().expect("the daemon's proxy runs");
    let system = inumaki_proxy::bench_text::harness_system(4096);
    let body = serde_json::json!({"model": "m", "max_tokens": 10, "system": system,
        "messages": [{"role": "user", "content": "Please summarize the rules."}]})
    .to_string();
    for session in ["memo-s1", "memo-s2"] {
        let req = axum::http::Request::post("/anthropic/v1/messages")
            .header("content-type", "application/json")
            .header("x-inumaki-client", &client)
            .header("x-inumaki-session", session)
            .body(Body::from(body.clone()))
            .unwrap();
        let r = proxy.router().oneshot(req).await.unwrap();
        assert_eq!(r.status().as_u16(), 200, "{session}");
    }
    let (_, status) = d.call(Method::GET, "/v1/proxy", None).await;
    let sc = &status["static_cache"];
    assert_eq!(sc["enabled"], true, "{sc}");
    assert!(
        sc["hits"].as_u64().unwrap() >= 1,
        "session 2 was served by the memo: {sc}"
    );
    assert!(
        sc["misses"].as_u64().unwrap() >= 1,
        "session 1 ran the models: {sc}"
    );
    assert_eq!(status["timing"]["window"], 2, "both requests were sampled");
    assert!(status["timing"]["last"]["local_ms"].is_u64());
    let sent = up.recorded();
    assert_eq!(sent.len(), 2);
    let settings = &d.state.cfg.proxy.session_tokens;
    let canon = |b: &[u8]| canon(settings, &String::from_utf8_lossy(b));
    assert_eq!(
        canon(&sent[0].1),
        canon(&sent[1].1),
        "equal after canonical renaming"
    );

    d.stop().await;
}

/// `s` with every token replaced by its kind label and the index of its
/// first occurrence, so texts of two sessions compare equal when only the
/// random token parts differ. Tokens never overlap (each ends with the
/// closing delimiter), so plain replacement is exact.
#[cfg(feature = "models-tests")]
fn canon(settings: &inumaki_core::config::TokenSettings, s: &str) -> String {
    let found = inumaki_core::rehydrate::Rehydrator::new(settings).tokens_in(s);
    let mut seen: Vec<&String> = Vec::new();
    for t in &found {
        if !seen.contains(&t) {
            seen.push(t);
        }
    }
    let mut out = s.to_string();
    for (i, t) in seen.iter().enumerate() {
        let label = inumaki_core::token::parse_token(settings, t)
            .expect("a token the pattern found parses")
            .label;
        out = out.replace(t.as_str(), &format!("<{label}#{i}>"));
    }
    out
}
