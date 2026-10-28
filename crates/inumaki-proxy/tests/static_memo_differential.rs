#![cfg(feature = "models-tests")]
//! The static-prompt NER memo's hard gate (M8 spec §20, amendment
//! 2026-10-12; integrator ruling L104 (a), plan Task 3): with the real
//! `support-email` models, the memo changes no forwarded byte and no
//! refusal.
//!
//! Inputs: the bench's two 20 KB system texts (the harness text and the
//! mail text, `inumaki bench --via-proxy` with its default seed 42), then
//! the closure-projection harness corpus (`projection_equivalence.rs`):
//! the `inumaki-eval` tuning and held-out families, each without and with
//! the noise transforms, seed 7. A corpus document shorter than the memo's
//! floor (`STATIC_MIN_BYTES`) is prefixed with the start of the harness text
//! to just above it, as an application's system prompt built around
//! business data would be; it stays one system leaf.
//!
//! Each input is sent as the top-level `system` of a Messages request with
//! the client header (a trusted request, so the leaf is eligible), in two
//! fresh sessions, through two in-process proxies over the same models: one
//! whose host provides a memo (on) and one whose host provides none (off).
//! The memo of the "on" proxy lives for the whole run, as in the daemon.
//! Since the 2026-10-20 amendment both sides read these system leaves as
//! harness-static text (trusted requests).
//! Per input and session, on and off must agree: the same status, and the
//! same forwarded body, or the same refusal body, after canonical token
//! renaming. Session 2 of the "on" run must have at least one memo hit.
//!
//! The report prints counts, diff kinds, and for a differing request its
//! input index and session number (numbers only), never text.
//!
//! The test is `#[ignore]`d so that a plain `cargo test` shows it as ignored
//! and can never record it as passed. Run it in release (debug tokenization
//! is many times slower), once per shard; it needs `INUMAKI_MODELS_DIR` and
//! fails without the models:
//! `INUMAKI_MEMO_DIFF_SHARD=i/n INUMAKI_MODELS_DIR=... cargo test --release
//! -p inumaki-proxy --features models-tests --test static_memo_differential
//! -- --ignored --nocapture`, for every `i` in `0..n` (the gate uses `n = 8`).
//! `INUMAKI_MEMO_DIFF_DOCS` sets the documents per corpus family (default
//! 200, as the projection harness; 800 corpus documents in all). Inputs are
//! sharded by index (`index % n == i`), the two bench texts first.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use inumaki_core::config::{CoreConfig, TokenSettings};
use inumaki_core::detect::{DetectCtx, Detector};
use inumaki_core::engine::Engine;
use inumaki_core::policy::Profile;
use inumaki_core::span::{DetectorId, EntityKind, Span};
use inumaki_eval::generate::{GenFamily, GenOptions, generate};
use inumaki_models::{BackendCache, ner_for_profile_with, resolve_models_dir};
use inumaki_proxy::bench_text::harness_system;
use inumaki_proxy::host::{HostBlock, HostError, ProxyEvent, ProxyHost, Scope};
use inumaki_proxy::memo::{
    NerMemo, NerRole, STATIC_MEMO_BYTES, STATIC_MEMO_ENTRIES, STATIC_MIN_BYTES,
};
use inumaki_proxy::{
    BaseUrls, BinaryMode, Proxy, ProxyConfig, Script, ScriptedUpstream, StaticNer, Step,
    TripwireMode, UncertainMode,
};
use tower::ServiceExt;
use zeroize::Zeroizing;

const PROFILE: &str = "support-email";
const CLIENT: &str = "memo-diff-client";

/// A detector that finds nothing: the host has no datasets.
struct Nothing;

impl Detector for Nothing {
    fn id(&self) -> DetectorId {
        DetectorId::Dictionary
    }
    fn detect(&self, _: &str, _: &DetectCtx) -> inumaki_core::Result<Vec<Span>> {
        Ok(Vec::new())
    }
}

/// A host with an engine, a policy, and no datasets. With a memo, `engine`
/// is the memo-wrapped engine and `plain` its unwrapped twin; without one,
/// both are the unwrapped engine.
struct DiffHost {
    engine: Arc<Engine>,
    plain: Arc<Engine>,
    policy: Arc<Profile>,
    dict: Arc<dyn Detector>,
    memo: Option<Arc<NerMemo>>,
}

impl ProxyHost for DiffHost {
    fn engine(&self, _: &str) -> Result<Arc<Engine>, HostError> {
        Ok(Arc::clone(&self.engine))
    }
    fn engine_unmemoized(&self, _: &str) -> Result<Arc<Engine>, HostError> {
        Ok(Arc::clone(&self.plain))
    }
    fn ner_memo(&self) -> Option<Arc<NerMemo>> {
        self.memo.clone()
    }
    fn policy(&self, _: &str) -> Result<Arc<Profile>, HostError> {
        Ok(Arc::clone(&self.policy))
    }
    fn dictionary(&self) -> Result<Arc<dyn Detector>, HostError> {
        Ok(Arc::clone(&self.dict))
    }
    fn scan_known(&self, _: &[String]) -> Result<Vec<(String, EntityKind, u32)>, HostError> {
        Ok(Vec::new())
    }
    fn identity(&self) -> Vec<(EntityKind, Zeroizing<String>)> {
        Vec::new()
    }
    fn dataset_token(
        &self,
        _: &EntityKind,
        _: &str,
    ) -> Result<Option<(String, Zeroizing<String>)>, HostError> {
        Ok(None)
    }
    fn resolve(
        &self,
        _: &[String],
        _: &Scope,
    ) -> Result<Vec<(String, EntityKind, Zeroizing<String>)>, HostError> {
        Ok(Vec::new())
    }
    fn released(&self, _: &[u8; 32]) -> bool {
        false
    }
    fn scan_definitions(&self, _: &[String]) -> Result<Vec<(EntityKind, u32)>, HostError> {
        Ok(Vec::new())
    }
    fn sanitize_dataset(&self, _: &str, _: Vec<String>) -> Result<Vec<HostBlock>, HostError> {
        Err(HostError::Unsupported)
    }
    fn record(&self, _: ProxyEvent) {}
}

/// The daemon's proxy defaults, with room for every session of the run.
fn config(tokens: TokenSettings) -> ProxyConfig {
    let nowhere = "http://127.0.0.1:9".to_string();
    ProxyConfig {
        enabled: true,
        listen: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        profile: PROFILE.to_string(),
        session_ttl: Duration::from_secs(4 * 3600),
        session_cap: 1 << 16,
        cache_bytes: 256 << 20,
        max_request_bytes: 8 << 20,
        max_inflight: 4,
        upstream_timeout: Duration::from_secs(600),
        binary: BinaryMode::Placeholder,
        uncertain: UncertainMode::Block,
        tripwire: TripwireMode::Notify,
        allowed_origins: Vec::new(),
        base_urls: BaseUrls {
            anthropic: nowhere.clone(),
            openai: nowhere.clone(),
            openai_codex: nowhere,
        },
        extra_headers: Default::default(),
        session_tokens: tokens,
        static_cache: true,
        static_ner: StaticNer::Scan,
        fingerprint: [0; 32],
    }
}

/// `s` with every token replaced by its kind label and the index of its
/// first occurrence, so texts of two sessions compare equal when only the
/// random token parts differ. Tokens never overlap (each ends with the
/// closing delimiter), so plain replacement is exact.
fn canon(settings: &TokenSettings, s: &str) -> String {
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

/// What one request produced: its status and, canonically renamed, the
/// body it forwarded (on a 200) or the refusal it answered (otherwise).
#[derive(PartialEq, Eq)]
struct Seen {
    status: u16,
    forwarded: Option<String>,
    refusal: Option<String>,
}

/// One proxy and the upstream it forwards to.
struct Side {
    proxy: Proxy,
    up: Arc<ScriptedUpstream>,
    tokens: TokenSettings,
}

impl Side {
    async fn send(&self, system: &str, session: &str) -> Seen {
        let body = serde_json::json!({"model": "m", "max_tokens": 16, "system": system,
            "messages": [{"role": "user", "content": "Please answer the customer briefly."}]})
        .to_string();
        let req = http::Request::post("/anthropic/v1/messages")
            .header("content-type", "application/json")
            .header("x-inumaki-client", CLIENT)
            .header("x-inumaki-session", session)
            .body(Body::from(body))
            .unwrap();
        let before = self.up.recorded().len();
        let r = self.proxy.router().oneshot(req).await.unwrap();
        let status = r.status().as_u16();
        let bytes = axum::body::to_bytes(r.into_body(), 64 << 20).await.unwrap();
        let sent = self.up.recorded();
        let forwarded = (sent.len() > before).then(|| {
            canon(
                &self.tokens,
                &String::from_utf8_lossy(&sent[sent.len() - 1].1),
            )
        });
        let refusal =
            (status != 200).then(|| canon(&self.tokens, &String::from_utf8_lossy(&bytes)));
        Seen {
            status,
            forwarded,
            refusal,
        }
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .map(|v| v.parse().expect("a number"))
        .unwrap_or(default)
}

/// `INUMAKI_MEMO_DIFF_SHARD=i/n`, default `0/1`.
fn shard() -> (usize, usize) {
    let Ok(v) = std::env::var("INUMAKI_MEMO_DIFF_SHARD") else {
        return (0, 1);
    };
    let (i, n) = v.split_once('/').expect("INUMAKI_MEMO_DIFF_SHARD=i/n");
    let (i, n): (usize, usize) = (i.parse().unwrap(), n.parse().unwrap());
    assert!(n > 0 && i < n, "INUMAKI_MEMO_DIFF_SHARD=i/n with i < n");
    (i, n)
}

/// The bench's mail system text (`inumaki bench --via-proxy`, seed 42):
/// untransformed tuning mails, each followed by a newline, to 20 KB.
fn bench_mail_system() -> String {
    let mut s = String::new();
    for d in generate(&GenOptions {
        seed: 42,
        count: 4000,
        transforms: false,
        family: GenFamily::Tuning,
    }) {
        if s.len() >= 20 * 1024 {
            break;
        }
        s.push_str(&d.text);
        s.push('\n');
    }
    s
}

/// Where an input came from (the report's counts).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Source {
    Bench,
    Corpus,
    /// A corpus document below the floor, prefixed with harness text.
    Padded,
}

/// A corpus document as an eligible system text: unchanged when long
/// enough, else after the start of the harness text, to just above the floor
/// (64 bytes of margin for NFC).
fn as_system(doc: &str) -> (Source, String) {
    let floor = STATIC_MIN_BYTES + 64;
    if doc.len() >= floor {
        return (Source::Corpus, doc.to_string());
    }
    (
        Source::Padded,
        format!("{}\n\n{doc}", harness_system(floor - doc.len())),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "hard gate (L104 a): --release, INUMAKI_MEMO_DIFF_SHARD=i/n, -- --ignored, every shard"]
// The report is the gate's output: counts and diff kinds only.
#[allow(clippy::print_stdout, clippy::print_stderr)]
async fn memo_on_equals_memo_off_over_the_harness_corpus() {
    let (shard, shards) = shard();
    let docs_per = env_usize("INUMAKI_MEMO_DIFF_DOCS", 200);

    let cfg = CoreConfig::from_toml(include_str!("../../../configs/default.toml")).unwrap();
    let p = cfg.resolve_profile(PROFILE).unwrap();
    let root = resolve_models_dir(None, cfg.ner.models_dir.as_deref());
    let ner = ner_for_profile_with(&cfg, &p, &root, &BackendCache::new())
        .expect("models (INUMAKI_MODELS_DIR)");
    let (s, v) = (
        ner.sanitizer.expect("support-email has a sanitizer NER"),
        ner.verifier.expect("support-email has a verifier NER"),
    );
    assert!(!Arc::ptr_eq(&s, &v));
    let build = |s, v| Arc::new(Engine::from_config(&cfg, PROFILE, Some(s), Some(v)).unwrap());
    let plain = build(Arc::clone(&s), Arc::clone(&v));
    let memo = NerMemo::new(PROFILE, [0; 32], STATIC_MEMO_ENTRIES, STATIC_MEMO_BYTES);
    let wrapped = build(
        memo.wrap(Arc::clone(&s), NerRole::Sanitizer),
        memo.wrap(Arc::clone(&v), NerRole::Verifier),
    );
    let policy = Arc::new(p);
    let tokens = plain.token_settings().clone();
    let side = |engine: &Arc<Engine>, memo: Option<Arc<NerMemo>>| {
        let host = Arc::new(DiffHost {
            engine: Arc::clone(engine),
            plain: Arc::clone(&plain),
            policy: Arc::clone(&policy),
            dict: Arc::new(Nothing),
            memo,
        });
        let up = Arc::new(ScriptedUpstream::new(Script(vec![Step::EchoUserText])));
        let proxy = Proxy::try_with_upstream(
            config(tokens.clone()),
            host,
            Zeroizing::new(CLIENT.into()),
            up.clone(),
        )
        .map_err(|e| e.kind())
        .unwrap();
        Side {
            proxy,
            up,
            tokens: tokens.clone(),
        }
    };
    let off = side(&plain, None);
    let on = side(&wrapped, Some(Arc::clone(&memo)));

    // The inputs: the two bench texts, then the corpus.
    let mut inputs: Vec<(Source, String)> = vec![
        (Source::Bench, harness_system(20 * 1024)),
        (Source::Bench, bench_mail_system()),
    ];
    for (family, transforms) in [
        (GenFamily::Tuning, false),
        (GenFamily::Tuning, true),
        (GenFamily::HeldOut, false),
        (GenFamily::HeldOut, true),
    ] {
        for d in generate(&GenOptions {
            seed: 7,
            count: docs_per,
            transforms,
            family,
        }) {
            inputs.push(as_system(&d.text));
        }
    }

    let (mut docs, mut bench, mut padded, mut refused) = (0u64, 0u64, 0u64, 0u64);
    let mut s2_hits = 0u64;
    let mut no_hit = 0u64;
    let mut diffs: std::collections::BTreeMap<&'static str, u64> = Default::default();
    // (input index, session number) of every differing request: numbers only.
    let mut differing: Vec<(usize, usize)> = Vec::new();
    for (n, (source, system)) in inputs.iter().enumerate() {
        if n % shards != shard {
            continue;
        }
        docs += 1;
        bench += u64::from(*source == Source::Bench);
        padded += u64::from(*source == Source::Padded);
        for (k, sess) in ["s1", "s2"].into_iter().enumerate() {
            let id = format!("{n}-{sess}");
            let a = off.send(system, &format!("off-{id}")).await;
            let before = memo.stats().hits;
            let b = on.send(system, &format!("on-{id}")).await;
            let hits = memo.stats().hits - before;
            if k == 1 {
                s2_hits += hits;
                if hits == 0 {
                    no_hit += 1;
                }
            }
            refused += u64::from(a.status != 200);
            let mut differs = false;
            if a.status != b.status {
                *diffs.entry("status").or_default() += 1;
                differs = true;
            }
            if a.forwarded != b.forwarded {
                *diffs.entry("forwarded").or_default() += 1;
                differs = true;
            }
            if a.refusal != b.refusal {
                *diffs.entry("refusal").or_default() += 1;
                differs = true;
            }
            if differs {
                differing.push((n, k + 1));
            }
        }
    }
    let st = memo.stats();
    println!(
        "memo differential shard {shard}/{shards}: documents {docs} (bench {bench}, corpus {}, padded {padded}) requests {} refused_per_side {refused} session2_hits {s2_hits} session2_without_hit {no_hit} memo hits {} misses {} entries {} clears {} diffs {:?} differing (input, session) {:?}",
        docs - bench,
        docs * 4,
        st.hits,
        st.misses,
        st.entries,
        st.clears,
        diffs,
        differing
    );
    assert!(docs > 0, "an empty shard proves nothing");
    assert!(
        diffs.is_empty(),
        "memo on and off differ: {diffs:?}; (input index, session) {differing:?}"
    );
    assert_eq!(no_hit, 0, "a session 2 without a memo hit");
}
