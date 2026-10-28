//! `inumaki bench --via-proxy` (M8 spec §14): the model-API proxy in
//! process with a scripted model upstream. Reports the latency the proxy
//! adds per turn (its wall time minus the upstream's) and the cold first
//! turn, plus the time to the first restored text byte of a streamed turn.
//! Measured, not a gate; nothing touches the daemon or the vault.
//!
//! Three wires: `messages` (Anthropic Messages, the default), `responses`
//! (OpenAI Responses with Codex-style input items: messages, reasoning,
//! function and local shell calls with their outputs) and `codex` (the same
//! body to the Codex ChatGPT route).
//!
//! The documents are synthetic (the eval generator); no value is printed.
//!
//! Environment knobs (defaults leave the behavior unchanged):
//! `INUMAKI_BENCH_MAILS=N`, `INUMAKI_BENCH_TRANSFORMS=1`,
//! `INUMAKI_BENCH_FAMILY=held-out`, `INUMAKI_BENCH_SYSTEM=harness` (a fixed
//! 20 KB coding-agent instruction text instead of mail text as the system
//! prompt, so the same text is the same in every session) and
//! `INUMAKI_BENCH_SESSIONS=2` (after session 1, one cold turn in a fresh
//! session: the same system text and one new mail).

use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow, bail};
use axum::body::Body;
use futures::StreamExt as _;
use inumaki_core::detect::{DetectCtx, Detector};
use inumaki_core::engine::Engine;
use inumaki_core::policy::Profile;
use inumaki_core::span::{DetectorId, EntityKind, Span};
use inumaki_eval::generate::{GenFamily, GenOptions, generate};
use inumaki_proxy::host::{HostBlock, HostError, ProxyEvent, ProxyHost, Scope};
use inumaki_proxy::memo::{NerMemo, NerRole, STATIC_MEMO_BYTES, STATIC_MEMO_ENTRIES};
use inumaki_proxy::upstream::{Upstream, UpstreamError, UpstreamRequest, UpstreamResponse};
use inumaki_proxy::{
    BaseUrls, BinaryMode, Proxy, ProxyConfig, Script, ScriptedUpstream, StaticNer, Step,
    TripwireMode, UncertainMode,
};
use serde_json::{Value, json};
use tower::ServiceExt;
use zeroize::Zeroizing;

use super::load_config;
use crate::exit;

/// A detector that finds nothing: the bench host has no datasets.
struct Nothing;

impl Detector for Nothing {
    fn id(&self) -> DetectorId {
        DetectorId::Dictionary
    }
    fn detect(&self, _: &str, _: &DetectCtx) -> inumaki_core::Result<Vec<Span>> {
        Ok(Vec::new())
    }
}

/// A host with an engine and a policy and no datasets: detection cost only.
/// Like the daemon's host, it provides the static-prompt NER memo: `engine`
/// has its NER detectors wrapped by `memo`, `plain` is its unwrapped twin.
struct BenchHost {
    engine: Arc<Engine>,
    plain: Arc<Engine>,
    policy: Arc<Profile>,
    /// The (empty) dataset dictionary: one `Arc` for the run, so the memo
    /// is not cleared on every request (the host contract).
    dict: Arc<dyn Detector>,
    memo: Arc<NerMemo>,
}

impl ProxyHost for BenchHost {
    fn engine(&self, _: &str) -> Result<Arc<Engine>, HostError> {
        Ok(Arc::clone(&self.engine))
    }
    fn engine_unmemoized(&self, _: &str) -> Result<Arc<Engine>, HostError> {
        Ok(Arc::clone(&self.plain))
    }
    fn ner_memo(&self) -> Option<Arc<NerMemo>> {
        Some(Arc::clone(&self.memo))
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

/// The scripted upstream, timing its own share (it builds its answer inside `send`).
struct Timed {
    inner: ScriptedUpstream,
    spent: Mutex<Duration>,
}

impl Upstream for Timed {
    fn send(
        &self,
        req: UpstreamRequest,
    ) -> futures::future::BoxFuture<'static, Result<UpstreamResponse, UpstreamError>> {
        let t = Instant::now();
        let f = self.inner.send(req);
        *self.spent.lock().unwrap_or_else(PoisonError::into_inner) += t.elapsed();
        f
    }
}

fn pct(sorted: &[f64], q: f64) -> f64 {
    sorted[((sorted.len() - 1) as f64 * q).round() as usize]
}

pub(crate) fn config(profile: &str, tokens: inumaki_core::config::TokenSettings) -> ProxyConfig {
    let nowhere = "http://127.0.0.1:9".to_string();
    ProxyConfig {
        enabled: true,
        listen: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        profile: profile.to_string(),
        session_ttl: Duration::from_secs(3600),
        session_cap: 16,
        cache_bytes: 512 << 20,
        max_request_bytes: 64 << 20,
        max_inflight: 4,
        upstream_timeout: Duration::from_secs(600),
        binary: BinaryMode::Refuse,
        uncertain: UncertainMode::Pass,
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

/// The profile's engine twice over one pair of NER models, as the daemon
/// builds its proxy engine: unwrapped, and with the sanitizer and verifier
/// NER each wrapped by a fresh memo. Returns `(plain, wrapped, memo)`.
fn engines(
    config_path: Option<&Path>,
    profile: &str,
    models_dir: Option<&Path>,
) -> Result<(Arc<Engine>, Arc<Engine>, Arc<NerMemo>)> {
    let cfg = load_config(config_path)?;
    let p = cfg
        .resolve_profile(profile)
        .with_context(|| format!("resolving profile {profile}"))?;
    let root = inumaki_models::resolve_models_dir(models_dir, cfg.ner.models_dir.as_deref());
    let ner = inumaki_models::ner_for_profile(&cfg, &p, &root)?;
    // Two wraps of one `Arc` would pass core's independence check (S6).
    if let (Some(a), Some(b)) = (&ner.sanitizer, &ner.verifier)
        && Arc::ptr_eq(a, b)
    {
        bail!("profile {profile}: the sanitizer and verifier NER are one detector");
    }
    let build = |s, v| {
        Engine::from_config(&cfg, profile, s, v)
            .map(Arc::new)
            .with_context(|| format!("building engine for profile {profile}"))
    };
    let plain = build(ner.sanitizer.clone(), ner.verifier.clone())?;
    let memo = NerMemo::new(profile, [0; 32], STATIC_MEMO_ENTRIES, STATIC_MEMO_BYTES);
    let wrapped = build(
        ner.sanitizer.map(|d| memo.wrap(d, NerRole::Sanitizer)),
        ner.verifier.map(|d| memo.wrap(d, NerRole::Verifier)),
    )?;
    Ok((plain, wrapped, memo))
}

/// The wire the bench speaks.
#[derive(Clone, Copy, PartialEq, Eq)]
enum BenchWire {
    Messages,
    Responses,
    Codex,
}

impl BenchWire {
    fn parse(s: &str) -> Result<BenchWire> {
        match s {
            "messages" => Ok(BenchWire::Messages),
            "responses" => Ok(BenchWire::Responses),
            "codex" => Ok(BenchWire::Codex),
            other => bail!("unknown wire {other:?} (messages, responses, codex)"),
        }
    }
    fn name(self) -> &'static str {
        match self {
            BenchWire::Messages => "messages",
            BenchWire::Responses => "responses",
            BenchWire::Codex => "codex",
        }
    }
    fn path(self) -> &'static str {
        match self {
            BenchWire::Messages => "/anthropic/v1/messages",
            BenchWire::Responses => "/openai/v1/responses",
            BenchWire::Codex => "/codex/responses",
        }
    }
    fn session_header(self) -> &'static str {
        match self {
            BenchWire::Messages => "x-claude-code-session-id",
            BenchWire::Responses => "x-inumaki-session",
            BenchWire::Codex => "session_id",
        }
    }
    fn is_messages(self) -> bool {
        self == BenchWire::Messages
    }
}

/// The value of `X-Inumaki-Client` the bench proxy is built with and sends: the
/// static-prompt memo serves trusted requests only, and an empty value never
/// matches.
const BENCH_CLIENT: &str = "bench-client";

/// The session header value of session 1; session 2 uses [`SESSION_2`].
const SESSION_1: &str = "bench";
const SESSION_2: &str = "bench-two";

async fn post(p: &Proxy, wire: BenchWire, session: &str, body: String) -> Result<(u16, Body)> {
    let r = http::Request::post(wire.path())
        .header("content-type", "application/json")
        .header("x-inumaki-client", BENCH_CLIENT)
        .header(wire.session_header(), session)
        .body(Body::from(body))?;
    let resp = p.router().oneshot(r).await?;
    Ok((resp.status().as_u16(), resp.into_body()))
}

/// A user message carrying `text`.
fn user_item(wire: BenchWire, text: &str) -> Value {
    if wire.is_messages() {
        json!({"role": "user", "content": text})
    } else {
        json!({"type": "message", "role": "user", "content": [{"type": "input_text", "text": text}]})
    }
}

/// One history exchange carrying `text`. Messages: a user mail and a short
/// assistant answer. Responses: the mail rides in one of five Codex item
/// kinds, rotating with `n`, so every walked field is exercised.
fn history_items(wire: BenchWire, n: usize, text: &str) -> Vec<Value> {
    if wire.is_messages() {
        return vec![
            user_item(wire, text),
            json!({"role": "assistant", "content": "ok"}),
        ];
    }
    let opaque = "gAAAAABnBenchOpaqueEncryptedContent0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789==";
    let mut out = vec![user_item(wire, "Continue with the next item.")];
    match n % 5 {
        0 => out.push(user_item(wire, text)),
        // A summary is provider-written (it shows tokens, never mail text) and is
        // scanned, not changed: mail text there would be refused by design. The
        // item carries a generic summary and a large opaque blob; the mail
        // rides in the user message before it.
        1 => {
            out.push(user_item(wire, text));
            out.push(json!({"type": "reasoning", "id": format!("rs_bench{n:05}"),
                "summary": [{"type": "summary_text", "text": "Reading the thread and planning a short reply."}],
                "encrypted_content": opaque.repeat(40)}));
        }
        2 => {
            out.push(json!({"type": "function_call", "id": format!("fc_bench{n:05}"),
                "call_id": format!("call_bench{n:05}"), "name": "read_mail", "status": "completed",
                "arguments": json!({"folder": "inbox", "note": text}).to_string()}));
            out.push(json!({"type": "function_call_output",
                "call_id": format!("call_bench{n:05}"), "output": text}));
        }
        3 => out.push(json!({"type": "message", "id": format!("msg_bench{n:05}"), "role": "assistant",
            "status": "completed", "content": [{"type": "output_text", "text": text, "annotations": []}]})),
        _ => {
            out.push(json!({"type": "local_shell_call", "id": format!("lsh_bench{n:05}"),
                "call_id": format!("call_bench{n:05}"), "status": "completed",
                "action": {"type": "exec", "command": ["cat", "mail.txt"], "env": {}, "working_directory": "/work"}}));
            out.push(json!({"type": "local_shell_call_output", "call_id": format!("call_bench{n:05}"),
                "output": json!({"output": text, "metadata": {"exit_code": 0, "duration_seconds": 0.1}}).to_string()}));
        }
    }
    out
}

/// The request body for `msgs` (history plus the new user message).
fn request_body(wire: BenchWire, system: &str, msgs: &[Value], stream: bool) -> String {
    if wire.is_messages() {
        json!({"model": "bench", "max_tokens": 16, "system": system, "messages": msgs, "stream": stream})
    } else {
        json!({"model": "bench", "instructions": system, "input": msgs, "stream": stream, "store": false})
    }
    .to_string()
}

/// What the harness appends to its history after an answer, as the proxy
/// restored it.
fn answer_items(wire: BenchWire, answer: &Value) -> Vec<Value> {
    if wire.is_messages() {
        vec![json!({"role": "assistant", "content": answer["content"].clone()})]
    } else {
        answer["output"].as_array().cloned().unwrap_or_default()
    }
}

/// Consume the complete SSE events in `buf`; true once one carries restored
/// answer text (Messages: a `text_delta` with text; Responses:
/// `response.output_text.delta` with a delta).
fn saw_text(wire: BenchWire, buf: &mut Vec<u8>) -> bool {
    while let Some(end) = buf.windows(2).position(|w| w == b"\n\n") {
        let event: Vec<u8> = buf.drain(..end + 2).collect();
        for line in event.split(|b| *b == b'\n') {
            let Some(data) = line.strip_prefix(b"data:") else {
                continue;
            };
            let Ok(v) = serde_json::from_slice::<Value>(data.trim_ascii()) else {
                continue;
            };
            let hit = if wire.is_messages() {
                v["type"] == "content_block_delta"
                    && v["delta"]["type"] == "text_delta"
                    && v["delta"]["text"].as_str().is_some_and(|t| !t.is_empty())
            } else {
                v["type"] == "response.output_text.delta"
                    && v["delta"].as_str().is_some_and(|t| !t.is_empty())
            };
            if hit {
                return true;
            }
        }
    }
    false
}

/// One streamed turn: `Some(ms)` from the request send to the first restored
/// text byte, minus the scripted upstream's own time; `None` when refused
/// (451) or when the stream carried no restored text.
async fn stream_turn(
    p: &Proxy,
    up: &Timed,
    wire: BenchWire,
    session: &str,
    system: &str,
    msgs: &[Value],
) -> Result<Option<f64>> {
    let body = request_body(wire, system, msgs, true);
    let reset = || std::mem::take(&mut *up.spent.lock().unwrap_or_else(PoisonError::into_inner));
    let _ = reset();
    let t = Instant::now();
    let (status, b) = post(p, wire, session, body).await?;
    if status == 451 {
        return Ok(None);
    }
    if status != 200 {
        bail!("streamed turn answered {status}");
    }
    let mut stream = b.into_data_stream();
    let mut buf = Vec::new();
    let mut first: Option<f64> = None;
    while let Some(chunk) = stream.next().await {
        buf.extend_from_slice(&chunk?);
        if first.is_none() && saw_text(wire, &mut buf) {
            first = Some(t.elapsed().saturating_sub(reset()).as_secs_f64() * 1000.0);
            // Not timed: the rest of the stream is drained so the turn ends cleanly.
            buf.clear();
        }
    }
    // A 200 stream that never carried restored text (an in-band error event)
    // is counted with the refused turns, not an abort.
    Ok(first)
}

pub fn run(
    config_path: Option<&Path>,
    profile: &str,
    models_dir: Option<&Path>,
    seed: u64,
    wire: &str,
) -> Result<u8> {
    let wire = BenchWire::parse(wire)?;
    let (plain, engine, memo) = engines(config_path, profile, models_dir)?;
    let policy = Arc::new(
        load_config(config_path)?
            .resolve_profile(profile)
            .with_context(|| format!("resolving profile {profile}"))?,
    );
    let cfg = config(profile, engine.token_settings().clone());
    let host = Arc::new(BenchHost {
        engine: Arc::clone(&engine),
        plain,
        policy,
        dict: Arc::new(Nothing),
        memo: Arc::clone(&memo),
    });
    let up = Arc::new(Timed {
        inner: ScriptedUpstream::new(Script(vec![Step::EchoUserText])),
        spent: Mutex::new(Duration::ZERO),
    });
    // The class only: a failure never carries more than a fixed kind.
    let proxy = Proxy::try_with_upstream(
        cfg,
        host,
        Zeroizing::new(BENCH_CLIENT.to_string()),
        up.clone(),
    )
    .map_err(|e| anyhow!("building the proxy failed: {}", e.kind()))?;
    // Untransformed mails by default (`transforms: false`), and the report says so: with
    // the noise transforms every turn was refused by the leak check at the
    // offline profile (a value caught once and missed in a mangled copy
    // elsewhere), and a refused history measures nothing. The numbers are
    // therefore for clean synthetic mail, optimistic for noisy real mail.
    //
    // Diagnosis knobs (environment, default behaviour unchanged):
    // `INUMAKI_BENCH_MAILS=N` sends exactly N history mails instead of
    // ~400 000 characters of them; `INUMAKI_BENCH_TRANSFORMS=1` turns the
    // generator's noise transforms on; `INUMAKI_BENCH_FAMILY=held-out`
    // draws the mails from the held-out family (any other value, or none,
    // is the tuning family); `INUMAKI_BENCH_SYSTEM=harness` uses the fixed
    // coding-agent instruction text as the system prompt;
    // `INUMAKI_BENCH_SESSIONS=2` adds a cold turn in a fresh session;
    // `INUMAKI_BENCH_REASONS=1` prints every refused turn with the proxy's
    // refusal message.
    let mails: Option<usize> = match std::env::var("INUMAKI_BENCH_MAILS") {
        Ok(v) => Some(
            v.trim()
                .parse()
                .context("INUMAKI_BENCH_MAILS must be a mail count")?,
        ),
        Err(_) => None,
    };
    let transforms = std::env::var("INUMAKI_BENCH_TRANSFORMS").is_ok_and(|v| v.trim() == "1");
    let family = match std::env::var("INUMAKI_BENCH_FAMILY") {
        Ok(v) if v.trim() == "held-out" => GenFamily::HeldOut,
        _ => GenFamily::Tuning,
    };
    let harness_system = match std::env::var("INUMAKI_BENCH_SYSTEM") {
        Ok(v) if v.trim() == "harness" => true,
        Ok(v) if v.trim().is_empty() => false,
        Ok(v) => bail!("INUMAKI_BENCH_SYSTEM must be `harness` or unset, not {v:?}"),
        Err(_) => false,
    };
    let sessions: usize = match std::env::var("INUMAKI_BENCH_SESSIONS") {
        Ok(v) => v
            .trim()
            .parse()
            .context("INUMAKI_BENCH_SESSIONS must be 1 or 2")?,
        Err(_) => 1,
    };
    if !(1..=2).contains(&sessions) {
        bail!("INUMAKI_BENCH_SESSIONS must be 1 or 2");
    }
    // `INUMAKI_BENCH_REASONS=1` prints every refused turn with the proxy's
    // refusal message, which names entity kinds and check ids only.
    let reasons = std::env::var("INUMAKI_BENCH_REASONS").is_ok_and(|v| v.trim() == "1");
    let mut docs = generate(&GenOptions {
        seed,
        count: 4000,
        transforms,
        family,
    })
    .into_iter()
    .map(|d| d.text);
    let mut take = |chars: usize| -> String {
        let mut s = String::new();
        while s.len() < chars {
            match docs.next() {
                Some(t) => {
                    s.push_str(&t);
                    s.push('\n');
                }
                None => break,
            }
        }
        s
    };
    let system = if harness_system {
        inumaki_proxy::bench_text::harness_system(20 * 1024)
    } else {
        take(20 * 1024)
    };
    let mut history: Vec<Value> = Vec::new();
    let mut chars = 0usize;
    let mut history_mails = 0usize;
    while mails.map_or(chars < 400_000, |n| history_mails < n) {
        let t = take(2_000);
        if t.is_empty() {
            bail!("the generator ran out of documents");
        }
        chars += t.len();
        history.extend(history_items(wire, history_mails, &t));
        history_mails += 1;
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let (mut cold, mut added, mut blocked) = (None, Vec::new(), 0usize);
        // Turn 0's time and status, whatever the status.
        let mut cold_line: Option<(f64, u16)> = None;
        // The proxy's own timing split of that turn and of the session 2 turn.
        let (mut split_one, mut split_two) = (String::new(), String::new());
        let mut first_refusal: Option<String> = None;
        let mut first_refused_turn: Option<usize> = None;
        // Discard counts from before the measured turns (anything the process
        // ran earlier); the print below covers the measured turns only.
        #[cfg(feature = "closure-shadow")]
        let _ = inumaki_proxy::shadow::take();
        let stale_before = inumaki_core::verify::second_pass::leak_index_stale_count();
        let failed_before = inumaki_core::verify::second_pass::leak_index_failed_count();
        // Turn 0 is the cold turn; turns 1-50 add about 500 tokens each.
        for i in 0..=50 {
            let mut msgs = history.clone();
            let next = take(2_000);
            if next.is_empty() {
                bail!("the generator ran out of documents");
            }
            msgs.push(user_item(wire, &next));
            let (status, answer, ms) = turn(&proxy, &up, wire, SESSION_1, &system, &msgs).await?;
            if i == 0 {
                cold_line = Some((ms, status));
                split_one = timing_split(&proxy);
            }
            match status {
                200 => {}
                451 => {
                    blocked += 1;
                    first_refused_turn.get_or_insert(i);
                    // The message names entity kinds and check ids only.
                    first_refusal.get_or_insert_with(|| {
                        answer["error"]["message"]
                            .as_str()
                            .unwrap_or("?")
                            .to_string()
                    });
                    if reasons {
                        println!(
                            "turn {i:>2}  refused  {}",
                            answer["error"]["message"].as_str().unwrap_or("?")
                        );
                    }
                    continue;
                }
                s => bail!("turn {i} answered {s}"),
            }
            if i == 0 {
                cold = Some(ms);
            } else {
                added.push(ms);
            }
            history = msgs;
            // The harness resends the answer as the proxy restored it.
            history.extend(answer_items(wire, &answer));
        }
        // Streamed turns on the final history plus one more message: the
        // time to the first restored text byte (the scripted upstream's own
        // time is subtracted, as for the other turns).
        // The cache counters are read first: the default line stays the 50 turns' figures.
        let c = proxy.status().incremental_cache;
        let (cache_hits, cache_misses) = (c.hits, c.misses);
        let (mut first, mut stream_refused) = (Vec::new(), 0usize);
        for _ in 0..20 {
            let mut msgs = history.clone();
            let next = take(2_000);
            if next.is_empty() {
                bail!("the generator ran out of documents");
            }
            msgs.push(user_item(wire, &next));
            match stream_turn(&proxy, &up, wire, SESSION_1, &system, &msgs).await? {
                Some(ms) => first.push(ms),
                None => stream_refused += 1,
            }
        }
        // Session 2: a fresh session with the same system text and one new mail.
        let mut cold_two: Option<(f64, u16)> = None;
        if sessions >= 2 {
            let next = take(2_000);
            if next.is_empty() {
                bail!("the generator ran out of documents");
            }
            let msgs = vec![user_item(wire, &next)];
            let (status, _, ms) = turn(&proxy, &up, wire, SESSION_2, &system, &msgs).await?;
            cold_two = Some((ms, status));
            split_two = timing_split(&proxy);
        }
        first.sort_by(|a, b| a.total_cmp(b));
        added.sort_by(|a, b| a.total_cmp(b));
        println!(
            "proxy bench  wire {}  profile {profile}  history {} mails ~{} tokens  system 20 KB{}  {} synthetic mails",
            wire.name(),
            history_mails,
            chars / 4,
            if harness_system { " (harness text)" } else { "" },
            if transforms { "transformed" } else { "untransformed" }
        );
        if let Some((ms, status)) = cold_line {
            println!("cold first turn  {ms:.1} ms  status {status}");
            println!("  proxy timing   {split_one}");
        }
        if let Some((ms, status)) = cold_two {
            println!("cold first turn (session 2)  {ms:.1} ms  status {status}");
            println!("  proxy timing   {split_two}");
        }
        if !added.is_empty() {
            println!(
                "added per turn ({})  p50 {:.1} ms  p95 {:.1} ms",
                added.len(),
                pct(&added, 0.5),
                pct(&added, 0.95)
            );
        }
        println!("refused turns        {blocked}");
        if let Some(t) = first_refused_turn {
            println!("first refused turn   {t}");
        }
        // Whether the history is re-scanned: every re-scanned block is a miss.
        println!("incremental cache    hits {cache_hits}  misses {cache_misses}");
        // The static-prompt NER memo over the whole run (counts only).
        let m = memo.stats();
        println!(
            "static cache         hits {}  misses {}  clears {}",
            m.hits, m.misses, m.clears
        );
        // Leak checks whose store-owned index was stale or failed to build
        // (Task 5, counts only).
        println!(
            "leak index stale     {}  failed {}",
            inumaki_core::verify::second_pass::leak_index_stale_count() - stale_before,
            inumaki_core::verify::second_pass::leak_index_failed_count() - failed_before
        );
        if let Some(m) = first_refusal {
            println!("first refusal        {m}");
        }
        if first.is_empty() {
            println!("first restored byte  refused or errored on all {stream_refused} streamed turns");
        } else {
            println!(
                "first restored byte  {:.1} ms  (p50 of {} streamed turns; p95 {:.1} ms; scripted upstream time subtracted{})",
                pct(&first, 0.5),
                first.len(),
                pct(&first, 0.95),
                if stream_refused > 0 {
                    format!("; {stream_refused} refused or errored")
                } else {
                    String::new()
                }
            );
        }
        // A closure-shadow build: the divergence counts of the measured turns
        // (counts and kind labels only).
        #[cfg(feature = "closure-shadow")]
        {
            let c = inumaki_proxy::shadow::take();
            println!("closure shadow:\n{}", c.report());
        }
        // No turn served at all: the report above stands, the run still failed.
        Ok(if cold.is_none() && added.is_empty() {
            exit::BLOCKED
        } else {
            exit::OK
        })
    })
}

/// The newest timing sample of the in-process proxy as one line of
/// milliseconds (`-` for a stage that did not run). Durations only.
/// Called right after a turn; a turn that recorded no sample would show the
/// previous one (cannot happen for the 200 and 451 turns the bench makes).
fn timing_split(p: &Proxy) -> String {
    let Some(t) = p.status().timing.last else {
        return "-".to_string();
    };
    let o = |v: Option<u64>| v.map_or_else(|| "-".to_string(), |v| v.to_string());
    format!(
        "total {}  local {}  read {}  queue {}  scan {}  engine {}  closure {}  project {}  first_byte {}  provider {}  restore {}  (ms)",
        t.total_ms,
        t.local_ms,
        t.read_ms,
        t.queue_ms,
        t.scan_ms,
        t.engine_ms,
        t.closure_ms,
        t.project_ms,
        o(t.first_byte_ms),
        o(t.provider_ms),
        t.restore_ms
    )
}

/// One non-streamed turn: status, answer, and the milliseconds the proxy added.
async fn turn(
    p: &Proxy,
    up: &Timed,
    wire: BenchWire,
    session: &str,
    system: &str,
    msgs: &[Value],
) -> Result<(u16, Value, f64)> {
    // Serialized before the clock starts: client work is not proxy latency.
    let body = request_body(wire, system, msgs, false);
    let reset = || std::mem::take(&mut *up.spent.lock().unwrap_or_else(PoisonError::into_inner));
    let _ = reset();
    let t = Instant::now();
    let (status, b) = post(p, wire, session, body).await?;
    let bytes = axum::body::to_bytes(b, 64 << 20).await?;
    let ms = t.elapsed().saturating_sub(reset()).as_secs_f64() * 1000.0;
    Ok((
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        ms,
    ))
}
