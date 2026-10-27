#![cfg(feature = "models-tests")]
//! The harness-origin hard gate (M8 spec §20, amendment 2026-10-20;
//! rulings L107, L120; plan 2026-10-20-origin-wiring, Task 4): with the real
//! `support-email` models, the proxy reads a trusted request's system leaf
//! as harness-static text and everything else, and every leaf of a
//! restricted request, as free text.
//!
//! Inputs: every document of the harness corpus
//! (`inumaki-eval/harness/harness-static.jsonl`) and the bench's 20 KB
//! harness text on both wires. A `codex/` document is sent as the
//! `instructions` of a Responses request, every other input as the `system`
//! of a Messages request. Each input runs twice, each time in a fresh
//! session: trusted (with the client header) and restricted (without).
//!
//! The expected result comes from the engine directly, on a fresh context:
//! trusted is `process_with_at(.., HarnessStatic)`, restricted is
//! `process_with_at(.., Free)`. The forwarded system leaf (or the refusal)
//! must equal it after canonical token renaming. The corpus is checked, not
//! assumed: the run fails unless at least one input differs between the two
//! origins.
//!
//! Shard 0 also sends user turns in trusted requests, per wire: a German
//! name is tokenized (this alone does not show the Free reading: the engine
//! tokenizes a full name under both origins); a name of a shape that
//! harness-static text drops equals the engine's Free result, which differs
//! from its HarnessStatic result (the Free reading); and a harness text that
//! the engine reads differently under the two origins, sent as a user turn,
//! equals the Free result.
//!
//! The report prints counts and fixed labels, never text; a mismatch prints
//! the input index, the wire and the mode.
//!
//! The test is `#[ignore]`d so that a plain `cargo test` shows it as ignored
//! and can never record it as passed. Run it in release, once per shard; it
//! needs `INUMAKI_MODELS_DIR` and fails without the models:
//! `INUMAKI_ORIGIN_SHARD=i/n INUMAKI_MODELS_DIR=... cargo test --release
//! -p inumaki-proxy --features models-tests --test harness_origin_models --
//! --ignored --nocapture`, for every `i` in `0..n`.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use inumaki_core::TextOrigin;
use inumaki_core::config::{CoreConfig, TokenSettings};
use inumaki_core::detect::{DetectCtx, Detector};
use inumaki_core::engine::{Engine, Outcome};
use inumaki_core::policy::Profile;
use inumaki_core::span::{DetectorId, EntityKind, Span};
use inumaki_core::token::{Context, ContextId};
use inumaki_models::{BackendCache, ner_for_profile_with, resolve_models_dir};
use inumaki_proxy::bench_text::harness_system;
use inumaki_proxy::host::{HostBlock, HostError, ProxyEvent, ProxyHost, Scope};
use inumaki_proxy::memo::NerMemo;
use inumaki_proxy::{
    BaseUrls, BinaryMode, Proxy, ProxyConfig, Script, ScriptedUpstream, Step, TripwireMode,
    UncertainMode,
};
use tower::ServiceExt;
use zeroize::Zeroizing;

const PROFILE: &str = "support-email";
const CLIENT: &str = "origin-gate-client";
const CORPUS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../inumaki-eval/harness/harness-static.jsonl"
);
const USER_TURN: &str =
    "Bitte antworte Sarah Leitner bis Freitag, sie wohnt in der Neubaugasse 22, 1070 Wien.";
/// User turns holding a name of a shape that harness-static text drops and
/// free text keeps (a lowercase surname-marked vocabulary word standing
/// alone, L98; a CamelCase surname glued into one token, L118). The gate
/// uses the first the engine reads differently under the two origins.
const DROPPED_SHAPES: [&str; 6] = [
    "Bitte frag HuberMaier wegen der Rechnung.",
    "Please ask HuberMaier about the invoice.",
    "Danke baker, ich melde mich morgen.",
    "Danke miller, ich melde mich morgen.",
    "Thanks wagner, I will call you tomorrow.",
    "Danke rust, ich melde mich morgen.",
];
/// A system text the engine leaves alone under both origins. The user-turn
/// checks hold only when the system leaf mints nothing: a value minted in
/// one leaf is tokenized in the others too (context consistency, which fails
/// closed), so a system text with a role word such as "You are a helpful
/// assistant." would change the user leaf's result (see
/// `a_role_word_minted_in_the_system_leaf_is_carried_into_the_user_leaf`).
const SHORT_SYSTEM: &str = "Answer in plain text.";
const BRIEF: &str = "Please answer briefly.";

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

/// A host with one engine (no memo), a policy, and no datasets.
struct DiffHost {
    engine: Arc<Engine>,
    policy: Arc<Profile>,
    dict: Arc<dyn Detector>,
}

impl ProxyHost for DiffHost {
    fn engine(&self, _: &str) -> Result<Arc<Engine>, HostError> {
        Ok(Arc::clone(&self.engine))
    }
    fn engine_unmemoized(&self, _: &str) -> Result<Arc<Engine>, HostError> {
        Ok(Arc::clone(&self.engine))
    }
    fn ner_memo(&self) -> Option<Arc<NerMemo>> {
        None
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

/// `INUMAKI_ORIGIN_SHARD=i/n`, default `0/1`.
fn shard() -> (usize, usize) {
    let Ok(v) = std::env::var("INUMAKI_ORIGIN_SHARD") else {
        return (0, 1);
    };
    let (i, n) = v.split_once('/').expect("INUMAKI_ORIGIN_SHARD=i/n");
    let (i, n): (usize, usize) = (i.parse().unwrap(), n.parse().unwrap());
    assert!(n > 0 && i < n, "INUMAKI_ORIGIN_SHARD=i/n with i < n");
    (i, n)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Wire {
    Messages,
    Responses,
}

impl Wire {
    fn label(self) -> &'static str {
        match self {
            Wire::Messages => "messages",
            Wire::Responses => "responses",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Trusted,
    Restricted,
}

impl Mode {
    fn label(self) -> &'static str {
        match self {
            Mode::Trusted => "trusted",
            Mode::Restricted => "restricted",
        }
    }
    fn origin(self) -> TextOrigin {
        match self {
            Mode::Trusted => TextOrigin::HarnessStatic,
            Mode::Restricted => TextOrigin::Free,
        }
    }
}

/// What the proxy did with one request: `None` is a refusal (451), else the
/// canonical forwarded leaves `(system, user)`.
type Seen = Option<(String, String)>;

struct Rig {
    proxy: Proxy,
    up: Arc<ScriptedUpstream>,
    engine: Arc<Engine>,
    tokens: TokenSettings,
}

impl Rig {
    /// One request in a fresh session. `system` is the harness leaf of the
    /// wire, `user` the user turn.
    async fn send(&self, wire: Wire, mode: Mode, system: &str, user: &str, session: &str) -> Seen {
        let (path, body) = match wire {
            Wire::Messages => (
                "/anthropic/v1/messages",
                serde_json::json!({"model": "m", "max_tokens": 16, "system": system,
                    "messages": [{"role": "user", "content": user}]}),
            ),
            Wire::Responses => (
                "/openai/v1/responses",
                serde_json::json!({"model": "gpt-x", "instructions": system,
                    "input": [{"type": "message", "role": "user",
                        "content": [{"type": "input_text", "text": user}]}]}),
            ),
        };
        let mut req = http::Request::post(path)
            .header("content-type", "application/json")
            .header("x-inumaki-session", session);
        if mode == Mode::Trusted {
            req = req.header("x-inumaki-client", CLIENT);
        }
        let req = req.body(Body::from(body.to_string())).unwrap();
        let before = self.up.recorded().len();
        let r = self.proxy.router().oneshot(req).await.unwrap();
        let status = r.status().as_u16();
        let _ = axum::body::to_bytes(r.into_body(), 64 << 20).await.unwrap();
        match status {
            200 => {
                let sent = self.up.recorded();
                assert!(sent.len() > before, "a 200 that forwarded nothing");
                let v: serde_json::Value =
                    serde_json::from_slice(&sent[sent.len() - 1].1).expect("a JSON body");
                let (s, u) = match wire {
                    Wire::Messages => (&v["system"], &v["messages"][0]["content"]),
                    Wire::Responses => (&v["instructions"], &v["input"][0]["content"][0]["text"]),
                };
                Some((
                    canon(&self.tokens, s.as_str().expect("a string system leaf")),
                    canon(&self.tokens, u.as_str().expect("a string user leaf")),
                ))
            }
            451 => None,
            other => panic!("unexpected status {other} ({session})"),
        }
    }

    /// The engine's result for `text` under `origin`, on a fresh context:
    /// the canonical sanitized text, or `None` for a refusal (the proxy runs
    /// `uncertain = "block"`).
    fn expected(&self, text: &str, origin: TextOrigin) -> Option<String> {
        let mut ctx = Context::new(
            ContextId("origin".into()),
            Duration::from_secs(3600),
            self.tokens.clone(),
        );
        match self
            .engine
            .process_with_at(text, &mut ctx, &[], origin)
            .expect("an in-memory store")
        {
            Outcome::Pass { sanitized } => Some(canon(&self.tokens, &sanitized.text)),
            Outcome::PassUncertain { .. } | Outcome::Blocked { .. } => None,
        }
    }
}

fn person_tokens(canonical: &str) -> u64 {
    canonical.matches("<PERSON#").count() as u64
}

/// The corpus, then the bench's harness text on each wire.
fn inputs() -> Vec<(Wire, String, String)> {
    let mut v = Vec::new();
    for line in std::fs::read_to_string(CORPUS)
        .expect("the harness corpus")
        .lines()
        .filter(|l| !l.trim().is_empty())
    {
        let d: serde_json::Value = serde_json::from_str(line).expect("a corpus line");
        let id = d["id"].as_str().expect("id").to_string();
        let text = d["text"].as_str().expect("text").to_string();
        let wire = if id.starts_with("codex/") {
            Wire::Responses
        } else {
            Wire::Messages
        };
        v.push((wire, id, text));
    }
    assert!(
        v.len() >= 93,
        "the harness corpus holds at least 93 documents"
    );
    for wire in [Wire::Messages, Wire::Responses] {
        v.push((wire, "bench".into(), harness_system(20 * 1024)));
    }
    v
}

/// The in-process proxy and its engine, over the real models.
fn rig() -> Rig {
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
    let engine = Arc::new(Engine::from_config(&cfg, PROFILE, Some(s), Some(v)).unwrap());
    let tokens = engine.token_settings().clone();
    let host = Arc::new(DiffHost {
        engine: Arc::clone(&engine),
        policy: Arc::new(p),
        dict: Arc::new(Nothing),
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
    Rig {
        proxy,
        up,
        engine,
        tokens,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "hard gate (L120): --release, INUMAKI_ORIGIN_SHARD=i/n, -- --ignored --nocapture"]
// The report is the gate's output: counts and fixed labels only.
#[allow(clippy::print_stdout, clippy::print_stderr)]
async fn system_leaves_read_as_harness_static_and_user_turns_stay_free() {
    let (shard, shards) = shard();

    let rig = rig();

    let all = inputs();
    let (mut docs, mut on_messages, mut on_responses) = (0u64, 0u64, 0u64);
    let mut differing = 0u64;
    let mut person = [0u64; 2];
    let mut refused = [0u64; 2];
    // (input index, wire, mode); the user-turn checks have no input index.
    let mut mismatches: Vec<(Option<usize>, &'static str, &'static str)> = Vec::new();
    let mut cc_system_trusted_ok = None;
    for (n, (wire, id, text)) in all.iter().enumerate() {
        if n % shards != shard {
            continue;
        }
        docs += 1;
        match wire {
            Wire::Messages => on_messages += 1,
            Wire::Responses => on_responses += 1,
        }
        let mut expected = [None, None];
        for (m, mode) in [Mode::Trusted, Mode::Restricted].into_iter().enumerate() {
            let want = rig.expected(text, mode.origin());
            let session = format!("o-{n}-{}", &mode.label()[..1]);
            let got = rig.send(*wire, mode, text, BRIEF, &session).await;
            if id == "synthetic/cc-system.txt" && mode == Mode::Trusted {
                cc_system_trusted_ok = Some(got.is_some());
            }
            refused[m] += u64::from(got.is_none());
            if let Some((sys, _)) = &got {
                person[m] += person_tokens(sys);
            }
            if got.as_ref().map(|(sys, _)| sys) != want.as_ref() {
                mismatches.push((Some(n), wire.label(), mode.label()));
            }
            expected[m] = want;
        }
        differing += u64::from(expected[0] != expected[1]);
    }

    // User turns (shard 0 only).
    let mut user_checks = 0u64;
    if shard == 0 {
        for wire in [Wire::Messages, Wire::Responses] {
            // The harness text of the wire: a document the engine passes as
            // harness-static text and reads differently as free text (so
            // "equals Free" cannot hold by accident); cc-system first.
            let discriminates = |text: &str| {
                let hs = rig.expected(text, TextOrigin::HarnessStatic);
                hs.is_some() && hs != rig.expected(text, TextOrigin::Free)
            };
            let harness = all
                .iter()
                .filter(|(w, _, text)| *w == wire && discriminates(text))
                .min_by_key(|(_, id, _)| id != "synthetic/cc-system.txt")
                .map(|(_, _, t)| t.as_str())
                .unwrap_or_else(|| panic!("{}: no discriminating harness text", wire.label()));
            let seen = rig
                .send(
                    wire,
                    Mode::Trusted,
                    harness,
                    USER_TURN,
                    &format!("ou-{}-1", wire.label()),
                )
                .await
                .unwrap_or_else(|| panic!("{}: name in a user turn refused", wire.label()));
            assert!(
                !seen.1.contains("Sarah") && !seen.1.contains("Leitner"),
                "{}: a name in a user turn left in clear",
                wire.label()
            );
            assert!(
                seen.1.contains("<PERSON#"),
                "{}: a name in a user turn not tokenized",
                wire.label()
            );
            // A name of a shape harness-static text drops is still
            // tokenized in a user turn: the Free reading.
            let shape = DROPPED_SHAPES
                .iter()
                .find(|t| {
                    let hs = rig.expected(t, TextOrigin::HarnessStatic);
                    let free = rig.expected(t, TextOrigin::Free);
                    free.as_deref().is_some_and(|f| f.contains("<PERSON#")) && hs != free
                })
                .unwrap_or_else(|| panic!("no dropped-shape name differs between origins"));
            let seen = rig
                .send(
                    wire,
                    Mode::Trusted,
                    harness,
                    shape,
                    &format!("ou-{}-3", wire.label()),
                )
                .await;
            if seen.as_ref().map(|(_, u)| u) != rig.expected(shape, TextOrigin::Free).as_ref() {
                mismatches.push((None, wire.label(), "user-turn-dropped-shape"));
            }
            assert_eq!(
                rig.expected(SHORT_SYSTEM, TextOrigin::HarnessStatic)
                    .as_deref(),
                Some(SHORT_SYSTEM),
                "the short system text must pass unchanged"
            );
            // Harness text as a user turn is free text.
            let seen = rig
                .send(
                    wire,
                    Mode::Trusted,
                    SHORT_SYSTEM,
                    harness,
                    &format!("ou-{}-2", wire.label()),
                )
                .await;
            let want = rig.expected(harness, TextOrigin::Free);
            if seen.as_ref().map(|(_, u)| u) != want.as_ref() {
                mismatches.push((None, wire.label(), "user-turn"));
            }
            user_checks += 3;
        }
    }

    println!(
        "harness origin shard {shard}/{shards}: documents {docs} (messages {on_messages}, responses {on_responses}) differing_harness_static_vs_free {differing} PERSON_tokens trusted {} restricted {} refused trusted {} restricted {} user_turn_checks {user_checks} mismatches {} {:?}",
        person[0],
        person[1],
        refused[0],
        refused[1],
        mismatches.len(),
        mismatches
    );
    assert!(docs > 0, "an empty shard proves nothing");
    // Finer shards may hold no differing input; the gate runs n = 2, where
    // each shard has one. For n > 2, sum the printed counts: the total must
    // be above zero.
    assert!(
        differing > 0 || shards > 2,
        "no input differs between HarnessStatic and Free: the comparison is vacuous"
    );
    assert!(
        mismatches.is_empty(),
        "proxy and engine differ (input, wire, mode): {mismatches:?}"
    );
    if let Some(ok) = cc_system_trusted_ok {
        assert!(ok, "synthetic/cc-system.txt: trusted request refused");
    }
    assert!(
        person[0] <= person[1],
        "more PERSON tokens in trusted system leaves than in restricted ones"
    );
    assert!(
        refused[0] <= refused[1],
        "more trusted refusals than restricted ones"
    );
}

/// The role-word false positive, pinned (ruling L126). The engine reads
/// `assistant` in "You are a helpful assistant." as a PERSON under both
/// origins (a false positive already present on main, queued for lane L3;
/// the origin does not change it). A value minted in one leaf is then
/// tokenized in every other leaf of the request: context consistency, which
/// fails closed (it only adds tokens). Hence the user-turn checks above use a
/// system text that mints nothing.
///
/// The expectation below is the false positive itself: when lane L3's
/// role-word fix lands, flip it (the system leaf stays "You are a helpful
/// assistant." and the user leaf stays clear); that is not a regression. The
/// pin is on the Responses wire only: context consistency is shared code, so
/// a Messages leg would test the same path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "hard gate (L120): --release, -- --ignored --nocapture"]
async fn a_role_word_minted_in_the_system_leaf_is_carried_into_the_user_leaf() {
    let rig = rig();
    let system = "You are a helpful assistant.";
    // A user turn the engine alone leaves without a PERSON token.
    let user = [
        "Please summarize what the assistant did.",
        "Thanks, the assistant answered quickly.",
        "Ask the assistant to continue.",
    ]
    .into_iter()
    .find(|u| {
        rig.expected(u, TextOrigin::Free)
            .is_some_and(|f| !f.contains("<PERSON#"))
    })
    .expect("a user turn the engine alone does not tokenize");
    for mode in [Mode::Trusted, Mode::Restricted] {
        let (sys, usr) = rig
            .send(
                Wire::Responses,
                mode,
                system,
                user,
                &format!("role-{}", mode.label()),
            )
            .await
            .unwrap_or_else(|| panic!("{}: refused", mode.label()));
        assert_eq!(
            sys,
            "You are a <PERSON#0>.",
            "{}: the system leaf mints the role word under both origins",
            mode.label()
        );
        assert!(
            usr.contains("<PERSON#") && !usr.contains("assistant"),
            "{}: the user leaf carries the token",
            mode.label()
        );
    }
}

/// Ruling L122 (3): the dynamic section of a Claude Code system prompt (the
/// environment block: working directory, git status and user, recent
/// commits) is read as harness-static text, yet a capitalized full name in
/// it is tokenized, in each position Claude Code puts a name: the `Git user:`
/// line, the working-directory path (dotted or spaced home directory), and a
/// commit subject. A lowercase surname-marked word in it is the acknowledged
/// residual (L98, dropped in harness-static text); its fate is reported, not
/// asserted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "hard gate (L120): --release, -- --ignored --nocapture"]
#[allow(clippy::print_stdout, clippy::print_stderr)]
async fn a_capitalized_name_in_the_dynamic_system_section_is_tokenized() {
    let rig = rig();
    // `(directory segment, branch, git user, commit subject)`.
    type Parts<'a> = (&'a str, &'a str, &'a str, &'a str);
    const NEUTRAL: Parts = ("dev", "main", "unknown", "parser edge case");
    let section = |base: &str, (dir, branch, user, subject): Parts| {
        format!(
            "{base}\n\n# Environment\nWorking directory: /Users/{dir}/project\nIs directory a git repo: yes\nPlatform: darwin\n\ngitStatus: Current branch: feature/{branch}\nGit user: {user}\n\nStatus:\n M src/main.rs\n\nRecent commits:\na1b2c3d fix: {subject}\n",
        )
    };
    // A neutral baseline: a harness prompt the engine accepts, with the
    // neutral section, under both origins (cc-system may be refused as free
    // text, which would make every comparison below vacuous).
    let accepted = |t: &str| {
        rig.expected(t, TextOrigin::HarnessStatic).is_some()
            && rig.expected(t, TextOrigin::Free).is_some()
    };
    let base = [
        inputs()
            .into_iter()
            .find(|(_, id, _)| id == "synthetic/cc-system.txt")
            .map(|(_, _, t)| t)
            .expect("synthetic/cc-system.txt"),
        harness_system(6 * 1024),
    ]
    .into_iter()
    .find(|b| accepted(&section(b, NEUTRAL)))
    .expect("a harness prompt accepted under both origins");
    let persons = |t: &str, o: TextOrigin| person_tokens(&rig.expected(t, o).expect("accepted"));
    let neutral = section(&base, NEUTRAL);

    // A lowercase surname-marked word standing alone in the path or the
    // branch: the first the engine tokenizes as free text and drops as
    // harness-static text, and that the neutral base does not contain.
    let candidates: [(&str, &str, &str); 4] = [
        ("huber", "huber", "main"),
        ("rust", "dev", "rust"),
        ("miller", "miller", "main"),
        ("baker", "dev", "baker"),
    ];
    // Per candidate: whether the word is tokenized as free text, and as
    // harness-static text (the engine alone, against the neutral section).
    let seen: Vec<(bool, bool)> = candidates
        .iter()
        .map(|(w, d, b)| {
            let t = section(&base, (d, b, NEUTRAL.2, NEUTRAL.3));
            assert!(
                !neutral.contains(w),
                "the neutral section holds a candidate"
            );
            assert!(accepted(&t), "a candidate section is refused");
            (
                persons(&t, TextOrigin::Free) > persons(&neutral, TextOrigin::Free),
                persons(&t, TextOrigin::HarnessStatic)
                    > persons(&neutral, TextOrigin::HarnessStatic),
            )
        })
        .collect();
    let lower = seen.iter().position(|(free, hs)| *free && !*hs);

    let name = "Sarah Leitner";
    // Each capitalized position alone, then (with a lowercase candidate)
    // the lowercase word alone and together with the git user name.
    let mut cases: Vec<(&str, String, Option<&str>)> = vec![
        (
            "git-user",
            section(&base, ("dev", "main", name, NEUTRAL.3)),
            None,
        ),
        (
            "path-surname",
            section(&base, ("Leitner", "main", NEUTRAL.2, NEUTRAL.3)),
            None,
        ),
        (
            "path-dotted",
            section(&base, ("Sarah.Leitner", "main", NEUTRAL.2, NEUTRAL.3)),
            None,
        ),
        (
            "path-spaced",
            section(&base, (name, "main", NEUTRAL.2, NEUTRAL.3)),
            None,
        ),
        (
            "commit-subject",
            section(
                &base,
                (
                    "dev",
                    "main",
                    NEUTRAL.2,
                    "parser edge case reported by Sarah Leitner",
                ),
            ),
            None,
        ),
    ];
    if let Some(k) = lower {
        let (w, d, b) = candidates[k];
        cases.push((
            "lowercase",
            section(&base, (d, b, NEUTRAL.2, NEUTRAL.3)),
            Some(w),
        ));
        cases.push(("both", section(&base, (d, b, name, NEUTRAL.3)), Some(w)));
    }
    let mut labels = Vec::new();
    for (label, system, word) in &cases {
        let got = rig
            .send(
                Wire::Messages,
                Mode::Trusted,
                system,
                BRIEF,
                &format!("dyn-{label}"),
            )
            .await
            .unwrap_or_else(|| panic!("{label}: refused"));
        let want = rig
            .expected(system, TextOrigin::HarnessStatic)
            .unwrap_or_else(|| panic!("{label}: the engine refuses"));
        assert_eq!(
            got.0, want,
            "{label}: proxy differs from the engine (HarnessStatic)"
        );
        if *label != "lowercase" {
            // A dropped capitalized name is a blocker.
            assert!(
                !got.0.contains("Sarah") && !got.0.contains("Leitner"),
                "BLOCKER {label}: the capitalized name was dropped"
            );
            assert!(
                got.0.contains("<PERSON#"),
                "BLOCKER {label}: no PERSON token"
            );
            labels.push(format!("{label}: capitalized name tokenized"));
        }
        if let Some(w) = word {
            labels.push(format!(
                "{label}: lowercase surname {}",
                if got.0.contains(w) {
                    "dropped (in clear)"
                } else {
                    "tokenized"
                }
            ));
        }
    }
    println!(
        "dynamic section: lowercase candidates {} tokenized as free text {} as harness-static text {} (origin-dependent index {lower:?}); {labels:?}",
        candidates.len(),
        seen.iter().filter(|(f, _)| *f).count(),
        seen.iter().filter(|(_, h)| *h).count(),
    );
}
