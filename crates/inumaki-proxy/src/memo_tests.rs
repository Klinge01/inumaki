//! The static-prompt NER memo in the proxy pipeline (M8 spec §20,
//! amendment 2026-10-12, part 1): the critical tests of plan Task 2.
//!
//! Every test runs whole requests through the router of an in-process proxy
//! over a recording upstream. The fake host's engine has counting NER
//! models in both roles (`testing::CountingNer`); a host built with a memo
//! wraps them in `engine()` and hands out the unwrapped twin from
//! `engine_unmemoized()`. The counters count calls on inputs of at least
//! `STATIC_MIN_BYTES` (the only ones the memo could serve). Canary values
//! are synthetic.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::body::Body;
use inumaki_core::detect::Detector;
use inumaki_core::detect::dictionary::DictionaryDetector;
use inumaki_core::span::EntityKind;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::check::CheckId;
use crate::handler_tests::Recording;
use crate::memo::{MemoStats, NerMemo, STATIC_MIN_BYTES};
use crate::scripted::{Script, Step};
use crate::testing::{CHECK_DS, CountingNer, FakeHost, MEMO_FORBIDDEN, MEMO_NAME, MEMO_V, NAME};

const CLIENT_VALUE: &str = "client-value";
/// A user-text canary (never flagged: it must simply never be logged).
const USER_CANARY: &str = "Wexlorian refund ledger";

/// A system text of at least `bytes` bytes: [`MEMO_NAME`] (which both fake
/// models flag) twice, and [`MEMO_V`] in clear (flagged only after `Mr. `).
fn system_text(bytes: usize) -> String {
    let mut s = format!(
        "You are the support assistant of {MEMO_NAME}. Escalate billing questions to \
         {MEMO_NAME} directly. Never change the {MEMO_V} valve settings.\n"
    );
    let filler = [
        "Answer in short paragraphs. ",
        "Cite the relevant section of the handbook when you can. ",
        "Ask one clarifying question when a request is ambiguous. ",
        "Keep a neutral and friendly tone with every customer. ",
    ];
    let mut i = 0;
    while s.len() < bytes {
        s.push_str(filler[i % filler.len()]);
        i += 1;
    }
    s
}

fn proxy_with(host: &Arc<FakeHost>, static_cache: bool) -> (crate::Proxy, Arc<Recording>) {
    proxy_with_ner(host, static_cache, crate::StaticNer::Scan)
}

/// [`proxy_with`] with `[proxy] harness_static_ner` set to `static_ner`.
fn proxy_with_ner(
    host: &Arc<FakeHost>,
    static_cache: bool,
    static_ner: crate::StaticNer,
) -> (crate::Proxy, Arc<Recording>) {
    let mut cfg = crate::pipeline::test_shared(host.clone()).cfg.clone();
    cfg.static_cache = static_cache;
    cfg.static_ner = static_ner;
    let up = Arc::new(Recording::default());
    let p = crate::Proxy::with_upstream(
        cfg,
        host.clone(),
        zeroize::Zeroizing::new(CLIENT_VALUE.into()),
        up.clone(),
    );
    (p, up)
}

/// A Messages body with a top-level `system` and these `messages`.
fn body(system: &str, messages: Value) -> Vec<u8> {
    json!({"model": "m", "max_tokens": 9, "system": system, "messages": messages})
        .to_string()
        .into_bytes()
}

fn user(text: &str) -> Value {
    json!([{"role": "user", "content": text}])
}

/// POST to `uri` in session `session`, with the client header when
/// `trusted`. Returns the status and the response body.
async fn post_to(
    p: &crate::Proxy,
    uri: &str,
    b: Vec<u8>,
    session: &str,
    trusted: bool,
) -> (u16, String) {
    let mut r = http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-inumaki-session", session);
    if trusted {
        r = r.header("x-inumaki-client", CLIENT_VALUE);
    }
    let resp = p
        .router()
        .oneshot(r.body(Body::from(b)).unwrap())
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 22)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn post(p: &crate::Proxy, b: Vec<u8>, session: &str, trusted: bool) -> (u16, String) {
    post_to(p, "/anthropic/v1/messages", b, session, trusted).await
}

/// The `n`th forwarded body.
fn sent(up: &Recording, n: usize) -> String {
    String::from_utf8(up.sent.lock().unwrap()[n].2.clone()).unwrap()
}

/// The `system` string of the `n`th forwarded body.
fn sent_system(up: &Recording, n: usize) -> String {
    let v: Value = serde_json::from_str(&sent(up, n)).unwrap();
    v["system"].as_str().unwrap().to_string()
}

/// `s` with every token replaced by its kind and its first-occurrence
/// index, so texts of two sessions compare equal when only the random
/// token parts differ.
fn canon(s: &str) -> String {
    let settings = inumaki_core::config::TokenSettings::default();
    let any = regex::Regex::new(&inumaki_core::rehydrate::Rehydrator::pattern(&settings)).unwrap();
    let kind = regex::Regex::new(&format!(
        "^{}([A-Z][A-Z0-9_]*?)_(?:[0-9a-f]{{4,12}}(?:_[0-9a-f]{{2}})?|REMOVED){}$",
        regex::escape(&settings.open),
        regex::escape(&settings.close)
    ))
    .unwrap();
    let mut seen: Vec<String> = Vec::new();
    any.replace_all(s, |c: &regex::Captures<'_>| {
        let t = c[0].to_string();
        let i = seen.iter().position(|x| *x == t).unwrap_or_else(|| {
            seen.push(t.clone());
            seen.len() - 1
        });
        let k = kind.captures(&t).unwrap()[1].to_string();
        format!("<{k}#{i}>")
    })
    .into_owned()
}

fn models(host: &FakeHost) -> (&CountingNer, &CountingNer) {
    let n = host.ner.as_ref().unwrap();
    (&n.sanitizer, &n.verifier)
}

/// Long calls of both models: `(sanitizer, verifier)`.
fn long_calls(host: &FakeHost) -> (usize, usize) {
    let (s, v) = models(host);
    (s.long(), v.long())
}

fn stats(host: &FakeHost) -> MemoStats {
    host.memo.as_ref().unwrap().stats()
}

/// Test 1: a second session's static leaf runs neither NER model, and its
/// forwarded text equals the first session's after canonical renaming. Two
/// requests with no dictionary change clear nothing (test 5, second half).
#[tokio::test]
async fn memo_cross_session_hit() {
    let host = FakeHost::with_ner(true);
    let (p, up) = proxy_with(&host, true);
    let sys = system_text(4096);

    let (st, _) = post(
        &p,
        body(&sys, user("Please summarize the rules.")),
        "A",
        true,
    )
    .await;
    assert_eq!(st, 200);
    let (sa, va) = long_calls(&host);
    assert!(sa >= 1 && va >= 1, "session A ran both models");
    assert_eq!(stats(&host).hits, 0);

    let (st, _) = post(&p, body(&sys, user("What about refunds?")), "B", true).await;
    assert_eq!(st, 200);
    assert_eq!(
        long_calls(&host),
        (sa, va),
        "session B ran no sanitizer NER on the system leaf and no verifier NER on its candidate"
    );
    let s = stats(&host);
    assert_eq!(s.hits, 2, "one sanitizer and one verifier hit");
    assert_eq!(s.clears, 0, "no dictionary change, no clear");

    let (a, b) = (sent_system(&up, 0), sent_system(&up, 1));
    assert!(!a.contains(MEMO_NAME) && a.contains("<PERSON_"), "{a}");
    assert!(!b.contains(MEMO_NAME) && b.contains("<PERSON_"), "{b}");
    assert_eq!(canon(&a), canon(&b));
}

/// Test 1 on the Codex/Responses wire (review M7), after the OpenAI routes
/// began to skip the NER models for harness-static leaves
/// (`[proxy] harness_static_ner = "skip"`, the default): a `>= 4 KiB`
/// `instructions` string runs no sanitizer NER and no verifier NER in either
/// session, the memo is never read or written, and the forwarded
/// `instructions` are equal.
#[tokio::test]
async fn a_skipping_route_runs_no_model_and_no_memo_on_responses_instructions() {
    let host = FakeHost::with_ner(true);
    let (p, up) = proxy_with_ner(&host, true, crate::StaticNer::Skip);
    let instructions = system_text(4096);
    let uri = "/openai/v1/responses";
    let req = |text: &str| {
        json!({"model": "m", "instructions": instructions, "input": text})
            .to_string()
            .into_bytes()
    };

    for (n, (text, session)) in [
        ("Please summarize the rules.", "A"),
        ("What about refunds?", "B"),
    ]
    .into_iter()
    .enumerate()
    {
        let (st, _) = post_to(&p, uri, req(text), session, true).await;
        assert_eq!(st, 200, "session {session}");
        assert_eq!(
            long_calls(&host),
            (0, 0),
            "session {session}: no long NER call"
        );
        let s = stats(&host);
        assert_eq!(
            (s.hits, s.misses, s.entries),
            (0, 0, 0),
            "{session}: memo untouched: {s:?}"
        );
        let v: Value = serde_json::from_str(&sent(&up, n)).unwrap();
        assert!(
            v["instructions"].as_str().unwrap().contains(MEMO_NAME),
            "no model, so the stand-in name is not found"
        );
    }
}

/// What one run of the on/off script produced.
struct ScriptRun {
    statuses: Vec<u16>,
    bodies: Vec<String>,
    /// The response bodies of the refused turns.
    refusals: Vec<String>,
    /// Long calls `(sanitizer, verifier)` made by B turn 2.
    b2_calls: (usize, usize),
    /// Long sanitizer calls made by C2.
    c2_calls: usize,
}

/// A, then B turn 1, then B turn 2, then C1 and C2. In B turn 2 the user
/// text mints [`MEMO_V`], which the system text holds in clear, and the
/// system leaf is new in B (B turn 1 had another one). C1 and C2 (two
/// sessions) send a system text holding [`MEMO_FORBIDDEN`], which the
/// policy refuses; with the memo on, C2's sanitizer NER is a hit.
async fn on_off_script(static_cache: bool) -> ScriptRun {
    let host = FakeHost::with_ner(true);
    let (p, up) = proxy_with(&host, static_cache);
    let sys = system_text(4096);
    let mut statuses = Vec::new();
    let (st, _) = post(
        &p,
        body(&sys, user("Please summarize the rules.")),
        "A",
        true,
    )
    .await;
    statuses.push(st);
    let b1 = json!([{"role": "user", "content": "Hello there."}]);
    let (st, _) = post(&p, body("You are brief.", b1), "B", true).await;
    statuses.push(st);
    let before = long_calls(&host);
    let b2 = json!([
        {"role": "user", "content": "Hello there."},
        {"role": "assistant", "content": "Hi, how can I help?"},
        {"role": "user", "content": format!("Mr. {MEMO_V} called about the valve.")},
    ]);
    let (st, _) = post(&p, body(&sys, b2), "B", true).await;
    statuses.push(st);
    let after = long_calls(&host);
    let forbidden = format!("{sys} The {MEMO_FORBIDDEN} archive is off limits.");
    let mut refusals = Vec::new();
    let mut c2_calls = 0;
    for session in ["C1", "C2"] {
        let before = long_calls(&host).0;
        let (st, b) = post(&p, body(&forbidden, user("Any news?")), session, true).await;
        statuses.push(st);
        if st != 200 {
            refusals.push(b);
        }
        c2_calls = long_calls(&host).0 - before;
    }
    let n = up.sent.lock().unwrap().len();
    let bodies: Vec<String> = (0..n).map(|i| sent(&up, i)).collect();

    // V is B's token in both runs: the user text's token for it, and the
    // system text holds that token, not V.
    let last: Value = serde_json::from_str(&bodies[2]).unwrap();
    let u = last["messages"][2]["content"].as_str().unwrap();
    let rest = u
        .strip_prefix("Mr. ")
        .expect("the user text kept its shape");
    let tok = &rest[..rest.find('>').unwrap() + 1];
    assert!(tok.starts_with("<PERSON_"), "V was tokenized: {u}");
    let sys_out = last["system"].as_str().unwrap();
    assert!(
        sys_out.contains(tok),
        "the system text carries B's token for V"
    );
    assert!(!sys_out.contains(MEMO_V) && !sys_out.contains(MEMO_NAME));

    ScriptRun {
        statuses,
        bodies,
        refusals,
        b2_calls: (after.0 - before.0, after.1 - before.1),
        c2_calls,
    }
}

/// Test 2 (a hard gate): the memo changes nothing. The forwarded bodies and
/// the refusals of the script are equal with the memo on and off, after
/// canonical renaming. In B turn 2 the sanitizer NER is a hit and the
/// verifier NER runs, because the masked candidate differs from A's (P6).
/// C2's refusal comes from a memo hit when the memo is on (M3).
#[tokio::test]
async fn memo_on_equals_off() {
    let on = on_off_script(true).await;
    let off = on_off_script(false).await;
    assert_eq!(on.statuses, vec![200, 200, 200, 451, 451]);
    assert_eq!(on.statuses, off.statuses);
    assert_eq!(on.refusals.len(), 2);
    assert_eq!(on.refusals.len(), off.refusals.len());
    for (a, b) in on.refusals.iter().zip(&off.refusals) {
        assert!(a.contains("FORBIDDEN"), "the refusal names the kind: {a}");
        assert_eq!(canon(a), canon(b));
    }
    assert_eq!(on.c2_calls, 0, "C2: the refusal came from a memo hit");
    assert!(off.c2_calls >= 1, "without the memo C2 ran the model");
    assert_eq!(on.bodies.len(), 3);
    assert_eq!(on.bodies.len(), off.bodies.len());
    for (a, b) in on.bodies.iter().zip(&off.bodies) {
        assert_eq!(canon(a), canon(b));
    }
    assert_eq!(on.b2_calls.0, 0, "B turn 2: the sanitizer NER hit");
    assert!(on.b2_calls.1 >= 1, "B turn 2: the verifier NER ran");
    assert!(
        off.b2_calls.0 >= 1,
        "without the memo the sanitizer NER ran"
    );
}

/// Test 3 (S2, L2-40): a restricted request never reads or writes the memo
/// and runs its models, even right after a trusted session stored the text
/// and while a trusted scope on it is open. With the header, a hit.
#[tokio::test]
async fn memo_restricted_mode_never_uses_the_memo() {
    let host = FakeHost::with_ner(true);
    let (p, _up) = proxy_with(&host, true);
    let sys = system_text(4096);
    for session in ["R1", "R2"] {
        let before = long_calls(&host);
        let (st, _) = post(&p, body(&sys, user("Restricted question.")), session, false).await;
        assert_eq!(st, 200);
        let after = long_calls(&host);
        assert!(
            after.0 > before.0 && after.1 > before.1,
            "{session}: models ran"
        );
    }
    assert_eq!(stats(&host), MemoStats::default(), "no hit, no entry");

    // A trusted session stores the text.
    let (st, _) = post(&p, body(&sys, user("Trusted question.")), "T1", true).await;
    assert_eq!(st, 200);
    let stored = stats(&host);
    assert!(stored.entries >= 1);

    // A trusted scope on the same text is open (the allow set is
    // process-wide): a restricted request still misses, stores nothing,
    // and runs its models.
    let memo = host.memo.clone().unwrap();
    let scope = memo.scope(&sys);
    let before = long_calls(&host);
    let (st, _) = post(&p, body(&sys, user("Restricted again.")), "R3", false).await;
    assert_eq!(st, 200);
    let after = long_calls(&host);
    assert!(after.0 > before.0 && after.1 > before.1, "R3: models ran");
    assert_eq!(stats(&host), stored, "R3: no hit, nothing stored");
    drop(scope);

    // With the header: a hit.
    let before = long_calls(&host);
    let (st, _) = post(&p, body(&sys, user("Trusted again.")), "T2", true).await;
    assert_eq!(st, 200);
    assert_eq!(long_calls(&host), before, "T2: answered from the memo");
    let hit = stats(&host);
    assert_eq!(hit.hits, stored.hits + 2);

    // A restricted request does not even adopt a new dictionary (no clear).
    let fresh: Arc<dyn Detector> =
        Arc::new(DictionaryDetector::from_entries([(EntityKind::Person, NAME)]).unwrap());
    host.set_dictionary(fresh);
    let (st, _) = post(&p, body(&sys, user("Restricted last.")), "R4", false).await;
    assert_eq!(st, 200);
    assert_eq!(stats(&host), hit, "R4: no clear, no hit, nothing stored");
}

/// M1 (L2-42): a trusted request's ineligible leaf runs on the unwrapped
/// engine, so it never uses the memo, not even while another request's
/// scope on the same bytes is open (the allow set is process-wide).
#[tokio::test]
async fn memo_trusted_ineligible_leaf_ignores_an_open_scope() {
    let host = FakeHost::with_ner(true);
    let (p, _up) = proxy_with(&host, true);
    let sys = system_text(4096);
    let (st, _) = post(&p, body(&sys, user("Store it.")), "T1", true).await;
    assert_eq!(st, 200);
    let stored = stats(&host);
    assert!(stored.entries >= 1);

    let memo = host.memo.clone().unwrap();
    let scope = memo.scope(&sys);
    for (session, msgs) in [
        ("U", user(&sys)),
        (
            "R",
            json!([{"role": "user", "content": [{"type": "tool_result",
                "tool_use_id": "toolu_01Hn4Bq9xL2mZ8cVt5sKpR3w", "content": sys}]}]),
        ),
    ] {
        let before = long_calls(&host);
        let (st, _) = post(&p, body("Be brief.", msgs), session, true).await;
        assert_eq!(st, 200);
        let after = long_calls(&host);
        assert!(
            after.0 > before.0 && after.1 > before.1,
            "{session}: models ran"
        );
        assert_eq!(stats(&host), stored, "{session}: no hit, nothing stored");
    }
    drop(scope);
}

/// D-3 (L120): the memo holds harness-static entries only. The same bytes
/// as a trusted user leaf, and as a restricted system leaf, are `Free`:
/// they run the model and never read the entry a trusted system leaf made.
#[tokio::test]
async fn free_leaves_never_read_a_harness_static_entry() {
    let host = FakeHost::with_ner(true);
    let (p, _up) = proxy_with(&host, true);
    let s = system_text(4096);
    let sanitizer_long = || models(&host).0.long();

    // A: a trusted system leaf makes an entry.
    let (st, _) = post(&p, body(&s, user("Store it.")), "A", true).await;
    assert_eq!(st, 200);
    let stored = stats(&host);
    assert!(stored.misses >= 1 && stored.entries >= 1, "{stored:?}");

    // B: the same bytes as a trusted user message run the model.
    let (before, hits) = (sanitizer_long(), stats(&host).hits);
    let (st, _) = post(&p, body("Be brief.", user(&s)), "B", true).await;
    assert_eq!(st, 200);
    assert_eq!(sanitizer_long(), before + 1, "B: the model ran");
    assert_eq!(stats(&host).hits, hits, "B: no hit");

    // C: the same bytes as a restricted system leaf run the model.
    let (before, hits) = (sanitizer_long(), stats(&host).hits);
    let (st, _) = post(&p, body(&s, user("Restricted.")), "C", false).await;
    assert_eq!(st, 200);
    assert_eq!(sanitizer_long(), before + 1, "C: the model ran");
    assert_eq!(stats(&host).hits, hits, "C: no hit");

    // D: a trusted system leaf still reads the entry.
    let hits = stats(&host).hits;
    let (st, _) = post(&p, body(&s, user("Trusted again.")), "D", true).await;
    assert_eq!(st, 200);
    assert!(stats(&host).hits > hits, "D: a hit");
}

/// L122: a system/developer item after the leading run is `Free`, so a
/// long one in a trusted request runs the models, also on a route that skips
/// them for the leading run. The same bytes as leading text run none.
#[tokio::test]
async fn a_mid_conversation_system_leaf_runs_the_models_on_a_skipping_route() {
    let host = FakeHost::with_ner(true);
    let (p, _up) = proxy_with_ner(&host, true, crate::StaticNer::Skip);
    let s = system_text(4096);
    let sanitizer_long = || models(&host).0.long();
    let responses = "/openai/v1/responses";

    // A: the text as leading `instructions` runs no model.
    let a = json!({"model": "m", "instructions": s, "input": "Store it."});
    let (st, _) = post_to(&p, responses, a.to_string().into_bytes(), "A", true).await;
    assert_eq!(st, 200);
    assert_eq!(sanitizer_long(), 0, "A: leading text, no model");

    // B, C: the same bytes after a user item (Responses) and after the
    // first user message (Chat) run the model.
    let mid = [
        (
            "B",
            responses,
            json!({"model": "m", "input": [
                {"type": "message", "role": "user", "content": "Hello."},
                {"type": "message", "role": "developer", "content": s}
            ]}),
        ),
        (
            "C",
            "/openai/v1/chat/completions",
            json!({"model": "m", "messages": [
                {"role": "user", "content": "Hello."},
                {"role": "system", "content": s}
            ]}),
        ),
    ];
    for (session, uri, b) in mid {
        let before = sanitizer_long();
        let (st, _) = post_to(&p, uri, b.to_string().into_bytes(), session, true).await;
        assert_eq!(st, 200, "{session}");
        assert_eq!(sanitizer_long(), before + 1, "{session}: the model ran");
        assert_eq!(stats(&host).hits, 0, "{session}: no hit");
    }

    // D: the same bytes as a leading developer item run none.
    let d = json!({"model": "m", "input": [
        {"type": "message", "role": "developer", "content": s},
        {"type": "message", "role": "user", "content": "Hello."}
    ]});
    let before = sanitizer_long();
    let (st, _) = post_to(&p, responses, d.to_string().into_bytes(), "D", true).await;
    assert_eq!(st, 200);
    assert_eq!(sanitizer_long(), before, "D: leading text, no model");
}

/// Codex responses-lite (0.162): the leading `additional_tools` item holds
/// the tool definitions and keeps the run going, so the long developer
/// prompt after it is leading: on a route that skips the models it runs none
/// in either session. The item's own `id` (`at_<uuid>`) is forwarded as
/// received: scanned as text it read as a phone number and the provider
/// refused the request.
#[tokio::test]
async fn codex_lite_developer_prompt_after_additional_tools_runs_no_model() {
    let host = FakeHost::with_ner(true);
    let (p, up) = proxy_with_ner(&host, true, crate::StaticNer::Skip);
    let s = system_text(4096);
    let at_id = "at_01a17f97-697e-7680-b202-dab7774aa1e3";
    let body = |u: &str| {
        json!({"model": "m", "input": [
            {"type": "additional_tools", "id": at_id, "role": "developer", "tools": [
                {"type": "namespace", "name": "ns", "description": "Shell tools.", "tools": [
                    {"type": "function", "name": "shell", "description": "Runs a command.",
                     "parameters": {"type": "object", "properties": {}}}
                ]}
            ]},
            {"type": "message", "role": "developer", "content": [{"type": "input_text", "text": s}]},
            {"type": "message", "role": "user", "content": u}
        ]})
        .to_string()
        .into_bytes()
    };
    let responses = "/openai/v1/responses";

    for (n, (u, session)) in [("First.", "A"), ("Second.", "B")].into_iter().enumerate() {
        let (st, _) = post_to(&p, responses, body(u), session, true).await;
        assert_eq!(st, 200);
        assert_eq!(long_calls(&host), (0, 0), "{session}: no model ran");
        let v: Value = serde_json::from_str(&sent(&up, n)).unwrap();
        assert_eq!(
            v["input"][0]["id"], at_id,
            "{session}: the item id is as received"
        );
    }
}

/// Test 4: user text, tool results, short system leaves, and check routes
/// never touch the memo.
#[tokio::test]
async fn memo_ineligible_leaves_never_touch_it() {
    let host = FakeHost::with_ner(true);
    let (p, up) = proxy_with(&host, true);
    let long = system_text(4096);
    let ran = |before: (usize, usize)| long_calls(&host).0 > before.0;

    // The long text as a user message, then as a tool result, in two
    // sessions each: the sanitizer NER runs every time.
    for (i, session) in ["U1", "U2"].iter().enumerate() {
        let before = long_calls(&host);
        let (st, _) = post(&p, body("Be brief.", user(&long)), session, true).await;
        assert_eq!(st, 200, "user text, request {i}");
        assert!(ran(before), "user text: the model ran ({session})");
    }
    for session in ["T1", "T2"] {
        let before = long_calls(&host);
        let msgs = json!([{"role": "user", "content": [{"type": "tool_result",
            "tool_use_id": "toolu_01Hn4Bq9xL2mZ8cVt5sKpR3w", "content": long}]}]);
        let (st, _) = post(&p, body("Be brief.", msgs), session, true).await;
        assert_eq!(st, 200, "tool result");
        assert!(ran(before), "tool result: the model ran ({session})");
    }
    // A 1 KiB system leaf.
    let short = system_text(1024);
    assert!(short.len() < STATIC_MIN_BYTES);
    for session in ["S1", "S2"] {
        let (st, _) = post(&p, body(&short, user("Short system.")), session, true).await;
        assert_eq!(st, 200);
    }
    assert_eq!(stats(&host), MemoStats::default(), "no hit, no entry");

    // A check-route request: sanitized by the check dataset, never by the
    // proxy engine.
    let id = "0123456789abcdef0123456789abcdef";
    p.check_routes().register(
        CheckId::from_hex(id).unwrap(),
        CHECK_DS,
        Script(vec![Step::EchoUserText]),
        Duration::from_secs(60),
    );
    let uri = format!("/check/{id}/anthropic/v1/messages");
    for session in ["C1", "C2"] {
        let (st, _) = post_to(&p, &uri, body(&long, user("Check.")), session, true).await;
        assert_eq!(st, 200);
    }
    assert_eq!(
        stats(&host),
        MemoStats::default(),
        "check route: no hit, no entry"
    );
    assert_eq!(
        up.sent.lock().unwrap().len(),
        6,
        "check routes never reach it"
    );
}

/// Test 5: a dictionary change between two sessions clears the memo, so the
/// second misses.
#[tokio::test]
async fn memo_dictionary_change_clears() {
    let host = FakeHost::with_ner(true);
    let (p, _up) = proxy_with(&host, true);
    let sys = system_text(4096);
    let (st, _) = post(&p, body(&sys, user("First.")), "A", true).await;
    assert_eq!(st, 200);
    assert_eq!(stats(&host).clears, 0, "the first adoption is not a clear");
    let stored = stats(&host);
    assert!(stored.entries >= 1);

    // A request whose dictionary changes while it is in flight (it holds
    // the old one) opens no scope: its models run, and the memo neither
    // answers, stores, nor clears (M2, S5).
    host.swap_after_next_read.store(true, Ordering::SeqCst);
    let before = long_calls(&host);
    let (st, _) = post(&p, body(&sys, user("In flight.")), "C", true).await;
    assert_eq!(st, 200);
    let after = long_calls(&host);
    assert!(after.0 > before.0 && after.1 > before.1, "C missed");
    assert!(
        !host.swap_after_next_read.load(Ordering::SeqCst),
        "the dictionary changed during C"
    );
    assert_eq!(stats(&host), stored, "C: no hit, no store, no clear");

    let fresh: Arc<dyn Detector> =
        Arc::new(DictionaryDetector::from_entries([(EntityKind::Person, NAME)]).unwrap());
    host.set_dictionary(fresh);
    let before = long_calls(&host);
    let (st, _) = post(&p, body(&sys, user("Second.")), "B", true).await;
    assert_eq!(st, 200);
    let after = long_calls(&host);
    assert!(after.0 > before.0 && after.1 > before.1, "B missed");
    let s = stats(&host);
    assert_eq!((s.hits, s.clears), (0, 1));
}

/// Test 6: a model error is never stored and fails closed: `503
/// model_unavailable` and nothing upstream. The next session runs the
/// failed model again and succeeds. For each role: when the verifier fails,
/// the sanitizer's entry stays (a pure function's result, whatever happens
/// to the request) and answers the next session; the verifier's is absent.
#[tokio::test]
async fn memo_model_error_is_not_stored() {
    for verifier in [false, true] {
        let host = FakeHost::with_ner(true);
        let (p, up) = proxy_with(&host, true);
        let sys = system_text(4096);
        let (s, v) = models(&host);
        let (failing, other) = if verifier { (v, s) } else { (s, v) };
        failing.fail.store(true, Ordering::SeqCst);
        let (st, b) = post(&p, body(&sys, user("First.")), "A", true).await;
        assert_eq!(st, 503, "verifier={verifier}");
        assert!(b.contains("model_unavailable"), "{b}");
        assert!(up.sent.lock().unwrap().is_empty(), "nothing left");
        assert!(failing.long() >= 1, "the failing model was called");
        let stored = u64::from(verifier && other.long() >= 1);
        assert_eq!(stats(&host).entries, stored, "verifier={verifier}");

        failing.fail.store(false, Ordering::SeqCst);
        let before = failing.long();
        let (st, _) = post(&p, body(&sys, user("Second.")), "B", true).await;
        assert_eq!(st, 200, "verifier={verifier}");
        assert!(failing.long() > before, "the failed model ran again");
        assert_eq!(up.sent.lock().unwrap().len(), 1);
        assert_eq!(stats(&host).hits, stored, "verifier={verifier}");
    }
}

/// Test 7: `static_cache = false` turns the memo off, even though the host
/// provides one: no scope opens, nothing is stored, and the effective state
/// is off.
#[tokio::test]
async fn memo_switch_off() {
    let host = FakeHost::with_ner(true);
    let (p, _up) = proxy_with(&host, false);
    assert!(p.inner.sh.memo.is_none(), "enabled: false");
    let sys = system_text(4096);
    for (i, session) in ["A", "B"].iter().enumerate() {
        let (st, _) = post(&p, body(&sys, user("Question.")), session, true).await;
        assert_eq!(st, 200);
        assert_eq!(long_calls(&host).0, i + 1, "the model ran every time");
    }
    assert_eq!(stats(&host), MemoStats::default(), "no scope, no store");
    // The status body (`GET /v1/proxy`) says so: configured off with a memo
    // on the host is not enabled, and it counts nothing.
    let off = serde_json::to_value(p.status()).unwrap();
    assert_eq!(
        off["static_cache"],
        json!({"enabled": false, "hits": 0, "misses": 0, "entries": 0, "clears": 0})
    );

    // And on: the effective state follows the host's memo.
    let (on, _) = proxy_with(&host, true);
    assert!(on.inner.sh.memo.is_some(), "enabled: true");
    assert_eq!(
        serde_json::to_value(on.status()).unwrap()["static_cache"]["enabled"],
        true
    );
    let (bare, _) = proxy_with(&FakeHost::with_ner(false), true);
    assert!(bare.inner.sh.memo.is_none(), "no host memo, enabled: false");
    // Configured on, but the host has no memo: not enabled either.
    assert_eq!(
        serde_json::to_value(bare.status()).unwrap()["static_cache"],
        json!({"enabled": false, "hits": 0, "misses": 0, "entries": 0, "clears": 0})
    );
}

/// The status body carries the memo's live counters, after `client_header`
/// and before anything else (the contract's field order).
#[tokio::test]
async fn memo_status_reports_the_counters() {
    let host = FakeHost::with_ner(true);
    let (p, _up) = proxy_with(&host, true);
    let sys = system_text(4096);
    for session in ["A", "B"] {
        let (st, _) = post(&p, body(&sys, user("Question.")), session, true).await;
        assert_eq!(st, 200);
    }
    let want = stats(&host);
    assert!(want.hits >= 1 && want.misses >= 1, "{want:?}");
    let v = serde_json::to_value(p.status()).unwrap();
    assert_eq!(v["static_cache"]["enabled"], true);
    assert_eq!(v["static_cache"]["hits"], want.hits);
    assert_eq!(v["static_cache"]["misses"], want.misses);
    assert_eq!(v["static_cache"]["entries"], want.entries);
    assert_eq!(v["static_cache"]["clears"], want.clears);
    // `Value` sorts its keys, so the order is read off the serialized text.
    let text = serde_json::to_string(&p.status()).unwrap();
    let at = |k: &str| text.find(&format!("\"{k}\":")).unwrap();
    assert!(at("client_header") < at("timing") && at("timing") < at("static_cache"));
    assert_eq!(v["timing"]["window"], 2, "both requests were sampled");
}

/// Captures every `tracing` event and span field at every level, from every
/// thread (the pipeline runs on the blocking pool): stricter than the
/// daemon's filter, which drops events this keeps. It records only while
/// [`CAPTURING`] is set, which test 8 does for its own window (M4); events
/// of tests running in that same window land in it too, which only widens
/// what is checked.
struct Capture(Arc<Mutex<String>>);

/// Whether [`Capture`] records (test 8's window).
static CAPTURING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

thread_local! {
    /// A per-thread sink (see [`LocalLogs`]); `Some` while one is open.
    static LOCAL: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// A capture of the events the opening thread logs, for tests whose code
/// under test logs on that thread (a current-thread runtime). It rides on
/// the same global [`Capture`], so it does not race [`Window`], and no
/// other test's lines land in it.
pub(crate) struct LocalLogs;

impl LocalLogs {
    /// Install the capture if needed and start recording this thread.
    pub(crate) fn open() -> LocalLogs {
        captured();
        LOCAL.with(|l| *l.borrow_mut() = Some(String::new()));
        LocalLogs
    }
    /// Stop recording and return this thread's lines.
    pub(crate) fn close(self) -> String {
        LOCAL.with(|l| l.borrow_mut().take()).unwrap_or_default()
    }
}

impl Drop for LocalLogs {
    fn drop(&mut self) {
        LOCAL.with(|l| *l.borrow_mut() = None);
    }
}

/// Whether a [`TimingLines`] capture is open.
static TIMING_OPEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The `proxy stream timing` lines of [`TimingLines`].
static TIMING_SINK: Mutex<String> = Mutex::new(String::new());

/// A capture of the `proxy stream timing` lines from every thread: a
/// stream's driver logs it on the blocking pool, where [`LocalLogs`] cannot
/// see it. Tests running at the same time add their own timing lines, so a
/// test checks every line it gets and never counts them.
pub(crate) struct TimingLines;

impl TimingLines {
    /// Install the capture if needed and start recording.
    pub(crate) fn open() -> TimingLines {
        captured();
        TIMING_SINK.lock().unwrap().clear();
        TIMING_OPEN.store(true, Ordering::SeqCst);
        TimingLines
    }
    /// Stop recording and return the lines.
    pub(crate) fn close(self) -> String {
        TIMING_OPEN.store(false, Ordering::SeqCst);
        std::mem::take(&mut *TIMING_SINK.lock().unwrap())
    }
}

impl Drop for TimingLines {
    fn drop(&mut self) {
        TIMING_OPEN.store(false, Ordering::SeqCst);
    }
}

/// Write `line` to this thread's sink when one is open; whether it was.
fn local_line(line: &str) -> bool {
    LOCAL.with(|l| match l.borrow_mut().as_mut() {
        Some(b) => {
            b.push_str(line);
            true
        }
        None => false,
    })
}

/// Test 8's capture window: clears the buffer and starts recording; stops
/// on drop (also when the test panics).
struct Window(Arc<Mutex<String>>);

impl Window {
    fn open() -> Window {
        let buf = captured();
        buf.lock().unwrap().clear();
        CAPTURING.store(true, Ordering::SeqCst);
        Window(buf)
    }
    /// Stop recording and return what the window captured.
    fn close(self) -> String {
        CAPTURING.store(false, Ordering::SeqCst);
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        CAPTURING.store(false, Ordering::SeqCst);
    }
}

struct Fields<'a>(&'a mut String);

impl tracing::field::Visit for Fields<'_> {
    fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
        let _ = write!(self.0, " {}={v:?}", f.name());
    }
}

impl tracing::Subscriber for Capture {
    /// Ask on every call, so the window can open and close.
    fn register_callsite(
        &self,
        _: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }
    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::TRACE)
    }
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        CAPTURING.load(Ordering::SeqCst)
            || TIMING_OPEN.load(Ordering::SeqCst)
            || LOCAL.with(|l| l.borrow().is_some())
    }
    fn new_span(&self, a: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let mut s = format!("span {}", a.metadata().name());
        a.record(&mut Fields(&mut s));
        self.0.lock().unwrap().push_str(&(s + "\n"));
        tracing::span::Id::from_u64(NEXT.fetch_add(1, Ordering::Relaxed))
    }
    fn record(&self, _: &tracing::span::Id, r: &tracing::span::Record<'_>) {
        let mut s = String::from("record");
        r.record(&mut Fields(&mut s));
        self.0.lock().unwrap().push_str(&(s + "\n"));
    }
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, e: &tracing::Event<'_>) {
        let mut s = format!("{} {}", e.metadata().level(), e.metadata().target());
        e.record(&mut Fields(&mut s));
        let line = s + "\n";
        if TIMING_OPEN.load(Ordering::SeqCst) && line.contains("proxy stream timing") {
            TIMING_SINK.lock().unwrap().push_str(&line);
        }
        // With only a timing capture open, other threads' events are dropped.
        let wanted = CAPTURING.load(Ordering::SeqCst) || !TIMING_OPEN.load(Ordering::SeqCst);
        if !local_line(&line) && wanted {
            self.0.lock().unwrap().push_str(&line);
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// The process-wide capture buffer, with [`Capture`] installed as the
/// global subscriber on first use. If another global subscriber were ever
/// installed first, the check could not run: that fails loudly here
/// rather than passing vacuously.
fn captured() -> Arc<Mutex<String>> {
    static BUF: OnceLock<Arc<Mutex<String>>> = OnceLock::new();
    BUF.get_or_init(|| {
        let buf = Arc::new(Mutex::new(String::new()));
        let installed = tracing::subscriber::set_global_default(Capture(Arc::clone(&buf))).is_ok();
        assert!(installed, "no other global subscriber in this test binary");
        buf
    })
    .clone()
}

/// Test 8: `Debug` of `Shared` and `NerMemo`, the status body, and every
/// log line at `TRACE` carry no canary.
#[tokio::test]
async fn memo_privacy_debug_status_and_logs() {
    let window = Window::open();
    let host = FakeHost::with_ner(true);
    let (p, _up) = proxy_with(&host, true);
    let sys = system_text(4096);
    let ask = format!("Mr. {MEMO_V} asked about the {USER_CANARY}.");
    for (session, trusted) in [("A", true), ("B", true), ("R", false)] {
        let (st, _) = post(&p, body(&sys, user(&ask)), session, trusted).await;
        assert_eq!(st, 200);
    }
    // And a model error, on a system text the memo does not hold.
    models(&host).0.fail.store(true, Ordering::SeqCst);
    let other = format!("{sys} Error case.");
    let (st, _) = post(&p, body(&other, user(&ask)), "E", true).await;
    assert_eq!(st, 503);
    assert!(stats(&host).hits >= 2, "the memo was used");

    let memo: &NerMemo = host.memo.as_deref().unwrap();
    let debug = format!("{:?} {memo:?}", p.inner.sh);
    let status = serde_json::to_string(&p.status()).unwrap();
    let logs = window.close();
    assert!(!logs.is_empty(), "the capture saw events");
    for (what, out) in [("debug", &debug), ("status", &status), ("logs", &logs)] {
        for needle in [
            MEMO_NAME,
            "Quilbert",
            "Xandover",
            MEMO_V,
            USER_CANARY,
            "Wexlorian",
            "<PERSON_",
        ] {
            assert!(!out.contains(needle), "{what} carries {needle}");
        }
    }
}
