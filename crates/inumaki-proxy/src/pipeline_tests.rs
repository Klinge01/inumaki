//! Spec §15 tests 1–4, 6, 7, 9 at the pipeline level (non-streaming).
//!
//! A failure here means `sanitize_request` produced no body: the handler
//! (Task 8) sends only a `Prepared` body, so no body means the upstream
//! receives nothing. `forward` below is that rule in miniature, over a
//! recording upstream, so the fail-closed tests can assert zero requests.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::json;

use crate::error::Fail;
use crate::pipeline::{Shared, sanitize_request};
use crate::routes::{UpstreamId, Wire};
use crate::session::{Session, SessionKey, SessionStore};
use crate::testing::{DS_TOKEN, EMAIL, FakeHost, IBAN, Mode, NAME};
use crate::upstream::{Upstream, UpstreamError, UpstreamRequest, UpstreamResponse};
use crate::walk::{walk, walk_for};

pub(crate) fn shared(host: Arc<FakeHost>) -> Shared {
    crate::pipeline::test_shared(host)
}

fn store() -> SessionStore {
    SessionStore::new(
        Duration::from_secs(60),
        16,
        inumaki_core::config::TokenSettings::default(),
        1 << 20,
    )
}

fn prep(
    sh: &Shared,
    s: &Session,
    wire: Wire,
    body: &[u8],
) -> Result<crate::pipeline::Prepared, Fail> {
    prep_timed(sh, s, wire, body, &mut crate::timing::StageTimes::default())
}

fn prep_timed(
    sh: &Shared,
    s: &Session,
    wire: Wire,
    body: &[u8],
    times: &mut crate::timing::StageTimes,
) -> Result<crate::pipeline::Prepared, Fail> {
    let w = walk_for(wire, body, sh.cfg.binary).map_err(|_| Fail::BadRequest)?;
    sanitize_request(
        sh,
        s,
        wire,
        body,
        &w,
        crate::session::ClientMode::Trusted,
        false,
        times,
    )
}

fn run(sh: &Shared, s: &Session, wire: Wire, body: &serde_json::Value) -> Result<String, Fail> {
    prep(sh, s, wire, body.to_string().as_bytes()).map(|p| String::from_utf8(p.body).unwrap())
}

/// What a forwarded request commits (spec §5 step 7).
fn commit(s: &Session, mut p: crate::pipeline::Prepared) {
    crate::pipeline::commit_cache(s, &mut p);
}

fn clean(out: &str) {
    for c in [NAME, EMAIL, IBAN, "Zyxwuria", "zyx.quolnath"] {
        assert!(!out.contains(c), "{c} leaked: {out}");
    }
}

/// Records every request it is sent.
#[derive(Default)]
struct Recording(Mutex<Vec<UpstreamRequest>>);

impl Upstream for Recording {
    fn send(
        &self,
        req: UpstreamRequest,
    ) -> futures::future::BoxFuture<'static, Result<UpstreamResponse, UpstreamError>> {
        self.0.lock().unwrap().push(req);
        Box::pin(async {
            Ok(UpstreamResponse {
                status: http::StatusCode::OK,
                headers: http::HeaderMap::new(),
                body: Box::pin(futures::stream::empty()),
            })
        })
    }
}

/// The handler's rule: only a body the pipeline produced is sent.
fn forward(
    up: &Recording,
    sh: &Shared,
    s: &Session,
    wire: Wire,
    body: &serde_json::Value,
) -> Result<(), Fail> {
    let p = prep(sh, s, wire, body.to_string().as_bytes())?;
    drop(up.send(UpstreamRequest {
        upstream: UpstreamId::Anthropic,
        method: http::Method::POST,
        path_and_query: "/v1/messages".into(),
        headers: http::HeaderMap::new(),
        body: p.body.into(),
    }));
    Ok(())
}

/// Spec §15 test 1 (non-streaming), review C1.
#[test]
fn no_original_leaves_in_any_leaf_class() {
    let host = FakeHost::new();
    let sh = shared(Arc::clone(&host));
    let st = store();
    let s = st.get(SessionKey([1; 32]));
    let msg = format!("{NAME}, {EMAIL}, {IBAN}");
    let messages = json!({
        "model": "claude-x",
        "system": [{"type": "text", "text": msg}],
        "unknown_param": {"deep": [msg]},
        "metadata": {"note": msg},
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": msg}, {"type": "future_block", "x": {"y": msg}}]},
            {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_01Hn4Bq9xL2mZ8cVt5sKpR3w", "name": "lookup", "input": {EMAIL: {"n": msg}}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_01Hn4Bq9xL2mZ8cVt5sKpR3w", "content": msg}]}
        ]
    });
    let out = run(&sh, &s, Wire::Messages, &messages).unwrap();
    clean(&out);
    assert!(
        out.contains(DS_TOKEN),
        "the known name reuses the dataset token: {out}"
    );
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["messages"][1]["content"][0]["name"], "lookup");
    assert_eq!(v["model"], "claude-x");

    let chat = json!({
        "model": "gpt-x", "user": EMAIL, "safety_identifier": EMAIL,
        "prediction": {"type": "content", "content": msg},
        "web_search_options": {"user_location": {"type": "approximate", "approximate": {"city": msg}}},
        "messages": [
            {"role": "user", "name": NAME, "content": msg},
            {"role": "assistant", "function_call": {"name": "f", "arguments": json!({"q": msg}).to_string()}},
            {"role": "function", "name": "f", "content": msg},
            {"role": "assistant", "tool_calls": [{"id": "call_Y7sK2pQ9vXm4Lw8RtZ3nB6cD", "type": "function", "function": {"name": "f", "arguments": json!({EMAIL: msg}).to_string()}}]},
            {"role": "tool", "tool_call_id": "call_Y7sK2pQ9vXm4Lw8RtZ3nB6cD", "content": msg}
        ]
    });
    let out = run(&sh, &s, Wire::Chat, &chat).unwrap();
    clean(&out);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let args: serde_json::Value = serde_json::from_str(
        v["messages"][3]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert!(
        args.as_object()
            .unwrap()
            .keys()
            .all(|k| k.starts_with("<EMAIL_")),
        "inner key tokenized: {args}"
    );
    let responses = json!({
        "model": "gpt-x", "instructions": msg, "metadata": {"k": msg},
        "prompt": {"id": "pmpt_68af2f9a2b5c8190a1b2c3d4", "variables": {"v": msg}},
        "input": [
            {"type": "message", "role": "user", "content": msg},
            {"type": "custom_tool_call", "call_id": "call_A1sD2fG3hJ4kL5zX6cV7bN8m", "name": "apply_patch", "input": msg},
            {"type": "function_call", "call_id": "call_N3bV8xQ2mK7pL4wR9tZ6yH1s", "name": "f", "arguments": json!({"a": msg}).to_string()},
            {"type": "function_call_output", "call_id": "call_N3bV8xQ2mK7pL4wR9tZ6yH1s", "output": msg}
        ]
    });
    let out = run(&sh, &s, Wire::Responses, &responses).unwrap();
    clean(&out);
}

/// Spec §15 test 2 (pipeline part), approved change 3: every failure yields
/// no body, so nothing reaches the upstream.
#[test]
fn failures_produce_no_body_and_nothing_is_sent() {
    let host = FakeHost::new();
    let sh = shared(Arc::clone(&host));
    let st = store();
    let s = st.get(SessionKey([2; 32]));
    let up = Recording::default();
    let body = json!({"messages": [{"role": "user", "content": EMAIL}]});
    *host.fail_engine.lock().unwrap() = true;
    assert_eq!(
        forward(&up, &sh, &s, Wire::Messages, &body).unwrap_err(),
        Fail::ModelUnavailable
    );
    *host.fail_engine.lock().unwrap() = false;
    *host.fail_vault.lock().unwrap() = true;
    assert_eq!(
        forward(&up, &sh, &s, Wire::Messages, &body).unwrap_err(),
        Fail::VaultUnavailable
    );
    *host.fail_vault.lock().unwrap() = false;
    let img = json!({"messages": [{"role": "user", "content": [{"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBOR"}}]}]});
    assert_eq!(
        forward(&up, &sh, &s, Wire::Messages, &img).unwrap_err(),
        Fail::UnsupportedContent
    );
    let def =
        json!({"tools": [{"name": "t", "description": format!("ask {NAME}")}], "messages": []});
    assert_eq!(
        forward(&up, &sh, &s, Wire::Messages, &def).unwrap_err(),
        Fail::UnsupportedContent
    );
    let think = json!({"messages": [{"role": "assistant", "content": [{"type": "thinking", "thinking": format!("{NAME} again"), "signature": "s"}]}]});
    match forward(&up, &sh, &s, Wire::Messages, &think).unwrap_err() {
        Fail::PrivacyBlock {
            kinds,
            checks,
            uncertain,
        } => {
            assert_eq!(
                (kinds, checks, uncertain),
                (
                    vec!["PERSON".to_string()],
                    vec!["ClearValue".to_string()],
                    false
                )
            );
        }
        f => panic!("expected 451, got {f:?}"),
    }
    // Approved change 3: a failed session-dictionary build fails the request.
    // This relies on the log growing: the good request mints the email, so
    // the next request must rebuild the session dictionary (an up-to-date
    // one is reused without a build, and the hook fails builds only).
    forward(&up, &sh, &s, Wire::Messages, &body).unwrap();
    assert_eq!(up.0.lock().unwrap().len(), 1, "the one good request");
    s.fail_originals_for_test(true);
    let other = json!({"messages": [{"role": "user", "content": "noch eine Frage"}]});
    assert_eq!(
        forward(&up, &sh, &s, Wire::Messages, &other).unwrap_err(),
        Fail::VaultUnavailable
    );
    s.fail_originals_for_test(false);
    assert_eq!(
        up.0.lock().unwrap().len(),
        1,
        "no failed request reached the upstream"
    );
}

/// Spec §15 test 4, review C4 and I1; Review Focus 1: same placeholder
/// bytes on every resend, nothing new recorded, never a 451.
#[test]
fn withheld_tool_result_resends_byte_identical() {
    let host = FakeHost::new();
    let sh = shared(Arc::clone(&host));
    let st = store();
    let s = st.get(SessionKey([3; 32]));
    let body = json!({"messages": [
        {"role": "user", "content": "please look"},
        {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_01D7FLrfh4GYq7yT1ULmeyqw", "name": "shot", "input": {}}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_01D7FLrfh4GYq7yT1ULmeyqw", "content": [{"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBOR"}}]}]}
    ]})
    .to_string();
    let first = prep(&sh, &s, Wire::Messages, body.as_bytes()).unwrap();
    assert_eq!(first.withheld.len(), 1);
    let a = String::from_utf8(first.body.clone()).unwrap();
    assert!(
        a.contains("[inumaki: tool result withheld (kinds: BINARY). Nothing was sent.]"),
        "{a}"
    );
    assert!(!a.contains("iVBOR"));
    // Uncommitted (the upstream refused): the same bytes again.
    let again = prep(&sh, &s, Wire::Messages, body.as_bytes()).unwrap();
    assert_eq!(again.body, first.body);
    let first_body = first.body.clone();
    commit(&s, first);
    for _ in 0..2 {
        let resend = prep(&sh, &s, Wire::Messages, body.as_bytes()).unwrap();
        assert_eq!(resend.body, first_body, "byte-identical resend");
        assert!(
            resend.withheld.is_empty() && resend.memo.is_empty(),
            "the memo answers; nothing new recorded"
        );
    }
}

/// Spec §15 test 3 at the pipeline level: protected tokens stay byte-identical.
#[test]
fn gateway_and_session_tokens_in_tool_results_are_kept() {
    let host = FakeHost::new();
    let sh = shared(Arc::clone(&host));
    let st = store();
    let s = st.get(SessionKey([4; 32]));
    let first = run(
        &sh,
        &s,
        Wire::Messages,
        &json!({"messages": [{"role": "user", "content": format!("an {EMAIL}")}]}),
    )
    .unwrap();
    let at = first.find("<EMAIL_").unwrap();
    let session_token = &first[at..at + first[at..].find('>').unwrap() + 1];
    let text = format!("Kunde {DS_TOKEN} wohnt in Wien, Mail {session_token}.");
    let body = json!({"messages": [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_01D7FLrfh4GYq7yT1ULmeyqw", "content": text}]}]});
    let out = run(&sh, &s, Wire::Messages, &body).unwrap();
    assert!(out.contains(&text), "{out}");
    // Provenance (decision 12): the dataset mapping never enters the session.
    s.with_context(|c| {
        assert!(c.original(DS_TOKEN).is_none());
        assert!(c.entries().all(|(_, o)| o != NAME));
    });
}

/// Spec §15 test 6, review I3 and the identity ruling.
#[test]
fn dictionary_keeps_tokens_without_the_cache_and_seeds_identity() {
    let host = FakeHost::with_identity("Pellqwyn Yrsabel", "pellqwyn@example.invalid");
    let sh = shared(Arc::clone(&host));
    let st = store();
    let s = st.get(SessionKey([5; 32]));
    let first = run(&sh, &s, Wire::Messages, &json!({"messages": [{"role": "user", "content": format!("mail {EMAIL} from Pellqwyn Yrsabel")}]})).unwrap();
    assert!(!first.contains("Pellqwyn"), "identity tokenized: {first}");
    s.cache().clear(); // the seed and the cache are gone
    let again = run(&sh, &s, Wire::Messages, &json!({"messages": [{"role": "user", "content": format!("an ungewohnter Stelle: {EMAIL}")}]})).unwrap();
    let tok = |t: &str| {
        t.split('<')
            .nth(1)
            .map(|x| x.split('>').next().unwrap().to_string())
    };
    assert!(first.contains("<EMAIL_") && again.contains("<EMAIL_"));
    assert_eq!(
        tok(&first[first.find("<EMAIL_").unwrap()..]),
        tok(&again[again.find("<EMAIL_").unwrap()..]),
        "same session token"
    );
}

/// Spec §15 test 9, review I8.
#[test]
fn tool_input_keys_and_nested_values_are_blocks() {
    let host = FakeHost::new();
    let sh = shared(Arc::clone(&host));
    let st = store();
    let s = st.get(SessionKey([6; 32]));
    let body = json!({"messages": [{"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_01D7FLrfh4GYq7yT1ULmeyqw", "name": "n", "input": {EMAIL: {"deep": [EMAIL, 7, true]}}}]}]});
    let out = run(&sh, &s, Wire::Messages, &body).unwrap();
    clean(&out);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let input = &v["messages"][0]["content"][0]["input"];
    let (k, inner) = input.as_object().unwrap().iter().next().unwrap();
    assert!(k.starts_with("<EMAIL_"));
    assert!(inner["deep"][0].as_str().unwrap().starts_with("<EMAIL_"));
    assert_eq!(inner["deep"][1], 7);
    assert_eq!(inner["deep"][2], true);
}

/// Spec §15 test 7, review I4: cache hits stop being hits when their
/// dataset token no longer resolves.
#[test]
fn a_forgotten_dataset_token_turns_a_hit_into_a_miss() {
    let host = FakeHost::new();
    let sh = shared(Arc::clone(&host));
    let st = store();
    let s = st.get(SessionKey([7; 32]));
    let body =
        json!({"messages": [{"role": "user", "content": format!("{NAME} ruft an")}]}).to_string();
    let p = prep(&sh, &s, Wire::Messages, body.as_bytes()).unwrap();
    assert!(
        String::from_utf8(p.body.clone())
            .unwrap()
            .contains(DS_TOKEN)
    );
    commit(&s, p);
    let hit = prep(&sh, &s, Wire::Messages, body.as_bytes()).unwrap();
    assert_eq!(
        (hit.hits, hit.misses),
        (1, 0),
        "a committed leaf hits while its token resolves"
    );
    host.forget(DS_TOKEN);
    let p2 = prep(&sh, &s, Wire::Messages, body.as_bytes()).unwrap();
    assert_eq!((p2.hits, p2.misses), (0, 1));
    let out = String::from_utf8(p2.body).unwrap();
    // The fake engine has no NER, so the forgotten name itself is not
    // detected again here; what matters is that the stale token is gone.
    assert!(!out.contains(DS_TOKEN), "{out}");
}

/// Cache correctness: a committed history is forwarded byte-identical from
/// the cache with no engine pass (the engine is not even available).
#[test]
fn committed_history_hits_without_the_engine() {
    let host = FakeHost::new();
    let sh = shared(Arc::clone(&host));
    let st = store();
    let s = st.get(SessionKey([8; 32]));
    let body = json!({"system": format!("Kontakt {EMAIL}"), "messages": [
        {"role": "user", "content": format!("{NAME} schreibt")},
        {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_01D7FLrfh4GYq7yT1ULmeyqw", "name": "n", "input": {"to": EMAIL}}]}
    ]})
    .to_string();
    let first = prep(&sh, &s, Wire::Messages, body.as_bytes()).unwrap();
    assert_eq!(first.missed.len(), first.inserts.len());
    let first_body = first.body.clone();
    commit(&s, first);
    *host.fail_engine.lock().unwrap() = true;
    let again = prep(&sh, &s, Wire::Messages, body.as_bytes()).unwrap();
    assert_eq!(again.body, first_body);
    assert_eq!(again.misses, 0);
    assert!(
        again.inserts.is_empty() && again.missed.is_empty(),
        "hits are not journaled or re-inserted"
    );
    // A cache entry is per wire format and leaf class: another wire misses.
    let chat = json!({"messages": [{"role": "user", "content": format!("{NAME} schreibt")}]});
    assert_eq!(
        run(&sh, &s, Wire::Chat, &chat).unwrap_err(),
        Fail::ModelUnavailable
    );
}

/// Review I1: a detector error is `503 model_unavailable`, never a placeholder or a memo.
#[test]
fn a_detector_error_is_unavailability_not_a_verdict() {
    let host = FakeHost::new();
    let sh = shared(Arc::clone(&host));
    let st = store();
    let s = st.get(SessionKey([10; 32]));
    *host.mode.lock().unwrap() = Mode::DetectorError;
    let user = json!({"messages": [{"role": "user", "content": "hallo"}]});
    assert_eq!(
        run(&sh, &s, Wire::Messages, &user).unwrap_err(),
        Fail::ModelUnavailable
    );
    let tool = json!({"messages": [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_01D7FLrfh4GYq7yT1ULmeyqw", "content": "hallo"}]}]});
    assert_eq!(
        run(&sh, &s, Wire::Messages, &tool).unwrap_err(),
        Fail::ModelUnavailable,
        "not withheld"
    );
    *host.mode.lock().unwrap() = Mode::Normal;
    assert!(
        run(&sh, &s, Wire::Messages, &tool)
            .unwrap()
            .contains("hallo"),
        "nothing was memoized"
    );
}

/// Spec §15 test 4, review C4 and I2: an uncertain user message refuses with 451 (uncertain).
#[test]
fn an_uncertain_user_message_is_refused() {
    let host = FakeHost::new();
    let sh = shared(Arc::clone(&host));
    let st = store();
    let s = st.get(SessionKey([11; 32]));
    *host.mode.lock().unwrap() = Mode::Uncertain;
    match run(
        &sh,
        &s,
        Wire::Messages,
        &json!({"messages": [{"role": "user", "content": "Grauzone kam"}]}),
    )
    .unwrap_err()
    {
        Fail::PrivacyBlock { uncertain, .. } => assert!(uncertain),
        f => panic!("expected 451, got {f:?}"),
    }
}

/// Review I2 and Review Focus 1: a verifier-blocked text tool result is
/// withheld; resends are byte-identical and add no withheld entry. The
/// leaves of a withheld group are neither cached nor journaled.
#[test]
fn a_blocked_text_tool_result_resends_byte_identical() {
    let host = FakeHost::new();
    let sh = shared(Arc::clone(&host));
    let st = store();
    let s = st.get(SessionKey([12; 32]));
    *host.mode.lock().unwrap() = Mode::Block;
    let body = json!({"messages": [
        {"role": "user", "content": "schau nach"},
        {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_01D7FLrfh4GYq7yT1ULmeyqw", "name": "grep", "input": {}}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_01D7FLrfh4GYq7yT1ULmeyqw", "content": [
            {"type": "text", "text": "erste Zeile"},
            {"type": "text", "text": "Sperrwort steht hier"}
        ]}]}
    ]})
    .to_string();
    let first = prep(&sh, &s, Wire::Messages, body.as_bytes()).unwrap();
    assert_eq!(first.withheld.len(), 1);
    assert_eq!(first.memo.len(), 1);
    assert_eq!(
        first.inserts.len(),
        1,
        "only the user text, not the withheld group's leaves"
    );
    assert!(first.missed.iter().all(|m| !m.contains("erste Zeile")));
    let out1 = String::from_utf8(first.body.clone()).unwrap();
    assert!(
        out1.contains("[inumaki: tool result withheld (kinds: PERSON). Nothing was sent.]")
            && !out1.contains("Sperrwort"),
        "{out1}"
    );
    assert!(
        !out1.contains("erste Zeile"),
        "the whole group is withheld: {out1}"
    );
    let first_body = first.body.clone();
    commit(&s, first);
    for _ in 0..2 {
        let again = prep(&sh, &s, Wire::Messages, body.as_bytes()).unwrap();
        assert_eq!(again.body, first_body, "byte-identical resend");
        assert!(
            again.withheld.is_empty() && again.memo.is_empty(),
            "the memo answers; nothing new is withheld or recorded"
        );
    }
}

/// A clear value in a scanned field inside a tool result (a `search_result`
/// source) withholds that tool result instead of refusing the request, so
/// it cannot block every later turn.
#[test]
fn a_clear_value_scanned_inside_a_tool_result_is_withheld_not_refused() {
    let host = FakeHost::new();
    let sh = shared(Arc::clone(&host));
    let st = store();
    let s = st.get(SessionKey([13; 32]));
    let body = json!({"messages": [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_01D7FLrfh4GYq7yT1ULmeyqw", "content": [
        {"type": "search_result", "source": format!("https://example.invalid/{NAME}"), "title": "t", "content": [{"type": "text", "text": "x"}]}
    ]}]}]});
    let p = prep(&sh, &s, Wire::Messages, body.to_string().as_bytes()).unwrap();
    let out = String::from_utf8(p.body).unwrap();
    clean(&out);
    assert!(
        out.contains("[inumaki: tool result withheld (kinds: PERSON). Nothing was sent.]"),
        "{out}"
    );
    assert_eq!(p.withheld[0].2, vec!["ClearValue".to_string()]);
}

/// Privacy: `Debug` of the pipeline's and the upstream seam's types and
/// every error message carry no request text.
#[test]
fn debug_and_errors_carry_no_text() {
    let host = FakeHost::new();
    let sh = shared(Arc::clone(&host));
    let st = store();
    let s = st.get(SessionKey([14; 32]));
    let msg = format!("{NAME} {EMAIL}");
    let p = prep(
        &sh,
        &s,
        Wire::Messages,
        json!({"messages": [{"role": "user", "content": msg}]})
            .to_string()
            .as_bytes(),
    )
    .unwrap();
    let req = UpstreamRequest {
        upstream: UpstreamId::Anthropic,
        method: http::Method::POST,
        path_and_query: format!("/v1/messages?{EMAIL}"),
        headers: http::HeaderMap::new(),
        body: p.body.clone().into(),
    };
    let think = json!({"messages": [{"role": "assistant", "content": [{"type": "thinking", "thinking": msg, "signature": "s"}]}]});
    let f = run(&sh, &s, Wire::Messages, &think).unwrap_err();
    let all = format!(
        "{p:?} {req:?} {sh:?} {f:?} {} {}",
        f.message(),
        UpstreamError::Unreachable
    );
    for needle in [NAME, EMAIL, "<PERSON_", "<EMAIL_", "Zyxwuria"] {
        assert!(!all.contains(needle), "{needle} in {all}");
    }
}

/// Fix round 1 (spec §5.4, §6.4): a scanned block holding a known value of
/// a kind the profile preserves is not refused; a non-preserved one is.
#[test]
fn scanned_blocks_skip_preserved_kinds() {
    let host = FakeHost::new();
    let url = "https://zyxwuria.example.invalid/akte";
    host.dataset.lock().unwrap().insert(
        "<URL_d1d1d1>".into(),
        (inumaki_core::span::EntityKind::Url, url.into()),
    );
    let sh = shared(Arc::clone(&host));
    let st = store();
    let s = st.get(SessionKey([15; 32]));
    let dict = crate::pipeline::ChatDict::new(&sh, s.closure_dict().unwrap()).unwrap();
    let text = format!("see {url} now");
    assert!(
        !dict.host_spans(&text, true).unwrap().is_empty(),
        "the dictionary knows the URL"
    );
    let think = |t: String| json!({"messages": [{"role": "assistant", "content": [{"type": "thinking", "thinking": t, "signature": "s"}]}]});
    let out = run(&sh, &s, Wire::Messages, &think(text.clone())).unwrap();
    assert!(out.contains(&text), "preserved kind, unchanged: {out}");
    assert!(matches!(
        run(&sh, &s, Wire::Messages, &think(format!("{text} {NAME}"))).unwrap_err(),
        Fail::PrivacyBlock { .. }
    ));
}

/// Final review I-1 (recall): the first pass reports every overlapping
/// identity match. A longer identity value of a preserved kind (ORGANIZATION)
/// must not hide a shorter, non-preserved one (PERSON) it overlaps.
#[test]
fn first_pass_redacts_an_identity_value_overlapped_by_a_preserved_one() {
    use inumaki_core::config::CoreConfig;
    use inumaki_core::span::EntityKind;
    let cfg = CoreConfig::from_toml(crate::testing::CFG_ORG_PRESERVED).unwrap();
    let policy = cfg.resolve_profile("fast").unwrap();
    let mut h = Arc::into_inner(FakeHost::new()).unwrap();
    h.identity = vec![
        (EntityKind::Organization, "Qorvex Brandl Beratung".into()),
        (EntityKind::Person, "Qorvex Brandl".into()),
    ];
    let sh = shared(Arc::new(h));
    let st = store();
    let s = st.get(SessionKey([17; 32]));
    let dict = crate::pipeline::ChatDict::new(&sh, s.closure_dict().unwrap()).unwrap();
    let text = "Bitte Qorvex Brandl Beratung anrufen.";
    let reds = dict.redactions(&policy, text).unwrap();
    let start = text.find("Qorvex").unwrap();
    assert!(
        reds.iter()
            .any(|r| r.start == start && r.end == start + "Qorvex Brandl".len()),
        "the shorter PERSON value is redacted: {}",
        reds.len()
    );
}

/// Fix round 1, decision 17 (recall): scanned keys under an unknown
/// parameter are ordinary data, so a validated identifier there is tokenized.
#[test]
fn scanned_keys_under_an_unknown_parameter_are_sanitized() {
    let host = FakeHost::new();
    let sh = shared(Arc::clone(&host));
    let st = store();
    let s = st.get(SessionKey([16; 32]));
    let msgs = json!({
        "unknown_param": {
            "cited_text": IBAN,
            "citations": [{"type": "char_location", "cited_text": IBAN}],
            "content": [{"type": "thinking", "thinking": IBAN}, {"type": "search_result", "source": IBAN}]
        },
        "messages": [{"role": "user", "content": "hallo"}]
    });
    let out = run(&sh, &s, Wire::Messages, &msgs).unwrap();
    clean(&out);
    assert_eq!(out.matches("<IBAN_").count(), 4, "{out}");
    let resp = json!({
        "unknown_param": {"type": "summary_text", "text": IBAN, "summary": [{"type": "summary_text", "text": IBAN}]},
        "input": [{"type": "message", "role": "user", "content": "hallo"}]
    });
    let out = run(&sh, &s, Wire::Responses, &resp).unwrap();
    clean(&out);
    assert_eq!(out.matches("<IBAN_").count(), 2, "{out}");
}

/// The real scanned positions (spec §5.2, decision 14): never changed; a
/// known original in clear refuses the request with 451 `ClearValue`; any
/// other text, a validated identifier included, is forwarded as received,
/// because the scan checks known originals only (the chat dictionary, §5.4)
/// and the bytes must stay as the provider signed or cited them.
#[test]
fn real_scanned_positions_refuse_known_values_and_are_never_changed() {
    let host = FakeHost::new();
    let sh = shared(Arc::clone(&host));
    let st = store();
    let s = st.get(SessionKey([17; 32]));
    let citation = |t: &str| {
        json!({"messages": [{"role": "assistant", "content": [
            {"type": "text", "text": "siehe", "citations": [{"type": "char_location", "cited_text": t}]}
        ]}]})
    };
    let summary = |t: &str| json!({"input": [{"type": "reasoning", "id": "rs_68af2f9b1c3c8190b0e4e2d5f6a7b8c9", "summary": [{"type": "summary_text", "text": t}]}]});
    for (wire, body) in [
        (Wire::Messages, citation(&format!("von {NAME}"))),
        (Wire::Responses, summary(&format!("von {NAME}"))),
    ] {
        match run(&sh, &s, wire, &body).unwrap_err() {
            Fail::PrivacyBlock {
                kinds,
                checks,
                uncertain,
            } => {
                assert_eq!(
                    (kinds, checks, uncertain),
                    (
                        vec!["PERSON".to_string()],
                        vec!["ClearValue".to_string()],
                        false
                    )
                );
            }
            f => panic!("expected 451, got {f:?}"),
        }
    }
    for (wire, body) in [
        (Wire::Messages, citation(IBAN)),
        (Wire::Responses, summary(IBAN)),
    ] {
        let b = body.to_string();
        let p = prep(&sh, &s, wire, b.as_bytes()).unwrap();
        assert_eq!(
            p.body,
            b.into_bytes(),
            "scanned text is forwarded as received"
        );
    }
}

/// Task 7 follow-up, decision 17 (recall): opaque signed keys under an
/// unknown parameter are sanitized; at their real positions they are
/// forwarded as received.
#[test]
fn opaque_signed_keys_are_untouched_only_at_real_positions() {
    let host = FakeHost::new();
    let sh = shared(Arc::clone(&host));
    let st = store();
    let s = st.get(SessionKey([18; 32]));
    let blocks = |v: &str| {
        json!([
            {"type": "thinking", "thinking": "t", "signature": v},
            {"type": "redacted_thinking", "data": v},
            {"type": "web_search_tool_result", "tool_use_id": "srvtoolu_014hJH82Qum7Td6UV8gDXThB", "content": [
                {"type": "web_search_result", "url": "https://example.invalid", "title": "t", "encrypted_content": v}
            ]},
            {"type": "text", "text": "x", "citations": [
                {"type": "web_search_result_location", "url": "https://example.invalid", "title": "t", "encrypted_index": v, "cited_text": "c"}
            ]}
        ])
    };
    let leak = json!({
        "unknown_param": {"content": blocks(EMAIL), "signature": EMAIL},
        "messages": [{"role": "user", "content": "hallo"}]
    });
    let out = run(&sh, &s, Wire::Messages, &leak).unwrap();
    clean(&out);
    assert_eq!(out.matches("<EMAIL_").count(), 5, "{out}");
    let resp = json!({
        "unknown_param": {"type": "reasoning", "encrypted_content": EMAIL},
        "input": [{"type": "message", "role": "user", "content": "hallo"}]
    });
    clean(&run(&sh, &s, Wire::Responses, &resp).unwrap());
    // Real positions: opaque, forwarded as received.
    let blob = "EpQBCkYIBxgCKkB+opaque/blob==";
    let real = json!({"messages": [{"role": "assistant", "content": blocks(blob)}]}).to_string();
    let p = prep(&sh, &s, Wire::Messages, real.as_bytes()).unwrap();
    assert_eq!(p.body, real.into_bytes());
    let real = json!({"input": [{"type": "reasoning", "id": "rs_68af2f9b1c3c8190b0e4e2d5f6a7b8c9", "summary": [], "encrypted_content": blob}]}).to_string();
    let p = prep(&sh, &s, Wire::Responses, real.as_bytes()).unwrap();
    assert_eq!(p.body, real.into_bytes());
}

/// Ruling 2026-10-05: real API ids, enums, models, and media types are
/// forwarded byte-identical through the pipeline; only the data changes.
#[test]
fn real_api_ids_and_enums_are_forwarded_byte_identical() {
    let host = FakeHost::new();
    let sh = shared(Arc::clone(&host));
    let st = store();
    let s = st.get(SessionKey([19; 32]));
    let mail = format!("schreib an {EMAIL}");
    let msgs = json!({
        "model": "claude-sonnet-4-5", "max_tokens": 1024,
        "messages": [
            {"role": "user", "content": [
                {"type": "image", "source": {"type": "url", "url": "https://x.invalid/a.png", "media_type": "image/png"}},
                {"type": "text", "text": mail, "cache_control": {"type": "ephemeral"}}
            ]},
            {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_01A09q90qw90lq917835lq9", "name": "Read", "input": {"file_path": "/tmp/a"}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_01A09q90qw90lq917835lq9", "content": "ok"}]}
        ]
    });
    let resp = json!({
        "model": "gpt-5.1-codex", "previous_response_id": "resp_68af2f9a2b5c8190a1b2c3d4e5f6a7b8",
        "reasoning": {"effort": "high"}, "text": {"verbosity": "low"},
        "input": [
            {"type": "message", "role": "developer", "content": [{"type": "input_text", "text": mail}]},
            {"type": "reasoning", "id": "rs_68af2f9b1c3c8190b0e4e2d5f6a7b8c9", "summary": []},
            {"type": "function_call", "id": "fc_68af2f9e7d4c8190a5a7c5e1b3f0e2d1", "call_id": "call_DdmO9pD3xa9XTPNJ32zg2hcA", "name": "shell", "arguments": "{}", "status": "completed"},
            {"type": "function_call_output", "call_id": "call_DdmO9pD3xa9XTPNJ32zg2hcA", "output": "ok"}
        ]
    });
    let chat = json!({
        "model": "gpt-5.1",
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": mail}, {"type": "image_url", "image_url": {"url": "https://x.invalid/a.png", "detail": "high"}}]},
            {"role": "assistant", "tool_calls": [{"id": "call_DdmO9pD3xa9XTPNJ32zg2hcA", "type": "function", "function": {"name": "f", "arguments": "{}"}}]},
            {"role": "tool", "tool_call_id": "call_DdmO9pD3xa9XTPNJ32zg2hcA", "content": "ok"}
        ]
    });
    let mut cfg_binary = shared(Arc::clone(&host));
    cfg_binary.cfg.binary = crate::config::BinaryMode::Forward; // the image URL part is binary content
    for (sh, wire, body) in [
        (&cfg_binary, Wire::Messages, msgs),
        (&sh, Wire::Responses, resp),
        (&cfg_binary, Wire::Chat, chat),
    ] {
        let input = body.to_string();
        let out = String::from_utf8(prep(sh, &s, wire, input.as_bytes()).unwrap().body).unwrap();
        let at = out.find("<EMAIL_").expect("the email is tokenized");
        let token = &out[at..at + out[at..].find('>').unwrap() + 1];
        assert_eq!(
            out.replace(token, EMAIL),
            input,
            "{wire:?}: only the data changed"
        );
    }
}

/// The leak closure (step 6b, always on): a detector that
/// fires on one leaf only. `Word` matches case-sensitively, so a capitalised
/// copy or a lone name part in another leaf is missed there, while the
/// leak check searches every case and every name part.
mod closure {
    use super::*;
    use crate::testing::{CFG, Word};
    use inumaki_core::config::CoreConfig;
    use inumaki_core::engine::Engine;

    const FULL: &str = "Qorvex Brandl";

    fn host(needle: &'static str) -> Arc<FakeHost> {
        let mut h = Arc::into_inner(FakeHost::new()).unwrap();
        let cfg = CoreConfig::from_toml(CFG).unwrap();
        h.engine = Arc::new(
            Engine::from_config(&cfg, "fast", None, None)
                .unwrap()
                .with_detector(Arc::new(Word(needle, Some(0.95)))),
        );
        Arc::new(h)
    }

    fn body(first: &str, second: &str) -> serde_json::Value {
        json!({"messages": [
            {"role": "user", "content": first},
            {"role": "assistant", "content": "ok"},
            {"role": "user", "content": second}
        ]})
    }

    /// No part of the name, in any case, word-bounded or not.
    fn no_clear(out: &str) {
        let low = out.to_lowercase();
        for c in ["qorvex", "brandl", "qoervex", "braendl"] {
            assert!(!low.contains(c), "{c} left in clear: {out}");
        }
    }

    /// The critical property: no original minted by the request stays in
    /// clear in any forwarded leaf, in either order, for a full copy, a
    /// name part, and a transliterated copy. Without the closure, A-then-B
    /// refused (Leak) and B-then-A forwarded the copy in clear: commit
    /// 328f61d asserts both, with the closure switched off.
    #[test]
    fn no_minted_original_left_in_clear_in_either_order() {
        let mut key = 40u8;
        for (needle, b) in [
            (FULL, "Gruss an QORVEX BRANDL."),
            (FULL, "Gruss an Brandl, bitte."),
            ("Qörvex Brändl", "Gruss an Qoervex Braendl."),
        ] {
            let a = format!("Bitte {needle} heute anrufen.");
            for flipped in [false, true] {
                let req = if flipped { body(b, &a) } else { body(&a, b) };
                let sh = shared(host(needle));
                let st = store();
                key += 1;
                let out = run(&sh, &st.get(SessionKey([key; 32])), Wire::Messages, &req)
                    .unwrap_or_else(|f| panic!("{b:?} flipped={flipped}: refused {f:?}"));
                no_clear(&out);
                let v: serde_json::Value = serde_json::from_str(&out).unwrap();
                let texts: Vec<&str> = [0, 2]
                    .iter()
                    .map(|i| v["messages"][i]["content"].as_str().unwrap())
                    .collect();
                assert!(
                    texts.iter().all(|t| t.contains("<PERSON_")),
                    "both leaves carry a person token: {texts:?}"
                );
            }
        }
    }

    /// Fail closed: what the closure does not settle still refuses. With no
    /// round to spend (budget 0), the leaf sent with a later-minted original
    /// in clear (B first) refuses; a policy block is never deferred.
    ///
    /// A first needs no closure round any more: the engine's
    /// referential-consistency pass (L3 step 2, Task 4) tokenizes the part
    /// in B with A's entity before verification, so it passes with budget 0
    /// and nothing in clear.
    #[test]
    fn an_unsettled_leak_and_a_policy_block_still_refuse() {
        let mut sh = shared(host(FULL));
        sh.closure = 0;
        let st = store();
        let a = format!("Bitte {FULL} heute anrufen.");
        match run(
            &sh,
            &st.get(SessionKey([61; 32])),
            Wire::Messages,
            &body("Gruss an Brandl, bitte.", &a),
        )
        .unwrap_err()
        {
            Fail::PrivacyBlock { checks, kinds, .. } => {
                assert_eq!(checks, vec!["Leak".to_string()]);
                assert_eq!(kinds, vec!["PERSON".to_string()]);
            }
            f => panic!("expected the leak refusal, got {f:?}"),
        }
        // A first: settled by the engine itself, in the same entity.
        let out = run(
            &sh,
            &st.get(SessionKey([60; 32])),
            Wire::Messages,
            &body(&a, "Gruss an Brandl, bitte."),
        )
        .unwrap_or_else(|f| panic!("A first: refused {f:?}"));
        no_clear(&out);

        let h = FakeHost::new();
        let sh = shared(Arc::clone(&h));
        *h.mode.lock().unwrap() = Mode::Block;
        match run(
            &sh,
            &st.get(SessionKey([70; 32])),
            Wire::Messages,
            &body("ask Sperrwort today", "ok then"),
        )
        .unwrap_err()
        {
            Fail::PrivacyBlock { checks, .. } => assert!(checks.contains(&"Policy".to_string())),
            f => panic!("expected the policy refusal, got {f:?}"),
        }
    }

    /// A cached leaf is re-scanned: turn 1 forwards H with a name part in
    /// clear (nothing knew the name then) and caches it; turn 2 adds a leaf
    /// that mints the full name. H's cached text must not be resent: it is
    /// re-run from its original text (a miss, not a hit) and its cache
    /// entry replaced. With budget 0 turn 2 refuses.
    #[test]
    pub(super) fn a_cached_leaf_with_a_later_minted_name_part_is_re_run() {
        let h_text = "Gruss an Brandl, bitte.";
        let turn1 = json!({"messages": [{"role": "user", "content": h_text}]});
        let a = format!("Bitte {FULL} heute anrufen.");
        let turn2 = json!({"messages": [
            {"role": "user", "content": h_text},
            {"role": "assistant", "content": "ok"},
            {"role": "user", "content": a}
        ]});
        let bytes = |v: &serde_json::Value| v.to_string().into_bytes();
        let st = store();
        for (n, budget) in [(0u8, 4usize), (1, 0)] {
            let mut sh = shared(host(FULL));
            sh.closure = budget;
            let s = st.get(SessionKey([80 + n; 32]));
            let p = prep(&sh, &s, Wire::Messages, &bytes(&turn1)).unwrap();
            assert!(
                String::from_utf8_lossy(&p.body).contains("Brandl"),
                "turn 1 forwards the part in clear (nothing knew it)"
            );
            commit(&s, p);
            let p = prep(&sh, &s, Wire::Messages, &bytes(&turn2));
            if budget == 0 {
                match p.unwrap_err() {
                    Fail::PrivacyBlock { checks, kinds, .. } => {
                        assert_eq!(checks, vec!["Leak".to_string()]);
                        assert_eq!(kinds, vec!["PERSON".to_string()]);
                    }
                    f => panic!("expected the leak refusal, got {f:?}"),
                }
                continue;
            }
            let p = p.unwrap();
            assert_eq!(p.hits, 0, "the cached leaf was re-run, not served");
            let out = String::from_utf8(p.body.clone()).unwrap();
            no_clear(&out);
            let v: serde_json::Value = serde_json::from_str(&out).unwrap();
            assert!(
                v["messages"][0]["content"]
                    .as_str()
                    .unwrap()
                    .contains("<PERSON_"),
                "H carries the person token: {out}"
            );
            commit(&s, p);
            // Turn 3, the same body: every leaf a hit, from replaced entries.
            let p = prep(&sh, &s, Wire::Messages, &bytes(&turn2)).unwrap();
            assert_eq!(p.misses, 0);
            no_clear(&String::from_utf8(p.body).unwrap());
        }
    }

    /// Task 7d (ruling L56): a minted value that is only a greeting word
    /// identifies no one, so it opens no cached leaf: H (cached on turn 1,
    /// holding the word in clear) is served from the cache on turn 2. A
    /// greeting next to a name (`Hallo Anna`) is a real value and still
    /// re-runs H, which then carries the person token.
    #[test]
    pub(super) fn a_greeting_only_mint_reruns_no_cached_leaf_but_greeting_and_name_does() {
        let st = store();
        for (n, needle, h_text, rerun) in [
            (0u8, "Hello", "hello, the invoice is attached.", false),
            (1, "Hallo Anna", "hallo anna, die Rechnung anbei.", true),
        ] {
            let sh = shared(host(needle));
            let s = st.get(SessionKey([100 + n; 32]));
            let turn1 = json!({"messages": [{"role": "user", "content": h_text}]});
            let p = prep(&sh, &s, Wire::Messages, turn1.to_string().as_bytes()).unwrap();
            commit(&s, p);
            let turn2 = body(h_text, &format!("{needle}, bitte heute anrufen."));
            let p = prep(&sh, &s, Wire::Messages, turn2.to_string().as_bytes())
                .unwrap_or_else(|f| panic!("case {n} refused {f:?}"));
            let out: serde_json::Value = serde_json::from_slice(&p.body).unwrap();
            let h = out["messages"][0]["content"].as_str().unwrap().to_string();
            if rerun {
                assert_eq!(p.hits, 0, "case {n}: H was re-run, not served");
                assert!(h.contains("<PERSON_"), "case {n}: H carries the token");
            } else {
                assert_eq!(p.hits, 1, "case {n}: H was served from the cache");
                assert_eq!(h, h_text, "case {n}: H unchanged");
            }
        }
    }

    /// Review finding 1: the session holds the name as an ORGANIZATION and
    /// this request mints it as a PERSON. The PERSON entry is new (its name
    /// parts are searched), so B, sent first with a part in clear, is re-run.
    #[test]
    fn a_value_minted_under_a_new_kind_counts_as_added() {
        let sh = shared(host(FULL));
        let st = store();
        let s = st.get(SessionKey([90; 32]));
        s.with_context(|c| c.token_for(&inumaki_core::span::EntityKind::Organization, FULL))
            .unwrap();
        let req = body(
            "Gruss an Brandl, bitte.",
            &format!("Bitte {FULL} heute anrufen."),
        );
        let out = run(&sh, &s, Wire::Messages, &req).unwrap_or_else(|f| panic!("refused {f:?}"));
        no_clear(&out);
    }

    /// Review finding 2: a scanned leaf (a search result's source) cannot be
    /// rewritten; a value another leaf of the request mints, in clear there,
    /// refuses the request (or withholds a tool result), never goes out.
    #[test]
    fn a_scanned_leaf_with_a_value_minted_later_is_never_forwarded() {
        let sh = shared(host(FULL));
        let st = store();
        let text = format!("Bitte {FULL} heute anrufen.");
        let user = json!({"messages": [{"role": "user", "content": [
            {"type": "search_result", "source": "crm://kontakte/brandl", "title": "t",
             "content": [{"type": "text", "text": text}]}
        ]}]});
        match run(&sh, &st.get(SessionKey([91; 32])), Wire::Messages, &user) {
            Err(Fail::PrivacyBlock { checks, kinds, .. }) => {
                assert_eq!(checks, vec!["Leak".to_string()]);
                assert_eq!(kinds, vec!["PERSON".to_string()]);
            }
            other => panic!("expected the leak refusal, got {other:?}"),
        }
        let tool = json!({"messages": [
            {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_01Hn4Bq9xL2mZ8cVt5sKpR3w", "name": "crm", "input": {}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_01Hn4Bq9xL2mZ8cVt5sKpR3w", "content": [
                {"type": "search_result", "source": "crm://kontakte/brandl", "title": "t",
                 "content": [{"type": "text", "text": text}]}
            ]}]}
        ]});
        let out = run(&sh, &st.get(SessionKey([92; 32])), Wire::Messages, &tool)
            .unwrap_or_else(|f| panic!("a tool result is withheld, not refused: {f:?}"));
        no_clear(&out);
    }

    /// Re-review finding A: the engine (a retry profile, here the test's
    /// own) tokenizes a URL the host policy preserves; the store then holds
    /// it, and a scanned copy of it in clear (a search result's source,
    /// which cannot be rewritten) must refuse, not pass as "preserved".
    #[test]
    fn a_scanned_leaf_with_a_minted_preserved_kind_is_never_forwarded() {
        const TOKENIZES_URL: &str = r#"
            [profiles.fast]
            default_action = "tokenize"
            default_min_confidence = 0.5
            escalate_below = 0.5
            [profiles.fast.entities.SECRET]
            action = "remove"
            min_confidence = 0.0
            [profiles.fast.verifier]
            on_uncertain = "block"
            allow_no_ner = true
        "#;
        let mut h = Arc::into_inner(FakeHost::new()).unwrap();
        let cfg = CoreConfig::from_toml(TOKENIZES_URL).unwrap();
        h.engine = Arc::new(Engine::from_config(&cfg, "fast", None, None).unwrap());
        let sh = shared(Arc::new(h));
        let st = store();
        let url = "https://crm.qorvex.at/k/4711";
        let req = json!({"messages": [{"role": "user", "content": [
            {"type": "search_result", "source": url, "title": "t",
             "content": [{"type": "text", "text": format!("Siehe {url} bitte.")}]}
        ]}]});
        match run(&sh, &st.get(SessionKey([93; 32])), Wire::Messages, &req) {
            Err(Fail::PrivacyBlock { checks, kinds, .. }) => {
                assert_eq!(checks, vec!["Leak".to_string()]);
                assert_eq!(kinds, vec!["URL".to_string()]);
            }
            other => panic!("expected the leak refusal, got {other:?}"),
        }
    }

    /// Review finding 5: a value one leaf REMOVED (the engine's profile
    /// removes PERSON here while the host policy, the closure's, would
    /// tokenize it) recurs in a leaf the detector misses. The closure must
    /// remove that copy too, never mint a restorable token for it, in
    /// either order.
    #[test]
    pub(super) fn a_removed_value_is_re_run_as_a_removal() {
        const REMOVES_PERSON: &str = r#"
            [profiles.fast]
            default_action = "tokenize"
            default_min_confidence = 0.5
            escalate_below = 0.5
            [profiles.fast.entities.PERSON]
            action = "remove"
            min_confidence = 0.0
            [profiles.fast.entities.SECRET]
            action = "remove"
            min_confidence = 0.0
            [profiles.fast.verifier]
            on_uncertain = "block"
            allow_no_ner = true
        "#;
        let a = format!("Bitte {FULL} heute anrufen.");
        let b = "Gruss an QORVEX BRANDL.";
        let restorable = regex::Regex::new(r"<PERSON_[0-9a-f]+>").unwrap();
        for (n, req) in [body(&a, b), body(b, &a)].iter().enumerate() {
            let mut h = Arc::into_inner(FakeHost::new()).unwrap();
            let cfg = CoreConfig::from_toml(REMOVES_PERSON).unwrap();
            h.engine = Arc::new(
                Engine::from_config(&cfg, "fast", None, None)
                    .unwrap()
                    .with_detector(Arc::new(Word(FULL, Some(0.95)))),
            );
            let sh = shared(Arc::new(h));
            let st = store();
            let out = run(
                &sh,
                &st.get(SessionKey([94 + n as u8; 32])),
                Wire::Messages,
                req,
            )
            .unwrap_or_else(|f| panic!("order {n}: refused {f:?}"));
            no_clear(&out);
            assert!(
                !restorable.is_match(&out),
                "order {n}: a restorable token: {out}"
            );
            assert_eq!(
                out.matches("<PERSON_REMOVED>").count(),
                2,
                "order {n}: {out}"
            );
        }
    }

    /// R2 (Review Focus 5): a scanned leaf (a search result's source,
    /// which cannot be rewritten) holding, in clear, any closure form of a
    /// value the store holds refuses the request on every turn: a name
    /// part, a transliterated name part, a value of a kind the policy
    /// preserves, a removed value; and a host value whose kind the policy
    /// preserves but which is an identifier-shaped ORGANIZATION (I2). The
    /// store is seeded directly, standing for a refused request or a
    /// subagent on the same session. Inside a tool result the result is
    /// withheld instead.
    #[test]
    fn a_scanned_leaf_with_any_store_form_is_never_forwarded() {
        use crate::testing::CFG_ORG_PRESERVED;
        use inumaki_core::span::EntityKind;
        type Seed = Box<dyn Fn(&Session)>;
        let org_host = || {
            let mut h = Arc::into_inner(FakeHost::new()).unwrap();
            let cfg = CoreConfig::from_toml(CFG_ORG_PRESERVED).unwrap();
            h.policy = Arc::new(cfg.resolve_profile("fast").unwrap());
            h.dataset.lock().unwrap().insert(
                "<ORGANIZATION_d2d2d2>".into(),
                (EntityKind::Organization, "K-482913".into()),
            );
            Arc::new(h)
        };
        let person = |v: &'static str| -> Seed {
            Box::new(move |s: &Session| {
                s.with_context(|c| c.token_for(&EntityKind::Person, v))
                    .unwrap();
            })
        };
        let rows: Vec<(Arc<FakeHost>, Seed, String, &str)> = vec![
            (
                FakeHost::new(),
                person("Qorvex Brandl"),
                "crm://kontakte/brandl".into(),
                "PERSON",
            ),
            (
                FakeHost::new(),
                person("Qörvex Brändl"),
                "crm://kontakte/braendl".into(),
                "PERSON",
            ),
            (
                FakeHost::new(),
                Box::new(|s: &Session| {
                    s.with_context(|c| {
                        c.token_for(&EntityKind::Url, "https://crm.qorvex.at/k/4711")
                    })
                    .unwrap();
                }),
                "https://crm.qorvex.at/k/4711".into(),
                "URL",
            ),
            (
                FakeHost::new(),
                Box::new(|s: &Session| {
                    s.with_context(|c| c.record_removed(&EntityKind::Iban, IBAN))
                }),
                format!("konto {IBAN}"),
                "IBAN",
            ),
            (
                org_host(),
                Box::new(|_: &Session| {}),
                "crm://kunden/K-482913".into(),
                "ORGANIZATION",
            ),
        ];
        let st = store();
        // Every row runs; the failures are reported together.
        let mut failed: Vec<String> = Vec::new();
        for (n, (h, seed, src, kind)) in rows.into_iter().enumerate() {
            let sh = shared(h);
            let s = st.get(SessionKey([100 + n as u8; 32]));
            seed(&s);
            let req = json!({"messages":[{"role":"user","content":[{"type":"search_result","source":src,"title":"t","content":[{"type":"text","text":"Siehe Akte."}]}]}]});
            match run(&sh, &s, Wire::Messages, &req) {
                Err(Fail::PrivacyBlock { checks, kinds, .. })
                    if checks == vec!["ClearValue".to_string()]
                        && kinds == vec![kind.to_string()] => {}
                other => failed.push(format!("row {n} ({kind}): {other:?}")),
            }
        }
        assert!(failed.is_empty(), "{failed:#?}");
        // The first row inside a tool result: withheld, not refused.
        let sh = shared(FakeHost::new());
        let s = st.get(SessionKey([110; 32]));
        person("Qorvex Brandl")(&s);
        let tool = json!({"messages": [
            {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_01Hn4Bq9xL2mZ8cVt5sKpR3w", "name": "crm", "input": {}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_01Hn4Bq9xL2mZ8cVt5sKpR3w", "content": [
                {"type": "search_result", "source": "crm://kontakte/brandl", "title": "t",
                 "content": [{"type": "text", "text": "Siehe Akte."}]}
            ]}]}
        ]});
        let out = run(&sh, &s, Wire::Messages, &tool)
            .unwrap_or_else(|f| panic!("a tool result is withheld, not refused: {f:?}"));
        assert!(out.contains("tool result withheld"), "{out}");
        assert!(!out.to_lowercase().contains("brandl"), "{out}");
    }

    /// NEEDS (a) (Review Focus 6): with no closure round to spend, the
    /// first pass alone redacts a store name part and a store value of a
    /// kind the policy preserves (a first-pass Tokenize outranks the
    /// engine's Preserve), so nothing is left for the leak check.
    #[test]
    fn the_first_pass_redacts_store_forms_without_the_closure() {
        use inumaki_core::span::EntityKind;
        let mut sh = shared(host(FULL));
        sh.closure = 0;
        let st = store();
        let s = st.get(SessionKey([111; 32]));
        s.with_context(|c| {
            c.token_for(&EntityKind::Person, FULL).unwrap();
            c.token_for(&EntityKind::Url, "https://crm.qorvex.at/k/4711")
                .unwrap();
        });
        let req = json!({"messages":[{"role":"user","content":"Gruss an Brandl, bitte. Siehe https://crm.qorvex.at/k/4711."}]});
        let out = run(&sh, &s, Wire::Messages, &req).unwrap_or_else(|f| panic!("refused {f:?}"));
        no_clear(&out);
        assert!(!out.contains("crm.qorvex.at"), "{out}");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        let content = v["messages"][0]["content"].as_str().unwrap();
        assert!(
            content.contains("<PERSON_") && content.contains("<URL_"),
            "{content}"
        );
    }

    /// The cached copy of H ("Gruss an Brandl, bitte."), resent after a
    /// later mint of the full name.
    const H: &str = "Gruss an Brandl, bitte.";

    /// Whether any part of the name is left in clear (`no_clear`'s rule).
    fn leaks(out: &str) -> bool {
        let low = out.to_lowercase();
        ["qorvex", "brandl", "qoervex", "braendl"]
            .iter()
            .any(|c| low.contains(c))
    }

    /// R1 (Review Focus 1, 2): H was forwarded and cached with "Brandl" in
    /// clear (nothing knew the name then). The full name is then minted
    /// outside any request that resends H (a refused request or a subagent
    /// on the same session id; minted here directly). A hits-only resend of
    /// H must re-scan it against what was minted since its stamp and re-run
    /// it: (a) a committed hit; (b) a seeded hit (a seed was never
    /// scanned); (d) a request prepared before the mint and committed after
    /// it (its insert claims the view's snapshot, not the store at commit).
    #[test]
    pub(super) fn a_cached_clear_copy_is_rescanned_after_an_outside_mint() {
        use crate::walk::Class;
        use inumaki_core::span::EntityKind;
        let sh = shared(host(FULL));
        let st = store();
        let bytes = |v: &serde_json::Value| v.to_string().into_bytes();
        let mint = |s: &Session| {
            s.with_context(|c| c.token_for(&EntityKind::Person, FULL))
                .unwrap();
        };
        let turn1 = json!({"messages": [{"role": "user", "content": H}]});
        let resend = body(H, "Danke.");
        // Every case runs; the failures are reported together.
        let mut failed: Vec<String> = Vec::new();

        // (a) a committed hit.
        let s = st.get(SessionKey([113; 32]));
        let p = prep(&sh, &s, Wire::Messages, &bytes(&turn1)).unwrap();
        assert!(String::from_utf8_lossy(&p.body).contains("Brandl"));
        commit(&s, p);
        mint(&s);
        match prep(&sh, &s, Wire::Messages, &bytes(&resend)) {
            Ok(p) => {
                let out = String::from_utf8(p.body.clone()).unwrap();
                let v: serde_json::Value = serde_json::from_str(&out).unwrap();
                let first = v["messages"][0]["content"].as_str().unwrap_or_default();
                if leaks(&out) || !first.contains("<PERSON_") || p.hits != 0 {
                    failed.push(format!("(a) hits={} {out}", p.hits));
                }
            }
            Err(f) => failed.push(format!("(a) refused {f:?}")),
        }

        // (b) a seeded hit, unverified.
        let s = st.get(SessionKey([114; 32]));
        crate::respond::seed_leaf(&sh, &s, Wire::Messages, Class::Text, H, H);
        mint(&s);
        let req = json!({"messages": [
            {"role": "user", "content": "Hallo"},
            {"role": "assistant", "content": H},
            {"role": "user", "content": "Danke."}
        ]});
        match run(&sh, &s, Wire::Messages, &req) {
            Ok(out) if !leaks(&out) => {}
            other => failed.push(format!("(b) {other:?}")),
        }

        // (d) the claim is taken before the mint, the commit after it.
        let s = st.get(SessionKey([115; 32]));
        let early = json!({"messages": [
            {"role": "user", "content": H},
            {"role": "assistant", "content": "ok"}
        ]});
        let p = prep(&sh, &s, Wire::Messages, &bytes(&early)).unwrap();
        mint(&s);
        commit(&s, p);
        match run(&sh, &s, Wire::Messages, &resend) {
            Ok(out) if !leaks(&out) => {}
            other => failed.push(format!("(d) {other:?}")),
        }

        // (c) the dataset variant (I3): the dataset value's token arrives
        // only through another cache hit, which a subagent's request on the
        // same session cached. The first hit was never verified against it.
        let s = st.get(SessionKey([117; 32]));
        let q = "Gruss an Quolnath, bitte.";
        let ruf = format!("Ruf {DS_TOKEN} an.");
        let p = prep(
            &sh,
            &s,
            Wire::Messages,
            &bytes(&json!({"messages": [{"role": "user", "content": q}]})),
        )
        .unwrap();
        assert!(String::from_utf8_lossy(&p.body).contains("Quolnath"));
        commit(&s, p);
        let sub = json!({"messages": [{"role": "user", "content": ruf}]});
        let p = prep(&sh, &s, Wire::Messages, &bytes(&sub)).unwrap();
        commit(&s, p);
        match run(&sh, &s, Wire::Messages, &body(q, &ruf)) {
            Ok(out) if !out.to_lowercase().contains("quolnath") => {}
            other => failed.push(format!("(c) {other:?}")),
        }
        assert!(failed.is_empty(), "{failed:#?}");
    }

    /// R4 (Review Focus 8): a cached tool result that a later request
    /// withholds (its cached text holds a name part the request mints;
    /// with no closure round to spend it cannot be re-run) leaves no cache
    /// entry behind once that request commits.
    #[test]
    pub(super) fn a_withheld_tool_result_leaves_no_cache_entry_behind() {
        let mut sh = shared(host(FULL));
        sh.closure = 0;
        let st = store();
        let s = st.get(SessionKey([116; 32]));
        let id = "toolu_01Hn4Bq9xL2mZ8cVt5sKpR3w";
        let mut messages = vec![
            json!({"role": "assistant", "content": [{"type": "tool_use", "id": id, "name": "crm", "input": {}}]}),
            json!({"role": "user", "content": [{"type": "tool_result", "tool_use_id": id, "content": H}]}),
        ];
        let turn1 = json!({ "messages": messages }).to_string().into_bytes();
        let p = prep(&sh, &s, Wire::Messages, &turn1).unwrap();
        commit(&s, p);
        let w = walk(Wire::Messages, &turn1).unwrap();
        let l = w.leaves.iter().find(|l| l.text == H).unwrap();
        let key = sh.keys.leaf(
            Wire::Messages,
            l.class,
            crate::pipeline::leaf_origin(l, crate::session::ClientMode::Trusted),
            l.text.as_bytes(),
        );
        assert!(s.cache().contains(&key), "turn 1 cached the tool result");
        messages.push(json!({"role": "assistant", "content": "ok"}));
        messages.push(json!({"role": "user", "content": format!("Bitte {FULL} heute anrufen.")}));
        let turn2 = json!({ "messages": messages }).to_string().into_bytes();
        let p = prep(&sh, &s, Wire::Messages, &turn2)
            .unwrap_or_else(|f| panic!("a tool result is withheld, not refused: {f:?}"));
        let out = String::from_utf8(p.body.clone()).unwrap();
        assert!(out.contains("tool result withheld"), "{out}");
        no_clear(&out);
        commit(&s, p);
        assert!(
            !s.cache().contains(&key),
            "the withheld leaf left the cache"
        );
    }

    /// No regression from resolving the scanned leaves' tokens up front: a
    /// dataset value whose token a scanned leaf carries still counts as
    /// added for the cached leaves, so a hit holding its name part in clear
    /// (forwarded on turn 1, when nothing knew the name) is re-run, not
    /// resent.
    #[test]
    pub(super) fn a_dataset_value_resolved_from_a_scanned_leaf_still_rescans_hits() {
        let sh = shared(FakeHost::new());
        let st = store();
        let s = st.get(SessionKey([112; 32]));
        let h_text = "Gruss an Quolnath, bitte.";
        let turn1 = json!({"messages": [{"role": "user", "content": h_text}]});
        let p = prep(&sh, &s, Wire::Messages, turn1.to_string().as_bytes()).unwrap();
        assert!(String::from_utf8_lossy(&p.body).contains("Quolnath"));
        commit(&s, p);
        let turn2 = json!({"messages": [
            {"role": "user", "content": h_text},
            {"role": "assistant", "content": [{"type": "thinking", "thinking": format!("Ich frage {DS_TOKEN}."), "signature": "s"}, {"type": "text", "text": "ok"}]},
            {"role": "user", "content": format!("Bitte {NAME} anrufen.")}
        ]});
        let p = prep(&sh, &s, Wire::Messages, turn2.to_string().as_bytes())
            .unwrap_or_else(|f| panic!("refused {f:?}"));
        let out = String::from_utf8(p.body).unwrap();
        assert!(!out.contains("Quolnath"), "{out}");
    }

    /// I1 (Review Focus 3): provider-written scanned text (a thinking block,
    /// a citation's source) is seeded with the producing request's claim.
    /// A value minted after that claim, in clear in the resent text,
    /// refuses the request (assistant) or withholds the tool result: it is
    /// never forwarded next to its token. Case (e): the stamp is the claim,
    /// not the logs' length when the answer arrives (N1).
    #[test]
    fn a_seeded_thinking_block_with_a_later_minted_value_is_never_forwarded() {
        use crate::session::SeedStamp;
        use inumaki_core::span::EntityKind;
        const T: &str = "Der Nutzer meint Brandl.";
        let sh = shared(host(FULL));
        let st = store();
        let mint = |s: &Session| {
            s.with_context(|c| c.token_for(&EntityKind::Person, FULL))
                .unwrap();
        };
        let thinking = json!({"messages": [
            {"role": "assistant", "content": [{"type": "thinking", "thinking": T, "signature": "s"}]},
            {"role": "user", "content": "Danke."}
        ]});
        let refused = |r: &Result<String, Fail>| {
            matches!(r, Err(Fail::PrivacyBlock { checks, kinds, .. })
                if *checks == ["ClearValue"] && *kinds == ["PERSON"])
        };
        let mut failed: Vec<String> = Vec::new();

        // Seeded at zero, then the mint.
        let s = st.get(SessionKey([118; 32]));
        crate::respond::seed_scan(&sh, &s, T, SeedStamp::unverified());
        mint(&s);
        let r = run(&sh, &s, Wire::Messages, &thinking);
        if !refused(&r) {
            failed.push(format!("(thinking) {r:?}"));
        }

        // The tool-result variant (N4): a seeded citation source inside a
        // tool result withholds that result.
        let s = st.get(SessionKey([119; 32]));
        crate::respond::seed_scan(&sh, &s, "crm://kontakte/brandl", SeedStamp::unverified());
        mint(&s);
        let text = format!("Bitte {FULL} heute anrufen.");
        let tool = json!({"messages": [
            {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_01Hn4Bq9xL2mZ8cVt5sKpR3w", "name": "crm", "input": {}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_01Hn4Bq9xL2mZ8cVt5sKpR3w", "content": [
                {"type": "search_result", "source": "crm://kontakte/brandl", "title": "t",
                 "content": [{"type": "text", "text": text}]}
            ]}]}
        ]});
        match run(&sh, &s, Wire::Messages, &tool) {
            Ok(out)
                if out.contains("tool result withheld")
                    && !out.to_lowercase().contains("brandl") => {}
            other => failed.push(format!("(tool result) {other:?}")),
        }

        // (e) P's claim is taken before the mint; the seed carries it.
        let s = st.get(SessionKey([120; 32]));
        let hallo = json!({"messages": [{"role": "user", "content": "Hallo"}]});
        let p = prep(&sh, &s, Wire::Messages, hallo.to_string().as_bytes()).unwrap();
        let seed = p.seed_stamp();
        mint(&s);
        crate::respond::seed_scan(&sh, &s, T, seed);
        commit(&s, p);
        let r = run(&sh, &s, Wire::Messages, &thinking);
        if !refused(&r) {
            failed.push(format!("(e) {r:?}"));
        }
        assert!(failed.is_empty(), "{failed:#?}");
    }

    /// I3 (Review Focus 4): a hits-only resend whose dataset tokens the
    /// cache entry was already verified against runs no closure and fetches
    /// no engine (a broken engine would fail it).
    #[test]
    fn a_hits_only_turn_with_covered_dataset_tokens_runs_no_closure() {
        let h = FakeHost::new();
        let sh = shared(Arc::clone(&h));
        let st = store();
        let s = st.get(SessionKey([121; 32]));
        let req = json!({"messages": [{"role": "user", "content": format!("Ruf {DS_TOKEN} an.")}]})
            .to_string()
            .into_bytes();
        let p = prep(&sh, &s, Wire::Messages, &req).unwrap();
        commit(&s, p);
        *h.fail_engine.lock().unwrap() = true;
        let p = prep(&sh, &s, Wire::Messages, &req).unwrap_or_else(|f| panic!("refused {f:?}"));
        assert_eq!((p.hits, p.misses), (1, 0));
        assert!(!p.closure_ran, "a covered hits-only turn runs no closure");
    }
}

/// Stage times (spec §20, amendment 2026-10-12, Part 2): `sanitize_request`
/// fills `StageTimes` on a miss, a hit, and an error.
mod stage_times {
    use super::*;
    use crate::timing::StageTimes;

    fn user(text: &str) -> Vec<u8> {
        json!({"messages": [{"role": "user", "content": text}]})
            .to_string()
            .into_bytes()
    }

    /// A miss runs the engine; the same text resent (an all-hit turn) runs
    /// neither the engine nor the closure.
    #[test]
    fn a_miss_costs_engine_time_and_an_all_hit_turn_costs_none() {
        let h = FakeHost::new();
        let sh = shared(Arc::clone(&h));
        let st = store();
        let s = st.get(SessionKey([131; 32]));
        // A dataset token: a covered hits-only resend runs no closure.
        let req = user(&format!("Ruf {DS_TOKEN} an."));
        let mut t = StageTimes::default();
        let p = prep_timed(&sh, &s, Wire::Messages, &req, &mut t).unwrap();
        assert_eq!((p.hits, p.misses), (0, 1));
        // (A miss that mints runs the closure, so `closure` is not asserted.)
        assert!(t.engine.get() > Duration::ZERO, "engine time on a miss");
        assert_eq!(t.project.get(), Duration::ZERO);
        commit(&s, p);
        let mut t = StageTimes::default();
        let p = prep_timed(&sh, &s, Wire::Messages, &req, &mut t).unwrap();
        assert_eq!((p.hits, p.misses), (1, 0));
        assert_eq!(
            t.engine.get(),
            Duration::ZERO,
            "no engine on an all-hit turn"
        );
        assert_eq!(t.closure.get(), Duration::ZERO);
        assert_eq!(t.project.get(), Duration::ZERO);
    }

    /// The out-parameter is filled when the request is refused, too.
    #[test]
    fn a_refusal_still_reports_the_engine_time() {
        let h = FakeHost::new();
        *h.mode.lock().unwrap() = Mode::Block;
        let sh = shared(Arc::clone(&h));
        let st = store();
        let s = st.get(SessionKey([132; 32]));
        let mut t = StageTimes::default();
        let r = prep_timed(&sh, &s, Wire::Messages, &user("ask Sperrwort now"), &mut t);
        assert!(matches!(r, Err(Fail::PrivacyBlock { .. })));
        assert!(t.engine.get() > Duration::ZERO);
    }
}

/// Closure projection (M8 spec §20, amendment 2026-10-12): step 6b projects
/// a hit-derived leaf instead of re-running it, and falls back to the full
/// engine on any abandonment.
mod projection {
    use super::*;
    use crate::testing::{CFG, Counting, Word};
    use inumaki_core::config::CoreConfig;
    use inumaki_core::engine::{Abandon, Engine};
    use inumaki_core::span::EntityKind;
    use inumaki_core::token::TokenStore;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const FULL: &str = "Qorvex Brandl";

    fn host_with(cfg: &str, calls: &Arc<AtomicUsize>) -> Arc<FakeHost> {
        let mut h = Arc::into_inner(FakeHost::new()).unwrap();
        let cfg = CoreConfig::from_toml(cfg).unwrap();
        h.engine = Arc::new(
            Engine::from_config(&cfg, "fast", None, None)
                .unwrap()
                .with_detector(Arc::new(Word(FULL, Some(0.95))))
                .with_detector(Arc::new(Counting(Arc::clone(calls)))),
        );
        Arc::new(h)
    }
    fn host(calls: &Arc<AtomicUsize>) -> Arc<FakeHost> {
        host_with(CFG, calls)
    }
    fn bytes(v: &serde_json::Value) -> Vec<u8> {
        v.to_string().into_bytes()
    }
    fn no_clear(out: &str) {
        let low = out.to_lowercase();
        for c in ["qorvex", "brandl"] {
            assert!(!low.contains(c), "{c} in clear");
        }
    }
    /// A history leaf `h`, the assistant's "ok", and a new leaf `new`.
    fn turn(h: &str, new: &str) -> serde_json::Value {
        json!({"messages": [
            {"role": "user", "content": h},
            {"role": "assistant", "content": "ok"},
            {"role": "user", "content": new}]})
    }
    /// A cache entry for the text leaf `text` holding `text` itself,
    /// stamped at zero (cached before anything was minted).
    fn cache_raw(sh: &Shared, s: &Session, text: &str) {
        s.cache().insert(
            sh.keys.leaf(
                Wire::Messages,
                crate::walk::Class::Text,
                inumaki_core::TextOrigin::Free,
                text.as_bytes(),
            ),
            crate::cache::Cached {
                text: text.into(),
                tokens: Vec::new(),
            },
            crate::closure::Gen::ZERO,
            Arc::from([]),
        );
    }
    fn mints() -> String {
        format!("Bitte {FULL} heute anrufen.")
    }
    /// The session store's size: entries plus removed values.
    fn store_size(s: &Session) -> usize {
        s.with_context(|c| TokenStore::entries(c).count() + TokenStore::removed_entries(c).count())
    }
    /// Prepare `body` twice, each time in a fresh session where `h_text` is
    /// cached raw: with projection on (key `on`) and with it off (key
    /// `off`). Returns the projection-on `Prepared`, after asserting that
    /// the store did not grow across any abandoned projection (measured
    /// around each call by the pipeline's test probe), and that both
    /// sessions' stores end the same size: an abandoned projection leaves
    /// the store as the full engine alone would.
    fn abandoned_mints_nothing(
        sh: &Shared,
        st: &SessionStore,
        on: u8,
        off: u8,
        h_text: &str,
        body: &serde_json::Value,
    ) -> crate::pipeline::Prepared {
        let s = st.get(SessionKey([on; 32]));
        cache_raw(sh, &s, h_text);
        let grew = crate::pipeline::abandoned_growth_on_this_thread();
        let p = prep(sh, &s, Wire::Messages, &bytes(body)).unwrap();
        assert_eq!(
            crate::pipeline::abandoned_growth_on_this_thread() - grew,
            0,
            "the abandoned projection left a mint"
        );
        let with = store_size(&s);
        let without = {
            let _off = crate::pipeline::disable_projection_on_this_thread();
            let s = st.get(SessionKey([off; 32]));
            cache_raw(sh, &s, h_text);
            let q = prep(sh, &s, Wire::Messages, &bytes(body)).unwrap();
            assert_eq!((q.projected, q.projection_abandoned), (0, 0));
            store_size(&s)
        };
        assert!(without > 0, "the full engine minted the new leaf's name");
        assert_eq!(with, without, "the store differs from a projection-off run");
        p
    }

    /// Turn 1 caches H with `Brandl` in clear; turn 2's new leaf mints the
    /// full name. H is projected (no full-engine pass over it), carries the
    /// entity's token, and counts as a projected miss. The assistant "ok"
    /// is a miss through the engine too (F2): two passes, neither over H.
    #[test]
    fn a_cached_leaf_with_a_later_minted_name_part_is_projected() {
        let calls = Arc::new(AtomicUsize::new(0));
        let sh = shared(host(&calls));
        let st = store();
        let s = st.get(SessionKey([201; 32]));
        let h_text = "Gruss an Brandl, bitte.";
        let t1 = json!({"messages": [{"role": "user", "content": h_text}]});
        commit(&s, prep(&sh, &s, Wire::Messages, &bytes(&t1)).unwrap());
        let t2 = turn(h_text, &mints());
        let before = calls.load(Ordering::SeqCst);
        let p = prep(&sh, &s, Wire::Messages, &bytes(&t2)).unwrap();
        assert_eq!((p.projected, p.projection_abandoned), (1, 0));
        assert_eq!(p.hits, 0, "a projected leaf is a miss");
        // "ok" and the new leaf run the engine once each; H does not (a
        // shadow build runs it once more, beside the projection).
        let shadow = usize::from(cfg!(feature = "closure-shadow"));
        assert_eq!(calls.load(Ordering::SeqCst) - before, 2 + shadow);
        let out = String::from_utf8(p.body.clone()).unwrap();
        no_clear(&out);
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(
            v["messages"][0]["content"]
                .as_str()
                .unwrap()
                .contains("<PERSON_")
        );
        commit(&s, p);
        let p = prep(&sh, &s, Wire::Messages, &bytes(&t2)).unwrap();
        assert_eq!(p.misses, 0, "turn 3: the projected text was cached");
        no_clear(&String::from_utf8(p.body).unwrap());
    }

    /// Step 6b's time is `closure`, and the projection inside it is
    /// `project`, which a closure that projects nothing leaves at zero.
    #[test]
    fn a_projected_closure_reports_closure_and_project_time() {
        let calls = Arc::new(AtomicUsize::new(0));
        let sh = shared(host(&calls));
        let st = store();
        let s = st.get(SessionKey([205; 32]));
        let h_text = "Gruss an Brandl, bitte.";
        let t1 = json!({"messages": [{"role": "user", "content": h_text}]});
        commit(&s, prep(&sh, &s, Wire::Messages, &bytes(&t1)).unwrap());
        let mut t = crate::timing::StageTimes::default();
        let p = prep_timed(
            &sh,
            &s,
            Wire::Messages,
            &bytes(&turn(h_text, &mints())),
            &mut t,
        )
        .unwrap();
        assert_eq!(p.projected, 1);
        assert!(t.project.get() > Duration::ZERO);
        assert!(
            t.closure.get() >= t.project.get(),
            "project is inside closure"
        );
        assert!(
            t.engine.get() > Duration::ZERO,
            "the other two leaves missed"
        );
    }

    /// Review Focus 2: the second new leaf mints the name the first holds
    /// as a part. The first was verified in this request, never sent: it
    /// takes the full engine (a fourth pass), not a projection.
    #[test]
    fn a_leaf_verified_in_this_request_is_never_projected() {
        let calls = Arc::new(AtomicUsize::new(0));
        let sh = shared(host(&calls));
        let st = store();
        let s = st.get(SessionKey([202; 32]));
        let body = turn("Gruss an Brandl, bitte.", &mints());
        let p = prep(&sh, &s, Wire::Messages, &bytes(&body)).unwrap();
        assert_eq!((p.projected, p.projection_abandoned), (0, 0));
        assert!(p.closure_ran);
        assert_eq!(calls.load(Ordering::SeqCst), 4, "three leaves + H's re-run");
        no_clear(&String::from_utf8(p.body).unwrap());
    }

    /// Review Focus 1: a seed carrying a token the model invented.
    #[test]
    fn a_seed_with_an_invented_token_takes_the_full_engine() {
        let calls = Arc::new(AtomicUsize::new(0));
        let sh = shared(host(&calls));
        let st = store();
        let s = st.get(SessionKey([203; 32]));
        // a seeded assistant leaf: key = its resent text, value = model text
        let resent = "Ich rufe Brandl an, siehe <PERSON_beef>.";
        cache_raw(&sh, &s, resent);
        let body = json!({"messages": [
            {"role": "user", "content": "hallo"},
            {"role": "assistant", "content": resent},
            {"role": "user", "content": mints()}]});
        let p = prep(&sh, &s, Wire::Messages, &bytes(&body)).unwrap();
        assert_eq!(p.projected, 0);
        assert!(
            p.abandoned_by
                .iter()
                .any(|(r, _)| *r == Abandon::ForgedToken)
        );
        no_clear(&String::from_utf8(p.body).unwrap());
    }

    /// Review Focus 3: an identity value in clear in the cached text
    /// abandons the projection (caller check); the full engine re-runs H,
    /// and the abandoned projection left no mint behind.
    #[test]
    fn an_abandoned_projection_falls_back_to_the_full_engine() {
        // The identity holds EMAIL; H holds it in clear only because it is
        // inserted directly, as an entry cached before the identity was read.
        let calls = Arc::new(AtomicUsize::new(0));
        let mut h = Arc::into_inner(host(&calls)).unwrap();
        h.identity = vec![(EntityKind::Email, EMAIL.to_string())];
        let sh = shared(Arc::new(h));
        let st = store();
        let h_text = format!("Brandl schreibt an {EMAIL}.");
        let body = turn(&h_text, &mints());
        let p = abandoned_mints_nothing(&sh, &st, 204, 214, &h_text, &body);
        assert_eq!(p.projected, 0);
        assert!(p.projection_abandoned >= 1);
        assert!(p.abandoned_by.iter().any(|(r, _)| *r == Abandon::Caller));
        let out = String::from_utf8(p.body).unwrap();
        no_clear(&out);
        assert!(!out.contains(EMAIL));
    }

    /// Cache `t0` as the sanitized text of the leaf `key_text` (a hit whose
    /// cached text differs from the leaf's original), stamped at zero.
    #[cfg(feature = "closure-shadow")]
    fn cache_as(sh: &Shared, s: &Session, key_text: &str, t0: &str) {
        s.cache().insert(
            sh.keys.leaf(
                Wire::Messages,
                crate::walk::Class::Text,
                inumaki_core::TextOrigin::Free,
                key_text.as_bytes(),
            ),
            crate::cache::Cached {
                text: t0.into(),
                tokens: Vec::new(),
            },
            crate::closure::Gen::ZERO,
            Arc::from([]),
        );
    }

    /// P2: the shadow's full re-run applies the identity redaction. The
    /// identity holds a name no detector finds; the leaf's original text has
    /// it, the cached text T0 does not, so T0 is projected (`Brandl` is
    /// replaced) and nothing but the shadow's full re-run, run over the
    /// original text, can redact the identity name. The forwarded body is
    /// the full re-run's: neither the identity name nor `Brandl` is in it.
    /// (Also pins the counters' wiring: this projection and the abandoned one
    /// below show up in `take()`.)
    #[cfg(feature = "closure-shadow")]
    #[test]
    fn a_shadow_build_forwards_no_identity_value_in_clear() {
        const ID_NAME: &str = "Zorbal Wexmund";
        let calls = Arc::new(AtomicUsize::new(0));
        let mut h = Arc::into_inner(host(&calls)).unwrap();
        h.identity = vec![(EntityKind::Person, ID_NAME.to_string())];
        let sh = shared(Arc::new(h));
        let st = store();
        let s = st.get(SessionKey([207; 32]));
        let original = format!("Brandl, Kopie an {ID_NAME}");
        cache_as(&sh, &s, &original, "Brandl, Kopie an");
        let _g = crate::shadow::TAKE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = crate::shadow::take();
        let before = calls.load(Ordering::SeqCst);
        let p = prep(&sh, &s, Wire::Messages, &bytes(&turn(&original, &mints()))).unwrap();
        assert_eq!(p.projected, 1, "the leaf was projected");
        assert_eq!(
            calls.load(Ordering::SeqCst) - before,
            3,
            "ok + new leaf + the shadow's full re-run of H"
        );
        let out = String::from_utf8(p.body).unwrap();
        no_clear(&out);
        assert!(
            !out.contains("Zorbal") && !out.contains("Wexmund"),
            "the identity name left in clear"
        );
        // The full re-run's text, not the projection's (T0 ends at "an").
        assert!(
            out.contains("Kopie an <PERSON_"),
            "the identity name was not tokenized by the full re-run"
        );
        // The abandoned case (the caller check) where the full re-run passes.
        let mut h = Arc::into_inner(host(&calls)).unwrap();
        h.identity = vec![(EntityKind::Email, EMAIL.to_string())];
        let sh = shared(Arc::new(h));
        let s = st.get(SessionKey([208; 32]));
        let h_text = format!("Brandl schreibt an {EMAIL}.");
        cache_raw(&sh, &s, &h_text);
        let q = prep(&sh, &s, Wire::Messages, &bytes(&turn(&h_text, &mints()))).unwrap();
        assert_eq!(q.projected, 0);
        let out = String::from_utf8(q.body).unwrap();
        no_clear(&out);
        assert!(!out.contains(EMAIL));
        // Other tests count into the same global: lower bounds only.
        let c = crate::shadow::take();
        assert!(
            c.attempted >= 2 && c.projected >= 1 && c.abandoned >= 1,
            "{c:?}"
        );
        assert!(
            c.r2.get("Caller").is_some_and(|n| *n >= 1),
            "R2 wiring: {c:?}"
        );
    }

    /// Review Focus 4: a removed value in clear in a cached leaf is
    /// projected to its removal marker, never a restorable token.
    #[test]
    fn a_cached_leaf_with_a_removed_value_is_projected_as_a_removal() {
        let calls = Arc::new(AtomicUsize::new(0));
        let sh = shared(host(&calls));
        let st = store();
        let s = st.get(SessionKey([205; 32]));
        s.with_context(|c| {
            TokenStore::record_removed(c, &EntityKind::custom("SECRET"), "hunter2pw").unwrap()
        });
        let h_text = "Brandl: pw hunter2pw";
        cache_raw(&sh, &s, h_text);
        let p = prep(&sh, &s, Wire::Messages, &bytes(&turn(h_text, &mints()))).unwrap();
        assert_eq!((p.projected, p.projection_abandoned), (1, 0));
        let out = String::from_utf8(p.body).unwrap();
        assert!(!out.contains("hunter2pw") && out.contains("_REMOVED>"));
        no_clear(&out);
    }

    /// Review Focus 5 and ruling P1: a projected leaf that the round's
    /// re-check reopens (forced through a test hook) is never projected
    /// again in this request. The projection mints (linking is on, so N1
    /// mints a surface token), so the store grows, which once let a
    /// size-keyed guard project again. H gets exactly one full re-run.
    #[test]
    fn a_projected_leaf_still_open_takes_the_full_engine_next_round() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut sh = shared(host(&calls));
        sh.force_reopen_projected = true;
        let st = store();
        let s = st.get(SessionKey([206; 32]));
        let h_text = "Gruss an Brandl, bitte.";
        let t1 = json!({"messages": [{"role": "user", "content": h_text}]});
        commit(&s, prep(&sh, &s, Wire::Messages, &bytes(&t1)).unwrap());
        let before = calls.load(Ordering::SeqCst);
        let p = prep(&sh, &s, Wire::Messages, &bytes(&turn(h_text, &mints()))).unwrap();
        assert_eq!(p.projected, 1, "projected once, never again");
        assert!(p.projection_mints >= 1, "the projection grew the store");
        // A shadow build also re-runs H beside the projection.
        let shadow = usize::from(cfg!(feature = "closure-shadow"));
        assert_eq!(
            calls.load(Ordering::SeqCst) - before,
            3 + shadow,
            "ok + new leaf + exactly one full re-run of H"
        );
        no_clear(&String::from_utf8(p.body).unwrap());
    }

    /// P3: the Regex abandon path in the pipeline. The cached leaf holds a
    /// bare identifier in clear; the projection abandons (`Regex`), mints
    /// nothing, and the full engine re-runs H (the domain pattern, F3,
    /// tokenizes the identifier).
    #[test]
    fn a_regex_abandon_falls_back_and_mints_nothing() {
        let calls = Arc::new(AtomicUsize::new(0));
        let cfg =
            format!("[[domain.patterns]]\nregex = \"K-[0-9]{{6}}\"\nkind = \"CUSTOMER_ID\"\n{CFG}");
        let sh = shared(host_with(&cfg, &calls));
        let st = store();
        let h_text = "Brandl K-482913 bitte";
        let body = turn(h_text, &mints());
        let p = abandoned_mints_nothing(&sh, &st, 208, 218, h_text, &body);
        assert_eq!(p.projected, 0);
        assert!(p.abandoned_by.iter().any(|(r, _)| *r == Abandon::Regex));
        let out = String::from_utf8(p.body).unwrap();
        no_clear(&out);
        assert!(!out.contains("K-482913"));
    }

    /// P8: a dataset-stale hit is projected to the dataset token (§5.3,
    /// ruling I3): H holds NAME in clear; the new leaf carries DS_TOKEN,
    /// which the view resolves to NAME.
    #[test]
    fn a_dataset_stale_hit_is_projected_to_the_dataset_token() {
        let calls = Arc::new(AtomicUsize::new(0));
        let sh = shared(host(&calls));
        let st = store();
        let s = st.get(SessionKey([209; 32]));
        let h_text = format!("Termin mit {NAME} morgen.");
        cache_raw(&sh, &s, &h_text);
        let body = turn(&h_text, &format!("Bitte {DS_TOKEN} anrufen."));
        let p = prep(&sh, &s, Wire::Messages, &bytes(&body)).unwrap();
        assert_eq!(p.projected, 1);
        let out = String::from_utf8(p.body).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        let h = v["messages"][0]["content"].as_str().unwrap();
        assert!(h.contains(DS_TOKEN) && !out.contains(NAME), "{}", h.len());
    }

    /// P7: the closure module's tests hold with projection switched off, so
    /// the full-engine path for hits stays pinned.
    #[test]
    fn the_closure_tests_hold_with_projection_disabled() {
        let _off = crate::pipeline::disable_projection_on_this_thread();
        // The switch took effect: test 1's turn 2 projects nothing.
        {
            let calls = Arc::new(AtomicUsize::new(0));
            let sh = shared(host(&calls));
            let st = store();
            let s = st.get(SessionKey([210; 32]));
            let h_text = "Gruss an Brandl, bitte.";
            let t1 = json!({"messages": [{"role": "user", "content": h_text}]});
            commit(&s, prep(&sh, &s, Wire::Messages, &bytes(&t1)).unwrap());
            let p = prep(&sh, &s, Wire::Messages, &bytes(&turn(h_text, &mints()))).unwrap();
            assert_eq!((p.projected, p.projection_abandoned), (0, 0));
        }
        super::closure::a_cached_leaf_with_a_later_minted_name_part_is_re_run();
        super::closure::a_greeting_only_mint_reruns_no_cached_leaf_but_greeting_and_name_does();
        super::closure::a_cached_clear_copy_is_rescanned_after_an_outside_mint();
        super::closure::a_withheld_tool_result_leaves_no_cache_entry_behind();
        super::closure::a_dataset_value_resolved_from_a_scanned_leaf_still_rescans_hits();
        super::closure::a_removed_value_is_re_run_as_a_removal();
    }

    /// P8: on a turn that does project (test 1's turn 2).
    #[test]
    fn prepared_debug_prints_projection_counts_only() {
        let calls = Arc::new(AtomicUsize::new(0));
        let sh = shared(host(&calls));
        let st = store();
        let s = st.get(SessionKey([207; 32]));
        let h_text = "Gruss an Brandl, bitte.";
        let t1 = json!({"messages": [{"role": "user", "content": h_text}]});
        commit(&s, prep(&sh, &s, Wire::Messages, &bytes(&t1)).unwrap());
        let p = prep(&sh, &s, Wire::Messages, &bytes(&turn(h_text, &mints()))).unwrap();
        assert_eq!(p.projected, 1);
        let d = format!("{p:?}");
        assert!(
            d.contains("projected") && !d.contains("Brandl") && !d.contains("Qorvex"),
            "{d}"
        );
    }
}

/// Spec §14 (I10): a tool result another front door released skips the
/// engine only when the deterministic re-check (the step-2 rule plus the
/// validated-regex tier) is clean; any doubt runs the full engine.
mod released {
    use super::*;
    use crate::testing::{CFG, Word};
    use inumaki_core::config::CoreConfig;
    use inumaki_core::engine::Engine;

    const ID: &str = "toolu_01D7FLrfh4GYq7yT1ULmeyqw";
    const ID2: &str = "toolu_01Hn4Bq9xL2mZ8cVt5sKpR3w";
    /// A word only the engine's detector finds (no dictionary, no regex).
    const W: &str = "Qelvornek";

    fn tool(t: &str) -> serde_json::Value {
        json!({"messages": [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": ID, "content": t}]}]})
    }

    fn word_host() -> Arc<FakeHost> {
        let mut h = Arc::into_inner(FakeHost::new()).unwrap();
        h.engine = Arc::new(
            Engine::from_config(&CoreConfig::from_toml(CFG).unwrap(), "fast", None, None)
                .unwrap()
                .with_detector(Arc::new(Word(W, Some(0.95)))),
        );
        Arc::new(h)
    }

    #[test]
    fn released_blocks_skip_detection_only_when_clean() {
        let host = FakeHost::new();
        let sh = shared(Arc::clone(&host));
        let st = store();
        let s = st.get(SessionKey([9; 32]));
        *host.fail_engine.lock().unwrap() = true; // proves the engine is not reached
        let clean = format!("Kunde {DS_TOKEN} hat bestellt");
        host.release(&clean);
        let out = run(&sh, &s, Wire::Messages, &tool(&clean))
            .unwrap_or_else(|f| panic!("a clean released block took the engine: {f:?}"));
        assert!(
            out.contains(&clean),
            "forwarded unchanged without the engine"
        );
        for dirty in [
            // a validated identifier
            format!("Kunde {DS_TOKEN} schreibt an {EMAIL}"),
            // a dataset value in clear (host dictionary)
            format!("Kunde {NAME} ruft an"),
            // a name part of a value this block's token resolves (closure form)
            format!("Kunde {DS_TOKEN}, Zyxwuria ruft an"),
            // an unresolved token
            "Kunde <PERSON_ffffff> ruft an".to_string(),
            // a forged removed marker of a label the system never emits
            "Kunde <QUOLNATH_REMOVED> ruft an".to_string(),
        ] {
            host.release(&dirty);
            assert_eq!(
                run(&sh, &s, Wire::Messages, &tool(&dirty)).unwrap_err(),
                Fail::ModelUnavailable,
                "re-check hit: full engine"
            );
        }
        let unreleased = format!("Kunde {DS_TOKEN} kam zurück");
        assert_eq!(
            run(&sh, &s, Wire::Messages, &tool(&unreleased)).unwrap_err(),
            Fail::ModelUnavailable
        );
        // Only tool results: released user text always takes the engine.
        let user = json!({"messages": [{"role": "user", "content": clean}]});
        assert_eq!(
            run(&sh, &s, Wire::Messages, &user).unwrap_err(),
            Fail::ModelUnavailable
        );
    }

    /// R1 for the skip: a released block holding, in clear, a value another
    /// leaf of the same request mints must still be seen by step 6b.
    #[test]
    fn a_skipped_block_is_rescanned_for_values_the_request_mints() {
        let host = word_host();
        let sh = shared(Arc::clone(&host));
        let st = store();
        let s = st.get(SessionKey([10; 32]));
        let first = format!("Notiz: {W} hat angerufen");
        host.release(&first);
        // Alone, the released block is clean and skipped (no engine).
        *host.fail_engine.lock().unwrap() = true;
        let out = run(&sh, &s, Wire::Messages, &tool(&first))
            .unwrap_or_else(|f| panic!("the released block was not skipped: {f:?}"));
        assert!(out.contains(&first));
        // With a second tool result that mints W through the engine.
        *host.fail_engine.lock().unwrap() = false;
        let body = json!({"messages": [{"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": ID, "content": first},
            {"type": "tool_result", "tool_use_id": ID2, "content": format!("{W} wohnt in Wien")}
        ]}]});
        // Strict (final review I5): the request is forwarded, and W is the
        // same token in both tool results (6b re-ran the skipped leaf).
        let out = run(&sh, &s, Wire::Messages, &body)
            .unwrap_or_else(|f| panic!("the request was refused: {f:?}"));
        assert!(!out.contains(W), "W left in clear: {out}");
        let sent: serde_json::Value = serde_json::from_str(&out).unwrap();
        let blocks = sent["messages"][0]["content"].as_array().unwrap();
        let texts: Vec<&str> = blocks
            .iter()
            .map(|b| b["content"].as_str().unwrap())
            .collect();
        let tok = regex::Regex::new(r"<[A-Z_]+_[0-9a-f]{4,12}>").unwrap();
        let first: Vec<&str> = tok.find_iter(texts[0]).map(|m| m.as_str()).collect();
        let second: Vec<&str> = tok.find_iter(texts[1]).map(|m| m.as_str()).collect();
        assert_eq!(first.len(), 1, "{out}");
        assert_eq!(first, second, "W has one token in both results: {out}");
    }

    /// A value the session already holds, in clear in a released block,
    /// sends it through the engine (the session dictionary of step 2).
    #[test]
    fn a_session_value_in_a_released_block_takes_the_engine() {
        let host = word_host();
        let sh = shared(Arc::clone(&host));
        let st = store();
        let s = st.get(SessionKey([11; 32]));
        let req = json!({"messages": [{"role": "user", "content": format!("Ruf {W} an.")}]});
        let p = prep(&sh, &s, Wire::Messages, req.to_string().as_bytes()).unwrap();
        commit(&s, p);
        *host.fail_engine.lock().unwrap() = true;
        let text = format!("Notiz: {W} hat angerufen");
        host.release(&text);
        assert_eq!(
            run(&sh, &s, Wire::Messages, &tool(&text)).unwrap_err(),
            Fail::ModelUnavailable
        );
    }
}

/// Codex 0.162 responses-lite: the tool definitions arrive in a leading
/// `additional_tools` input item. They are checked like the top-level
/// `tools` (a clear value refuses the request) and a clean list is
/// forwarded unchanged.
#[test]
fn codex_lite_additional_tools_are_checked_definitions() {
    let host = FakeHost::new();
    let sh = shared(Arc::clone(&host));
    let st = store();
    let s = st.get(SessionKey([62; 32]));
    let up = Recording::default();
    let lite = |description: String| {
        json!({"model": "m", "input": [
            {"type": "additional_tools", "role": "developer", "tools": [
                {"type": "namespace", "name": "mcp__crm", "description": "CRM tools",
                 "tools": [{"type": "function", "name": "lookup_record", "description": description,
                            "parameters": {"type": "object", "properties": {}}}]}]},
            {"type": "message", "role": "user", "content": "hello there"}
        ]})
    };
    assert_eq!(
        forward(&up, &sh, &s, Wire::Responses, &lite(format!("ask {NAME}"))).unwrap_err(),
        Fail::UnsupportedContent
    );
    let clean = lite("Looks a record up.".into());
    forward(&up, &sh, &s, Wire::Responses, &clean).unwrap();
    let sent = up.0.lock().unwrap();
    assert_eq!(sent.len(), 1, "only the clean definition left");
    let sent: serde_json::Value = serde_json::from_slice(&sent[0].body).unwrap();
    assert_eq!(sent["input"][0], clean["input"][0], "definitions unchanged");
}

/// Codex 0.159.2 shapes (M8 spec §20 amendment 2026-10-10): a `namespace`
/// tool's nested function definitions are definitions, refused with a
/// clear value exactly like a flat tool's; a resent `function_call` with a
/// `namespace` has that field sanitized like the call's arguments, and a
/// plain namespace passes unchanged.
#[test]
fn codex_namespace_tools_and_calls_are_scanned() {
    let host = FakeHost::new();
    let sh = shared(Arc::clone(&host));
    let st = store();
    let s = st.get(SessionKey([61; 32]));
    let up = Recording::default();
    let input = json!([{"type": "message", "role": "user", "content": "hello there"}]);
    let flat = json!({"model": "m", "input": input, "tools": [
        {"type": "function", "name": "lookup_record", "description": format!("ask {NAME}")}]});
    let nested = json!({"model": "m", "input": input, "tools": [
        {"type": "namespace", "name": "mcp__crm", "description": "CRM tools",
         "tools": [{"type": "function", "name": "lookup_record", "description": format!("ask {NAME}"),
                    "parameters": {"type": "object", "properties": {}}}]}]});
    let in_schema = json!({"model": "m", "input": input, "tools": [
        {"type": "namespace", "name": "mcp__crm", "description": "CRM tools",
         "tools": [{"type": "function", "name": "lookup_record",
                    "parameters": {"type": "object", "properties": {"q": {"type": "string", "description": format!("e.g. {EMAIL}")}}}}]}]});
    for body in [&flat, &nested, &in_schema] {
        assert_eq!(
            forward(&up, &sh, &s, Wire::Responses, body).unwrap_err(),
            Fail::UnsupportedContent,
            "{body}"
        );
    }
    let clean_ns = json!({"model": "m", "input": input, "tools": [
        {"type": "namespace", "name": "mcp__crm", "description": "CRM tools",
         "tools": [{"type": "function", "name": "lookup_record", "parameters": {}}]}]});
    forward(&up, &sh, &s, Wire::Responses, &clean_ns).unwrap();
    assert_eq!(
        up.0.lock().unwrap().len(),
        1,
        "only the clean definition left"
    );

    let resend = json!({"model": "m", "input": [
        {"type": "message", "role": "user", "content": "look it up"},
        {"type": "function_call", "call_id": "call_1", "name": "lookup_record", "namespace": "mcp__inumaki_check_ab", "arguments": "{}"},
        {"type": "function_call", "call_id": "call_2", "name": "lookup_record", "namespace": format!("mcp__{NAME}"), "arguments": "{}"},
        {"type": "function_call_output", "call_id": "call_1", "output": "ok"}
    ]});
    let out = run(&sh, &s, Wire::Responses, &resend).unwrap();
    clean(&out);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["input"][1]["namespace"], "mcp__inumaki_check_ab");
    assert_eq!(v["input"][1]["name"], "lookup_record");
    assert_ne!(v["input"][2]["namespace"], format!("mcp__{NAME}"));
}

/// Ruling L58 (Option D): the top-level `client_metadata["x-codex-turn-metadata"]`
/// leaves a Responses body before anything is sanitized: never sanitized
/// (a policy-blocked word inside it refuses nothing), never cached, never
/// forwarded. The other `client_metadata` members and every byte outside
/// the removed member stay as received; an only member leaves `{}`. A copy
/// anywhere else (history, nested) is ordinary data and is sanitized.
#[test]
fn codex_turn_metadata_body_entry_is_dropped_before_sanitizing() {
    const CANARY: &str = "/Users/zyxcanary/Clients/ZyxAcme/repo";
    let host = FakeHost::new();
    let sh = shared(Arc::clone(&host));
    let st = store();
    let s = st.get(SessionKey([62; 32]));
    let meta = serde_json::to_string(&json!({
        "turn_id": "t1",
        "workspaces": {CANARY: {"latest_git_commit_hash": "0123abcd", "note": "Sperrwort"}}
    }))
    .unwrap();
    let meta = crate::json::quote(&meta);
    let head = r#"{"model":"gpt-x", "input":[{"type":"message","role":"user","content":"status please"},{"type":"message","role":"user","content":[{"type":"input_text","text":"see"}],"client_metadata":{"x-codex-turn-metadata":"#;
    let nested = format!(
        "{}}}}}],\n \"client_metadata\":{{",
        crate::json::quote(NAME)
    );
    // Several members, the removed one first, odd whitespace around it.
    let body = format!(
        r#"{head}{nested}"x-codex-turn-metadata" : {meta} , "x-keep":"keep-me"}}, "stream":false}}"#
    );
    let expect_tail = r#""x-keep":"keep-me"}, "stream":false}"#;
    let p = prep(&sh, &s, Wire::Responses, body.as_bytes()).unwrap();
    let out = String::from_utf8(p.body.clone()).unwrap();
    assert!(
        !out.contains("zyxcanary") && !out.contains("Sperrwort"),
        "{out}"
    );
    assert!(p.missed.iter().all(|t| !t.contains("zyxcanary")));
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["client_metadata"], json!({"x-keep": "keep-me"}));
    // The history copy is data: present, sanitized, not removed.
    assert!(!out.contains(NAME), "{out}");
    assert!(v["input"][1]["client_metadata"]["x-codex-turn-metadata"].is_string());
    // Byte-identical outside the removed member (the nested name aside).
    let sanitized_nested = out.find("\n \"client_metadata\":{").unwrap();
    assert_eq!(
        &out[sanitized_nested..],
        format!("\n \"client_metadata\":{{{expect_tail}")
    );
    assert!(out.starts_with(head), "{out}");

    // From here "Sperrwort" is a PERSON the policy blocks: inside the
    // removed member it refuses nothing, because it is never sanitized.
    *host.mode.lock().unwrap() = Mode::Block;
    // The only member, the last of several, and the Messages wire.
    let only = format!(
        r#"{{"model":"m","client_metadata":{{"x-codex-turn-metadata":{meta}}},"input":"hi"}}"#
    );
    let out = String::from_utf8(
        prep(&sh, &s, Wire::Responses, only.as_bytes())
            .unwrap()
            .body,
    )
    .unwrap();
    assert_eq!(out, r#"{"model":"m","client_metadata":{},"input":"hi"}"#);
    let last = format!(
        r#"{{"model":"m","client_metadata":{{"a":"b","x-codex-turn-metadata":{meta}}},"input":"hi"}}"#
    );
    let out = String::from_utf8(
        prep(&sh, &s, Wire::Responses, last.as_bytes())
            .unwrap()
            .body,
    )
    .unwrap();
    assert_eq!(
        out,
        r#"{"model":"m","client_metadata":{"a":"b"},"input":"hi"}"#
    );
    // A key spelled with escapes is the same key to the provider: removed too.
    let escaped = format!(
        r#"{{"model":"m","client_metadata":{{"a":"b","\u0078-codex-turn-metadata":{meta}}},"input":"hi"}}"#
    );
    assert!(escaped.contains(r"\u0078-codex"));
    let out = String::from_utf8(
        prep(&sh, &s, Wire::Responses, escaped.as_bytes())
            .unwrap()
            .body,
    )
    .unwrap();
    assert_eq!(
        out,
        r#"{"model":"m","client_metadata":{"a":"b"},"input":"hi"}"#
    );
    assert!(!out.contains("zyxcanary"));
    // Fail closed on any other shape: left to the sanitizer, which refuses
    // the blocked word as before.
    let odd = format!(r#"{{"model":"m","client_metadata":[{meta}],"input":"hi"}}"#);
    assert!(prep(&sh, &s, Wire::Responses, odd.as_bytes()).is_err());
    let msgs = format!(
        r#"{{"model":"m","client_metadata":{{"x-codex-turn-metadata":{meta}}},"messages":[{{"role":"user","content":"hi"}}]}}"#
    );
    assert!(prep(&sh, &s, Wire::Messages, msgs.as_bytes()).is_err());
}

/// M8 spec §20 amendment 2026-10-11 (F2), review findings 9, 11, 12 and
/// ruling L65, at the pipeline: what a `placeholder` walk replaces.
mod parts {
    use super::*;
    use crate::config::BinaryMode;
    use crate::handler_tests::parts::{P, no_part_left, object_placeholder};

    fn in_mode(host: &Arc<FakeHost>, mode: BinaryMode) -> Shared {
        let mut sh = shared(Arc::clone(host));
        sh.cfg.binary = mode;
        sh
    }

    /// L65: one edit spans the part object from `{` to `}`: the forwarded
    /// body is the received body with exactly that substring replaced.
    #[test]
    fn one_edit_spans_the_part_object_exactly() {
        let host = FakeHost::new();
        let sh = in_mode(&host, BinaryMode::Placeholder);
        let s = store().get(SessionKey([40; 32]));
        let part = r#"{"type" : "image", "source":{"type":"base64","media_type":"image/x-zyxmedia","data":"iVBORZYXPAYLOAD"}, "cache_control":{"type":"ephemeral"}}"#;
        let body = format!(
            r#"{{"model":"m","messages":[{{"role":"user","content":[{{"type":"text","text":"a"}}, {part} ,{{"type":"text","text":"b"}}]}}]}}"#
        );
        let p = prep(&sh, &s, Wire::Messages, body.as_bytes()).unwrap();
        assert_eq!(
            String::from_utf8(p.body).unwrap(),
            body.replace(part, &object_placeholder(Wire::Messages))
        );
    }

    /// Identical parts in one request count once: the memo key is the
    /// part's bytes.
    #[test]
    fn identical_parts_count_once() {
        let host = FakeHost::new();
        let sh = in_mode(&host, BinaryMode::Placeholder);
        let s = store().get(SessionKey([43; 32]));
        let img = json!({"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORZYXPAYLOAD"}});
        let body = json!({"messages": [{"role": "user", "content": [img, img]}]}).to_string();
        let p = prep(&sh, &s, Wire::Messages, body.as_bytes()).unwrap();
        let binary: Vec<u32> = p
            .kinds
            .iter()
            .filter(|(k, _)| k.label() == "BINARY")
            .map(|(_, n)| *n)
            .collect();
        assert_eq!(binary, vec![1]);
        assert_eq!(p.memo.len(), 1);
        let out = String::from_utf8(p.body).unwrap();
        assert_eq!(out.matches(&object_placeholder(Wire::Messages)).count(), 2);
    }

    /// Review finding 9: a tool result nested inside a binary container
    /// makes the part's and the group's edits overlap: `500 internal`,
    /// nothing forwarded.
    #[test]
    fn a_tool_result_inside_a_part_fails_closed() {
        let host = FakeHost::new();
        let sh = in_mode(&host, BinaryMode::Placeholder);
        let s = store().get(SessionKey([41; 32]));
        let up = Recording::default();
        let body = json!({"messages": [{"role": "user", "content": [
            {"type": "image", "source": {"type": "base64", "data": "iVBORZYXPAYLOAD"},
             "extra": {"type": "tool_result", "tool_use_id": "t", "content": "x"}}
        ]}]});
        assert_eq!(
            forward(&up, &sh, &s, Wire::Messages, &body).unwrap_err(),
            Fail::Internal
        );
        assert!(up.0.lock().unwrap().is_empty());
    }

    /// Review findings 9, 11, 12 and L65: where a part is found, and what
    /// is not a part.
    #[test]
    fn parts_at_odd_positions_are_replaced() {
        let host = FakeHost::new();
        let sh = in_mode(&host, BinaryMode::Placeholder);
        let s = store().get(SessionKey([42; 32]));
        let msg = |content: serde_json::Value| json!({"messages": [{"role": "user", "content": [content]}]});
        // A content-sourced document: only the image inside is a part; the
        // document's own text is sanitized.
        let out = run(
            &sh,
            &s,
            Wire::Messages,
            &msg(json!({"type": "document", "title": "Notiz", "source": {"type": "content", "content": [
                {"type": "text", "text": format!("Mail {EMAIL}")},
                {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORZYXPAYLOAD"}}
            ]}})),
        )
        .unwrap();
        assert_eq!(out.matches(&object_placeholder(Wire::Messages)).count(), 1);
        assert!(
            out.contains("\"title\":\"Notiz\"") && out.contains("<EMAIL_") && !out.contains(EMAIL)
        );
        no_part_left(&out);
        // A document whose source type is unknown is a part (fail closed).
        let unknown = msg(json!({"type": "document", "title": "ZyxTitle",
            "source": {"type": "zyx_future", "blob": "ZYXPAYLOAD"}}));
        let out = run(&sh, &s, Wire::Messages, &unknown).unwrap();
        assert_eq!(out.matches(&object_placeholder(Wire::Messages)).count(), 1);
        no_part_left(&out);
        assert_eq!(
            run(
                &in_mode(&host, BinaryMode::Refuse),
                &s,
                Wire::Messages,
                &unknown
            )
            .unwrap_err(),
            Fail::UnsupportedContent
        );
        // A binary block inside a tool call's input: no payload byte leaves.
        let out = run(
            &sh,
            &s,
            Wire::Messages,
            &json!({"messages": [{"role": "assistant", "content": [{"type": "tool_use",
                "id": "toolu_01D7FLrfh4GYq7yT1ULmeyqw", "name": "attach", "input": {"file": {"type": "image",
                "source": {"type": "base64", "media_type": "image/png", "data": "iVBORZYXPAYLOAD"}}}}]}]}),
        )
        .unwrap();
        assert_eq!(out.matches(&object_placeholder(Wire::Messages)).count(), 1);
        no_part_left(&out);
        // A data URI in a nested unknown object, and one in upper case.
        for uri in [
            "data:image/png;base64,iVBORZYXPAYLOAD",
            "DATA:IMAGE/PNG;BASE64,iVBORZYXPAYLOAD",
        ] {
            let out = run(
                &sh,
                &s,
                Wire::Messages,
                &json!({"messages": [], "zyx_unknown": {"deep": [{"blob": uri}]}}),
            )
            .unwrap();
            assert!(out.contains(&format!(r#""blob":"{P}""#)), "{out}");
            no_part_left(&out);
        }
        // Review finding 12: a Responses part inside an assistant message.
        let out = run(
            &sh,
            &s,
            Wire::Responses,
            &json!({"input": [{"type": "message", "role": "assistant", "content": [
                {"type": "output_text", "text": "hier"},
                {"type": "input_image", "image_url": "https://zyx-url.invalid/x.png"}
            ]}]}),
        )
        .unwrap();
        assert_eq!(out.matches(&object_placeholder(Wire::Responses)).count(), 1);
        no_part_left(&out);
    }

    /// Security review findings 1, 3, 4 (Task 2b): what is sent of `body`
    /// in `placeholder` mode, and the `refuse` mode verdict.
    fn both_modes(host: &Arc<FakeHost>, key: u8, wire: Wire, body: &serde_json::Value) -> String {
        let s = store().get(SessionKey([key; 32]));
        let refuse = in_mode(host, BinaryMode::Refuse);
        assert_eq!(
            run(&refuse, &s, wire, body).unwrap_err(),
            Fail::UnsupportedContent
        );
        let up = Recording::default();
        forward(&up, &in_mode(host, BinaryMode::Placeholder), &s, wire, body).unwrap();
        let sent = up.0.lock().unwrap();
        assert_eq!(sent.len(), 1);
        String::from_utf8(sent[0].body.to_vec()).unwrap()
    }

    /// Security finding 1: a binary container under a structural top-level
    /// parameter is a part like any other; a binary container inside a
    /// definition is refused in both modes.
    #[test]
    fn attachments_under_structural_parameters_are_parts() {
        let host = FakeHost::new();
        let responses = json!({"reasoning": {"x": {"type": "input_image",
            "image_url": "https://h.example/max-mustermann.png", "file_id": "file-ZQX123abc"}},
            "input": []});
        let out = both_modes(&host, 44, Wire::Responses, &responses);
        for m in ["h.example", "max-mustermann", "file-ZQX123abc"] {
            assert!(!out.contains(m), "{m} left the proxy: {out}");
        }
        assert_eq!(out.matches(&object_placeholder(Wire::Responses)).count(), 1);

        let messages = json!({"thinking": {"type": "image", "source": {"type": "base64",
            "media_type": "image/x-zyxmedia", "data": "iVBORZYXPAYLOAD"}}, "messages": []});
        let out = both_modes(&host, 45, Wire::Messages, &messages);
        no_part_left(&out);
        assert_eq!(out.matches(&object_placeholder(Wire::Messages)).count(), 1);

        let s = store().get(SessionKey([46; 32]));
        let definition = json!({"tools": [{"type": "function", "name": "f",
            "parameters": {"x": {"type": "input_image", "image_url": "https://zyx-url.invalid/x.png"}}}],
            "input": []});
        for mode in [BinaryMode::Placeholder, BinaryMode::Refuse] {
            assert_eq!(
                run(&in_mode(&host, mode), &s, Wire::Responses, &definition).unwrap_err(),
                Fail::UnsupportedContent
            );
        }
    }

    /// Security findings 3 and 4: `container_upload` and the
    /// OpenAI-compatible `video_url` are binary parts too.
    #[test]
    fn container_uploads_and_video_urls_are_parts() {
        let host = FakeHost::new();
        let upload = json!({"messages": [{"role": "user", "content": [
            {"type": "text", "text": "look"},
            {"type": "container_upload", "file_id": "file_011ZyxFileId8iCJcU1wXNR6q"}
        ]}]});
        let out = both_modes(&host, 47, Wire::Messages, &upload);
        no_part_left(&out);
        assert_eq!(out.matches(&object_placeholder(Wire::Messages)).count(), 1);

        let video = json!({"messages": [{"role": "user", "content": [
            {"type": "text", "text": "look"},
            {"type": "video_url", "video_url": {"url": "https://zyx-url.invalid/v.mp4"}}
        ]}]});
        let out = both_modes(&host, 48, Wire::Chat, &video);
        no_part_left(&out);
        assert_eq!(out.matches(&object_placeholder(Wire::Chat)).count(), 1);
    }
}
