//! The text origin of a leaf in the proxy pipeline (M8 spec §20, amendment
//! 2026-10-20; rulings L107, L120): the critical tests of plan
//! 2026-10-20-origin-wiring, Task 2.
//!
//! The pipeline runs directly with the client mode explicit. The fake host's
//! engine ([`FakeHost::with_origin_ner`]) reads the origin: its sanitizer NER
//! flags `rust` as a PERSON at 0.6, which core drops only in harness-static
//! text (L98), and its verifier NER flags `Claude` at 0.99, which core
//! accepts only in harness-static text (L103). Bodies are raw JSON with the
//! system text before the messages: `serde_json::json!` sorts keys, and
//! tests 3 and 4 need the system leaf processed first.

use std::time::Duration;

use crate::error::Fail;
use crate::pipeline::{Prepared, Shared, sanitize_request};
use crate::routes::Wire;
use crate::session::{ClientMode, Session, SessionKey, SessionStore};
use crate::testing::FakeHost;
use crate::walk::walk_for;

const SYS_WORD: &str = "Answer every question briefly, danke rust";
const SYS_PRODUCT: &str = "You are Claude. Answer every question briefly.";
const SYS_BOTH: &str = "You are Claude. Answer every question briefly, danke rust";
const USER_WORD: &str = "danke rust";
const CALL: &str = "call_DdmO9pD3xa9XTPNJ32zg2hcA";

fn store() -> SessionStore {
    SessionStore::new(
        Duration::from_secs(60),
        16,
        inumaki_core::config::TokenSettings::default(),
        1 << 20,
    )
}

fn shared() -> Shared {
    crate::pipeline::test_shared(FakeHost::with_origin_ner())
}

fn prep_mode(
    sh: &Shared,
    s: &Session,
    wire: Wire,
    body: &str,
    mode: ClientMode,
) -> Result<Prepared, Fail> {
    prep_route(sh, s, wire, body, mode, false)
}

/// [`prep_mode`] for a route that does (`skip_static_ner`) or does not skip
/// the NER models on its harness-static leaves.
fn prep_route(
    sh: &Shared,
    s: &Session,
    wire: Wire,
    body: &str,
    mode: ClientMode,
    skip_static_ner: bool,
) -> Result<Prepared, Fail> {
    let w = walk_for(wire, body.as_bytes(), sh.cfg.binary).map_err(|_| Fail::BadRequest)?;
    sanitize_request(
        sh,
        s,
        wire,
        body.as_bytes(),
        &w,
        mode,
        skip_static_ner,
        &mut crate::timing::StageTimes::default(),
    )
}

/// What a forwarded request commits (spec §5 step 7).
fn commit(s: &Session, mut p: Prepared) {
    crate::pipeline::commit_cache(s, &mut p);
}

/// A JSON string literal.
fn q(t: &str) -> String {
    serde_json::to_string(t).unwrap()
}

fn out(p: Prepared) -> String {
    String::from_utf8(p.body).unwrap()
}

/// A Messages body: `system` (when given) first, then the `messages`.
fn msgs(system: Option<&str>, messages: &[(&str, &str)]) -> String {
    let m: Vec<String> = messages
        .iter()
        .map(|(role, text)| format!(r#"{{"role":"{role}","content":{}}}"#, q(text)))
        .collect();
    let sys = system.map_or(String::new(), |t| format!(r#""system":{},"#, q(t)));
    format!(
        r#"{{"model":"claude-sonnet-4-5","max_tokens":16,{sys}"messages":[{}]}}"#,
        m.join(",")
    )
}

fn tokenized(body: &str) {
    assert!(!body.contains(USER_WORD), "left in clear: {body}");
    assert!(body.contains("<PERSON_"), "no token minted: {body}");
}

fn is_block(r: &Result<Prepared, Fail>) -> bool {
    matches!(r, Err(Fail::PrivacyBlock { .. }))
}

/// The token after `danke ` in `text`.
fn token_in(text: &str) -> String {
    let at = text.find("danke <PERSON_").expect("a minted token") + "danke ".len();
    let end = at + text[at..].find('>').unwrap() + 1;
    text[at..end].to_string()
}

fn field(body: &str, path: &[&str]) -> String {
    let mut v: serde_json::Value = serde_json::from_str(body).unwrap();
    for p in path {
        v = match p.parse::<usize>() {
            Ok(i) => v[i].take(),
            Err(_) => v[*p].take(),
        };
    }
    v.as_str().unwrap().to_string()
}

/// Test 1: the leading system prompt of a trusted request reads as
/// harness-static text (ruling L122: Messages top-level `system`, Responses
/// `instructions` and leading system/developer items, Chat leading
/// system/developer messages); the same bodies in a restricted request do
/// not. Later system/developer items are test 2's.
#[test]
fn system_positions_of_trusted_requests_read_as_harness_static() {
    let sh = shared();
    let st = store();
    let user_resp =
        r#"{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}"#;
    let cases: Vec<(&str, Wire, String)> = vec![
        (
            "messages system string",
            Wire::Messages,
            msgs(Some(SYS_WORD), &[("user", "hi")]),
        ),
        (
            "messages system block",
            Wire::Messages,
            format!(
                r#"{{"model":"m","max_tokens":16,"system":[{{"type":"text","text":{}}}],"messages":[{{"role":"user","content":"hi"}}]}}"#,
                q(SYS_WORD)
            ),
        ),
        (
            "responses instructions",
            Wire::Responses,
            format!(
                r#"{{"model":"gpt-5.1","instructions":{},"input":[{user_resp}]}}"#,
                q(SYS_WORD)
            ),
        ),
        (
            "responses developer message",
            Wire::Responses,
            format!(
                r#"{{"model":"gpt-5.1","input":[{{"type":"message","role":"developer","content":[{{"type":"input_text","text":{}}}]}},{user_resp}]}}"#,
                q(SYS_WORD)
            ),
        ),
        (
            "responses system item after a developer item",
            Wire::Responses,
            format!(
                r#"{{"model":"gpt-5.1","input":[{{"type":"message","role":"developer","content":"Be brief."}},{{"role":"system","content":{}}},{user_resp}]}}"#,
                q(SYS_WORD)
            ),
        ),
        (
            "chat system message",
            Wire::Chat,
            format!(
                r#"{{"model":"gpt-5.1","messages":[{{"role":"system","content":{}}},{{"role":"user","content":"hi"}}]}}"#,
                q(SYS_WORD)
            ),
        ),
        (
            "chat developer message after a system message",
            Wire::Chat,
            format!(
                r#"{{"model":"gpt-5.1","messages":[{{"role":"system","content":"Be brief."}},{{"role":"developer","content":{}}},{{"role":"user","content":"hi"}}]}}"#,
                q(SYS_WORD)
            ),
        ),
    ];
    for (i, (name, wire, body)) in cases.iter().enumerate() {
        let n = u8::try_from(i).unwrap();
        let trusted = prep_mode(
            &sh,
            &st.get(SessionKey([n; 32])),
            *wire,
            body,
            ClientMode::Trusted,
        )
        .unwrap_or_else(|_| panic!("{name}: trusted request refused"));
        assert_eq!(out(trusted), *body, "{name}: trusted: clear, byte for byte");
        let restricted = prep_mode(
            &sh,
            &st.get(SessionKey([n + 50; 32])),
            *wire,
            body,
            ClientMode::Restricted,
        )
        .unwrap_or_else(|_| panic!("{name}: restricted request refused"));
        tokenized(&out(restricted));
    }

    // The verifier side: `Claude` is accepted in a system position only.
    let product = [
        (
            "messages",
            Wire::Messages,
            msgs(Some(SYS_PRODUCT), &[("user", "hi")]),
        ),
        (
            "responses",
            Wire::Responses,
            format!(
                r#"{{"model":"gpt-5.1","instructions":{},"input":[{user_resp}]}}"#,
                q(SYS_PRODUCT)
            ),
        ),
    ];
    for (i, (name, wire, body)) in product.iter().enumerate() {
        let n = 100 + u8::try_from(i).unwrap();
        let trusted = prep_mode(
            &sh,
            &st.get(SessionKey([n; 32])),
            *wire,
            body,
            ClientMode::Trusted,
        )
        .unwrap_or_else(|_| panic!("{name}: trusted product text refused"));
        assert_eq!(out(trusted), *body, "{name}: trusted: clear");
        let restricted = prep_mode(
            &sh,
            &st.get(SessionKey([n + 20; 32])),
            *wire,
            body,
            ClientMode::Restricted,
        );
        assert!(is_block(&restricted), "{name}: restricted must block");
    }
}

/// Test 2: no other position of a trusted request is harness-static,
/// including a system/developer item after the leading run (ruling L122).
#[test]
fn every_other_position_stays_free() {
    let sh = shared();
    let st = store();
    let t = q(SYS_WORD);
    let user_resp = r#"{"type":"message","role":"user","content":"hi"}"#;
    let call_resp =
        format!(r#"{{"type":"function_call","call_id":"{CALL}","name":"f","arguments":"{{}}"}}"#);
    let cases: Vec<(&str, Wire, String, bool)> = vec![
        (
            "messages system object in messages",
            Wire::Messages,
            msgs(None, &[("system", SYS_WORD), ("user", "hi")]),
            false,
        ),
        (
            "responses developer item after a user item",
            Wire::Responses,
            format!(
                r#"{{"model":"gpt-5.1","instructions":"Be brief.","input":[{user_resp},{{"type":"message","role":"developer","content":[{{"type":"input_text","text":{t}}}]}}]}}"#
            ),
            false,
        ),
        (
            "responses system item after a function_call item",
            Wire::Responses,
            format!(
                r#"{{"model":"gpt-5.1","input":[{{"role":"developer","content":"Be brief."}},{call_resp},{{"role":"system","content":{t}}}]}}"#
            ),
            false,
        ),
        (
            "chat system message after the first user message",
            Wire::Chat,
            format!(
                r#"{{"model":"gpt-5.1","messages":[{{"role":"system","content":"Be brief."}},{{"role":"user","content":"hi"}},{{"role":"system","content":{t}}}]}}"#
            ),
            false,
        ),
        (
            "chat developer message after an assistant message",
            Wire::Chat,
            format!(
                r#"{{"model":"gpt-5.1","messages":[{{"role":"assistant","content":"ok"}},{{"role":"developer","content":{t}}}]}}"#
            ),
            false,
        ),
        (
            "messages user",
            Wire::Messages,
            msgs(None, &[("user", SYS_WORD)]),
            false,
        ),
        (
            "messages tool_result",
            Wire::Messages,
            format!(
                r#"{{"model":"m","max_tokens":16,"messages":[{{"role":"user","content":[{{"type":"tool_result","tool_use_id":"toolu_01Hn4Bq9xL2mZ8cVt5sKpR3w","content":{t}}}]}}]}}"#
            ),
            true,
        ),
        (
            "messages assistant",
            Wire::Messages,
            msgs(None, &[("user", "hi"), ("assistant", SYS_WORD)]),
            false,
        ),
        (
            "responses plain input",
            Wire::Responses,
            format!(r#"{{"model":"gpt-5.1","input":{t}}}"#),
            false,
        ),
        (
            "chat tool message",
            Wire::Chat,
            format!(
                r#"{{"model":"gpt-5.1","messages":[{{"role":"user","content":"hi"}},{{"role":"assistant","tool_calls":[{{"id":"{CALL}","type":"function","function":{{"name":"f","arguments":"{{}}"}}}}]}},{{"role":"tool","tool_call_id":"{CALL}","content":{t}}}]}}"#
            ),
            true,
        ),
        (
            "chat unknown role",
            Wire::Chat,
            format!(
                r#"{{"model":"gpt-5.1","messages":[{{"role":"narrator","content":{t}}},{{"role":"user","content":"hi"}}]}}"#
            ),
            false,
        ),
    ];
    for (i, (name, wire, body, may_withhold)) in cases.iter().enumerate() {
        let r = prep_mode(
            &sh,
            &st.get(SessionKey([u8::try_from(i).unwrap(); 32])),
            *wire,
            body,
            ClientMode::Trusted,
        )
        .unwrap_or_else(|_| panic!("{name}: trusted request refused"));
        let sent = out(r);
        assert!(!sent.contains(USER_WORD), "{name}: left in clear: {sent}");
        if *may_withhold && !sent.contains("<PERSON_") {
            assert!(
                !sent.contains("rust"),
                "{name}: neither tokenized nor withheld"
            );
        } else {
            assert!(sent.contains("<PERSON_"), "{name}: not tokenized: {sent}");
        }
    }
    // The verifier side: `Claude` in a user message blocks.
    let r = prep_mode(
        &sh,
        &st.get(SessionKey([90; 32])),
        Wire::Messages,
        &msgs(None, &[("user", SYS_PRODUCT)]),
        ClientMode::Trusted,
    );
    assert!(
        is_block(&r),
        "a user message with the product name must block"
    );
    // `Claude` in a system/developer item after the leading run blocks.
    for (i, (name, wire, body)) in [
        (
            "chat",
            Wire::Chat,
            format!(
                r#"{{"model":"gpt-5.1","messages":[{{"role":"user","content":"hi"}},{{"role":"system","content":{}}}]}}"#,
                q(SYS_PRODUCT)
            ),
        ),
        (
            "responses",
            Wire::Responses,
            format!(
                r#"{{"model":"gpt-5.1","input":[{user_resp},{{"role":"developer","content":{}}}]}}"#,
                q(SYS_PRODUCT)
            ),
        ),
    ]
    .iter()
    .enumerate()
    {
        let r = prep_mode(
            &sh,
            &st.get(SessionKey([91 + u8::try_from(i).unwrap(); 32])),
            *wire,
            body,
            ClientMode::Trusted,
        );
        assert!(
            is_block(&r),
            "{name}: a later system item with the product name must block"
        );
    }
}

/// Test 2b (final review M3, ruling L2-58): a Chat message's `name` inside
/// the leading system run is a name field, not harness prose. A dropped
/// shape there is tokenized, while the same text as the message's content
/// stays harness-static.
#[test]
fn a_leading_chat_name_stays_free() {
    let sh = shared();
    let st = store();
    let body = format!(
        r#"{{"model":"gpt-5.1","messages":[{{"role":"system","name":{},"content":"Be brief."}},{{"role":"user","content":"hi"}}]}}"#,
        q(SYS_WORD)
    );
    let r = prep_mode(
        &sh,
        &st.get(SessionKey([7; 32])),
        Wire::Chat,
        &body,
        ClientMode::Trusted,
    )
    .expect("trusted request refused");
    tokenized(&out(r));
}

/// Test 3: the same bytes under two origins never share a session cache
/// entry (step 5).
#[test]
fn same_bytes_under_two_origins_never_share_a_cache_entry() {
    let sh = shared();
    let st = store();
    let trusted = ClientMode::Trusted;

    // A system entry never answers a user leaf of the same bytes.
    let s = st.get(SessionKey([1; 32]));
    let t1 = prep_mode(
        &sh,
        &s,
        Wire::Messages,
        &msgs(Some(SYS_WORD), &[("user", "hi")]),
        trusted,
    )
    .unwrap();
    commit(&s, t1);
    let t2 = msgs(
        Some(SYS_WORD),
        &[("user", "hi"), ("assistant", "ok"), ("user", SYS_WORD)],
    );
    let p = prep_mode(&sh, &s, Wire::Messages, &t2, trusted).unwrap();
    // The one hit is `hi`. A system-leaf hit would be re-run by step 6b (the
    // user leaf mints `rust`) and counts as a miss, so the hit count does not
    // observe the system entry; the assertions below do.
    assert_eq!(p.hits, 1, "only `hi` is a hit");
    let sent = out(p);
    assert!(
        !sent.contains(USER_WORD),
        "a system entry answered a user leaf: {sent}"
    );
    assert!(sent.contains("<PERSON_"), "no token minted: {sent}");

    // A user entry never answers a system leaf of the same bytes.
    let s = st.get(SessionKey([2; 32]));
    let t1 = prep_mode(
        &sh,
        &s,
        Wire::Messages,
        &msgs(None, &[("user", SYS_WORD)]),
        trusted,
    )
    .unwrap();
    commit(&s, t1);
    let t2 = msgs(Some(SYS_WORD), &[("user", SYS_WORD)]);
    let p = prep_mode(&sh, &s, Wire::Messages, &t2, trusted).unwrap();
    assert_eq!(
        (p.misses, p.hits),
        (1, 1),
        "the system leaf ran the engine; the user leaf hit"
    );
}

/// Test 4: the leak closure's full re-run (step 6b) and the verifier keep
/// the leaf's origin.
#[test]
fn the_closure_and_the_verifier_keep_the_leaf_origin() {
    let sh = shared();
    let st = store();
    let trusted = ClientMode::Trusted;
    let both = |s: &Session, messages: &[(&str, &str)]| {
        prep_mode(
            &sh,
            s,
            Wire::Messages,
            &msgs(Some(SYS_BOTH), messages),
            trusted,
        )
    };
    let check = |sent: &str, user_at: &str| {
        let token = token_in(&field(sent, &["messages", user_at, "content"]));
        assert_eq!(
            field(sent, &["system"]),
            format!("You are Claude. Answer every question briefly, danke {token}"),
            "`rust` tokenized with the user leaf's token, `Claude` in clear"
        );
    };

    // One request: the system leaf passes first with `rust` in clear, then
    // step 6b re-runs it with the user leaf's mint.
    let s = st.get(SessionKey([1; 32]));
    let p = both(&s, &[("user", USER_WORD)]).expect("trusted: ok");
    check(&out(p), "0");
    let restricted = prep_mode(
        &sh,
        &st.get(SessionKey([2; 32])),
        Wire::Messages,
        &msgs(Some(SYS_BOTH), &[("user", USER_WORD)]),
        ClientMode::Restricted,
    );
    assert!(is_block(&restricted), "restricted: `Claude` blocks");

    // Across turns: the system leaf is a cache hit, re-run by the
    // projection (6b), then by the full engine with the projection off.
    // The projection path is origin-independent (D-6): in the default build
    // the `true` leg pins the origin-bearing cache key and result equality
    // only.
    for (n, projection) in [(3u8, true), (4u8, false)] {
        let _off = (!projection).then(crate::pipeline::disable_projection_on_this_thread);
        let s = st.get(SessionKey([n; 32]));
        let t1 = both(&s, &[("user", "hi")]).expect("turn 1");
        commit(&s, t1);
        let p = both(
            &s,
            &[("user", "hi"), ("assistant", "ok"), ("user", USER_WORD)],
        )
        .unwrap_or_else(|_| panic!("turn 2 (projection {projection}): refused"));
        assert!(
            p.hits >= 1,
            "the system leaf is a hit (projection {projection})"
        );
        check(&out(p), "2");
    }
}

/// A static system text of more than `STATIC_MIN_BYTES`, with an email and
/// nothing a stand-in model would be needed for.
fn long_static(email: &str) -> String {
    let mut t = format!("Write to {email} when a request is unclear. ");
    while t.len() < crate::memo::STATIC_MIN_BYTES + 512 {
        t.push_str("Answer in short paragraphs and keep a calm tone. ");
    }
    t
}

/// The NER calls (both roles) on inputs of at least `STATIC_MIN_BYTES`.
fn ner_calls(host: &FakeHost) -> usize {
    let n = host.ner.as_ref().unwrap();
    n.sanitizer.long() + n.verifier.long()
}

/// A route that skips the NER models for its harness-static leaves runs
/// them on the model-free engine: no model call, the deterministic
/// detectors still tokenize an email, and the same request on a route that
/// does not skip reaches the models.
#[test]
fn a_skipping_route_keeps_the_models_off_harness_static_leaves() {
    let st = store();
    let sys = long_static("ops@example.at");
    let body = msgs(Some(&sys), &[("user", "hi")]);

    let host = FakeHost::with_ner(false);
    let sh = crate::pipeline::test_shared(host.clone());
    let p = prep_route(
        &sh,
        &st.get(SessionKey([1; 32])),
        Wire::Messages,
        &body,
        ClientMode::Trusted,
        true,
    )
    .unwrap();
    assert_eq!(ner_calls(&host), 0, "no model ran on the static leaf");
    let sent = field(&out(p), &["system"]);
    assert!(!sent.contains("ops@example.at"), "email still tokenized");
    assert!(sent.contains("<EMAIL_"), "{sent}");

    let host = FakeHost::with_ner(false);
    let sh = crate::pipeline::test_shared(host.clone());
    prep_route(
        &sh,
        &st.get(SessionKey([2; 32])),
        Wire::Messages,
        &body,
        ClientMode::Trusted,
        false,
    )
    .unwrap();
    assert!(
        ner_calls(&host) > 0,
        "a route that scans reaches the models"
    );
}

/// Only harness-static leaves skip: a restricted request (no client header)
/// and a user message of any size still reach the models on a skipping route.
#[test]
fn a_skipping_route_still_scans_user_text_and_restricted_requests() {
    let st = store();
    let long = long_static("ops@example.at");

    let host = FakeHost::with_ner(false);
    let sh = crate::pipeline::test_shared(host.clone());
    prep_route(
        &sh,
        &st.get(SessionKey([3; 32])),
        Wire::Messages,
        &msgs(Some(&long), &[("user", "hi")]),
        ClientMode::Restricted,
        true,
    )
    .unwrap();
    assert!(ner_calls(&host) > 0, "restricted: the system text is Free");

    let host = FakeHost::with_ner(false);
    let sh = crate::pipeline::test_shared(host.clone());
    prep_route(
        &sh,
        &st.get(SessionKey([4; 32])),
        Wire::Messages,
        &msgs(Some("Be brief."), &[("user", &long)]),
        ClientMode::Trusted,
        true,
    )
    .unwrap();
    assert!(
        ner_calls(&host) > 0,
        "a user message is Free whatever its size"
    );
}
