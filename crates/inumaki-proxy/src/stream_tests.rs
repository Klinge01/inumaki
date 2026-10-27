//! Streaming tests (spec §15 tests 5, 10, 11 streaming parts; Review Focus 4).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use inumaki_core::TextOrigin;
use inumaki_core::config::TokenSettings;
use inumaki_core::span::EntityKind;
use serde_json::{Value, json};

use crate::closure::Gen;
use crate::config::TripwireMode;
use crate::host::{ProxyEvent, Scope};
use crate::pipeline::{Shared, test_shared};
use crate::routes::{UpstreamId, Wire};
use crate::session::{ClientMode, SeedStamp, Session, SessionKey, SessionStore};
use crate::sse::SseEvent;
use crate::sse::{MAX_EVENT, SseParser, serialize};
use crate::stream::P::K;
use crate::stream::{Abort, Act, ChanKey, ChanKind, Codec, Rewriter, abort_message, find, str_at};
use crate::testing::{CHECK_DS, CHECK_NAME, CHECK_TOKEN, DS_TOKEN, FakeHost, NAME};
use crate::walk::Class;

pub(crate) fn ev(name: Option<&str>, data: Value) -> Vec<u8> {
    serialize(name, None, data.to_string().as_bytes()).unwrap()
}

/// What a client sees in a stream.
#[derive(Debug, Default)]
pub(crate) struct Visible {
    pub text: String,
    pub args: Vec<String>,
    pub repeats: Vec<String>,
    pub error: Option<String>,
    pub message: Option<String>,
    pub seqs: Vec<u64>,
    pub tool_starts: usize,
}

/// Decode the client-visible content of a stream of `wire`.
pub(crate) fn visible(wire: Wire, bytes: &[u8]) -> Visible {
    let mut p = SseParser::new(MAX_EVENT);
    let mut evs = p.push(bytes).unwrap();
    evs.extend(p.finish().unwrap());
    let mut v = Visible::default();
    let mut args: BTreeMap<(u64, u64), String> = BTreeMap::new();
    for e in evs {
        let Some(d) = e.data else { continue };
        let Ok(j) = serde_json::from_slice::<Value>(&d) else {
            continue;
        };
        match wire {
            Wire::Messages => match j["type"].as_str() {
                Some("content_block_start") if j["content_block"]["type"] == "tool_use" => {
                    v.tool_starts += 1
                }
                Some("content_block_delta") => match j["delta"]["type"].as_str() {
                    Some("text_delta") => v.text.push_str(j["delta"]["text"].as_str().unwrap()),
                    Some("input_json_delta") => args
                        .entry((j["index"].as_u64().unwrap(), 0))
                        .or_default()
                        .push_str(j["delta"]["partial_json"].as_str().unwrap()),
                    _ => {}
                },
                Some("error") => {
                    v.error = j["error"]["type"].as_str().map(str::to_string);
                    v.message = j["error"]["message"].as_str().map(str::to_string);
                }
                _ => {}
            },
            Wire::Responses => {
                if let Some(s) = j["sequence_number"].as_u64() {
                    v.seqs.push(s);
                }
                let item = |it: &Value, v: &mut Visible| {
                    for c in it["content"].as_array().into_iter().flatten() {
                        if let Some(t) = c["text"].as_str() {
                            v.repeats.push(t.into());
                        }
                    }
                    if let Some(a) = it["arguments"].as_str() {
                        v.repeats.push(a.into());
                    }
                };
                match j["type"].as_str() {
                    Some("response.output_item.added") if j["item"]["type"] == "function_call" => {
                        v.tool_starts += 1
                    }
                    Some("response.output_text.delta") => {
                        v.text.push_str(j["delta"].as_str().unwrap())
                    }
                    Some(
                        "response.function_call_arguments.delta"
                        | "response.custom_tool_call_input.delta",
                    ) => args
                        .entry((j["output_index"].as_u64().unwrap(), 0))
                        .or_default()
                        .push_str(j["delta"].as_str().unwrap()),
                    Some("response.output_text.done") => {
                        v.repeats.push(j["text"].as_str().unwrap().into())
                    }
                    Some("response.content_part.done") => v
                        .repeats
                        .push(j["part"]["text"].as_str().unwrap_or_default().into()),
                    Some("response.function_call_arguments.done") => {
                        v.repeats.push(j["arguments"].as_str().unwrap().into())
                    }
                    Some("response.output_item.done") => item(&j["item"], &mut v),
                    Some("response.completed") => {
                        for it in j["response"]["output"].as_array().into_iter().flatten() {
                            item(it, &mut v)
                        }
                    }
                    Some("response.failed") => {
                        v.error = j["response"]["error"]["code"].as_str().map(str::to_string)
                    }
                    _ => {}
                }
            }
            Wire::Chat => {
                if let Some(t) = j["error"]["type"].as_str() {
                    v.error = Some(t.into());
                }
                for c in j["choices"].as_array().into_iter().flatten() {
                    if let Some(t) = c["delta"]["content"].as_str() {
                        v.text.push_str(t);
                    }
                    for tc in c["delta"]["tool_calls"].as_array().into_iter().flatten() {
                        if tc["function"]["name"].is_string() {
                            v.tool_starts += 1;
                        }
                        if let Some(a) = tc["function"]["arguments"].as_str() {
                            args.entry((
                                c["index"].as_u64().unwrap_or(0),
                                tc["index"].as_u64().unwrap_or(0),
                            ))
                            .or_default()
                            .push_str(a);
                        }
                    }
                }
            }
        }
    }
    v.args = args.into_values().collect();
    v
}

pub(crate) fn rig(host: Arc<FakeHost>) -> (Shared, SessionStore) {
    (
        test_shared(host),
        SessionStore::new(
            Duration::from_secs(60),
            4,
            TokenSettings::default(),
            1 << 20,
        ),
    )
}

/// Run `stream` through a Rewriter in one chunk; the client's bytes and
/// whether it completed. The driver contract of plan M8-2 Task 5: an `Err`
/// from `event` is answered with `abort` and nothing else is called.
pub(crate) fn rewrite(
    sh: &Shared,
    s: &Session,
    wire: Wire,
    mode: ClientMode,
    scope: Scope,
    seed: SeedStamp,
    stream: &[u8],
) -> (Vec<u8>, bool) {
    let up = if wire == Wire::Messages {
        UpstreamId::Anthropic
    } else {
        UpstreamId::Openai
    };
    drive(Rewriter::new(sh, s, wire, up, mode, scope, seed), stream)
}

/// Feed `stream` to `rw` in one chunk, following the driver contract.
fn drive(mut rw: Rewriter<'_>, stream: &[u8]) -> (Vec<u8>, bool) {
    let mut p = SseParser::new(MAX_EVENT);
    let mut out = Vec::new();
    let mut evs = p.push(stream).unwrap();
    evs.extend(p.finish().unwrap());
    for e in evs {
        match rw.event(e) {
            Ok(o) => o.into_iter().for_each(|b| out.extend(b)),
            Err(a) => {
                rw.abort(&a).into_iter().for_each(|b| out.extend(b));
                return (out, false);
            }
        }
    }
    let (fin, ok) = rw.finish();
    fin.into_iter().for_each(|b| out.extend(b));
    (out, ok)
}

/// [`rewrite`] on a normal route with an unverified stamp.
pub(crate) fn rewrite_session(
    sh: &Shared,
    s: &Session,
    wire: Wire,
    mode: ClientMode,
    stream: &[u8],
) -> (Vec<u8>, bool) {
    rewrite(
        sh,
        s,
        wire,
        mode,
        Scope::Datasets,
        SeedStamp::unverified(),
        stream,
    )
}

/// Two-part splits of `s` at every character boundary.
pub(crate) fn halves(s: &str) -> Vec<[&str; 2]> {
    (0..=s.len())
        .filter(|i| s.is_char_boundary(*i))
        .map(|i| [&s[..i], &s[i..]])
        .collect()
}

/// An original that needs JSON escaping, minted as a session token.
pub(crate) const ODD: &str = "Zoë \"Q\" \\ Quolnath\nzwei";

pub(crate) fn session_token(s: &Session) -> String {
    s.with_context(|c| inumaki_core::token::TokenStore::token_for(c, &EntityKind::Person, ODD))
        .unwrap()
        .as_str()
        .to_string()
}

pub(crate) fn messages_stream(text: &[&str], args: &[&str], thinking: &str, end: bool) -> Vec<u8> {
    let d = |i: u32, delta: Value| {
        ev(
            Some("content_block_delta"),
            json!({"type": "content_block_delta", "index": i, "delta": delta}),
        )
    };
    let mut s = Vec::new();
    s.extend(ev(
        Some("message_start"),
        json!({"type": "message_start", "message": {"id": "m", "type": "message", "role": "assistant", "content": [], "model": "x"}}),
    ));
    s.extend(ev(
        Some("content_block_start"),
        json!({"type": "content_block_start", "index": 0, "content_block": {"type": "thinking", "thinking": ""}}),
    ));
    s.extend(d(
        0,
        json!({"type": "thinking_delta", "thinking": thinking}),
    ));
    s.extend(d(0, json!({"type": "signature_delta", "signature": "sig"})));
    s.extend(ev(
        Some("content_block_stop"),
        json!({"type": "content_block_stop", "index": 0}),
    ));
    s.extend(ev(
        Some("content_block_start"),
        json!({"type": "content_block_start", "index": 1, "content_block": {"type": "text", "text": ""}}),
    ));
    for t in text {
        s.extend(d(1, json!({"type": "text_delta", "text": t})));
    }
    if !end {
        return s; // the upstream cut here
    }
    s.extend(ev(
        Some("content_block_stop"),
        json!({"type": "content_block_stop", "index": 1}),
    ));
    s.extend(tool_block(2, args));
    s.extend(ev(
        Some("message_delta"),
        json!({"type": "message_delta", "delta": {"stop_reason": "tool_use"}}),
    ));
    s.extend(ev(Some("message_stop"), json!({"type": "message_stop"})));
    s
}

/// A `tool_use` block at `index` with `args` as its `input_json_delta`s.
fn tool_block(index: u32, args: &[&str]) -> Vec<u8> {
    let mut s = ev(
        Some("content_block_start"),
        json!({"type": "content_block_start", "index": index, "content_block": {"type": "tool_use", "id": "t", "name": "write", "input": {}}}),
    );
    for a in args {
        s.extend(ev(
            Some("content_block_delta"),
            json!({"type": "content_block_delta", "index": index, "delta": {"type": "input_json_delta", "partial_json": a}}),
        ));
    }
    s.extend(ev(
        Some("content_block_stop"),
        json!({"type": "content_block_stop", "index": index}),
    ));
    s
}

/// Spec §15 tests 10 and 11 (Messages), decision 12 (arguments: session tokens only).
#[test]
fn messages_stream_restores_split_tokens_and_escapes_session_arguments() {
    let (sh, st) = rig(FakeHost::new());
    let s = st.get(SessionKey([1; 32]));
    let tok = session_token(&s);
    let text = format!("Hallo {tok} und {DS_TOKEN}.");
    let args = format!(r#"{{"to":"{tok}","cc":"{DS_TOKEN}"}}"#);
    let want = format!("Hallo {ODD} und {NAME}.");
    let check = |out: &[u8]| {
        let v = visible(Wire::Messages, out);
        assert_eq!(v.text, want);
        let a: Value = serde_json::from_str(&v.args[0]).expect("arguments stay JSON");
        assert_eq!(a["to"], ODD, "session token restored, JSON-escaped");
        assert_eq!(a["cc"], DS_TOKEN, "dataset token left in arguments");
    };
    for [x, y] in halves(&text) {
        let (out, ok) = rewrite_session(
            &sh,
            &s,
            Wire::Messages,
            ClientMode::Trusted,
            &messages_stream(&[x, y], &[args.as_str()], "", true),
        );
        assert!(ok);
        check(&out);
    }
    for [x, y] in halves(&args) {
        let (out, ok) = rewrite_session(
            &sh,
            &s,
            Wire::Messages,
            ClientMode::Trusted,
            &messages_stream(&[text.as_str()], &[x, y], "", true),
        );
        assert!(ok);
        check(&out);
    }
    // Restricted mode: dataset tokens stay tokens in text too.
    let (out, _) = rewrite_session(
        &sh,
        &s,
        Wire::Messages,
        ClientMode::Restricted,
        &messages_stream(&[text.as_str()], &[args.as_str()], "", true),
    );
    assert_eq!(
        visible(Wire::Messages, &out).text,
        format!("Hallo {ODD} und {DS_TOKEN}.")
    );
}

/// Spec §15 test 5 (streaming part): thinking passes unchanged and is
/// seeded with the producing request's stamp; text and arguments are
/// seeded as the request walker keys them.
#[test]
fn streamed_thinking_passes_unchanged_and_is_seeded() {
    let (sh, st) = rig(FakeHost::new());
    let s = st.get(SessionKey([2; 32]));
    let tok = session_token(&s);
    let thinking = format!("{tok} denkt nach");
    let stamp = SeedStamp {
        generation: Gen {
            entries: 3,
            removed: 1,
        },
        ds: Arc::from([7u64]),
    };
    let args = format!(r#"{{"to":"{tok}"}}"#);
    let (out, ok) = rewrite(
        &sh,
        &s,
        Wire::Messages,
        ClientMode::Trusted,
        Scope::Datasets,
        stamp.clone(),
        &messages_stream(
            &["fertig ", tok.as_str()],
            &[args.as_str()],
            &thinking,
            true,
        ),
    );
    assert!(ok);
    let sent: Vec<String> = String::from_utf8_lossy(&out)
        .lines()
        .filter_map(|l| l.strip_prefix("data: "))
        .filter_map(|d| serde_json::from_str::<Value>(d).ok())
        .filter_map(|j| j["delta"]["thinking"].as_str().map(str::to_string))
        .collect();
    assert_eq!(
        sent,
        vec![thinking.clone()],
        "thinking passes unchanged, token included"
    );
    let st = s
        .seed_stamp(&sh.keys.digest("scan", thinking.as_bytes()))
        .expect("provider-written reasoning is seeded");
    assert_eq!(
        st.generation, stamp.generation,
        "the producing request's stamp"
    );
    assert_eq!(&*st.ds, &*stamp.ds);
    let restored = format!("fertig {ODD}");
    let hit = s
        .cache()
        .get(&sh.keys.leaf(
            Wire::Messages,
            Class::Text,
            TextOrigin::Free,
            restored.as_bytes(),
        ))
        .expect("the text the harness will resend is seeded");
    assert_eq!(
        hit.cached.text,
        format!("fertig {tok}"),
        "mapped to what the model wrote"
    );
    let arg = s
        .cache()
        .get(&sh.keys.leaf(
            Wire::Messages,
            Class::ToolInput,
            TextOrigin::Free,
            ODD.as_bytes(),
        ))
        .expect("each argument leaf is seeded as the request walker keys it");
    assert_eq!(arg.cached.text, tok);
}

/// Review Focus 4: an upstream cut never shows the partial token, ends with the abort event, seeds nothing.
#[test]
fn an_upstream_cut_ends_with_the_abort_event_and_seeds_nothing() {
    let (sh, st) = rig(FakeHost::new());
    let s = st.get(SessionKey([3; 32]));
    let (out, ok) = rewrite_session(
        &sh,
        &s,
        Wire::Messages,
        ClientMode::Trusted,
        &messages_stream(&["Hallo <PERS"], &[], "denkt", false),
    );
    assert!(!ok);
    let v = visible(Wire::Messages, &out);
    assert_eq!(v.error.as_deref(), Some("api_error"));
    assert_eq!(v.message.as_deref(), Some("inumaki: stream_aborted"));
    assert_eq!(v.text, "Hallo ", "the held partial token is not sent");
    assert!(!String::from_utf8_lossy(&out).contains("<PERS"));
    assert_eq!(s.cache().len(), 0, "nothing seeded");
    assert!(
        s.seed_stamp(&sh.keys.digest("scan", b"denkt")).is_none(),
        "no reasoning seeded"
    );
}

/// A resolver error (the vault fails while a dataset token completes) ends
/// the stream with the abort event; nothing of the token or after it is
/// forwarded, nothing is seeded (carried from the Task 1 review).
#[test]
fn a_resolver_error_aborts_without_forwarding_the_partial_token() {
    let host = FakeHost::new();
    let (sh, st) = rig(Arc::clone(&host));
    let s = st.get(SessionKey([5; 32]));
    *host.fail_vault.lock().unwrap() = true;
    let (head, tail) = DS_TOKEN.split_at(5);
    let (out, ok) = rewrite_session(
        &sh,
        &s,
        Wire::Messages,
        ClientMode::Trusted,
        &messages_stream(
            &["Hallo ", head, &format!("{tail} und mehr")],
            &[],
            "",
            true,
        ),
    );
    assert!(!ok);
    let v = visible(Wire::Messages, &out);
    assert_eq!(v.error.as_deref(), Some("api_error"));
    assert_eq!(v.text, "Hallo ");
    let shown = String::from_utf8_lossy(&out);
    assert!(
        !shown.contains(head) && !shown.contains("und mehr"),
        "{shown}"
    );
    assert_eq!(s.cache().len(), 0, "nothing seeded");
}

/// Spec §6.4: in block mode a tool call carrying a clear known value never
/// reaches the client; in notify mode it does, and the answer seeds no text
/// or arguments (per-answer seeding stop, spec §5.6 amendment 2026-10-05).
#[test]
fn block_mode_withholds_a_tool_call_with_a_clear_known_value() {
    let host = FakeHost::new();
    let (mut sh, st) = rig(Arc::clone(&host));
    sh.cfg.tripwire = TripwireMode::Block;
    let s = st.get(SessionKey([4; 32]));
    let args = format!(r#"{{"to":"{NAME}"}}"#);
    let (out, ok) = rewrite_session(
        &sh,
        &s,
        Wire::Messages,
        ClientMode::Trusted,
        &messages_stream(&["ok"], &[args.as_str()], "", true),
    );
    assert!(!ok);
    let v = visible(Wire::Messages, &out);
    assert_eq!(v.text, "ok", "text channels are never blocked");
    assert_eq!(v.tool_starts, 0, "the tool call's start event was withheld");
    assert!(v.args.is_empty());
    assert_eq!(v.error.as_deref(), Some("privacy_block"));
    assert!(
        v.message
            .as_deref()
            .is_some_and(|m| m.starts_with("The request was sent sanitized;")),
        "{:?}",
        v.message
    );
    assert!(!String::from_utf8_lossy(&out).contains(NAME));
    assert!(
        host.events
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, ProxyEvent::ClearValue { blocked: true, .. }))
    );
    assert_eq!(s.cache().len(), 0, "an aborted stream seeds nothing");
    // Notify mode: delivered and recorded; the answer's text is not seeded.
    sh.cfg.tripwire = TripwireMode::Notify;
    let s = st.get(SessionKey([6; 32]));
    let (out, ok) = rewrite_session(
        &sh,
        &s,
        Wire::Messages,
        ClientMode::Trusted,
        &messages_stream(&["ok"], &[args.as_str()], "", true),
    );
    assert!(ok);
    assert_eq!(visible(Wire::Messages, &out).tool_starts, 1);
    assert!(
        host.events
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, ProxyEvent::ClearValue { blocked: false, .. }))
    );
    assert!(
        s.cache()
            .get(
                &sh.keys
                    .leaf(Wire::Messages, Class::Text, TextOrigin::Free, b"ok")
            )
            .is_none(),
        "a tripped answer seeds no text"
    );
}

/// Spec §6.4 amendment: the tripwire scans decoded argument leaves, so a
/// clear value the model wrote with JSON escapes is still caught in block mode.
#[test]
fn block_mode_catches_a_json_escaped_clear_value() {
    let (mut sh, st) = rig(FakeHost::new());
    sh.cfg.tripwire = TripwireMode::Block;
    let s = st.get(SessionKey([7; 32]));
    // `NAME` with its last letter written as a JSON escape.
    let escaped = format!(
        "{}\\u{:04x}",
        &NAME[..NAME.len() - 1],
        NAME.as_bytes()[NAME.len() - 1]
    );
    let args = format!(r#"{{"to":"{escaped}"}}"#);
    let (out, ok) = rewrite_session(
        &sh,
        &s,
        Wire::Messages,
        ClientMode::Trusted,
        &messages_stream(&["ok"], &[args.as_str()], "", true),
    );
    assert!(!ok);
    let v = visible(Wire::Messages, &out);
    assert_eq!(v.error.as_deref(), Some("privacy_block"));
    assert!(v.args.is_empty() && v.tool_starts == 0);
}

/// Block mode cannot be bypassed by argument deltas after a tool block's
/// stop: a non-empty delta on an ended channel aborts the stream.
#[test]
fn a_delta_after_its_channel_ended_aborts_the_stream() {
    let (mut sh, st) = rig(FakeHost::new());
    sh.cfg.tripwire = TripwireMode::Block;
    let s = st.get(SessionKey([8; 32]));
    let mut stream = messages_stream(&["ok"], &[], "", false);
    stream.extend(ev(
        Some("content_block_stop"),
        json!({"type": "content_block_stop", "index": 1}),
    ));
    stream.extend(tool_block(2, &[r#"{"to":"#, r#""x"}"#]));
    stream.extend(ev(
        Some("content_block_delta"),
        json!({"type": "content_block_delta", "index": 2, "delta": {"type": "input_json_delta", "partial_json": format!(r#",{{"cc":"{NAME}"}}"#)}}),
    ));
    stream.extend(ev(Some("message_stop"), json!({"type": "message_stop"})));
    let (out, ok) = rewrite_session(&sh, &s, Wire::Messages, ClientMode::Trusted, &stream);
    assert!(!ok);
    assert_eq!(
        visible(Wire::Messages, &out).error.as_deref(),
        Some("api_error")
    );
    assert!(!String::from_utf8_lossy(&out).contains(NAME));
    assert_eq!(s.cache().len(), 0);
}

/// Check routes (spec §12.3): only the check's tokens restore, session
/// tokens stay, no tripwire runs (nothing blocks, nothing is recorded), and
/// nothing is seeded.
#[test]
fn a_check_route_stream_restores_check_tokens_only_and_writes_nothing() {
    let host = FakeHost::new();
    let (mut sh, st) = rig(Arc::clone(&host));
    sh.cfg.tripwire = TripwireMode::Block;
    let s = st.get(SessionKey([9; 32]));
    let tok = session_token(&s);
    let text = format!("{CHECK_TOKEN} {tok} {DS_TOKEN}");
    let args = format!(r#"{{"to":"{NAME}"}}"#);
    let (out, ok) = rewrite(
        &sh,
        &s,
        Wire::Messages,
        ClientMode::Restricted,
        Scope::Check(CHECK_DS.into()),
        SeedStamp::unverified(),
        &messages_stream(&[text.as_str()], &[args.as_str()], "denkt", true),
    );
    assert!(ok);
    let v = visible(Wire::Messages, &out);
    assert_eq!(v.text, format!("{CHECK_NAME} {tok} {DS_TOKEN}"));
    assert_eq!(v.tool_starts, 1);
    assert!(
        host.events.lock().unwrap().is_empty(),
        "no tripwire records"
    );
    assert_eq!(s.cache().len(), 0, "nothing seeded");
    assert!(s.seed_stamp(&sh.keys.digest("scan", b"denkt")).is_none());
}

/// Review I1: after an upstream error event nothing more reaches the
/// client, so later argument deltas cannot bypass the block-mode queue.
#[test]
fn nothing_after_an_upstream_error_event_reaches_the_client() {
    let (mut sh, st) = rig(FakeHost::new());
    sh.cfg.tripwire = TripwireMode::Block;
    let s = st.get(SessionKey([10; 32]));
    let mut stream = messages_stream(&["ok"], &[], "", false);
    stream.extend(ev(
        Some("content_block_stop"),
        json!({"type": "content_block_stop", "index": 1}),
    ));
    stream.extend(ev(
        Some("content_block_start"),
        json!({"type": "content_block_start", "index": 2, "content_block": {"type": "tool_use", "id": "t", "name": "write", "input": {}}}),
    ));
    stream.extend(ev(
        Some("error"),
        json!({"type": "error", "error": {"type": "overloaded_error", "message": "busy"}}),
    ));
    stream.extend(ev(
        Some("content_block_delta"),
        json!({"type": "content_block_delta", "index": 2, "delta": {"type": "input_json_delta", "partial_json": format!(r#"{{"to":"{NAME}"}}"#)}}),
    ));
    stream.extend(ev(
        Some("content_block_stop"),
        json!({"type": "content_block_stop", "index": 2}),
    ));
    stream.extend(ev(Some("message_stop"), json!({"type": "message_stop"})));
    let (out, ok) = rewrite_session(&sh, &s, Wire::Messages, ClientMode::Trusted, &stream);
    assert!(!ok);
    let v = visible(Wire::Messages, &out);
    assert_eq!(
        v.error.as_deref(),
        Some("overloaded_error"),
        "the upstream's error is forwarded"
    );
    assert!(v.args.is_empty() && v.tool_starts == 0);
    assert!(!String::from_utf8_lossy(&out).contains(NAME));
    assert_eq!(s.cache().len(), 0);
}

/// Review Minor 1: events after the terminal event are dropped.
#[test]
fn events_after_the_terminal_event_are_dropped() {
    let (sh, st) = rig(FakeHost::new());
    let s = st.get(SessionKey([11; 32]));
    let mut stream = messages_stream(&["ok"], &["{}"], "", true);
    stream.extend(ev(
        Some("content_block_delta"),
        json!({"type": "content_block_delta", "index": 3, "delta": {"type": "text_delta", "text": "spät"}}),
    ));
    let (out, ok) = rewrite_session(&sh, &s, Wire::Messages, ClientMode::Trusted, &stream);
    assert!(ok);
    assert_eq!(visible(Wire::Messages, &out).text, "ok");
}

/// Review I2 (ruling): a tool-use start whose `input` is not `{}` would
/// reach the client unrestored and untripwired: the stream aborts.
#[test]
fn a_tool_use_start_carrying_input_aborts() {
    let (mut sh, st) = rig(FakeHost::new());
    sh.cfg.tripwire = TripwireMode::Block;
    let s = st.get(SessionKey([12; 32]));
    let mut stream = messages_stream(&["ok"], &[], "", false);
    stream.extend(ev(
        Some("content_block_stop"),
        json!({"type": "content_block_stop", "index": 1}),
    ));
    stream.extend(ev(
        Some("content_block_start"),
        json!({"type": "content_block_start", "index": 2, "content_block": {"type": "tool_use", "id": "t", "name": "write", "input": {"to": NAME}}}),
    ));
    stream.extend(ev(
        Some("content_block_stop"),
        json!({"type": "content_block_stop", "index": 2}),
    ));
    stream.extend(ev(Some("message_stop"), json!({"type": "message_stop"})));
    let (out, ok) = rewrite_session(&sh, &s, Wire::Messages, ClientMode::Trusted, &stream);
    assert!(!ok);
    assert_eq!(
        visible(Wire::Messages, &out).error.as_deref(),
        Some("api_error")
    );
    assert!(!String::from_utf8_lossy(&out).contains(NAME));
}

/// Review Minor 2: restored arguments that no longer scan (a restored key
/// colliding with another) abort, as `non_streaming` refuses them.
#[test]
fn a_restored_key_collision_aborts() {
    let (sh, st) = rig(FakeHost::new());
    let s = st.get(SessionKey([13; 32]));
    let tok = session_token(&s);
    let q = crate::json::quote(ODD);
    let args = format!(r#"{{"{tok}":1,{q}:2}}"#);
    let (out, ok) = rewrite_session(
        &sh,
        &s,
        Wire::Messages,
        ClientMode::Trusted,
        &messages_stream(&["ok"], &[args.as_str()], "", true),
    );
    assert!(!ok);
    let v = visible(Wire::Messages, &out);
    assert_eq!(v.error.as_deref(), Some("api_error"));
    assert_eq!(
        v.tool_starts, 1,
        "Messages starts are not queued in notify mode"
    );
    assert_eq!(s.cache().len(), 0);
}

/// A minimal codec for the engine's repeat path (Messages has none):
/// `{"type": "open"|"d"|"done"|"end", "k": "args"|"text", "v": "…"}`.
struct Toy;

impl Codec for Toy {
    fn classify(&mut self, _: &SseEvent, _: &[u8], nodes: &[crate::json::Node]) -> Vec<Act> {
        let kind = match str_at(nodes, &[K("k")]) {
            Some("args") => ChanKind::JsonArgs,
            _ => ChanKind::Text,
        };
        let ch = ChanKey { a: 0, b: 0 };
        let v = find(nodes, &[K("v")]);
        match str_at(nodes, &[K("type")]).unwrap_or("") {
            "open" => vec![Act::Open { ch, kind }],
            "d" => v
                .map(|n| vec![Act::Delta { ch, kind, node: n }])
                .unwrap_or_default(),
            "done" => vec![Act::Repeat {
                end: vec![ch],
                fields: v.map(|n| vec![(n, ch, kind)]).unwrap_or_default(),
            }],
            "end" => vec![Act::Terminal { fields: Vec::new() }],
            _ => vec![Act::Pass],
        }
    }
    fn synth(
        &mut self,
        _: ChanKey,
        _: ChanKind,
        text: &str,
    ) -> Result<Vec<u8>, crate::error::Fail> {
        Ok(ev(None, json!({"type": "d", "v": text})))
    }
    fn rewrite(
        &mut self,
        ev: &SseEvent,
        data: &[u8],
        _: &[crate::json::Node],
        edits: Vec<(std::ops::Range<usize>, Vec<u8>)>,
    ) -> Result<Vec<u8>, crate::error::Fail> {
        if edits.is_empty() {
            return Ok(ev.raw.clone());
        }
        let d = crate::json::splice(data, edits).map_err(|_| crate::error::Fail::Internal)?;
        Ok(serialize(None, None, &d).unwrap())
    }
    fn abort(&mut self, why: &Abort) -> Option<Vec<u8>> {
        Some(ev(
            None,
            json!({"type": "error", "class": abort_message(why).0}),
        ))
    }
}

fn toy(sh: &Shared, s: &Session, events: &[Value]) -> (Vec<u8>, bool) {
    let stream: Vec<u8> = events.iter().flat_map(|e| ev(None, e.clone())).collect();
    let rw = Rewriter::new(
        sh,
        s,
        Wire::Responses,
        UpstreamId::Openai,
        ClientMode::Trusted,
        Scope::Datasets,
        SeedStamp::unverified(),
    )
    .with_codec(Box::new(Toy));
    drive(rw, &stream)
}

/// Review I3 (ruling): an argument repeat that is not the channel's raw
/// deltas aborts, so a clear value only the `done` field carries never
/// reaches the client (Codex runs tools from the `done` events).
#[test]
fn an_argument_repeat_that_differs_from_the_deltas_aborts() {
    let (mut sh, st) = rig(FakeHost::new());
    sh.cfg.tripwire = TripwireMode::Block;
    let s = st.get(SessionKey([14; 32]));
    let (out, ok) = toy(
        &sh,
        &s,
        &[
            json!({"type": "open", "k": "args"}),
            json!({"type": "d", "k": "args", "v": r#"{"to":"x"}"#}),
            json!({"type": "done", "k": "args", "v": format!(r#"{{"to":"{NAME}"}}"#)}),
            json!({"type": "end"}),
        ],
    );
    assert!(!ok);
    let shown = String::from_utf8_lossy(&out);
    assert!(!shown.contains(NAME), "{shown}");
    assert!(shown.contains("stream_aborted"), "{shown}");
}

/// Review I3 (ruling): a text repeat that differs from the deltas is
/// tripwired before it is released (text never blocks): the hit is
/// recorded and the answer's text is not seeded.
#[test]
fn a_text_repeat_that_differs_is_tripwired() {
    let host = FakeHost::new();
    let (sh, st) = rig(Arc::clone(&host));
    let s = st.get(SessionKey([15; 32]));
    let (_, ok) = toy(
        &sh,
        &s,
        &[
            json!({"type": "d", "k": "text", "v": "hallo"}),
            json!({"type": "done", "k": "text", "v": format!("hallo {NAME}")}),
            json!({"type": "end"}),
        ],
    );
    assert!(ok);
    assert!(
        host.events
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, ProxyEvent::ClearValue { blocked: false, .. }))
    );
    assert_eq!(s.cache().len(), 0, "a tripped answer seeds no text");
}

/// A Responses stream: one message item (text deltas), one function call
/// (argument deltas); the `done` events and `response.completed` repeat
/// `full_text` and `full_args`. Sequence numbers count from 0.
pub(crate) fn responses_stream(
    text: &[&str],
    args: &[&str],
    full_text: &str,
    full_args: &str,
) -> Vec<u8> {
    let mut n = 0u64;
    let mut s = Vec::new();
    let mut push = |name: &str, mut data: Value| {
        data["type"] = json!(name);
        data["sequence_number"] = json!(n);
        n += 1;
        s.extend(ev(Some(name), data));
    };
    push(
        "response.created",
        json!({"response": {"id": "resp_1", "status": "in_progress", "output": []}}),
    );
    push(
        "response.output_item.added",
        json!({"output_index": 0, "item": {"type": "message", "id": "msg_1", "role": "assistant", "content": []}}),
    );
    for t in text {
        push(
            "response.output_text.delta",
            json!({"item_id": "msg_1", "output_index": 0, "content_index": 0, "delta": t}),
        );
    }
    push(
        "response.output_text.done",
        json!({"item_id": "msg_1", "output_index": 0, "content_index": 0, "text": full_text}),
    );
    push(
        "response.content_part.done",
        json!({"item_id": "msg_1", "output_index": 0, "content_index": 0, "part": {"type": "output_text", "text": full_text, "annotations": []}}),
    );
    let msg = json!({"type": "message", "id": "msg_1", "role": "assistant", "status": "completed", "content": [{"type": "output_text", "text": full_text, "annotations": []}]});
    push(
        "response.output_item.done",
        json!({"output_index": 0, "item": msg.clone()}),
    );
    push(
        "response.output_item.added",
        json!({"output_index": 1, "item": {"type": "function_call", "id": "fc_1", "call_id": "c1", "name": "write", "arguments": ""}}),
    );
    for a in args {
        push(
            "response.function_call_arguments.delta",
            json!({"item_id": "fc_1", "output_index": 1, "delta": a}),
        );
    }
    push(
        "response.function_call_arguments.done",
        json!({"item_id": "fc_1", "output_index": 1, "arguments": full_args}),
    );
    let fc = json!({"type": "function_call", "id": "fc_1", "call_id": "c1", "name": "write", "arguments": full_args, "status": "completed"});
    push(
        "response.output_item.done",
        json!({"output_index": 1, "item": fc.clone()}),
    );
    push(
        "response.completed",
        json!({"response": {"id": "resp_1", "status": "completed", "output": [msg, fc]}}),
    );
    s
}

/// A Chat Completions stream: content deltas, then one tool call whose
/// arguments arrive as `args`, `finish_reason: tool_calls`, `[DONE]`.
pub(crate) fn chat_stream(text: &[&str], args: &[&str]) -> Vec<u8> {
    let chunk = |delta: Value, finish: Value| {
        ev(
            None,
            json!({"id": "c", "object": "chat.completion.chunk", "created": 1, "model": "x", "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}),
        )
    };
    let mut s = chunk(json!({"role": "assistant", "content": ""}), Value::Null);
    for t in text {
        s.extend(chunk(json!({"content": t}), Value::Null));
    }
    s.extend(chunk(
        json!({"tool_calls": [{"index": 0, "id": "call_1", "type": "function", "function": {"name": "write", "arguments": ""}}]}),
        Value::Null,
    ));
    for a in args {
        s.extend(chunk(
            json!({"tool_calls": [{"index": 0, "function": {"arguments": a}}]}),
            Value::Null,
        ));
    }
    s.extend(chunk(json!({}), json!("tool_calls")));
    s.extend_from_slice(b"data: [DONE]\n\n");
    s
}

/// Spec §15 tests 10, 11 (Responses, `<` form included); Review Focus 5.
#[test]
fn responses_stream_repeats_match_and_sequence_numbers_increase() {
    let (sh, st) = rig(FakeHost::new());
    let s = st.get(SessionKey([20; 32]));
    let tok = session_token(&s);
    // A trailing "<" is held until the done event: the flush is a synthesized delta.
    let text = format!("Hallo {tok} und {DS_TOKEN} <");
    let want = format!("Hallo {ODD} und {NAME} <");
    let esc = tok.replace('<', "\\u003c").replace('>', "\\u003e");
    let args = format!(r#"{{"to":"{tok}","bcc":"{esc}","cc":"{DS_TOKEN}"}}"#);
    for [x, y] in halves(&text) {
        let (out, ok) = rewrite_session(
            &sh,
            &s,
            Wire::Responses,
            ClientMode::Trusted,
            &responses_stream(&[x, y], &[args.as_str()], &text, &args),
        );
        assert!(ok);
        let v = visible(Wire::Responses, &out);
        assert_eq!(v.text, want);
        assert!(v.seqs.windows(2).all(|w| w[0] < w[1]), "{:?}", v.seqs);
        for r in v.repeats.iter().filter(|r| !r.starts_with('{')) {
            assert_eq!(r, &want, "a done repeat equals what the deltas showed");
        }
    }
    for [x, y] in halves(&args) {
        let (out, ok) = rewrite_session(
            &sh,
            &s,
            Wire::Responses,
            ClientMode::Trusted,
            &responses_stream(&[text.as_str()], &[x, y], &text, &args),
        );
        assert!(ok);
        let v = visible(Wire::Responses, &out);
        for a in v
            .args
            .iter()
            .chain(v.repeats.iter().filter(|r| r.starts_with('{')))
        {
            let j: Value = serde_json::from_str(a).expect("arguments stay JSON");
            assert_eq!(j["to"], ODD);
            assert_eq!(
                j["bcc"], ODD,
                "escaped delimiters restore to the escaped original"
            );
            assert_eq!(j["cc"], DS_TOKEN, "dataset token left in arguments");
        }
    }
}

/// Spec §15 tests 10, 11 (Chat Completions).
#[test]
fn chat_stream_restores_split_tokens_and_tool_arguments() {
    let (sh, st) = rig(FakeHost::new());
    let s = st.get(SessionKey([21; 32]));
    let tok = session_token(&s);
    let text = format!("Hallo {tok} und {DS_TOKEN}.");
    let want = format!("Hallo {ODD} und {NAME}.");
    let args = format!(r#"{{"to":"{tok}","cc":"{DS_TOKEN}"}}"#);
    for [x, y] in halves(&text) {
        let (out, ok) = rewrite_session(
            &sh,
            &s,
            Wire::Chat,
            ClientMode::Trusted,
            &chat_stream(&[x, y], &[args.as_str()]),
        );
        assert!(ok);
        assert_eq!(visible(Wire::Chat, &out).text, want);
    }
    for [x, y] in halves(&args) {
        let (out, ok) = rewrite_session(
            &sh,
            &s,
            Wire::Chat,
            ClientMode::Trusted,
            &chat_stream(&[text.as_str()], &[x, y]),
        );
        assert!(ok);
        let j: Value =
            serde_json::from_str(&visible(Wire::Chat, &out).args[0]).expect("arguments stay JSON");
        assert_eq!(j["to"], ODD);
        assert_eq!(j["cc"], DS_TOKEN);
    }
    // A clean end after every `finish_reason` without `[DONE]` completes (spec §6.2 "stream end").
    let mut no_done = chat_stream(&[text.as_str()], &[args.as_str()]);
    no_done.truncate(no_done.len() - b"data: [DONE]\n\n".len());
    let (out, ok) = rewrite_session(&sh, &s, Wire::Chat, ClientMode::Trusted, &no_done);
    assert!(ok, "completed");
    assert_eq!(visible(Wire::Chat, &out).text, want);
}

/// Codex runs tools from the `done` events: an arguments repeat that is not
/// what the deltas carried aborts, so a clear value only the `done` field
/// holds never reaches the client.
#[test]
fn a_responses_arguments_done_that_differs_from_the_deltas_aborts() {
    let (mut sh, st) = rig(FakeHost::new());
    sh.cfg.tripwire = TripwireMode::Block;
    let s = st.get(SessionKey([22; 32]));
    let (out, ok) = rewrite_session(
        &sh,
        &s,
        Wire::Responses,
        ClientMode::Trusted,
        &responses_stream(
            &["ok"],
            &[r#"{"to":"x"}"#],
            "ok",
            &format!(r#"{{"to":"{NAME}"}}"#),
        ),
    );
    assert!(!ok);
    let v = visible(Wire::Responses, &out);
    assert_eq!(v.error.as_deref(), Some("stream_aborted"));
    assert!(!String::from_utf8_lossy(&out).contains(NAME));
    assert_eq!(s.cache().len(), 0, "nothing seeded");
}

/// Spec §6.4 on both wires: in block mode a tool call carrying a clear
/// known value is withheld whole and the stream ends with the wire's
/// privacy error; text before it is delivered.
#[test]
fn block_mode_withholds_a_responses_and_a_chat_tool_call() {
    let (mut sh, st) = rig(FakeHost::new());
    sh.cfg.tripwire = TripwireMode::Block;
    let args = format!(r#"{{"to":"{NAME}"}}"#);
    let s = st.get(SessionKey([23; 32]));
    let (out, ok) = rewrite_session(
        &sh,
        &s,
        Wire::Responses,
        ClientMode::Trusted,
        &responses_stream(&["ok"], &[args.as_str()], "ok", &args),
    );
    assert!(!ok);
    let v = visible(Wire::Responses, &out);
    assert_eq!(v.text, "ok");
    assert_eq!(v.tool_starts, 0, "the call's added event was withheld");
    assert!(v.args.is_empty());
    assert_eq!(v.error.as_deref(), Some("privacy_block"));
    assert!(!String::from_utf8_lossy(&out).contains(NAME));
    assert_eq!(s.cache().len(), 0);
    let s = st.get(SessionKey([24; 32]));
    let (out, ok) = rewrite_session(
        &sh,
        &s,
        Wire::Chat,
        ClientMode::Trusted,
        &chat_stream(&["ok"], &[args.as_str()]),
    );
    assert!(!ok);
    let v = visible(Wire::Chat, &out);
    assert_eq!(v.text, "ok");
    assert_eq!(v.tool_starts, 0);
    assert!(v.args.is_empty());
    assert_eq!(v.error.as_deref(), Some("privacy_block"));
    assert!(!String::from_utf8_lossy(&out).contains(NAME));
    assert_eq!(s.cache().len(), 0);
}

/// Review Focus 4 on the OpenAI wires: a cut mid-token never shows the
/// partial token. Responses ends with `response.failed`; Chat ends without
/// `[DONE]` or an error chunk (spec §7). Nothing is seeded.
#[test]
fn an_upstream_cut_on_the_openai_wires_hides_the_partial_token() {
    let (sh, st) = rig(FakeHost::new());
    let s = st.get(SessionKey([25; 32]));
    let cut = |full: Vec<u8>, marker: &[u8]| {
        let at = full
            .windows(marker.len())
            .position(|w| w == marker)
            .expect("marker");
        full[..at].to_vec()
    };
    let r = cut(
        responses_stream(&["Hallo <PERS"], &[], "x", "{}"),
        b"event: response.output_text.done",
    );
    let (out, ok) = rewrite_session(&sh, &s, Wire::Responses, ClientMode::Trusted, &r);
    assert!(!ok);
    let v = visible(Wire::Responses, &out);
    assert_eq!(v.error.as_deref(), Some("stream_aborted"));
    assert_eq!(v.text, "Hallo ");
    assert!(!String::from_utf8_lossy(&out).contains("<PERS"));
    let c = cut(
        chat_stream(&["Hallo <PERS"], &[]),
        b"data: {\"choices\":[{\"delta\":{\"tool_calls\"",
    );
    let (out, ok) = rewrite_session(&sh, &s, Wire::Chat, ClientMode::Trusted, &c);
    assert!(!ok);
    let v = visible(Wire::Chat, &out);
    assert_eq!(v.text, "Hallo ");
    assert!(v.error.is_none(), "Chat streams end without an error chunk");
    assert!(!String::from_utf8_lossy(&out).contains("<PERS"));
    assert_eq!(s.cache().len(), 0);
}

/// Framing the engine cannot check aborts instead of passing a clear value
/// unrestored and untripwired: a Responses call item added with arguments,
/// a custom tool item added with input, a message part added with text, and
/// Chat tool-call or content deltas of a shape the codec cannot map. Final
/// review I1: a payload that does not scan (duplicate keys, a lone
/// surrogate) under any event name, an event name that differs from the
/// payload's `type`, a leading byte-order mark, and a Messages
/// `message_start` that already carries content.
#[test]
fn unchecked_provider_framing_aborts() {
    let (mut sh, st) = rig(FakeHost::new());
    sh.cfg.tripwire = TripwireMode::Block;
    let n = 30u8..;
    let added = |item: Value| {
        ev(
            Some("response.output_item.added"),
            json!({"type": "response.output_item.added", "output_index": 0, "item": item}),
        )
    };
    let part_added = ev(
        Some("response.content_part.added"),
        json!({"type": "response.content_part.added", "output_index": 0, "content_index": 0, "part": {"type": "output_text", "text": NAME}}),
    );
    let chunk = |delta: Value| {
        ev(
            None,
            json!({"id": "c", "object": "chat.completion.chunk", "created": 1, "model": "x", "choices": [{"index": 0, "delta": delta, "finish_reason": null}]}),
        )
    };
    let cases: Vec<(Wire, Vec<u8>)> = vec![
        (
            Wire::Responses,
            added(
                json!({"type": "function_call", "id": "f", "call_id": "c", "name": "w", "arguments": format!(r#"{{"to":"{NAME}"}}"#)}),
            ),
        ),
        (
            Wire::Responses,
            added(
                json!({"type": "custom_tool_call", "id": "f", "call_id": "c", "name": "w", "input": NAME}),
            ),
        ),
        (
            Wire::Responses,
            added(
                json!({"type": "message", "id": "m", "role": "assistant", "content": [{"type": "output_text", "text": NAME}]}),
            ),
        ),
        (Wire::Responses, part_added),
        (
            Wire::Chat,
            chunk(
                json!({"tool_calls": [{"index": 0, "function": {"name": "w", "arguments": {"to": NAME}}}]}),
            ),
        ),
        (
            Wire::Chat,
            chunk(
                json!({"tool_calls": [{"index": 0, "type": "custom", "custom": {"name": "w", "input": NAME}}]}),
            ),
        ),
        (
            Wire::Chat,
            chunk(json!({"content": [{"type": "text", "text": NAME}]})),
        ),
        (
            Wire::Chat,
            chunk(json!({"function_call": {"name": "w", "arguments": {"to": NAME}}})),
        ),
        // I1.1: duplicate keys (a client keeps the last `type`) under an
        // event name the codec does not rewrite.
        (
            Wire::Messages,
            serialize(
                Some("message_delta"),
                None,
                format!(
                    r#"{{"type":"message_delta","type":"content_block_delta","index":1,"delta":{{"type":"input_json_delta","partial_json":"{{\"to\":\"{NAME}\"}}"}}}}"#
                )
                .as_bytes(),
            )
            .unwrap(),
        ),
        // I1.1: a lone surrogate, which `JSON.parse` accepts.
        (
            Wire::Responses,
            serialize(
                Some("response.output_text.annotation.added"),
                None,
                format!(
                    r#"{{"type":"response.function_call_arguments.delta","output_index":0,"item_id":"f","delta":"{{\"to\":\"{NAME}\ud800\"}}","sequence_number":1}}"#
                )
                .as_bytes(),
            )
            .unwrap(),
        ),
        // I1.1: an event name that differs from the payload's `type`.
        (
            Wire::Messages,
            ev(
                Some("ping"),
                json!({"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": format!(r#"{{"to":"{NAME}"}}"#)}}),
            ),
        ),
        (
            Wire::Responses,
            ev(
                Some("response.output_text.annotation.added"),
                json!({"type": "response.function_call_arguments.delta", "output_index": 0, "item_id": "f", "delta": format!(r#"{{"to":"{NAME}"}}"#), "sequence_number": 1}),
            ),
        ),
        // I1.2: a leading byte-order mark (a client's decoder strips it).
        (Wire::Chat, {
            let mut b = b"\xEF\xBB\xBF".to_vec();
            b.extend(chunk(
                json!({"tool_calls": [{"index": 0, "id": "call_1", "type": "function", "function": {"name": "w", "arguments": format!(r#"{{"to":"{NAME}"}}"#)}}]}),
            ));
            b
        }),
        // M1: a block index out of range is refused, not truncated.
        (
            Wire::Messages,
            ev(
                Some("content_block_delta"),
                json!({"type": "content_block_delta", "index": 4_294_967_298u64, "delta": {"type": "text_delta", "text": NAME}}),
            ),
        ),
        // I1.3: a `message_start` whose message already holds a tool call.
        (
            Wire::Messages,
            ev(
                Some("message_start"),
                json!({"type": "message_start", "message": {"id": "m", "type": "message", "role": "assistant", "model": "x", "content": [{"type": "tool_use", "id": "t", "name": "w", "input": {"to": NAME}}]}}),
            ),
        ),
    ];
    for ((wire, mut bytes), k) in cases.into_iter().zip(n) {
        // A clean ending follows, so only the refusal can make the stream fail.
        match wire {
            Wire::Messages => bytes.extend(ev(Some("message_stop"), json!({"type": "message_stop"}))),
            Wire::Responses => bytes.extend(ev(
                Some("response.completed"),
                json!({"type": "response.completed", "response": {"id": "r", "status": "completed", "output": []}}),
            )),
            _ => {
                bytes.extend(ev(
                    None,
                    json!({"id": "c", "object": "chat.completion.chunk", "created": 1, "model": "x", "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}),
                ));
                bytes.extend_from_slice(b"data: [DONE]\n\n");
            }
        }
        let s = st.get(SessionKey([k; 32]));
        let (out, ok) = rewrite_session(&sh, &s, wire, ClientMode::Trusted, &bytes);
        let shown = String::from_utf8_lossy(&out);
        assert!(!ok, "{wire:?} {shown}");
        assert!(!shown.contains(NAME), "{wire:?} {shown}");
        assert_eq!(s.cache().len(), 0);
    }
}

/// Reasoning is never changed (addendum item 4): a `reasoning_text` content
/// part passes byte-identical in `content_part.done` and `output_item.done`,
/// is not tripwired, and does not suppress seeding of the answer's text.
#[test]
fn a_reasoning_text_part_passes_unchanged_and_does_not_trip() {
    let host = FakeHost::new();
    let (sh, st) = rig(Arc::clone(&host));
    let s = st.get(SessionKey([40; 32]));
    let tok = session_token(&s);
    let mut n = 0u64;
    let mut stream = Vec::new();
    let mut part_done = Vec::new();
    let mut push = |name: &str, mut data: Value| {
        data["type"] = json!(name);
        data["sequence_number"] = json!(n);
        n += 1;
        let b = ev(Some(name), data);
        if name == "response.content_part.done" {
            part_done = b.clone();
        }
        stream.extend(b);
    };
    let reasoning = format!("{tok} und {NAME} bedacht");
    push(
        "response.output_item.added",
        json!({"output_index": 0, "item": {"type": "reasoning", "id": "rs_1", "summary": [], "content": []}}),
    );
    push(
        "response.reasoning_text.delta",
        json!({"item_id": "rs_1", "output_index": 0, "content_index": 0, "delta": reasoning}),
    );
    push(
        "response.content_part.done",
        json!({"item_id": "rs_1", "output_index": 0, "content_index": 0, "part": {"type": "reasoning_text", "text": reasoning}}),
    );
    push(
        "response.output_item.done",
        json!({"output_index": 0, "item": {"type": "reasoning", "id": "rs_1", "summary": [], "content": [{"type": "reasoning_text", "text": reasoning}]}}),
    );
    push(
        "response.output_item.added",
        json!({"output_index": 1, "item": {"type": "message", "id": "msg_1", "role": "assistant", "content": []}}),
    );
    let text = format!("fertig {tok}");
    push(
        "response.output_text.delta",
        json!({"item_id": "msg_1", "output_index": 1, "content_index": 0, "delta": text}),
    );
    push(
        "response.output_text.done",
        json!({"item_id": "msg_1", "output_index": 1, "content_index": 0, "text": text}),
    );
    push(
        "response.completed",
        json!({"response": {"id": "r", "status": "completed", "output": []}}),
    );
    let (out, ok) = rewrite_session(&sh, &s, Wire::Responses, ClientMode::Trusted, &stream);
    assert!(ok);
    assert!(
        out.windows(part_done.len()).any(|w| w == part_done),
        "the reasoning part's done event is forwarded byte-identical"
    );
    assert!(
        host.events.lock().unwrap().is_empty(),
        "reasoning is not tripwired"
    );
    let restored = format!("fertig {ODD}");
    assert!(
        s.cache()
            .get(&sh.keys.leaf(
                Wire::Responses,
                Class::Text,
                TextOrigin::Free,
                restored.as_bytes()
            ))
            .is_some(),
        "the answer's text is still seeded"
    );
}

/// An upstream `response.failed` is forwarded without its `output`: a call
/// the provider completed before failing is neither restored nor tripwired,
/// so its copy must not reach the client. Same for a Chat error chunk with `choices`.
#[test]
fn a_forwarded_upstream_failure_carries_no_output() {
    let (mut sh, st) = rig(FakeHost::new());
    sh.cfg.tripwire = TripwireMode::Block;
    let s = st.get(SessionKey([41; 32]));
    let call = json!({"type": "function_call", "id": "fc", "call_id": "c", "name": "w", "arguments": format!(r#"{{"to":"{NAME}"}}"#)});
    let failed = ev(
        Some("response.failed"),
        json!({"type": "response.failed", "sequence_number": 0, "response": {"id": "r", "status": "failed", "error": {"code": "server_error", "message": "boom"}, "output": [call]}}),
    );
    let (out, ok) = rewrite_session(&sh, &s, Wire::Responses, ClientMode::Trusted, &failed);
    assert!(!ok);
    let shown = String::from_utf8_lossy(&out);
    assert!(!shown.contains(NAME), "{shown}");
    let j: Value = serde_json::from_str(
        shown
            .lines()
            .find_map(|l| l.strip_prefix("data: "))
            .expect("the failure is forwarded"),
    )
    .unwrap();
    assert_eq!(j["response"]["error"]["code"], "server_error");
    assert_eq!(j["response"]["output"], json!([]));
    let chunk = ev(
        None,
        json!({"error": {"message": "boom", "type": "server_error"}, "choices": [{"index": 0, "delta": {"content": NAME}, "finish_reason": null}]}),
    );
    let (out, ok) = rewrite_session(&sh, &s, Wire::Chat, ClientMode::Trusted, &chunk);
    assert!(!ok);
    let shown = String::from_utf8_lossy(&out);
    assert!(!shown.contains(NAME), "{shown}");
    assert!(
        shown.contains("server_error"),
        "the error is forwarded: {shown}"
    );
}

/// Final review I2: one streamed answer is bounded like a non-streamed one
/// (`max_request_bytes`, the stream's `ResponseTooLarge`). A text or an
/// argument channel over the cap aborts and seeds nothing; an answer under
/// it completes.
#[test]
fn a_streamed_answer_over_the_size_cap_aborts() {
    let (mut sh, st) = rig(FakeHost::new());
    sh.cfg.max_request_bytes = 4096;
    let piece = "x".repeat(1000);
    let five = vec![piece.as_str(); 5];
    let arg = format!(r#"{{"a":"{}"}}"#, "y".repeat(5000));
    let s = st.get(SessionKey([50; 32]));
    for stream in [
        messages_stream(&five, &[], "", true),
        messages_stream(&["ok"], &[arg.as_str()], "", true),
    ] {
        let (out, ok) = rewrite_session(&sh, &s, Wire::Messages, ClientMode::Trusted, &stream);
        assert!(!ok, "over the cap");
        assert_eq!(
            visible(Wire::Messages, &out).error.as_deref(),
            Some("api_error")
        );
        assert_eq!(s.cache().len(), 0, "an aborted stream seeds nothing");
    }
    let three = vec![piece.as_str(); 3];
    let (_, ok) = rewrite_session(
        &sh,
        &s,
        Wire::Messages,
        ClientMode::Trusted,
        &messages_stream(&three, &[], "", true),
    );
    assert!(ok, "under the cap");
}

/// Final review M4: a channel cut off by an upstream cut (or an upstream
/// error event) is still tripwired for the record: in notify mode its bytes
/// already reached the client, and the `ClearValue` record is the only
/// signal. Nothing is seeded.
#[test]
fn a_cut_off_channel_is_still_recorded() {
    let host = FakeHost::new();
    let (sh, st) = rig(Arc::clone(&host));
    let args = format!(r#"{{"to":"{NAME}"}}"#);
    let mut stream = ev(
        Some("content_block_start"),
        json!({"type": "content_block_start", "index": 0, "content_block": {"type": "tool_use", "id": "t", "name": "w", "input": {}}}),
    );
    stream.extend(ev(
        Some("content_block_delta"),
        json!({"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": args}}),
    ));
    let cleared = |h: &FakeHost| {
        h.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| matches!(e, ProxyEvent::ClearValue { blocked: false, .. }))
            .count()
    };
    let s = st.get(SessionKey([51; 32]));
    let (_, ok) = rewrite_session(&sh, &s, Wire::Messages, ClientMode::Trusted, &stream);
    assert!(!ok);
    assert_eq!(cleared(&host), 1, "the cut-off channel was recorded");
    let mut failed = stream.clone();
    failed.extend(ev(
        Some("error"),
        json!({"type": "error", "error": {"type": "overloaded_error", "message": "x"}}),
    ));
    let s = st.get(SessionKey([52; 32]));
    let (_, ok) = rewrite_session(&sh, &s, Wire::Messages, ClientMode::Trusted, &failed);
    assert!(!ok);
    assert_eq!(cleared(&host), 2, "and before an upstream error event");
    assert_eq!(s.cache().len(), 0);
}

/// A Responses stream with one output item: `added` starts it, `done`
/// completes it (and `response.completed` repeats `done`); `between` are
/// further events (each a name and its payload) after `added`.
fn item_stream(added: Value, between: &[(&str, Value)], done: Value) -> Vec<u8> {
    let mut n = 0u64;
    let mut s = Vec::new();
    let mut push = |name: &str, mut data: Value| {
        data["type"] = json!(name);
        data["sequence_number"] = json!(n);
        n += 1;
        s.extend(ev(Some(name), data));
    };
    push(
        "response.created",
        json!({"response": {"id": "resp_1", "status": "in_progress", "output": []}}),
    );
    push(
        "response.output_item.added",
        json!({"output_index": 0, "item": added}),
    );
    for (name, data) in between {
        push(name, data.clone());
    }
    push(
        "response.output_item.done",
        json!({"output_index": 0, "item": done.clone()}),
    );
    push(
        "response.completed",
        json!({"response": {"id": "resp_1", "status": "completed", "output": [done]}}),
    );
    s
}

/// Codex items that run locally or call a tool, as `(added, done)` with
/// `v` in their model-written strings: a command, a patch, typed text, MCP
/// arguments. `added` carries `v` where the item arrives whole.
fn codex_items(v: &str) -> Vec<(&'static str, Value, Value)> {
    let args = json!({"to": v}).to_string();
    vec![
        (
            "shell_call",
            json!({"type": "shell_call", "id": "sh_1", "call_id": "c1", "status": "in_progress", "action": {"commands": []}}),
            json!({"type": "shell_call", "id": "sh_1", "call_id": "c1", "status": "completed", "action": {"commands": [format!("mail -s hi '{v}'")], "timeout_ms": 1000}}),
        ),
        (
            "local_shell_call",
            json!({"type": "local_shell_call", "id": "ls_1", "call_id": "c2", "status": "in_progress", "action": {"type": "exec", "command": ["bash", "-lc", format!("echo {v}")], "env": {}}}),
            json!({"type": "local_shell_call", "id": "ls_1", "call_id": "c2", "status": "completed", "action": {"type": "exec", "command": ["bash", "-lc", format!("echo {v}")], "env": {}}}),
        ),
        (
            "apply_patch_call",
            json!({"type": "apply_patch_call", "id": "ap_1", "call_id": "c3", "status": "in_progress", "operation": {"type": "update_file", "path": "notes.txt", "diff": ""}}),
            json!({"type": "apply_patch_call", "id": "ap_1", "call_id": "c3", "status": "completed", "operation": {"type": "update_file", "path": "notes.txt", "diff": format!("@@\n+{v}\n")}}),
        ),
        (
            "computer_call",
            json!({"type": "computer_call", "id": "cu_1", "call_id": "c4", "status": "completed", "action": {"type": "type", "text": v}, "pending_safety_checks": []}),
            json!({"type": "computer_call", "id": "cu_1", "call_id": "c4", "status": "completed", "action": {"type": "type", "text": v}, "pending_safety_checks": []}),
        ),
        (
            "mcp_approval_request",
            json!({"type": "mcp_approval_request", "id": "mr_1", "server_label": "s", "name": "send", "arguments": args}),
            json!({"type": "mcp_approval_request", "id": "mr_1", "server_label": "s", "name": "send", "arguments": args}),
        ),
    ]
}

/// Fix wave 2a (B): Codex shell, patch, computer, and MCP approval items
/// are argument channels. In block mode an item whose model-written strings
/// hold a known value in clear never reaches the client (its start event
/// included); in notify mode it does, with a `ClearValue` record.
#[test]
fn codex_shell_and_patch_items_are_tripwired_and_withheld_in_block_mode() {
    let host = FakeHost::new();
    let (mut sh, st) = rig(Arc::clone(&host));
    let blocked = |h: &FakeHost, b: bool| {
        h.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| matches!(e, ProxyEvent::ClearValue { blocked, .. } if *blocked == b))
            .count()
    };
    for (i, (ty, added, done)) in codex_items(NAME).into_iter().enumerate() {
        let stream = item_stream(added, &[], done);
        sh.cfg.tripwire = TripwireMode::Block;
        let s = st.get(SessionKey([60 + i as u8; 32]));
        let before = blocked(&host, true);
        let (out, ok) = rewrite_session(&sh, &s, Wire::Responses, ClientMode::Trusted, &stream);
        let shown = String::from_utf8_lossy(&out);
        assert!(!ok, "{ty}");
        assert_eq!(
            visible(Wire::Responses, &out).error.as_deref(),
            Some("privacy_block"),
            "{ty}"
        );
        assert!(!shown.contains("Zyxwuria"), "{ty}: {shown}");
        assert!(
            !shown.contains(ty),
            "{ty}: the item's start was withheld: {shown}"
        );
        assert!(blocked(&host, true) > before, "{ty}");
        sh.cfg.tripwire = TripwireMode::Notify;
        let s = st.get(SessionKey([80 + i as u8; 32]));
        let before = blocked(&host, false);
        let (out, ok) = rewrite_session(&sh, &s, Wire::Responses, ClientMode::Trusted, &stream);
        assert!(ok, "{ty}");
        assert!(String::from_utf8_lossy(&out).contains("Zyxwuria"), "{ty}");
        assert!(blocked(&host, false) > before, "{ty}: recorded");
    }
}

/// Fix wave 2a (B): an MCP call's streamed arguments are a JSON argument
/// channel like a function call's: queued and tripwired in block mode,
/// restored by the arguments column.
#[test]
fn codex_mcp_call_arguments_are_an_argument_channel() {
    let host = FakeHost::new();
    let (mut sh, st) = rig(Arc::clone(&host));
    let stream = |to: &str| {
        let full = json!({"to": to}).to_string();
        let (a, b) = full.split_at(full.len() / 2);
        let d = |x: &str| {
            (
                "response.mcp_call_arguments.delta",
                json!({"item_id": "mcp_1", "output_index": 0, "delta": x}),
            )
        };
        item_stream(
            json!({"type": "mcp_call", "id": "mcp_1", "server_label": "s", "name": "send", "arguments": ""}),
            &[
                d(a),
                d(b),
                (
                    "response.mcp_call_arguments.done",
                    json!({"item_id": "mcp_1", "output_index": 0, "arguments": full}),
                ),
                (
                    "response.mcp_call.completed",
                    json!({"item_id": "mcp_1", "output_index": 0}),
                ),
            ],
            json!({"type": "mcp_call", "id": "mcp_1", "server_label": "s", "name": "send", "arguments": full, "output": "sent"}),
        )
    };
    sh.cfg.tripwire = TripwireMode::Block;
    let s = st.get(SessionKey([90; 32]));
    let (out, ok) = rewrite_session(&sh, &s, Wire::Responses, ClientMode::Trusted, &stream(NAME));
    assert!(!ok);
    assert_eq!(
        visible(Wire::Responses, &out).error.as_deref(),
        Some("privacy_block")
    );
    let shown = String::from_utf8_lossy(&out);
    assert!(
        !shown.contains("Zyxwuria") && !shown.contains("mcp_call"),
        "{shown}"
    );
    // A session token in the arguments is restored; a dataset token stays.
    sh.cfg.tripwire = TripwireMode::Notify;
    let s = st.get(SessionKey([91; 32]));
    let tok = session_token(&s);
    let (out, ok) = rewrite_session(
        &sh,
        &s,
        Wire::Responses,
        ClientMode::Trusted,
        &stream(&format!("{tok} {DS_TOKEN}")),
    );
    assert!(ok, "{}", String::from_utf8_lossy(&out));
    let want = json!({"to": format!("{ODD} {DS_TOKEN}")}).to_string();
    let v = visible(Wire::Responses, &out);
    assert!(v.repeats.contains(&want), "{:?}", v.repeats);
    assert!(!String::from_utf8_lossy(&out).contains(&tok));
}

/// Every string in `v`, and in the JSON text of an `arguments` string.
fn strings(v: &Value) -> Vec<String> {
    match v {
        Value::String(t) => vec![t.clone()],
        Value::Array(a) => a.iter().flat_map(strings).collect(),
        Value::Object(o) => o
            .iter()
            .flat_map(|(k, x)| match (k.as_str(), x.as_str()) {
                ("arguments", Some(t)) => strings(&serde_json::from_str(t).unwrap_or(Value::Null)),
                _ => strings(x),
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Fix wave 2a (B): the strings of a shell command or a patch are
/// restored by the arguments column (session tokens; dataset tokens stay
/// tokens), in every event that carries the item.
#[test]
fn codex_shell_and_patch_items_restore_session_tokens() {
    let (sh, st) = rig(FakeHost::new());
    let s = st.get(SessionKey([92; 32]));
    let tok = session_token(&s);
    let v = format!("{tok} {DS_TOKEN}");
    for (ty, added, done) in codex_items(&v) {
        let (out, ok) = rewrite_session(
            &sh,
            &s,
            Wire::Responses,
            ClientMode::Trusted,
            &item_stream(added, &[], done),
        );
        assert!(ok, "{ty}: {}", String::from_utf8_lossy(&out));
        let shown = String::from_utf8_lossy(&out);
        assert!(!shown.contains(&tok), "{ty}: {shown}");
        assert!(shown.contains(DS_TOKEN), "{ty}");
        let mut p = SseParser::new(MAX_EVENT);
        let done: Vec<Value> = p
            .push(&out)
            .unwrap()
            .into_iter()
            .filter_map(|e| serde_json::from_slice::<Value>(&e.data?).ok())
            .filter(|j| j["type"] == "response.output_item.done")
            .collect();
        assert!(
            strings(&done[0]["item"]).iter().any(|t| t.contains(ODD)),
            "{ty}: {}",
            done[0]
        );
    }
}

/// Fix wave 2a (B): events that stream parts of these items in a shape the
/// engine does not know abort the stream (fail closed); a status event
/// with ids only passes.
#[test]
fn unknown_events_of_codex_items_abort() {
    let (sh, st) = rig(FakeHost::new());
    let item = json!({"type": "apply_patch_call", "id": "ap_1", "call_id": "c3", "status": "in_progress", "operation": {"type": "update_file", "path": "notes.txt", "diff": ""}});
    let cases = [
        (
            "response.apply_patch_call_operation_diff.delta",
            json!({"item_id": "ap_1", "output_index": 0, "delta": "+x"}),
            false,
        ),
        (
            "response.shell_call_command.delta",
            json!({"item_id": "ap_1", "output_index": 0, "command_index": 0, "delta": "ls"}),
            false,
        ),
        (
            "response.custom_unknown.delta",
            json!({"item_id": "ap_1", "output_index": 0, "delta": "x"}),
            false,
        ),
        (
            "response.apply_patch_call.in_progress",
            json!({"item_id": "ap_1", "output_index": 0}),
            true,
        ),
    ];
    for (i, (name, data, passes)) in cases.into_iter().enumerate() {
        let s = st.get(SessionKey([93 + i as u8; 32]));
        let (out, ok) = rewrite_session(
            &sh,
            &s,
            Wire::Responses,
            ClientMode::Trusted,
            &item_stream(item.clone(), &[(name, data)], item.clone()),
        );
        assert_eq!(ok, passes, "{name}: {}", String::from_utf8_lossy(&out));
        if !passes {
            assert_eq!(
                visible(Wire::Responses, &out).error.as_deref(),
                Some("stream_aborted"),
                "{name}"
            );
        }
    }
}

/// Fix wave 2a (D, final re-review N2): on Messages and Responses an
/// event with an `event:` name and no payload `type` aborts: the SDKs
/// dispatch on the name, the engine on the type, so it would pass
/// unrestored and untripwired.
#[test]
fn a_named_event_without_a_payload_type_aborts() {
    let host = FakeHost::new();
    let (sh, st) = rig(Arc::clone(&host));
    let args = json!({"to": NAME}).to_string();
    let named =
        |name: &str, data: Value| serialize(Some(name), None, data.to_string().as_bytes()).unwrap();
    let cases = [
        (
            Wire::Messages,
            [
                named(
                    "content_block_delta",
                    json!({"index": 0, "delta": {"type": "input_json_delta", "partial_json": args}}),
                ),
                ev(Some("message_stop"), json!({"type": "message_stop"})),
            ],
        ),
        (
            Wire::Responses,
            [
                named(
                    "response.function_call_arguments.delta",
                    json!({"output_index": 0, "item_id": "f", "delta": args}),
                ),
                ev(
                    Some("response.completed"),
                    json!({"type": "response.completed", "response": {"id": "r", "output": []}}),
                ),
            ],
        ),
    ];
    for (i, (wire, evs)) in cases.into_iter().enumerate() {
        let s = st.get(SessionKey([110 + i as u8; 32]));
        let (out, ok) = rewrite_session(&sh, &s, wire, ClientMode::Trusted, &evs.concat());
        assert!(!ok, "{wire:?}");
        assert!(
            !String::from_utf8_lossy(&out).contains("Zyxwuria"),
            "{wire:?}"
        );
    }
}

/// Follow-up N3: a text first seen as a plain argument string (tripwired
/// raw) and then as JSON arguments (tripwired on its decoded leaves) is
/// checked again as JSON, so a JSON-escaped clear value is caught.
#[test]
fn a_text_seen_as_plain_then_json_arguments_is_checked_as_json() {
    let (mut sh, st) = rig(FakeHost::new());
    sh.cfg.tripwire = TripwireMode::Block;
    // `a` is `a`: the raw text does not hold the name, the decoded one does.
    let escaped = r#"{"to":"Zyxwuri\u0061 Quoln\u0061th"}"#;
    let shell = json!({"type": "shell_call", "id": "sh_1", "call_id": "c1", "status": "completed", "action": {"commands": [escaped]}});
    let approval = json!({"type": "mcp_approval_request", "id": "mr_1", "server_label": "s", "name": "send", "arguments": escaped});
    let mut n = 0u64;
    let mut s = Vec::new();
    let mut push = |name: &str, mut data: Value| {
        data["type"] = json!(name);
        data["sequence_number"] = json!(n);
        n += 1;
        s.extend(ev(Some(name), data));
    };
    push(
        "response.created",
        json!({"response": {"id": "resp_1", "status": "in_progress", "output": []}}),
    );
    for (oi, it) in [(0, &shell), (1, &approval)] {
        push(
            "response.output_item.added",
            json!({"output_index": oi, "item": it}),
        );
        push(
            "response.output_item.done",
            json!({"output_index": oi, "item": it}),
        );
    }
    push(
        "response.completed",
        json!({"response": {"id": "resp_1", "status": "completed", "output": [shell, approval]}}),
    );
    let sess = st.get(SessionKey([120; 32]));
    let (out, ok) = rewrite_session(&sh, &sess, Wire::Responses, ClientMode::Trusted, &s);
    assert!(!ok, "{}", String::from_utf8_lossy(&out));
    assert_eq!(
        visible(Wire::Responses, &out).error.as_deref(),
        Some("privacy_block")
    );
    assert!(!String::from_utf8_lossy(&out).contains("mcp_approval_request"));
}

/// Follow-up N4: every string of a whole item is checked except `id`,
/// `call_id`, `status`, and `type`, so a variant shape (a top-level
/// `command`) holding a known value in clear is withheld in block mode.
#[test]
fn a_variant_field_of_a_whole_item_is_checked() {
    let (mut sh, st) = rig(FakeHost::new());
    sh.cfg.tripwire = TripwireMode::Block;
    let item = json!({"type": "shell_call", "id": "sh_1", "call_id": "c1", "status": "completed", "command": format!("mail '{NAME}'"), "action": {"commands": []}});
    let s = st.get(SessionKey([121; 32]));
    let (out, ok) = rewrite_session(
        &sh,
        &s,
        Wire::Responses,
        ClientMode::Trusted,
        &item_stream(item.clone(), &[], item),
    );
    assert!(!ok);
    assert_eq!(
        visible(Wire::Responses, &out).error.as_deref(),
        Some("privacy_block")
    );
    assert!(!String::from_utf8_lossy(&out).contains("Zyxwuria"));
}

/// A Codex MCP call as Codex 0.159.2 expects it (M8 spec §20 amendment
/// 2026-10-10): a `function_call` carrying `namespace` and the bare name.
fn namespaced_call_stream(ns: &str, args: &str) -> Vec<u8> {
    let mut s = Vec::new();
    let mut seq = 0u64;
    let mut push = |name: &str, mut d: Value| {
        d["type"] = json!(name);
        d["sequence_number"] = json!(seq);
        seq += 1;
        s.extend(ev(Some(name), d));
    };
    push(
        "response.created",
        json!({"response": {"id": "resp_1", "status": "in_progress", "output": []}}),
    );
    push(
        "response.output_item.added",
        json!({"output_index": 0, "item": {"type": "function_call", "id": "fc_1", "call_id": "c1",
            "name": "lookup_record", "namespace": ns, "arguments": "", "status": "in_progress"}}),
    );
    push(
        "response.function_call_arguments.delta",
        json!({"item_id": "fc_1", "output_index": 0, "delta": args}),
    );
    push(
        "response.function_call_arguments.done",
        json!({"item_id": "fc_1", "output_index": 0, "arguments": args}),
    );
    let fc = json!({"type": "function_call", "id": "fc_1", "call_id": "c1", "name": "lookup_record",
        "namespace": ns, "arguments": args, "status": "completed"});
    push(
        "response.output_item.done",
        json!({"output_index": 0, "item": fc.clone()}),
    );
    push(
        "response.completed",
        json!({"response": {"id": "resp_1", "status": "completed", "output": [fc]}}),
    );
    s
}

/// The `function_call` items a client sees, from every event that carries one.
fn call_items(bytes: &[u8]) -> Vec<Value> {
    let mut p = SseParser::new(MAX_EVENT);
    let mut evs = p.push(bytes).unwrap();
    evs.extend(p.finish().unwrap());
    let mut out = Vec::new();
    for e in evs {
        let Some(j) = e
            .data
            .and_then(|d| serde_json::from_slice::<Value>(&d).ok())
        else {
            continue;
        };
        if j["item"]["type"] == "function_call" {
            out.push(j["item"].clone());
        }
        for it in j["response"]["output"].as_array().into_iter().flatten() {
            out.push(it.clone());
        }
    }
    out
}

/// A streamed `function_call` with `namespace` passes the rewriter: its
/// arguments are restored as a flat call's, the namespace and name reach
/// the client unchanged; a known value in clear in the namespace is
/// tripwired as an argument (block mode aborts, notify mode records).
#[test]
fn a_streamed_namespaced_call_is_restored_and_its_namespace_tripwired() {
    let host = FakeHost::new();
    let (mut sh, st) = rig(Arc::clone(&host));
    let s = st.get(SessionKey([62; 32]));
    let tok = session_token(&s);
    let args = format!(r#"{{"to":"{tok}","cc":"{DS_TOKEN}"}}"#);
    let (out, ok) = rewrite_session(
        &sh,
        &s,
        Wire::Responses,
        ClientMode::Trusted,
        &namespaced_call_stream("mcp__inumaki_check_ab", &args),
    );
    assert!(ok, "{}", String::from_utf8_lossy(&out));
    let v = visible(Wire::Responses, &out);
    assert!(v.error.is_none());
    let a: Value = serde_json::from_str(&v.args[0]).unwrap();
    assert_eq!(
        (a["to"].as_str(), a["cc"].as_str()),
        (Some(ODD), Some(DS_TOKEN)),
        "restored as a flat call's: session token yes, dataset token no"
    );
    let items = call_items(&out);
    assert_eq!(items.len(), 3, "added, done, completed");
    for it in &items {
        assert_eq!(it["namespace"], "mcp__inumaki_check_ab");
        assert_eq!(it["name"], "lookup_record");
    }
    let done: Value = serde_json::from_str(items[2]["arguments"].as_str().unwrap()).unwrap();
    assert_eq!(done["to"], ODD, "the repeat is restored too");

    let clear = namespaced_call_stream(&format!("mcp__{NAME}"), "{}");
    sh.cfg.tripwire = TripwireMode::Block;
    let s = st.get(SessionKey([63; 32]));
    let (out, ok) = rewrite_session(&sh, &s, Wire::Responses, ClientMode::Trusted, &clear);
    assert!(!ok, "block mode: the call is withheld");
    let shown = String::from_utf8_lossy(&out);
    assert!(!shown.contains(NAME), "{shown}");
    sh.cfg.tripwire = TripwireMode::Notify;
    let s = st.get(SessionKey([64; 32]));
    let (_, ok) = rewrite_session(&sh, &s, Wire::Responses, ClientMode::Trusted, &clear);
    assert!(ok);
    assert!(
        host.events
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, ProxyEvent::ClearValue { blocked: false, .. })),
        "notify mode records the clear namespace"
    );
}
