//! The scripted model upstream (M8 spec §12.1): answers every wire format
//! from a script, choosing the step from the request's turn count, so it is
//! stateless. Used as the check's model (plan M8-3) and as the test upstream.
//!
//! Privacy: it records the bodies it receives (sanitized, after the
//! pipeline) and never logs them; `Debug` prints counts only. Scripts hold
//! synthetic test data.

use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use serde_json::{Value, json};

use crate::routes::{Endpoint, UpstreamId, Wire};
use crate::upstream::{Upstream, UpstreamError, UpstreamRequest, UpstreamResponse};

/// One tool call of a [`Step::CallTools`].
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCall {
    /// Matched against the advertised tool names: exact first, else the
    /// first name ending with it; no match skips the call. A Responses tool
    /// inside a `namespace` tool (how Codex advertises MCP tools) matches by
    /// its own name or by `<namespace>__<name>`, and is called with its
    /// namespace.
    pub name_suffix: String,
    /// The call's arguments.
    pub arguments: Value,
}

/// One scripted answer.
#[derive(Debug, Clone, PartialEq)]
pub enum Step {
    /// Call these tools (those advertised); all skipped → the next step answers.
    CallTools(Vec<ToolCall>),
    /// Answer `Tool results:` and the text of every tool result since the last assistant turn.
    EchoToolResults,
    /// Answer the text of the last user message.
    EchoUserText,
}

/// The steps, by turn count.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Script(pub Vec<Step>);

fn text_of(c: &Value) -> String {
    match c {
        Value::String(s) => s.clone(),
        Value::Array(a) => a
            .iter()
            .filter_map(|b| b.get("text").and_then(Value::as_str).or_else(|| b.as_str()))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// Assistant turns already in the request (spec §12.1).
pub fn turn_count(wire: Wire, v: &Value) -> usize {
    match wire {
        Wire::Messages | Wire::Chat => v["messages"]
            .as_array()
            .map_or(0, |m| m.iter().filter(|x| x["role"] == "assistant").count()),
        Wire::Responses => {
            let assistant = |x: &Value| {
                matches!(
                    x["type"].as_str(),
                    Some("function_call" | "custom_tool_call" | "reasoning" | "local_shell_call")
                ) || (x["type"] == "message" && x["role"] == "assistant")
            };
            let mut runs = 0;
            let mut prev = false;
            for x in v["input"].as_array().into_iter().flatten() {
                let a = assistant(x);
                if a && !prev {
                    runs += 1;
                }
                prev = a;
            }
            let prior = v["previous_response_id"]
                .as_str()
                .and_then(|s| s.strip_prefix("resp_ink_"))
                .and_then(|s| s.split('_').next())
                .and_then(|n| n.parse::<usize>().ok())
                .map_or(0, |n| n + 1);
            runs + prior
        }
    }
}

/// How deep Responses `namespace` tools are followed.
const MAX_NAMESPACE_DEPTH: usize = 4;

/// An advertised tool: its namespace (a Responses `namespace` tool's
/// name, the innermost one) and its name.
type Advertised = (Option<String>, String);

fn advertised(wire: Wire, v: &Value) -> Vec<Advertised> {
    let mut out = Vec::new();
    match wire {
        Wire::Chat => {
            for x in v["tools"].as_array().into_iter().flatten() {
                if let Some(n) = x["function"]["name"].as_str() {
                    out.push((None, n.to_string()));
                }
            }
        }
        Wire::Messages => {
            for x in v["tools"].as_array().into_iter().flatten() {
                if let Some(n) = x["name"].as_str() {
                    out.push((None, n.to_string()));
                }
            }
        }
        Wire::Responses => responses_tools(&v["tools"], None, 0, &mut out),
    }
    out
}

/// Responses tools, following `namespace` tools' nested `tools` up to
/// [`MAX_NAMESPACE_DEPTH`] levels.
fn responses_tools(tools: &Value, ns: Option<&str>, depth: usize, out: &mut Vec<Advertised>) {
    for x in tools.as_array().into_iter().flatten() {
        if x["type"] == "namespace" {
            if let (Some(name), true) = (x["name"].as_str(), depth < MAX_NAMESPACE_DEPTH) {
                responses_tools(&x["tools"], Some(name), depth + 1, out);
            }
            continue;
        }
        if let Some(n) = x["name"].as_str() {
            out.push((ns.map(str::to_string), n.to_string()));
        }
    }
}

/// The name a suffix is matched against: `<namespace>__<name>` for a
/// namespaced tool, else the name.
fn full_name((ns, name): &Advertised) -> String {
    match ns {
        Some(ns) => format!("{ns}__{name}"),
        None => name.clone(),
    }
}

fn tool_results_after_last_assistant(wire: Wire, v: &Value) -> Vec<String> {
    let mut out = Vec::new();
    match wire {
        Wire::Messages => {
            for m in v["messages"].as_array().into_iter().flatten() {
                if m["role"] == "assistant" {
                    out.clear();
                    continue;
                }
                for b in m["content"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|b| b["type"] == "tool_result")
                {
                    out.push(text_of(&b["content"]));
                }
            }
        }
        Wire::Chat => {
            for m in v["messages"].as_array().into_iter().flatten() {
                if m["role"] == "assistant" {
                    out.clear();
                    continue;
                }
                if m["role"] == "tool" {
                    out.push(text_of(&m["content"]));
                }
            }
        }
        Wire::Responses => {
            for x in v["input"].as_array().into_iter().flatten() {
                match x["type"].as_str() {
                    Some("function_call_output" | "custom_tool_call_output") => {
                        out.push(text_of(&x["output"]));
                    }
                    Some("function_call" | "custom_tool_call") => out.clear(),
                    _ => {}
                }
            }
        }
    }
    out
}

fn last_user_text(wire: Wire, v: &Value) -> String {
    match wire {
        Wire::Responses => match &v["input"] {
            Value::String(s) => s.clone(),
            Value::Array(a) => a
                .iter()
                .rev()
                .find(|x| x["role"] == "user")
                .map(|x| text_of(&x["content"]))
                .unwrap_or_default(),
            _ => String::new(),
        },
        _ => v["messages"]
            .as_array()
            .and_then(|m| m.iter().rev().find(|x| x["role"] == "user"))
            .map(|x| text_of(&x["content"]))
            .unwrap_or_default(),
    }
}

/// One call: the tool's namespace (Responses only), its name, its arguments.
type Call = (Option<String>, String, Value);

enum Reply {
    Text(String),
    Calls(Vec<Call>),
}

fn decide(wire: Wire, v: &Value, script: &Script) -> Reply {
    let mut i = turn_count(wire, v);
    let names = advertised(wire, v);
    loop {
        let step = match script.0.get(i) {
            Some(s) => s,
            // Beyond the end: the last step again, unless it calls tools.
            None => match script.0.last() {
                Some(Step::CallTools(_)) | None => {
                    return Reply::Text("inumaki check: script finished".into());
                }
                Some(s) => s,
            },
        };
        match step {
            Step::CallTools(calls) => {
                let chosen: Vec<Call> = calls
                    .iter()
                    .filter_map(|c| {
                        let s = c.name_suffix.as_str();
                        names
                            .iter()
                            .find(|a| a.1 == s || full_name(a) == s)
                            .or_else(|| names.iter().find(|a| full_name(a).ends_with(s)))
                            .map(|(ns, n)| (ns.clone(), n.clone(), c.arguments.clone()))
                    })
                    .collect();
                if chosen.is_empty() {
                    i += 1;
                    continue;
                }
                return Reply::Calls(chosen);
            }
            Step::EchoToolResults => {
                let r = tool_results_after_last_assistant(wire, v);
                return Reply::Text(if r.is_empty() {
                    "Tool results:\n(no tool results)".into()
                } else {
                    format!("Tool results:\n{}", r.join("\n"))
                });
            }
            Step::EchoUserText => return Reply::Text(last_user_text(wire, v)),
        }
    }
}

/// A non-streaming answer for `body` on `ep`.
pub fn answer(ep: Endpoint, body: &[u8], script: &Script) -> (http::StatusCode, Value) {
    let Ok(v) = serde_json::from_slice::<Value>(body) else {
        return (
            http::StatusCode::BAD_REQUEST,
            json!({"error": {"type": "invalid_request_error"}}),
        );
    };
    let model = v["model"].as_str().unwrap_or("inumaki-check").to_string();
    let wire = match ep {
        Endpoint::CountTokens => {
            return (
                http::StatusCode::OK,
                json!({"input_tokens": body.len() / 4}),
            );
        }
        Endpoint::Models => {
            return (
                http::StatusCode::OK,
                json!({"data": [{"id": "inumaki-check", "type": "model", "object": "model"}], "object": "list"}),
            );
        }
        Endpoint::Model => {
            return (
                http::StatusCode::OK,
                json!({"id": "inumaki-check", "type": "model", "object": "model"}),
            );
        }
        Endpoint::Messages => Wire::Messages,
        Endpoint::Responses => Wire::Responses,
        Endpoint::ChatCompletions => Wire::Chat,
    };
    let turn = turn_count(wire, &v);
    let body = match (wire, decide(wire, &v, script)) {
        (Wire::Messages, Reply::Text(t)) => json!({
            "id": format!("msg_ink_{turn}"), "type": "message", "role": "assistant", "model": model,
            "content": [{"type": "text", "text": t}], "stop_reason": "end_turn",
            "usage": {"input_tokens": 0, "output_tokens": 0}}),
        (Wire::Messages, Reply::Calls(c)) => json!({
            "id": format!("msg_ink_{turn}"), "type": "message", "role": "assistant", "model": model,
            "content": c.iter().enumerate().map(|(n, (_, name, args))| json!({
                "type": "tool_use", "id": format!("toolu_ink_{turn}_{n}"), "name": name, "input": args})).collect::<Vec<_>>(),
            "stop_reason": "tool_use", "usage": {"input_tokens": 0, "output_tokens": 0}}),
        (Wire::Responses, Reply::Text(t)) => json!({
            "id": format!("resp_ink_{turn}_0"), "object": "response", "status": "completed", "model": model,
            "output": [{"type": "message", "id": format!("msg_ink_{turn}"), "role": "assistant", "status": "completed",
                "content": [{"type": "output_text", "text": t, "annotations": []}]}],
            "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}}),
        (Wire::Responses, Reply::Calls(c)) => json!({
            "id": format!("resp_ink_{turn}_0"), "object": "response", "status": "completed", "model": model,
            "output": c.iter().enumerate().map(|(n, (ns, name, args))| with_namespace(json!({
                "type": "function_call", "id": format!("fc_ink_{turn}_{n}"), "call_id": format!("call_ink_{turn}_{n}"),
                "name": name, "arguments": args.to_string(), "status": "completed"}), ns.as_deref())).collect::<Vec<_>>(),
            "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}}),
        (Wire::Chat, Reply::Text(t)) => json!({
            "id": format!("chatcmpl-ink-{turn}"), "object": "chat.completion", "model": model,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": t}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}),
        (Wire::Chat, Reply::Calls(c)) => json!({
            "id": format!("chatcmpl-ink-{turn}"), "object": "chat.completion", "model": model,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": null,
                "tool_calls": c.iter().enumerate().map(|(n, (_, name, args))| json!({
                    "id": format!("call_ink_{turn}_{n}"), "type": "function",
                    "function": {"name": name, "arguments": args.to_string()}})).collect::<Vec<_>>()},
                "finish_reason": "tool_calls"}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}),
    };
    (http::StatusCode::OK, body)
}

/// A Responses `function_call` item, with `"namespace"` when the tool was
/// advertised inside a `namespace` tool (Codex expects it there).
fn with_namespace(mut item: Value, ns: Option<&str>) -> Value {
    if let Some(ns) = ns {
        item["namespace"] = json!(ns);
    }
    item
}

fn ev(name: Option<&str>, data: Value) -> Vec<u8> {
    // Fixed event names: never a line break.
    crate::sse::serialize(name, None, data.to_string().as_bytes()).unwrap_or_default()
}

/// Text in pieces of `n` characters (spec §12.1: 5-character deltas).
fn char_chunks(s: &str, n: usize) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    chars.chunks(n).map(|c| c.iter().collect()).collect()
}

/// Bytes in pieces of at most `n`, cut on character boundaries (7-byte
/// argument fragments).
fn byte_chunks(s: &str, n: usize) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    while start < s.len() {
        let mut end = (start + n).min(s.len());
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        if end == start {
            end = start + s[start..].chars().next().map_or(1, char::len_utf8);
        }
        out.push(&s[start..end]);
        start = end;
    }
    out
}

fn messages_events(turn: usize, model: &str, reply: Reply) -> Vec<Vec<u8>> {
    let mut out = vec![ev(
        Some("message_start"),
        json!({"type": "message_start", "message": {"id": format!("msg_ink_{turn}"), "type": "message",
            "role": "assistant", "model": model, "content": [], "stop_reason": null,
            "usage": {"input_tokens": 0, "output_tokens": 0}}}),
    )];
    let delta = |i: usize, d: Value| {
        ev(
            Some("content_block_delta"),
            json!({"type": "content_block_delta", "index": i, "delta": d}),
        )
    };
    let stop = match reply {
        Reply::Text(t) => {
            out.push(ev(
                Some("content_block_start"),
                json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
            ));
            out.extend(
                char_chunks(&t, 5)
                    .into_iter()
                    .map(|c| delta(0, json!({"type": "text_delta", "text": c}))),
            );
            out.push(ev(
                Some("content_block_stop"),
                json!({"type": "content_block_stop", "index": 0}),
            ));
            "end_turn"
        }
        Reply::Calls(calls) => {
            for (n, (_, name, args)) in calls.iter().enumerate() {
                out.push(ev(
                    Some("content_block_start"),
                    json!({"type": "content_block_start", "index": n, "content_block": {"type": "tool_use",
                        "id": format!("toolu_ink_{turn}_{n}"), "name": name, "input": {}}}),
                ));
                let a = args.to_string();
                out.extend(
                    byte_chunks(&a, 7)
                        .into_iter()
                        .map(|c| delta(n, json!({"type": "input_json_delta", "partial_json": c}))),
                );
                out.push(ev(
                    Some("content_block_stop"),
                    json!({"type": "content_block_stop", "index": n}),
                ));
            }
            "tool_use"
        }
    };
    out.push(ev(
        Some("message_delta"),
        json!({"type": "message_delta", "delta": {"stop_reason": stop}, "usage": {"output_tokens": 0}}),
    ));
    out.push(ev(Some("message_stop"), json!({"type": "message_stop"})));
    out
}

fn responses_events(turn: usize, model: &str, reply: Reply) -> Vec<Vec<u8>> {
    let mut seq = 0u64;
    let mut out = Vec::new();
    let mut push = |name: &str, mut d: Value| {
        d["type"] = json!(name);
        d["sequence_number"] = json!(seq);
        seq += 1;
        out.push(ev(Some(name), d));
    };
    let id = format!("resp_ink_{turn}_0");
    push(
        "response.created",
        json!({"response": {"id": id, "object": "response", "status": "in_progress", "model": model, "output": []}}),
    );
    let mut items = Vec::new();
    match reply {
        Reply::Text(t) => {
            let mid = format!("msg_ink_{turn}");
            push(
                "response.output_item.added",
                json!({"output_index": 0, "item": {"type": "message", "id": mid, "role": "assistant",
                    "status": "in_progress", "content": []}}),
            );
            push(
                "response.content_part.added",
                json!({"item_id": mid, "output_index": 0, "content_index": 0,
                    "part": {"type": "output_text", "text": "", "annotations": []}}),
            );
            for c in char_chunks(&t, 5) {
                push(
                    "response.output_text.delta",
                    json!({"item_id": mid, "output_index": 0, "content_index": 0, "delta": c}),
                );
            }
            push(
                "response.output_text.done",
                json!({"item_id": mid, "output_index": 0, "content_index": 0, "text": t}),
            );
            push(
                "response.content_part.done",
                json!({"item_id": mid, "output_index": 0, "content_index": 0,
                    "part": {"type": "output_text", "text": t, "annotations": []}}),
            );
            let item = json!({"type": "message", "id": mid, "role": "assistant", "status": "completed",
                "content": [{"type": "output_text", "text": t, "annotations": []}]});
            push(
                "response.output_item.done",
                json!({"output_index": 0, "item": item.clone()}),
            );
            items.push(item);
        }
        Reply::Calls(calls) => {
            for (n, (ns, name, args)) in calls.iter().enumerate() {
                let (fid, a) = (format!("fc_ink_{turn}_{n}"), args.to_string());
                let ns = ns.as_deref();
                push(
                    "response.output_item.added",
                    json!({"output_index": n, "item": with_namespace(json!({"type": "function_call", "id": fid,
                        "call_id": format!("call_ink_{turn}_{n}"), "name": name, "arguments": "",
                        "status": "in_progress"}), ns)}),
                );
                for c in byte_chunks(&a, 7) {
                    push(
                        "response.function_call_arguments.delta",
                        json!({"item_id": fid, "output_index": n, "delta": c}),
                    );
                }
                push(
                    "response.function_call_arguments.done",
                    json!({"item_id": fid, "output_index": n, "arguments": a}),
                );
                let item = with_namespace(
                    json!({"type": "function_call", "id": fid, "call_id": format!("call_ink_{turn}_{n}"),
                        "name": name, "arguments": a, "status": "completed"}),
                    ns,
                );
                push(
                    "response.output_item.done",
                    json!({"output_index": n, "item": item.clone()}),
                );
                items.push(item);
            }
        }
    }
    push(
        "response.completed",
        json!({"response": {"id": id, "object": "response", "status": "completed", "model": model,
            "output": items, "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}}}),
    );
    out
}

fn chat_events(turn: usize, model: &str, reply: Reply) -> Vec<Vec<u8>> {
    let chunk = |delta: Value, finish: Value| {
        ev(
            None,
            json!({"id": format!("chatcmpl-ink-{turn}"), "object": "chat.completion.chunk", "created": 0,
                "model": model, "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}),
        )
    };
    let mut out = vec![chunk(
        json!({"role": "assistant", "content": ""}),
        Value::Null,
    )];
    let finish = match reply {
        Reply::Text(t) => {
            out.extend(
                char_chunks(&t, 5)
                    .into_iter()
                    .map(|c| chunk(json!({"content": c}), Value::Null)),
            );
            "stop"
        }
        Reply::Calls(calls) => {
            for (n, (_, name, args)) in calls.iter().enumerate() {
                out.push(chunk(
                    json!({"tool_calls": [{"index": n, "id": format!("call_ink_{turn}_{n}"), "type": "function",
                        "function": {"name": name, "arguments": ""}}]}),
                    Value::Null,
                ));
                let a = args.to_string();
                out.extend(byte_chunks(&a, 7).into_iter().map(|c| {
                    chunk(
                        json!({"tool_calls": [{"index": n, "function": {"arguments": c}}]}),
                        Value::Null,
                    )
                }));
            }
            "tool_calls"
        }
    };
    out.push(chunk(json!({}), json!(finish)));
    out.push(b"data: [DONE]\n\n".to_vec());
    out
}

/// The event stream for `body` on `ep` (spec §12.1 "Streaming"), one event
/// per element; empty for an endpoint without a wire format or a body that
/// is not JSON.
pub fn stream_answer(ep: Endpoint, body: &[u8], script: &Script) -> Vec<Vec<u8>> {
    let Ok(v) = serde_json::from_slice::<Value>(body) else {
        return Vec::new();
    };
    let Some(wire) = ep.wire() else {
        return Vec::new();
    };
    let model = v["model"].as_str().unwrap_or("inumaki-check").to_string();
    let turn = turn_count(wire, &v);
    let reply = decide(wire, &v, script);
    match wire {
        Wire::Messages => messages_events(turn, &model, reply),
        Wire::Responses => responses_events(turn, &model, reply),
        Wire::Chat => chat_events(turn, &model, reply),
    }
}

type Body = futures::stream::BoxStream<'static, Result<bytes::Bytes, UpstreamError>>;

fn one(b: bytes::Bytes) -> Body {
    futures::StreamExt::boxed(futures::stream::once(async move { Ok(b) }))
}

/// The scripted upstream's answer to one request: an event stream when the
/// request asks for one (`"stream": true` on a wire endpoint), else the
/// JSON answer.
pub(crate) fn respond(req: &UpstreamRequest, script: &Script) -> UpstreamResponse {
    let path = req
        .path_and_query
        .split('?')
        .next()
        .unwrap_or(&req.path_and_query);
    let ep = crate::routes::endpoint(req.upstream, &req.method, path);
    let streaming = serde_json::from_slice::<Value>(&req.body).is_ok_and(|v| v["stream"] == true);
    let mut headers = http::HeaderMap::new();
    let (status, body) = match ep {
        Some(ep) if streaming && ep.wire().is_some() => {
            headers.insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("text/event-stream"),
            );
            let events = stream_answer(ep, &req.body, script);
            let body: Body = futures::StreamExt::boxed(futures::stream::iter(
                events.into_iter().map(|e| Ok(bytes::Bytes::from(e))),
            ));
            (http::StatusCode::OK, body)
        }
        Some(ep) => {
            headers.insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/json"),
            );
            let (status, v) = answer(ep, &req.body, script);
            (status, one(bytes::Bytes::from(v.to_string())))
        }
        None => {
            headers.insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/json"),
            );
            (
                http::StatusCode::NOT_FOUND,
                one(bytes::Bytes::from_static(
                    br#"{"error":{"type":"not_found"}}"#,
                )),
            )
        }
    };
    UpstreamResponse {
        status,
        headers,
        body,
    }
}

/// One request to the scripted HTTP server (plan M8-3 Task 4 records what
/// a harness sends; synthetic runs with dummy credentials only, never
/// user traffic). `Debug` prints the method and the path length.
#[derive(Clone)]
pub struct RequestLine {
    /// HTTP method.
    pub method: String,
    /// Path, without the query.
    pub path: String,
    /// Query string, if any.
    pub query: Option<String>,
    /// `User-Agent`, if sent.
    pub user_agent: Option<String>,
    /// Names (not values) of all request headers.
    pub header_names: Vec<String>,
    /// Whether the request carried an `Upgrade` header.
    pub upgrade: bool,
}

impl fmt::Debug for RequestLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestLine")
            .field("method", &self.method)
            .field("path_len", &self.path.len())
            .finish()
    }
}

/// A scripted upstream that records what it receives (bodies only; the
/// HTTP server also records [`RequestLine`]s, never header values other
/// than `User-Agent`). `Debug` prints counts only.
pub struct ScriptedUpstream {
    script: Script,
    recorded: Mutex<Vec<(UpstreamId, Vec<u8>)>>,
    lines: Mutex<Vec<RequestLine>>,
}

impl fmt::Debug for ScriptedUpstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScriptedUpstream")
            .field("steps", &self.script.0.len())
            .field(
                "recorded",
                &self
                    .recorded
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .len(),
            )
            .finish()
    }
}

impl ScriptedUpstream {
    /// An upstream answering from `script`.
    pub fn new(script: Script) -> ScriptedUpstream {
        ScriptedUpstream {
            script,
            recorded: Mutex::new(Vec::new()),
            lines: Mutex::new(Vec::new()),
        }
    }

    /// The request lines the HTTP server received so far, in arrival order.
    pub fn lines(&self) -> Vec<RequestLine> {
        self.lines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The bodies received so far, in arrival order (what left the proxy).
    pub fn recorded(&self) -> Vec<(UpstreamId, Vec<u8>)> {
        self.recorded
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Upstream for ScriptedUpstream {
    fn send(
        &self,
        req: UpstreamRequest,
    ) -> futures::future::BoxFuture<'static, Result<UpstreamResponse, UpstreamError>> {
        self.recorded
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((req.upstream, req.body.to_vec()));
        let r = respond(&req, &self.script);
        Box::pin(async move { Ok(r) })
    }
}

/// Serve a scripted upstream over HTTP on loopback (inumakid's tests point
/// `[proxy.upstreams.*] base_url` at it). Paths are the upstream's own:
/// `/v1/messages…` is Anthropic, `/responses` and `/models` the Codex
/// backend, anything else OpenAI.
#[doc(hidden)]
pub async fn spawn_http(script: Script) -> (std::net::SocketAddr, Arc<ScriptedUpstream>) {
    let up = Arc::new(ScriptedUpstream::new(script));
    let u = Arc::clone(&up);
    let app = axum::Router::new().fallback(
        move |method: http::Method,
              uri: http::Uri,
              headers: http::HeaderMap,
              body: axum::body::Bytes| {
            let u = Arc::clone(&u);
            async move {
                u.lines
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(RequestLine {
                        method: method.to_string(),
                        path: uri.path().to_string(),
                        query: uri.query().map(str::to_string),
                        user_agent: headers
                            .get(http::header::USER_AGENT)
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_string),
                        header_names: headers.keys().map(|k| k.as_str().to_string()).collect(),
                        upgrade: headers.contains_key(http::header::UPGRADE),
                    });
                let path = uri.path().to_string();
                let upstream = if path == "/responses" || path == "/models" {
                    UpstreamId::OpenaiCodex
                } else if path.starts_with("/v1/messages") {
                    UpstreamId::Anthropic
                } else {
                    UpstreamId::Openai
                };
                let req = UpstreamRequest {
                    upstream,
                    method,
                    path_and_query: path,
                    headers: http::HeaderMap::new(),
                    body,
                };
                let Ok(resp) = u.send(req).await else {
                    return (
                        http::StatusCode::BAD_GATEWAY,
                        http::HeaderMap::new(),
                        axum::body::Body::empty(),
                    );
                };
                // Streamed as produced, so daemon tests receive real event streams.
                (
                    resp.status,
                    resp.headers,
                    axum::body::Body::from_stream(resp.body),
                )
            }
        },
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let addr = l.local_addr().expect("a bound address");
    tokio::spawn(async move {
        let _ = axum::serve(l, app).await;
    });
    (addr, up)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn lines_record_the_request_shape_and_debug_hides_the_path() {
        crate::forward::ensure_crypto_provider();
        let (addr, up) = spawn_http(Script(vec![Step::EchoUserText])).await;
        let r = reqwest::Client::new()
            .get(format!("http://{addr}/secret-path?client_version=1"))
            .header("user-agent", "probe/1.0")
            .header("upgrade", "websocket")
            .header("x-custom", "value-not-recorded")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 404);
        let lines = up.lines();
        assert_eq!(lines.len(), 1);
        let l = &lines[0];
        assert_eq!(
            (l.method.as_str(), l.path.as_str(), l.query.as_deref()),
            ("GET", "/secret-path", Some("client_version=1"))
        );
        assert_eq!(l.user_agent.as_deref(), Some("probe/1.0"));
        assert!(l.upgrade);
        assert!(l.header_names.iter().any(|n| n == "x-custom"));
        assert!(!format!("{l:?}").contains("secret-path"));
    }

    fn lookup_script() -> Script {
        Script(vec![
            Step::CallTools(vec![ToolCall {
                name_suffix: "lookup_record".into(),
                arguments: json!({"id": "K-1"}),
            }]),
            Step::EchoToolResults,
        ])
    }

    /// Codex 0.159.2 advertises MCP tools as a `namespace` tool and calls
    /// them as a `function_call` carrying `namespace` and the bare name.
    fn codex_request() -> Value {
        json!({"model": "m", "tools": [
            {"type": "function", "name": "shell"},
            {"type": "namespace", "name": "mcp__inumaki_check_ab", "description": "d",
             "tools": [{"type": "function", "name": "lookup_record", "parameters": {}}]},
            {"type": "web_search"}
        ], "input": [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": "go"}]}]})
    }

    #[test]
    fn a_namespaced_tool_is_called_with_its_namespace() {
        let body = codex_request().to_string();
        let (_, a) = answer(Endpoint::Responses, body.as_bytes(), &lookup_script());
        let out = a["output"].as_array().unwrap();
        assert_eq!(out.len(), 1, "{a}");
        assert_eq!(out[0]["type"], "function_call");
        assert_eq!(out[0]["name"], "lookup_record");
        assert_eq!(out[0]["namespace"], "mcp__inumaki_check_ab");
        assert_eq!(out[0]["arguments"], r#"{"id":"K-1"}"#);

        let events = stream_answer(Endpoint::Responses, body.as_bytes(), &lookup_script());
        let evs: Vec<Value> = events
            .iter()
            .filter_map(|e| {
                let s = std::str::from_utf8(e).unwrap();
                let d = s.lines().find_map(|l| l.strip_prefix("data: "))?;
                serde_json::from_str(d).ok()
            })
            .collect();
        let items: Vec<&Value> = evs
            .iter()
            .filter(|e| {
                matches!(
                    e["type"].as_str(),
                    Some("response.output_item.added" | "response.output_item.done")
                )
            })
            .map(|e| &e["item"])
            .chain(
                evs.iter()
                    .filter(|e| e["type"] == "response.completed")
                    .map(|e| &e["response"]["output"][0]),
            )
            .collect();
        assert_eq!(items.len(), 3, "added, done, completed");
        for it in items {
            assert_eq!(it["name"], "lookup_record");
            assert_eq!(it["namespace"], "mcp__inumaki_check_ab");
        }

        // A flat Responses tool is still called by its own name, no namespace.
        let flat = json!({"tools": [{"type": "function", "name": "mcp__inumaki-check-ab__lookup_record"}], "input": "go"});
        let (_, f) = answer(
            Endpoint::Responses,
            flat.to_string().as_bytes(),
            &lookup_script(),
        );
        assert_eq!(
            f["output"][0]["name"],
            "mcp__inumaki-check-ab__lookup_record"
        );
        assert!(f["output"][0].get("namespace").is_none());
    }

    #[test]
    fn namespaces_nest_only_a_few_levels() {
        let mut tools = json!([{"type": "function", "name": "lookup_record"}]);
        for d in 0..6 {
            tools = json!([{"type": "namespace", "name": format!("ns{d}"), "tools": tools}]);
        }
        let deep = json!({"tools": tools, "input": "go"});
        let (_, a) = answer(
            Endpoint::Responses,
            deep.to_string().as_bytes(),
            &lookup_script(),
        );
        assert_eq!(
            a["output"][0]["type"], "message",
            "too deep: not advertised"
        );
        let mut tools = json!([{"type": "function", "name": "lookup_record"}]);
        for d in 0..2 {
            tools = json!([{"type": "namespace", "name": format!("ns{d}"), "tools": tools}]);
        }
        let shallow = json!({"tools": tools, "input": "go"});
        let (_, b) = answer(
            Endpoint::Responses,
            shallow.to_string().as_bytes(),
            &lookup_script(),
        );
        assert_eq!(
            b["output"][0]["namespace"], "ns0",
            "the innermost namespace"
        );
    }

    #[test]
    fn step_follows_the_turn_count_and_skips_unadvertised_tools() {
        let script = Script(vec![
            Step::CallTools(vec![
                ToolCall {
                    name_suffix: "lookup_record".into(),
                    arguments: json!({}),
                },
                ToolCall {
                    name_suffix: "Read".into(),
                    arguments: json!({"file_path": "/x"}),
                },
            ]),
            Step::EchoToolResults,
        ]);
        let turn0 = json!({"tools": [{"name": "mcp__inumaki-check-ab__lookup_record"}], "messages": [{"role": "user", "content": "go"}]});
        let (_, a) = answer(Endpoint::Messages, turn0.to_string().as_bytes(), &script);
        let calls: Vec<_> = a["content"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|c| c["type"] == "tool_use")
            .collect();
        assert_eq!(calls.len(), 1, "Read is not advertised: skipped");
        assert_eq!(calls[0]["name"], "mcp__inumaki-check-ab__lookup_record");
        let (_, again) = answer(Endpoint::Messages, turn0.to_string().as_bytes(), &script);
        assert_eq!(a, again, "stateless: the same request gets the same answer");
        let turn1 = json!({"messages": [
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_ink_0_0", "name": "x", "input": {}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_ink_0_0", "content": "Record: <PERSON_a1b2c3>"}]}
        ]});
        let (_, b) = answer(Endpoint::Messages, turn1.to_string().as_bytes(), &script);
        assert_eq!(
            b["content"][0]["text"],
            "Tool results:\nRecord: <PERSON_a1b2c3>"
        );
        let none = json!({"messages": [{"role": "user", "content": "go"}]});
        let (_, c) = answer(Endpoint::Messages, none.to_string().as_bytes(), &script);
        assert_eq!(
            c["content"][0]["text"], "Tool results:\n(no tool results)",
            "all calls skipped: the next step answers"
        );
    }
}
