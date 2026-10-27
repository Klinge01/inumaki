//! The gateway against the request sequences real MCP clients send, as raw
//! HTTP (no rmcp client): the 2026-07-28 per-request lifecycle that Claude
//! Code 2.1.296 uses (`server/discover`, then lists and calls that carry
//! their protocol version in `_meta` and headers, then a held
//! `subscriptions/listen` stream), and the 2025 session lifecycle
//! (`initialize`, `notifications/initialized`, `Mcp-Session-Id`) with the
//! optional methods clients send after connecting.
//!
//! The modern client validates every result against the 2026-07-28
//! schema: `resultType: "complete"` on all of them, and `ttlMs` and
//! `cacheScope` on lists and reads. Without the hints every list failed on
//! the client and the server was left with no tools; without `resultType`
//! every tool call failed. Each modern reply here goes through `wire`, a
//! hand-written copy of that schema. `subscriptions/listen` answered with METHOD_NOT_FOUND becomes an
//! HTTP 404 that the client retries and then gives up on, so the agent
//! never hears about catalog changes.

mod common;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;

use common::gateway::*;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const MODERN: &str = "2026-07-28";
const LEGACY: &str = "2025-11-25";

/// Write one POST to `/mcp/crm` and return the open connection.
async fn send(addr: SocketAddr, bearer: &str, headers: &[(&str, &str)], body: &Value) -> TcpStream {
    let body = body.to_string();
    let mut s = TcpStream::connect(addr).await.unwrap();
    let mut req = format!(
        "POST /mcp/crm HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: {}\r\n\
         Content-Type: application/json\r\nAccept: application/json, text/event-stream\r\n\
         Authorization: Bearer {bearer}\r\n",
        body.len()
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(&body);
    s.write_all(req.as_bytes()).await.unwrap();
    s
}

/// Read from `s` until `needle` appears (or the connection closes, or
/// `wait` passes); everything read so far.
async fn read_until(s: &mut TcpStream, seen: &mut String, needle: &str, wait: Duration) {
    let deadline = tokio::time::Instant::now() + wait;
    let mut buf = [0u8; 8192];
    while !seen.contains(needle) {
        match tokio::time::timeout_at(deadline, s.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => seen.push_str(&String::from_utf8_lossy(&buf[..n])),
            _ => return,
        }
    }
}

/// A whole exchange: status, response headers and body text, and the
/// JSON-RPC message in it (an SSE `data:` line or a JSON body).
struct Reply {
    status: u16,
    text: String,
    message: Value,
}

async fn post(addr: SocketAddr, bearer: &str, headers: &[(&str, &str)], body: &Value) -> Reply {
    let mut s = send(addr, bearer, headers, body).await;
    let mut text = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), s.read_to_string(&mut text)).await;
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let message = text
        .lines()
        .filter_map(|l| l.strip_prefix("data: ").or(l.strip_prefix('{').map(|_| l)))
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find(|m| m.get("id").is_some())
        .unwrap_or(Value::Null);
    Reply {
        status,
        text,
        message,
    }
}

/// A hand-written check of the 2026-07-28 wire shapes, taken from the zod
/// schemas Claude Code 2.1.296 validates with (its `decodeResult` and the
/// `ListToolsResultSchema`, `CallToolResultSchema`, ... builder; read from
/// the installed binary): `resultType` must be the string `complete`, then
/// the method's schema applies. Objects may carry extra keys except the
/// JSON-RPC envelope, which is strict. `Err` names the first violation.
mod wire {
    use serde_json::Value;

    type R = Result<(), String>;

    fn obj<'a>(v: &'a Value, at: &str) -> Result<&'a serde_json::Map<String, Value>, String> {
        v.as_object().ok_or_else(|| format!("{at}: not an object"))
    }
    fn string(v: &Value, key: &str, at: &str) -> R {
        match v.get(key) {
            Some(Value::String(_)) => Ok(()),
            other => Err(format!("{at}.{key}: required string, got {other:?}")),
        }
    }
    /// `z.string().optional()`: absent or a string (null fails).
    fn opt_string(v: &Value, key: &str, at: &str) -> R {
        match v.get(key) {
            None | Some(Value::String(_)) => Ok(()),
            other => Err(format!("{at}.{key}: optional string, got {other:?}")),
        }
    }
    /// `.nullish()`: absent, null, or the type.
    fn nullish(v: &Value, key: &str, at: &str, ok: fn(&Value) -> bool) -> R {
        match v.get(key) {
            None | Some(Value::Null) => Ok(()),
            Some(x) if ok(x) => Ok(()),
            other => Err(format!("{at}.{key}: wrong type, got {other:?}")),
        }
    }
    fn opt_bool(v: &Value, key: &str, at: &str) -> R {
        match v.get(key) {
            None | Some(Value::Bool(_)) => Ok(()),
            other => Err(format!("{at}.{key}: optional bool, got {other:?}")),
        }
    }
    fn opt_object(v: &Value, key: &str, at: &str) -> R {
        match v.get(key) {
            None | Some(Value::Object(_)) => Ok(()),
            other => Err(format!("{at}.{key}: optional object, got {other:?}")),
        }
    }
    fn array<'a>(v: &'a Value, key: &str, at: &str) -> Result<&'a Vec<Value>, String> {
        v.get(key)
            .and_then(Value::as_array)
            .ok_or_else(|| format!("{at}.{key}: required array"))
    }
    /// Standard base64 (what `atob` accepts for a padded string).
    fn base64(v: &Value, key: &str, at: &str) -> R {
        let s = v
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{at}.{key}: required base64 string"))?;
        let body = s.trim_end_matches('=');
        let ok = s.len() % 4 == 0
            && s.len() - body.len() <= 2
            && body
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/');
        if ok {
            Ok(())
        } else {
            Err(format!("{at}.{key}: not base64"))
        }
    }
    fn annotations(v: &Value, at: &str) -> R {
        let Some(a) = v.get("annotations") else {
            return Ok(());
        };
        let at = format!("{at}.annotations");
        obj(a, &at)?;
        if let Some(aud) = a.get("audience") {
            let ok = aud.as_array().is_some_and(|l| {
                l.iter()
                    .all(|r| matches!(r.as_str(), Some("user" | "assistant")))
            });
            if !ok {
                return Err(format!("{at}.audience: {aud}"));
            }
        }
        if let Some(p) = a.get("priority") {
            if !p.as_f64().is_some_and(|p| (0.0..=1.0).contains(&p)) {
                return Err(format!("{at}.priority: {p}"));
            }
        }
        opt_string(a, "lastModified", &at)
    }
    fn resource_contents(v: &Value, at: &str) -> R {
        obj(v, at)?;
        string(v, "uri", at)?;
        nullish(v, "mimeType", at, Value::is_string)?;
        opt_object(v, "_meta", at)?;
        match (v.get("text"), v.get("blob")) {
            (Some(Value::String(_)), _) => Ok(()),
            (None, Some(_)) => base64(v, "blob", at),
            _ => Err(format!("{at}: neither text nor blob")),
        }
    }
    fn resource(v: &Value, at: &str) -> R {
        obj(v, at)?;
        string(v, "name", at)?;
        string(v, "uri", at)?;
        opt_string(v, "title", at)?;
        nullish(v, "description", at, Value::is_string)?;
        nullish(v, "mimeType", at, Value::is_string)?;
        nullish(v, "size", at, Value::is_number)?;
        nullish(v, "_meta", at, Value::is_object)?;
        annotations(v, at)
    }
    pub fn content_block(v: &Value, at: &str) -> R {
        obj(v, at)?;
        opt_object(v, "_meta", at)?;
        annotations(v, at)?;
        match v.get("type").and_then(Value::as_str) {
            Some("text") => string(v, "text", at),
            Some("image" | "audio") => {
                base64(v, "data", at)?;
                string(v, "mimeType", at)
            }
            Some("resource_link") => resource(v, at),
            Some("resource") => resource_contents(
                v.get("resource")
                    .ok_or_else(|| format!("{at}.resource: required"))?,
                &format!("{at}.resource"),
            ),
            other => Err(format!("{at}.type: {other:?}")),
        }
    }
    fn tool(v: &Value, at: &str) -> R {
        obj(v, at)?;
        string(v, "name", at)?;
        opt_string(v, "title", at)?;
        opt_string(v, "description", at)?;
        let schema = v
            .get("inputSchema")
            .ok_or_else(|| format!("{at}.inputSchema: required"))?;
        obj(schema, &format!("{at}.inputSchema"))?;
        if schema.get("type") != Some(&Value::from("object")) {
            return Err(format!("{at}.inputSchema.type: not \"object\""));
        }
        opt_object(v, "outputSchema", at)?;
        opt_object(v, "_meta", at)?;
        if let Some(a) = v.get("annotations") {
            obj(a, &format!("{at}.annotations"))?;
            opt_string(a, "title", at)?;
            for hint in [
                "readOnlyHint",
                "destructiveHint",
                "idempotentHint",
                "openWorldHint",
            ] {
                opt_bool(a, hint, &format!("{at}.annotations"))?;
            }
        }
        Ok(())
    }
    fn prompt(v: &Value, at: &str) -> R {
        obj(v, at)?;
        string(v, "name", at)?;
        opt_string(v, "title", at)?;
        nullish(v, "description", at, Value::is_string)?;
        nullish(v, "_meta", at, Value::is_object)?;
        if let Some(args) = v.get("arguments").filter(|a| !a.is_null()) {
            for (i, a) in args
                .as_array()
                .ok_or_else(|| format!("{at}.arguments: not an array"))?
                .iter()
                .enumerate()
            {
                let at = format!("{at}.arguments[{i}]");
                obj(a, &at)?;
                string(a, "name", &at)?;
                nullish(a, "description", &at, Value::is_string)?;
                nullish(a, "required", &at, Value::is_boolean)?;
            }
        }
        Ok(())
    }
    fn template(v: &Value, at: &str) -> R {
        obj(v, at)?;
        string(v, "name", at)?;
        string(v, "uriTemplate", at)?;
        nullish(v, "description", at, Value::is_string)?;
        nullish(v, "mimeType", at, Value::is_string)?;
        nullish(v, "_meta", at, Value::is_object)?;
        annotations(v, at)
    }
    fn cache_hints(v: &Value, at: &str) -> R {
        if v.get("ttlMs").and_then(Value::as_u64).is_none() {
            return Err(format!("{at}.ttlMs: required non-negative integer"));
        }
        match v.get("cacheScope").and_then(Value::as_str) {
            Some("public" | "private") => Ok(()),
            other => Err(format!("{at}.cacheScope: {other:?}")),
        }
    }
    fn each(v: &Value, key: &str, at: &str, f: fn(&Value, &str) -> R) -> R {
        for (i, item) in array(v, key, at)?.iter().enumerate() {
            f(item, &format!("{at}.{key}[{i}]"))?;
        }
        Ok(())
    }

    /// A result of `method` for a 2026-07-28 peer.
    pub fn result(method: &str, v: &Value) -> R {
        let at = method;
        obj(v, at)?;
        match v.get("resultType") {
            Some(Value::String(s)) if s == "complete" => {}
            None => return Err(format!("{at}: missing required resultType")),
            other => return Err(format!("{at}.resultType: {other:?}")),
        }
        opt_object(v, "_meta", at)?;
        opt_string(v, "nextCursor", at)?;
        match method {
            "tools/call" => {
                each(v, "content", at, content_block)?;
                // `z.record(...)`: an object when present
                opt_object(v, "structuredContent", at)?;
                opt_bool(v, "isError", at)
            }
            // the final result of a listen that ended gracefully
            "subscriptions/listen" => {
                let m = v
                    .get("_meta")
                    .ok_or_else(|| format!("{at}._meta: required"))?;
                match m.get("io.modelcontextprotocol/subscriptionId") {
                    Some(Value::String(_)) => Ok(()),
                    Some(n) if n.is_i64() => Ok(()),
                    other => Err(format!("{at}._meta.subscriptionId: {other:?}")),
                }
            }
            "tools/list" => {
                cache_hints(v, at)?;
                each(v, "tools", at, tool)
            }
            "prompts/list" => {
                cache_hints(v, at)?;
                each(v, "prompts", at, prompt)
            }
            "prompts/get" => {
                opt_string(v, "description", at)?;
                for (i, m) in array(v, "messages", at)?.iter().enumerate() {
                    let at = format!("{at}.messages[{i}]");
                    obj(m, &at)?;
                    match m.get("role").and_then(Value::as_str) {
                        Some("user" | "assistant") => {}
                        other => return Err(format!("{at}.role: {other:?}")),
                    }
                    content_block(
                        m.get("content")
                            .ok_or_else(|| format!("{at}.content: required"))?,
                        &format!("{at}.content"),
                    )?;
                }
                Ok(())
            }
            "resources/list" => {
                cache_hints(v, at)?;
                each(v, "resources", at, resource)
            }
            "resources/templates/list" => {
                cache_hints(v, at)?;
                each(v, "resourceTemplates", at, template)
            }
            "resources/read" => {
                cache_hints(v, at)?;
                each(v, "contents", at, resource_contents)
            }
            "server/discover" => {
                for (i, s) in array(v, "supportedVersions", at)?.iter().enumerate() {
                    if !s.is_string() {
                        return Err(format!("{at}.supportedVersions[{i}]: {s}"));
                    }
                }
                obj(
                    v.get("capabilities")
                        .ok_or_else(|| format!("{at}.capabilities: required"))?,
                    at,
                )?;
                opt_string(v, "instructions", at)
            }
            other => Err(format!("no schema for {other}")),
        }
    }

    /// A JSON-RPC response to request `id`: strict envelope, then a result
    /// for `method` or an error object.
    pub fn response(method: &str, id: &Value, m: &Value) -> R {
        let o = obj(m, "response")?;
        if m.get("jsonrpc") != Some(&Value::from("2.0")) {
            return Err(format!("{method}: jsonrpc is not \"2.0\""));
        }
        if m.get("id") != Some(id) {
            return Err(format!("{method}: id {:?} is not {id}", m.get("id")));
        }
        for k in o.keys() {
            if !matches!(k.as_str(), "jsonrpc" | "id" | "result" | "error") {
                return Err(format!("{method}: extra envelope key {k}"));
            }
        }
        match (m.get("result"), m.get("error")) {
            (Some(r), None) => result(method, r),
            (None, Some(e)) => {
                let at = format!("{method}.error");
                obj(e, &at)?;
                if !e.get("code").is_some_and(|c| c.is_i64()) {
                    return Err(format!("{at}.code: not an integer"));
                }
                string(e, "message", &at)
            }
            _ => Err(format!("{method}: not exactly one of result and error")),
        }
    }

    /// Every message of one request's SSE stream: notifications, and at
    /// most one response, to `id`.
    pub fn stream(method: &str, id: &Value, messages: &[Value]) -> R {
        let mut responses = 0;
        for m in messages {
            if m.get("id").is_some() {
                responses += 1;
                response(method, id, m)?;
            } else {
                notification(m)?;
            }
        }
        if responses > 1 {
            return Err(format!("{method}: {responses} responses on one stream"));
        }
        Ok(())
    }

    /// A server notification on a listen stream.
    pub fn notification(m: &Value) -> R {
        let method = m
            .get("method")
            .and_then(Value::as_str)
            .ok_or("notification without method")?;
        if m.get("jsonrpc") != Some(&Value::from("2.0")) || m.get("id").is_some() {
            return Err(format!("{method}: bad notification envelope"));
        }
        match method {
            "notifications/subscriptions/acknowledged" => {
                let p = m.get("params").ok_or("ack without params")?;
                obj(p, method)?;
                opt_object(p, "_meta", method)?;
                let n = p.get("notifications").ok_or("ack without notifications")?;
                obj(n, method)?;
                for k in [
                    "toolsListChanged",
                    "promptsListChanged",
                    "resourcesListChanged",
                ] {
                    opt_bool(n, k, method)?;
                }
                Ok(())
            }
            "notifications/tools/list_changed"
            | "notifications/prompts/list_changed"
            | "notifications/resources/list_changed" => match m.get("params") {
                None => Ok(()),
                Some(p) => {
                    obj(p, method)?;
                    opt_object(p, "_meta", method)
                }
            },
            other => Err(format!("unexpected notification {other}")),
        }
    }
}

/// Every JSON-RPC message in an SSE body (`data:` lines).
fn sse_messages(text: &str) -> Vec<Value> {
    text.lines()
        .filter_map(|l| l.strip_prefix("data: "))
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .collect()
}

fn meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": MODERN,
        "io.modelcontextprotocol/clientInfo": { "name": "lifecycle-test", "version": "0" },
        "io.modelcontextprotocol/clientCapabilities": {}
    })
}

/// A 2026-07-28 request as Claude Code 2.1.296 sends it: protocol version,
/// client info and capabilities in `_meta`, `MCP-Protocol-Version` and
/// `Mcp-Method` (and `Mcp-Name` for a call or a read) as headers.
async fn modern(
    addr: SocketAddr,
    bearer: &str,
    id: Value,
    method: &str,
    mut params: Value,
) -> Reply {
    params["_meta"] = meta();
    let name = params["name"]
        .as_str()
        .or(params["uri"].as_str())
        .map(str::to_string);
    let mut headers = vec![("MCP-Protocol-Version", MODERN), ("Mcp-Method", method)];
    if let Some(n) = name.as_deref() {
        headers.push(("Mcp-Name", n));
    }
    let body = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
    let r = post(addr, bearer, &headers, &body).await;
    // every reply on the modern path must pass the 2026-07-28 schema
    if let Err(e) = wire::response(method, &id, &r.message) {
        panic!("{method}: {e}\n{}", r.text);
    }
    // and so must every other message on its stream
    if let Err(e) = wire::stream(method, &id, &sse_messages(&r.text)) {
        panic!("{method}: {e}\n{}", r.text);
    }
    r
}

/// Open a `subscriptions/listen` stream for the three list-change kinds
/// and read up to its acknowledgment (asserted).
async fn listen(addr: SocketAddr, bearer: &str, n: usize) -> (TcpStream, String) {
    let body = json!({
        "jsonrpc": "2.0", "id": format!("listen:{n}"), "method": "subscriptions/listen",
        "params": {
            "_meta": meta(),
            "notifications": {
                "toolsListChanged": true,
                "promptsListChanged": true,
                "resourcesListChanged": true
            }
        }
    });
    let mut stream = send(
        addr,
        bearer,
        &[
            ("MCP-Protocol-Version", MODERN),
            ("Mcp-Method", "subscriptions/listen"),
        ],
        &body,
    )
    .await;
    let mut seen = String::new();
    read_until(
        &mut stream,
        &mut seen,
        "notifications/subscriptions/acknowledged",
        Duration::from_secs(10),
    )
    .await;
    assert!(seen.starts_with("HTTP/1.1 200"), "{seen}");
    assert!(
        seen.contains("notifications/subscriptions/acknowledged"),
        "{seen}"
    );
    (stream, seen)
}

/// Whether the server closes `s` within `wait` (everything read is
/// appended to `seen`).
async fn reaches_eof(s: &mut TcpStream, seen: &mut String, wait: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + wait;
    let mut buf = [0u8; 8192];
    loop {
        match tokio::time::timeout_at(deadline, s.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return true,
            Ok(Ok(n)) => seen.push_str(&String::from_utf8_lossy(&buf[..n])),
            Err(_) => return false,
        }
    }
}

/// The cache hints the 2026-07-28 schema requires on list and read results
/// (`ttlMs` a non-negative integer, `cacheScope` public or private).
fn has_cache_hints(result: &Value) -> bool {
    result["ttlMs"].as_u64().is_some()
        && matches!(result["cacheScope"].as_str(), Some("public" | "private"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_modern_per_request_lifecycle_lists_calls_and_listens() {
    let (d, _dict) = daemon("").await;
    add_dataset(&d, "crm", "offline").await;
    add_stdio(&d, "crm", "a", BTreeMap::new(), BTreeMap::new(), true).await;
    wait_running(&d, "crm", "a").await;
    let t = token(&d).await;
    let addr = d.gateway_addr();

    // server/discover: the probe that selects the modern era
    let r = modern(
        addr,
        &t,
        json!("server-discover-probe-1"),
        "server/discover",
        json!({}),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text);
    let disc = &r.message["result"];
    assert!(
        disc["supportedVersions"]
            .as_array()
            .unwrap()
            .contains(&json!(MODERN)),
        "{}",
        r.text
    );
    for list in ["tools", "prompts", "resources"] {
        assert_eq!(
            disc["capabilities"][list]["listChanged"], true,
            "{}",
            r.text
        );
    }

    // every list carries the required cache hints
    let mut uris = Vec::new();
    for (i, (method, key)) in [
        ("tools/list", "tools"),
        ("prompts/list", "prompts"),
        ("resources/list", "resources"),
        ("resources/templates/list", "resourceTemplates"),
    ]
    .into_iter()
    .enumerate()
    {
        let r = modern(addr, &t, json!(i + 1), method, json!({})).await;
        assert_eq!(r.status, 200, "{method}: {}", r.text);
        let result = &r.message["result"];
        assert!(result[key].is_array(), "{method}: {}", r.text);
        assert!(
            has_cache_hints(result),
            "{method} has no cache hints: {}",
            r.text
        );
        assert!(!r.text.contains(CANARY), "{method} leaked the canary");
        if method == "tools/list" {
            let names: Vec<&str> = result[key]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|t| t["name"].as_str())
                .collect();
            assert!(
                names.contains(&"record") && names.contains(&"lookup"),
                "{names:?}"
            );
        }
        if method == "resources/list" {
            uris = result[key]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|r| r["uri"].as_str().map(str::to_string))
                .collect();
        }
    }

    // a read carries them too, and stays sanitized
    let uri = uris.first().expect("a resource is listed").clone();
    let r = modern(addr, &t, json!(10), "resources/read", json!({ "uri": uri })).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert!(has_cache_hints(&r.message["result"]), "{}", r.text);
    assert!(!r.text.contains(CANARY), "the read leaked the canary");

    // a call on the per-request path is sanitized like any other
    let r = modern(
        addr,
        &t,
        json!(11),
        "tools/call",
        json!({ "name": "record", "arguments": {} }),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert!(r.message["result"]["content"].is_array(), "{}", r.text);
    assert!(!r.text.contains(CANARY), "the call leaked the canary");

    // every other result kind a call can come back as: structured content,
    // a resource link, an image, an upstream error, an unknown tool; and a
    // prompt (each reply is checked against the schema inside `modern`)
    for (i, (name, args)) in [
        (
            "nested",
            json!({ "filter": { "n": 1, "names": ["a", "b"] } }),
        ),
        ("linked", json!({})),
        ("binary", json!({})),
        ("fail", json!({ "query": "harmless" })),
        ("dynamic", json!({})),
        ("no_such_tool", json!({})),
    ]
    .into_iter()
    .enumerate()
    {
        let r = modern(
            addr,
            &t,
            json!(30 + i),
            "tools/call",
            json!({ "name": name, "arguments": args }),
        )
        .await;
        assert!(!r.text.contains(CANARY), "{name} leaked the canary");
        let result = &r.message["result"];
        match name {
            // a result with structured content (an object)
            "nested" | "dynamic" => {
                assert_eq!(r.status, 200, "{name}: {}", r.text);
                assert_ne!(result["isError"], true, "{name}: {}", r.text);
                assert!(
                    result["structuredContent"].is_object(),
                    "{name}: {}",
                    r.text
                );
            }
            // a result with a resource link
            "linked" => {
                assert_eq!(r.status, 200, "{name}: {}", r.text);
                assert_ne!(result["isError"], true, "{name}: {}", r.text);
                assert!(
                    result["content"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|b| b["type"] == "resource_link"),
                    "{name}: {}",
                    r.text
                );
            }
            // refused before or after the upstream: INVALID_PARAMS, HTTP 400
            "binary" | "no_such_tool" => {
                assert_eq!(r.status, 400, "{name}: {}", r.text);
                assert!(r.message["error"].is_object(), "{name}: {}", r.text);
            }
            // an upstream JSON-RPC error: a fixed-class error, HTTP 200
            "fail" => {
                assert_eq!(r.status, 200, "{name}: {}", r.text);
                assert_eq!(
                    r.message["error"]["message"], "upstream_error",
                    "{}",
                    r.text
                );
            }
            other => unreachable!("{other}"),
        }
    }
    let r = modern(
        addr,
        &t,
        json!(40),
        "prompts/get",
        json!({ "name": "greet", "arguments": { "name": "Anna" } }),
    )
    .await;
    assert!(r.message["result"]["messages"].is_array(), "{}", r.text);
    assert!(!r.text.contains(CANARY), "the prompt leaked the canary");

    // subscriptions/listen is acknowledged and held open, then carries the
    // list change a catalog rebuild announces
    let (mut stream, mut seen) = listen(addr, &t, 1).await;
    assert!(seen.contains("toolsListChanged"), "{seen}");
    let r = modern(
        addr,
        &t,
        json!(12),
        "tools/call",
        json!({ "name": "change_tools", "arguments": {} }),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text);
    read_until(
        &mut stream,
        &mut seen,
        "notifications/tools/list_changed",
        Duration::from_secs(10),
    )
    .await;
    assert!(seen.contains("notifications/tools/list_changed"), "{seen}");
    assert!(!seen.contains(CANARY));
    let messages = sse_messages(&seen);
    assert!(messages.len() >= 2, "{seen}");
    if let Err(e) = wire::stream("subscriptions/listen", &json!("listen:1"), &messages) {
        panic!("{e}\n{seen}");
    }
    drop(stream);

    // optional methods a client may send: an error for what is not served
    // (no result, no upstream content), never a 2xx success
    for (i, method) in ["logging/setLevel", "resources/subscribe", "ping"]
        .into_iter()
        .enumerate()
    {
        let params = match method {
            "logging/setLevel" => json!({ "level": "info" }),
            "resources/subscribe" => json!({ "uri": uri }),
            _ => json!({}),
        };
        let r = modern(addr, &t, json!(20 + i), method, params).await;
        assert!(r.message["result"].is_null(), "{method}: {}", r.text);
        assert!(r.message["error"].is_object(), "{method}: {}", r.text);
    }
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_legacy_session_lifecycle_is_unchanged() {
    let (d, _dict) = daemon("").await;
    add_dataset(&d, "crm", "offline").await;
    add_stdio(&d, "crm", "a", BTreeMap::new(), BTreeMap::new(), true).await;
    wait_running(&d, "crm", "a").await;
    let t = token(&d).await;
    let addr = d.gateway_addr();

    let init = json!({
        "jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {
            "protocolVersion": LEGACY,
            "capabilities": {},
            "clientInfo": { "name": "lifecycle-test", "version": "0" }
        }
    });
    let r = post(addr, &t, &[], &init).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let sid = r
        .text
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("mcp-session-id")
                .then(|| v.trim().to_string())
        })
        .expect("a session id");
    let h = [
        ("Mcp-Session-Id", sid.as_str()),
        ("MCP-Protocol-Version", LEGACY),
    ];
    let r = post(
        addr,
        &t,
        &h,
        &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    )
    .await;
    assert_eq!(r.status, 202, "{}", r.text);

    let mut uri = String::new();
    for (i, (method, key)) in [
        ("tools/list", "tools"),
        ("prompts/list", "prompts"),
        ("resources/list", "resources"),
    ]
    .into_iter()
    .enumerate()
    {
        let r = post(
            addr,
            &t,
            &h,
            &json!({ "jsonrpc": "2.0", "id": i + 1, "method": method }),
        )
        .await;
        assert_eq!(r.status, 200, "{method}: {}", r.text);
        let result = &r.message["result"];
        assert!(result[key].is_array(), "{method}: {}", r.text);
        // the 2025 wire shape: no 2026-07-28 fields
        assert!(result.get("ttlMs").is_none(), "{method}: {}", r.text);
        assert!(result.get("resultType").is_none(), "{method}: {}", r.text);
        if method == "resources/list" {
            uri = result[key][0]["uri"].as_str().unwrap().to_string();
        }
    }

    // a call, a prompt, and a read: the stamped resultType and the cache
    // hints are 2026-07-28 only; a 2025 session gets neither
    for (i, (method, params)) in [
        ("tools/call", json!({ "name": "record", "arguments": {} })),
        (
            "prompts/get",
            json!({ "name": "greet", "arguments": { "name": "Anna" } }),
        ),
        ("resources/read", json!({ "uri": uri })),
    ]
    .into_iter()
    .enumerate()
    {
        let r = post(
            addr,
            &t,
            &h,
            &json!({ "jsonrpc": "2.0", "id": 5 + i, "method": method, "params": params }),
        )
        .await;
        assert_eq!(r.status, 200, "{method}: {}", r.text);
        let result = &r.message["result"];
        assert!(result.is_object(), "{method}: {}", r.text);
        for k in ["resultType", "ttlMs", "cacheScope"] {
            assert!(result.get(k).is_none(), "{method} has {k}: {}", r.text);
        }
    }

    // ping is served; what is not served stays a JSON-RPC error (fail
    // closed) that a session client reads as a failed request, not a
    // dead session (HTTP 200)
    let r = post(
        addr,
        &t,
        &h,
        &json!({ "jsonrpc": "2.0", "id": 9, "method": "ping" }),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert!(r.message["result"].is_object(), "{}", r.text);
    for (i, (method, params)) in [
        ("logging/setLevel", json!({ "level": "info" })),
        ("resources/subscribe", json!({ "uri": "inumaki://res/0" })),
        (
            "subscriptions/listen",
            json!({ "notifications": { "toolsListChanged": true } }),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let r = post(
            addr,
            &t,
            &h,
            &json!({ "jsonrpc": "2.0", "id": 10 + i, "method": method, "params": params }),
        )
        .await;
        assert_eq!(r.status, 200, "{method}: {}", r.text);
        assert!(r.message["error"].is_object(), "{method}: {}", r.text);
        assert!(r.message["result"].is_null(), "{method}: {}", r.text);
    }
    d.stop().await;
}

/// A held listen must not outlive its dataset's service: a reload and a
/// removal each end the stream, and a listener that went away is not
/// waited on by the next catalog change.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn held_listens_end_with_their_service_and_their_client() {
    let (d, _dict) = daemon("").await;
    add_dataset(&d, "crm", "offline").await;
    add_stdio(&d, "crm", "a", BTreeMap::new(), BTreeMap::new(), true).await;
    wait_running(&d, "crm", "a").await;
    let t = token(&d).await;
    let addr = d.gateway_addr();

    // a client that disconnects: the next change neither hangs nor fails
    let (gone, _) = listen(addr, &t, 1).await;
    drop(gone);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let r = tokio::time::timeout(
        Duration::from_secs(10),
        modern(
            addr,
            &t,
            json!(1),
            "tools/call",
            json!({ "name": "change_tools", "arguments": {} }),
        ),
    )
    .await
    .expect("a change after a listener left does not hang");
    assert_eq!(r.status, 200, "{}", r.text);
    let r = modern(addr, &t, json!(2), "tools/list", json!({})).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert!(r.message["result"]["tools"].is_array(), "{}", r.text);

    // a reload (an upstream added) ends the stream
    let (mut held, mut seen) = listen(addr, &t, 2).await;
    add_stdio(&d, "crm", "b", BTreeMap::new(), BTreeMap::new(), true).await;
    assert!(
        reaches_eof(&mut held, &mut seen, Duration::from_secs(10)).await,
        "the listen outlived a reload: {seen}"
    );
    if let Err(e) = wire::stream(
        "subscriptions/listen",
        &json!("listen:2"),
        &sse_messages(&seen),
    ) {
        panic!("{e}\n{seen}");
    }
    wait_running(&d, "crm", "b").await;

    // a removal ends the stream
    let (mut held, mut seen) = listen(addr, &t, 3).await;
    let (code, body) = d
        .call(hyper::Method::DELETE, "/v1/datasets/crm", None)
        .await;
    assert!((200..300).contains(&code), "{code} {body}");
    assert!(
        reaches_eof(&mut held, &mut seen, Duration::from_secs(10)).await,
        "the listen outlived its dataset: {seen}"
    );
    if let Err(e) = wire::stream(
        "subscriptions/listen",
        &json!("listen:3"),
        &sse_messages(&seen),
    ) {
        panic!("{e}\n{seen}");
    }
    assert!(!seen.contains(CANARY));
    d.stop().await;
}

/// Open listens are capped per dataset; one more is refused with the
/// gateway's limit error (not a 404 a client would read as a dead
/// server), and a listener that leaves frees its slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn open_listens_are_capped_per_dataset() {
    use inumaki_gateway::handler::MAX_SUBSCRIPTIONS;
    let (d, _dict) = daemon("").await;
    add_dataset(&d, "crm", "offline").await;
    add_stdio(&d, "crm", "a", BTreeMap::new(), BTreeMap::new(), true).await;
    wait_running(&d, "crm", "a").await;
    let t = token(&d).await;
    let addr = d.gateway_addr();

    let mut held = Vec::new();
    for n in 0..MAX_SUBSCRIPTIONS {
        held.push(listen(addr, &t, n).await.0);
    }
    let (mut over, mut seen) = listen(addr, &t, MAX_SUBSCRIPTIONS).await;
    assert!(
        reaches_eof(&mut over, &mut seen, Duration::from_secs(10)).await,
        "{seen}"
    );
    assert!(seen.starts_with("HTTP/1.1 200"), "{seen}");
    assert!(seen.contains("resource_limit"), "{seen}");
    assert!(seen.contains("subscriptions"), "{seen}");
    // the ack, then the refusal as a well-formed error to the listen
    let id = json!(format!("listen:{MAX_SUBSCRIPTIONS}"));
    let messages = sse_messages(&seen);
    assert!(
        messages
            .iter()
            .any(|m| m["id"] == id && m["error"].is_object()),
        "{seen}"
    );
    if let Err(e) = wire::stream("subscriptions/listen", &id, &messages) {
        panic!("{e}\n{seen}");
    }

    // one leaves: its slot opens (the next one is held, not refused)
    drop(held.pop());
    let mut freed = false;
    for n in 0..50 {
        let (mut s, mut seen) = listen(addr, &t, 1000 + n).await;
        if !reaches_eof(&mut s, &mut seen, Duration::from_millis(500)).await {
            freed = true;
            held.push(s);
            break;
        }
        assert!(seen.contains("resource_limit"), "{seen}");
    }
    assert!(freed, "a closed listen did not free its slot");
    drop(held);
    d.stop().await;
}

/// A blocked result reaches a 2026-07-28 client as a well-formed tool
/// error naming kinds and checks only.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_blocked_result_is_a_well_formed_modern_tool_error() {
    let (d, _dict) = daemon("").await;
    add_dataset(&d, "crm", "blocky").await;
    add_stdio(&d, "crm", "a", BTreeMap::new(), BTreeMap::new(), true).await;
    wait_running(&d, "crm", "a").await;
    let t = token(&d).await;
    let r = modern(
        d.gateway_addr(),
        &t,
        json!(1),
        "tools/call",
        json!({ "name": "record", "arguments": {} }),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.message["result"]["isError"], true, "{}", r.text);
    assert!(r.text.contains("blocked by inumaki"), "{}", r.text);
    assert!(!r.text.contains(CANARY) && !r.text.contains("AT61"));
    d.stop().await;
}
