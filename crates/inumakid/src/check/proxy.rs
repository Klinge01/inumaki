//! The proxy path of the check. M8 ships `inumaki_proxy::CheckRoutes`
//! (M6 spec §9.6, M8 spec §12.2); the daemon sees it through
//! [`ProxyCheckRoutes`], which Task 9a of the M6-3 plan implements for M8's
//! type and registers with `CheckSlot::set_proxy_routes`. Without it the
//! proxy path is `proxy_unavailable`.
//!
//! M8's scripted upstream picks the step from the request's turn count (so
//! a retry, or a second harness on the same route, gets the same script) and
//! skips a `CallTools` entry whose name matches no advertised tool.

use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant};

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;

use super::runner::{LiveCheck, random_id, rehydrate};
use super::types::{CheckHarnessBody, CheckResults, HarnessId, PathAvail, PathReason, PathResult};
use super::verdict::{Evidence, not_checked, verdict};
use crate::state::AppState;

/// One model turn of the scripted upstream (spec §9.6 `Step`).
#[derive(Clone)]
pub enum ScriptStep {
    /// Call tools: (tool name suffix, JSON arguments).
    CallTools(Vec<(String, serde_json::Value)>),
    /// Answer with a text repeating the tool results.
    EchoToolResults,
    /// Answer with the user's text.
    EchoUserText,
}

/// The kind and the number of calls only: the arguments hold file paths
/// and shell commands.
impl std::fmt::Debug for ScriptStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScriptStep::CallTools(calls) => write!(f, "CallTools({} calls)", calls.len()),
            ScriptStep::EchoToolResults => f.write_str("EchoToolResults"),
            ScriptStep::EchoUserText => f.write_str("EchoUserText"),
        }
    }
}

/// One request the scripted upstream recorded: body bytes, no headers.
pub struct RecordedBody {
    /// `anthropic`, `openai`, `openai-codex`.
    pub upstream: String,
    /// The request body as the upstream received it.
    pub body: Vec<u8>,
}

impl std::fmt::Debug for RecordedBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordedBody")
            .field("upstream", &self.upstream)
            .field("len", &self.body.len())
            .finish()
    }
}

/// M8's check routes, as the check module needs them.
pub trait ProxyCheckRoutes: Send + Sync {
    /// Register `/check/<id>/…` for `dataset` with `script` for `ttl`;
    /// returns (upstream, base URL) per route.
    fn register(
        &self,
        id: &str,
        dataset: &str,
        script: Vec<ScriptStep>,
        ttl: Duration,
    ) -> Vec<(String, String)>;
    /// Requests recorded so far for `id`.
    fn recorded(&self, id: &str) -> Vec<RecordedBody>;
    /// Remove the routes of `id`.
    fn remove(&self, id: &str);
    /// Requests of `id` the recorder dropped instead of keeping (M8 keeps at
    /// most 256 bodies of at most 4 MiB per id). A dropped body was never
    /// inspected, so a route with drops can never pass: the run fails
    /// closed as `harness_failed` (a leak seen in the kept bodies is still
    /// reported as `canary_in_upstream`).
    fn dropped(&self, _id: &str) -> u64 {
        0
    }
}

fn routes(state: &AppState) -> Option<Arc<dyn ProxyCheckRoutes>> {
    state
        .check
        .proxy
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// Whether the model-API proxy is listening right now (its status state is
/// `running`); not started, disabled, and bind-failed all read as not.
fn proxy_running(state: &AppState) -> bool {
    state
        .proxy
        .get()
        .is_some_and(|p| matches!(p.listen_state(), inumaki_proxy::ListenState::Running(_)))
}

/// Register two check routes: one under the check id for harness runs
/// (call the canary tool, and with a mirror `Read` the mirrored file and
/// `cat` the source file, then repeat the results), one under a second
/// random id for the direct run (repeat the user's text). Without a running
/// proxy, without M8's routes, or when either registration or the second id fails, the path
/// stays unavailable and nothing stays registered.
pub fn prepare(state: &Arc<AppState>, live: &mut LiveCheck) {
    // No URL while the proxy is not listening: a squatter on the port would
    // get the check conversation and the harness's credentials. Routes that
    // outlive a listener (or were forced in) are not enough; `remove` and
    // the readers below stay ungated so cleanup always works.
    if !proxy_running(state) {
        return;
    }
    let Some(r) = routes(state) else { return };
    // The route id is the route's protection: no predictable fallback.
    let Some(id2) = random_id() else { return };
    let ttl = live.deadline.saturating_duration_since(Instant::now());
    let mut calls = vec![(super::canary_mcp::TOOL.to_string(), serde_json::json!({}))];
    if let (Some(path), Some(m)) = (super::mirror::entry(live).map(|e| e.path), &live.mirror) {
        // Claude Code reads the mirrored file, and `cat`s the *source* file
        // through Bash: a harness with `inumaki-hook` gets tokens back, one
        // without it has Bash denied by the check invocation (M6-3 Task 8a),
        // so the source text never reaches the model either way (spec §11).
        calls.push(("Read".to_string(), serde_json::json!({ "file_path": path })));
        let source = m.source_dir().join("canary.txt");
        calls.push((
            "Bash".to_string(),
            serde_json::json!({ "command": format!("cat '{}'", source.display()) }),
        ));
    }
    let harness = r.register(
        &live.id,
        &live.dataset,
        vec![ScriptStep::CallTools(calls), ScriptStep::EchoToolResults],
        ttl,
    );
    let direct = r.register(&id2, &live.dataset, vec![ScriptStep::EchoUserText], ttl);
    if harness.is_empty() || direct.is_empty() {
        r.remove(&live.id);
        r.remove(&id2);
        return;
    }
    live.proxy = Some(harness);
    live.proxy_direct = Some((id2, direct));
    live.paths.proxy = PathAvail::yes();
}

async fn post_json(base_url: &str, path: &str, body: serde_json::Value) -> Option<String> {
    let uri: hyper::Uri = format!("{base_url}{path}").parse().ok()?;
    let authority = uri.authority()?.to_string();
    let stream = tokio::net::TcpStream::connect(&authority).await.ok()?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .ok()?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = hyper::Request::post(uri.path())
        .header("host", &authority)
        .header("content-type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .header("x-api-key", "inumaki-check-dummy")
        .body(Full::new(Bytes::from(body.to_string())))
        .ok()?;
    let resp = sender.send_request(req).await.ok()?;
    let bytes = resp.into_body().collect().await.ok()?.to_bytes();
    String::from_utf8(bytes.to_vec()).ok()
}

/// Tokens restored by the check dataset: `true` when rehydration changed `text`.
async fn has_tokens(state: &Arc<AppState>, dataset: &str, text: String) -> bool {
    rehydrate(state, dataset, text.clone())
        .await
        .is_some_and(|r| r != text)
}

/// Evidence from the bodies `route_id` recorded after the first `skip`.
/// `lost` is the route's sticky loss flag: set here when the route returns
/// fewer bodies than were already judged (the store only appends, so
/// bodies went uncounted), and once set every later run fails closed,
/// even after the store refills past the old count.
async fn recorded_evidence(
    state: &Arc<AppState>,
    live: &LiveCheck,
    route_id: &str,
    skip: usize,
    lost: &mut bool,
) -> (Evidence, Vec<String>) {
    let r = routes(state);
    // The snapshot first, then the drop count: a loss before the snapshot
    // is then always in the count.
    let all = r.as_ref().map(|r| r.recorded(route_id)).unwrap_or_default();
    // Conservative: any drop on the route, in this window or an earlier one.
    let dropped = r.as_ref().is_some_and(|r| r.dropped(route_id) > 0);
    *lost |= all.len() < skip;
    let bodies: Vec<String> = all
        .into_iter()
        .skip(skip)
        .map(|b| String::from_utf8_lossy(&b.body).into_owned())
        .collect();
    let mut tokens = false;
    for b in &bodies {
        tokens |= has_tokens(state, &live.dataset, b.clone()).await;
    }
    let e = Evidence {
        upstream_requests: bodies.len() as u64,
        canary_in_upstream: bodies.iter().any(|b| live.canary.appears_in(b)),
        tokens_seen: tokens,
        harness_failed: dropped || *lost,
        ..Evidence::default()
    };
    (e, bodies)
}

/// The proxy direct run: send the canary through the direct route and
/// expect it back restored, with only tokens recorded upstream. Each run is
/// judged only on the requests recorded since the previous one.
pub async fn direct(state: &Arc<AppState>, live: &mut LiveCheck) -> PathResult {
    // The listener may have ended since the check was created: whatever
    // holds the address now must not get the made-up canary. Send nothing.
    if !proxy_running(state) {
        return not_checked(Some(PathReason::ProxyUnavailable));
    }
    let Some((id2, routes)) = &live.proxy_direct else {
        return not_checked(Some(PathReason::ProxyUnavailable));
    };
    let Some((_, base)) = routes
        .iter()
        .find(|(u, _)| u == "anthropic")
        .or(routes.first())
    else {
        return not_checked(Some(PathReason::ProxyUnavailable));
    };
    let c = &live.canary;
    let body = serde_json::json!({
        "model": "inumaki-check", "max_tokens": 256,
        "messages": [{ "role": "user", "content": format!("Please repeat exactly: Record: {}, IBAN {}, email {}", c.full_name(), c.iban, c.email) }]
    });
    let answer = tokio::time::timeout(
        state.check.path_wait(),
        post_json(base, "/v1/messages", body),
    )
    .await;
    let mut lost = live.direct_lost;
    let (mut e, bodies) = recorded_evidence(state, live, id2, live.direct_seen, &mut lost).await;
    live.direct_lost = lost;
    live.direct_seen += bodies.len();
    match answer {
        Ok(Some(text)) => e.rehydrated_in_output = c.restored_in(&text),
        Ok(None) => {}
        Err(_) => e.timed_out = true,
    }
    verdict(&e)
}

/// What the scripted `Bash` call (the `cat` of the source file) came back
/// as in the requests a harness run recorded (M6-3 Task 9b diagnostics).
/// A closed set: the run logs it, never the text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BashResult {
    /// No recorded request holds a `Bash` tool use (no mirror, or the
    /// harness does not advertise `Bash`).
    NotCalled,
    /// A `Bash` tool use, but no recorded request carries its result.
    NoResult,
    /// The result is an error that reads as a refusal: the call was denied,
    /// needed approval, or touched a path outside the allowed directories.
    /// Claude Code runs no `PostToolUse` hook for an error result.
    ErrorPermission,
    /// The result is an error that reads as a missing file (`No such file`).
    ErrorMissing,
    /// Any other error result.
    ErrorOther,
    /// The hook's block message replaced the output.
    HookBlock,
    /// The output holds tokens (the hook or the proxy tokenized it).
    Tokens,
    /// The output holds no tokens.
    Plain,
}

/// The text of a `tool_result` block's `content` (a string or text blocks).
fn result_text(content: &serde_json::Value) -> String {
    match content {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(parts) => parts
            .iter()
            .filter_map(|p| p.get("text").and_then(serde_json::Value::as_str))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// Fixed lowercase substrings that mark an error result as a refusal.
const PERMISSION_MARKS: &[&str] = &[
    "permission",
    "not allowed",
    "denied",
    "requires approval",
    "outside",
    "blocked",
];

/// Name the cause of an error result with fixed substring checks on its text,
/// which stays in memory: only the enum name is logged.
fn error_class(text: &str) -> BashResult {
    let t = text.to_ascii_lowercase();
    if t.contains("no such file") {
        BashResult::ErrorMissing
    } else if PERMISSION_MARKS.iter().any(|m| t.contains(m)) {
        BashResult::ErrorPermission
    } else {
        BashResult::ErrorOther
    }
}

/// Classify the `Bash` result in Anthropic Messages request bodies; the
/// last body that holds one decides.
pub(crate) fn bash_result(bodies: &[String], has_tokens: impl Fn(&str) -> bool) -> BashResult {
    let mut out = BashResult::NotCalled;
    for b in bodies {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(b) else {
            continue;
        };
        let blocks: Vec<&serde_json::Value> = v
            .get("messages")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|m| m.get("content").and_then(serde_json::Value::as_array))
            .flatten()
            .collect();
        let ids: Vec<&str> = blocks
            .iter()
            .filter(|c| c["type"] == "tool_use" && c["name"] == "Bash")
            .filter_map(|c| c["id"].as_str())
            .collect();
        if ids.is_empty() {
            continue;
        }
        out = BashResult::NoResult;
        let result = blocks.iter().find(|c| {
            c["type"] == "tool_result"
                && c["tool_use_id"].as_str().is_some_and(|i| ids.contains(&i))
        });
        if let Some(r) = result {
            let text = result_text(&r["content"]);
            out = if r["is_error"] == true {
                error_class(&text)
            } else if text.contains("blocked by inumaki (") {
                BashResult::HookBlock
            } else if has_tokens(&text) {
                BashResult::Tokens
            } else {
                BashResult::Plain
            };
        }
    }
    out
}

/// Verdicts of one harness run from what its route recorded and its output.
pub async fn harness_results(
    state: &Arc<AppState>,
    live: &mut LiveCheck,
    body: &CheckHarnessBody,
) -> CheckResults {
    if live.proxy.is_none() {
        let n = || not_checked(Some(PathReason::ProxyUnavailable));
        return CheckResults {
            gateway: n(),
            mirror: n(),
            proxy: n(),
        };
    }
    // Only the requests since the previous harness POST belong to this run.
    let id = live.id.clone();
    let mut lost = live.recorded_lost;
    let (mut e, bodies) = recorded_evidence(state, live, &id, live.recorded_seen, &mut lost).await;
    live.recorded_lost = lost;
    live.recorded_seen += bodies.len();
    let live = &*live;
    // Diagnostics only (M6-3 Task 9b): with `inumaki-hook` the Bash result
    // should be `Tokens`; without it the check invocation denies Bash
    // (`ErrorPermission`). The verdicts do not depend on it. `bash_result` reads
    // Anthropic Messages bodies, which only Claude Code sends, so the `bash`
    // field is logged for Claude Code alone; for other harnesses it would
    // always read `NotCalled` and mislead.
    if body.harness == HarnessId::ClaudeCode {
        let bash = bash_result(&bodies, |t| {
            !state.namespace_rehydrator.tokens_in(t).is_empty()
        });
        tracing::info!(
            harness = ?body.harness,
            requests = bodies.len(),
            bash = ?bash,
            "check harness requests"
        );
    } else {
        tracing::info!(
            harness = ?body.harness,
            requests = bodies.len(),
            "check harness requests"
        );
    }
    e.harness_failed |= body.exit_code != 0 || body.output.trim().is_empty();
    e.chat_not_routed = bodies.is_empty();
    e.rehydrated_in_output = live.canary.restored_in(&body.output);
    let gateway = if live.gateway.is_some() {
        verdict(&e)
    } else {
        not_checked(None)
    };
    let mirror = match (&live.mirror, body.harness) {
        (None, _) => not_checked(Some(PathReason::MirrorUnavailable)),
        // Only the Claude Code script reads the mirrored file.
        (Some(_), h) if h != HarnessId::ClaudeCode => not_checked(None),
        (Some(_), _) => {
            let mirrored = super::mirror::mirrored_text(live).unwrap_or_default();
            let key = mirrored.trim();
            let mut m = e.clone();
            m.tokens_seen = !key.is_empty() && bodies.iter().any(|b| b.contains(key));
            verdict(&m)
        }
    };
    CheckResults {
        gateway,
        mirror,
        proxy: verdict(&e),
    }
}

/// Remove both check routes.
pub fn remove(state: &Arc<AppState>, live: &LiveCheck) {
    if let Some(r) = routes(state) {
        r.remove(&live.id);
        if let Some((id2, _)) = &live.proxy_direct {
            r.remove(id2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn turn1() -> serde_json::Value {
        json!({ "role": "assistant", "content": [
            { "type": "tool_use", "id": "toolu_1", "name": "mcp__check__lookup_record", "input": {} },
            { "type": "tool_use", "id": "toolu_2", "name": "Bash", "input": { "command": "cat '/x'" } }
        ] })
    }

    fn with_result(content: serde_json::Value, is_error: Option<bool>) -> String {
        let mut r = json!({ "type": "tool_result", "tool_use_id": "toolu_2", "content": content });
        if let Some(e) = is_error {
            r["is_error"] = json!(e);
        }
        json!({ "model": "m", "messages": [
            { "role": "user", "content": "Call the lookup_record tool" }, turn1(),
            { "role": "user", "content": [
                { "type": "tool_result", "tool_use_id": "toolu_1", "content": "<PERSON_a1b2c3>" }, r
            ] }
        ] })
        .to_string()
    }

    /// M6-3 Task 9b: what the scripted `Bash` call came back as, as a
    /// closed set the harness run logs.
    #[test]
    fn the_scripted_bash_result_is_classified() {
        let tokens = |t: &str| t.contains("<PERSON_");
        let first = json!({ "messages": [{ "role": "user", "content": "hi" }] }).to_string();
        assert_eq!(
            bash_result(std::slice::from_ref(&first), tokens),
            BashResult::NotCalled
        );
        let only_use =
            json!({ "messages": [{ "role": "user", "content": "hi" }, turn1()] }).to_string();
        assert_eq!(
            bash_result(&[first.clone(), only_use], tokens),
            BashResult::NoResult
        );
        let cases = [
            (
                with_result(json!("Record: <PERSON_d4e5f6>"), None),
                BashResult::Tokens,
            ),
            (
                with_result(
                    json!([{ "type": "text", "text": "Record: <PERSON_d4e5f6>" }]),
                    Some(false),
                ),
                BashResult::Tokens,
            ),
            (with_result(json!("Record: plain"), None), BashResult::Plain),
            (
                with_result(json!("Permission to use Bash was denied"), Some(true)),
                BashResult::ErrorPermission,
            ),
            (
                with_result(
                    json!("synthetic: path is outside the allowed working directories"),
                    Some(true),
                ),
                BashResult::ErrorPermission,
            ),
            (
                with_result(
                    json!("synthetic: this command requires approval"),
                    Some(true),
                ),
                BashResult::ErrorPermission,
            ),
            (
                with_result(json!("synthetic: tool NOT ALLOWED"), Some(true)),
                BashResult::ErrorPermission,
            ),
            (
                with_result(
                    json!([{ "type": "text", "text": "Exit code 1\ncat: /x: No such file or directory" }]),
                    Some(true),
                ),
                BashResult::ErrorMissing,
            ),
            (
                with_result(json!("Exit code 2\nsynthetic failure"), Some(true)),
                BashResult::ErrorOther,
            ),
            (with_result(json!(""), Some(true)), BashResult::ErrorOther),
            (
                with_result(
                    json!("blocked by inumaki (unparsable_payload; kinds: none)"),
                    None,
                ),
                BashResult::HookBlock,
            ),
        ];
        for (body, want) in cases {
            assert_eq!(bash_result(&[first.clone(), body], tokens), want);
        }
    }
}
