//! `POST /v1/hook` (M6 spec §5, §9.7 as amended 2026-09-29), control
//! socket only: one request per tool result, carrying all its texts. The
//! body can hold originals: `Debug` prints counts, logs carry the action
//! and counts, a block answers with kinds only, and an error answers with
//! its status class and a fixed message (no dataset id, no text).

use std::path::PathBuf;
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use inumaki_core::span::EntityKind;
use inumaki_core::verify::Reason;
use inumaki_vault::{CheckLabel, Direction, FrontDoor, KindCount, KindLabel, NewActivity, Verdict};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{ApiError, blocking};
use crate::hook::{HookInput, HookOutcome, HookTrace, run_hook_traced};
use crate::state::AppState;

/// Harness of a hook call: Claude Code and Codex only (spec §5).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HookHarness {
    /// Claude Code.
    ClaudeCode,
    /// Codex.
    Codex,
}

/// Tool class (spec §9.7).
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookTool {
    /// Shell.
    Bash,
    /// Read.
    Read,
    /// Grep.
    Grep,
    /// Glob.
    Glob,
    /// Edit.
    Edit,
    /// WebFetch.
    WebFetch,
    /// MCP.
    Mcp,
    /// Anything else.
    Other,
}

/// Request body.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookBody {
    /// Harness.
    pub harness: HookHarness,
    /// Tool.
    pub tool: HookTool,
    /// Working directory.
    pub cwd: String,
    /// Referenced paths.
    pub paths: Vec<String>,
    /// Keys, strings, and numbers of the tool output, in the hook's order.
    pub texts: Vec<String>,
}

impl std::fmt::Debug for HookBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HookBody")
            .field("harness", &self.harness)
            .field("tool", &self.tool)
            .field("paths", &self.paths.len())
            .field("texts", &self.texts.len())
            .finish_non_exhaustive()
    }
}

fn labels(kinds: &[EntityKind]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for k in kinds {
        let l = k.label().to_string();
        if !out.contains(&l) {
            out.push(l);
        }
    }
    out
}

/// One activity record per tool result, front door `hook`. A failed write
/// is logged without detail and does not change the answer.
#[allow(clippy::too_many_arguments)]
async fn record(
    state: &Arc<AppState>,
    dataset: String,
    verdict: Verdict,
    kinds: &[EntityKind],
    reasons: &[Reason],
    tripwire: bool,
    bytes: u64,
    released: Option<String>,
) {
    let s = Arc::clone(state);
    let kinds: Vec<KindCount> = kinds
        .iter()
        .map(|k| KindCount {
            kind: KindLabel::of(k),
            count: 1,
        })
        .collect();
    let mut checks: Vec<CheckLabel> = Vec::new();
    for r in reasons {
        let c = CheckLabel::of(&r.check);
        if !checks.contains(&c) {
            checks.push(c);
        }
    }
    let res = blocking(move || {
        let v = &s.vault;
        v.append_activity(NewActivity {
            dataset: v.opaque_ref(&dataset),
            front_door: FrontDoor::Hook,
            upstream: None,
            direction: Direction::Result,
            verdict,
            checks,
            kinds,
            tripwire,
            bytes,
            released: released.map(|t| v.released_digest(t.as_bytes())),
        })?;
        Ok(())
    })
    .await;
    if res.is_err() {
        tracing::warn!("hook activity record failed");
    }
}

/// Handler.
pub async fn hook(
    State(state): State<Arc<AppState>>,
    body: Result<Json<HookBody>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(b) = body?;
    // Relative paths resolve against `cwd`; a relative `cwd` would resolve
    // against the daemon's own directory and miss the folder rule.
    if !std::path::Path::new(&b.cwd).is_absolute() {
        return Err(ApiError::bad_request("cwd must be an absolute path"));
    }
    let bytes = b.texts.iter().map(String::len).sum::<usize>() as u64;
    // The log line's closed set (M6-3 Task 9b): the tool class, counts,
    // and flags; never a path, a dataset, or text.
    let (tool, n_paths, n_texts) = (b.tool, b.paths.len(), b.texts.len());
    let input = HookInput {
        cwd: PathBuf::from(&b.cwd),
        paths: b.paths,
        texts: b.texts,
    };
    let s = Arc::clone(&state);
    let (outcome, t) = blocking(move || {
        let mut t = HookTrace::default();
        let outcome = run_hook_traced(&s, &input, &mut t).map_err(|e| {
            // Fail closed with the error's status class; the message can
            // name a dataset or profile, so a fixed one replaces it.
            let e = ApiError::from(e);
            tracing::warn!(
                status = e.status.as_u16(),
                kind = e.kind,
                tool = ?tool,
                paths = n_paths,
                texts = n_texts,
                root_match = t.root_match,
                mirror_match = t.mirror_match,
                "hook failed"
            );
            ApiError {
                message: "the tool result could not be checked; it was withheld".into(),
                kinds: Vec::new(),
                checks: Vec::new(),
                unresolved: None,
                ..e
            }
        })?;
        Ok((outcome, t))
    })
    .await?;
    match outcome {
        HookOutcome::Pass => {
            tracing::info!(
                action = "pass",
                tool = ?tool,
                paths = n_paths,
                texts = n_texts,
                root_match = t.root_match,
                mirror_match = t.mirror_match,
                "hook"
            );
            Ok(Json(json!({ "action": "pass" })))
        }
        HookOutcome::Replace {
            texts,
            kinds,
            dataset,
            tripwire,
        } => {
            // One activity record per tool result; the digest covers every text.
            record(
                &state,
                dataset,
                Verdict::Released,
                &kinds,
                &[],
                tripwire,
                bytes,
                Some(texts.join("\n")),
            )
            .await;
            tracing::info!(
                action = "replace",
                tool = ?tool,
                paths = n_paths,
                texts = n_texts,
                root_match = t.root_match,
                mirror_match = t.mirror_match,
                kinds = kinds.len(),
                tripwire,
                "hook"
            );
            Ok(Json(
                json!({ "action": "replace", "texts": texts, "kinds": labels(&kinds) }),
            ))
        }
        HookOutcome::Block {
            kinds,
            reasons,
            dataset,
            tripwire,
        } => {
            record(
                &state,
                dataset,
                Verdict::Blocked,
                &kinds,
                &reasons,
                tripwire,
                bytes,
                None,
            )
            .await;
            tracing::info!(
                action = "block",
                tool = ?tool,
                paths = n_paths,
                texts = n_texts,
                root_match = t.root_match,
                mirror_match = t.mirror_match,
                kinds = kinds.len(),
                tripwire,
                "hook"
            );
            Err(ApiError::privacy_block(&kinds, &reasons))
        }
    }
}
