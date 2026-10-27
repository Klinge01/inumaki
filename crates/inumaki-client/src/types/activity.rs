//! `GET /v1/activity`, `GET /v1/activity/verify` (`inumakid/src/api/activity.rs`,
//! `inumaki-vault/src/activity.rs`). Both bodies are built with `json!`.

use serde::{Deserialize, Serialize};

/// Front door of a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrontDoor {
    /// MCP gateway.
    Gateway,
    /// Control API.
    Control,
    /// Model-API proxy.
    Proxy,
    /// Folder mirror.
    Mirror,
    /// Tool-result hook.
    Hook,
}

/// Direction of a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Upstream result to the agent.
    Result,
    /// Model-written arguments to the upstream.
    Arguments,
    /// Request to a provider.
    Request,
    /// Provider response.
    Response,
}

/// Verdict of a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Released.
    Released,
    /// Blocked.
    Blocked,
    /// Withheld as uncertain.
    Uncertain,
    /// Unresolved placeholders.
    Unresolved,
    /// Unsupported content.
    Unsupported,
}

/// A check that fired, serialized as the variant name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckLabel {
    /// Leak check.
    Leak,
    /// Regex re-scan.
    Regex,
    /// NER re-scan.
    Ner,
    /// Combination heuristic.
    Combination,
    /// Policy.
    Policy,
    /// Detector error.
    DetectorError,
    /// Clear-value tripwire.
    ClearValue,
}

/// A kind with a count.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KindCount {
    /// Kind label.
    pub kind: String,
    /// Count.
    pub count: u32,
}

/// One record. `dataset` is the local id when the dataset still exists,
/// else the opaque label: not in `Debug`.
#[derive(Clone, Serialize, Deserialize)]
pub struct ActivityRecord {
    /// 32 hex.
    pub id: String,
    /// Unix seconds.
    pub at: i64,
    /// Local id or opaque label.
    pub dataset: String,
    /// Front door.
    pub front_door: FrontDoor,
    /// Opaque upstream label.
    pub upstream: Option<String>,
    /// Direction.
    pub direction: Direction,
    /// Verdict.
    pub verdict: Verdict,
    /// Checks that fired.
    pub checks: Vec<CheckLabel>,
    /// Kinds with counts.
    pub kinds: Vec<KindCount>,
    /// Tripwire fired.
    pub tripwire: bool,
    /// Payload bytes.
    pub bytes: u64,
    /// Keyed digest of the released bytes.
    pub released: Option<String>,
}

debug_fields!(ActivityRecord {
    id,
    at,
    front_door,
    upstream,
    direction,
    verdict,
    checks,
    kinds,
    tripwire,
    bytes,
    released
});

/// `GET /v1/activity` answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityList {
    /// Newest first.
    pub records: Vec<ActivityRecord>,
}

/// `GET /v1/activity/verify` answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityVerify {
    /// Records checked.
    pub records: u64,
    /// Always `true` in a 200.
    pub ok: bool,
}

/// Query of `GET /v1/activity`.
#[derive(Clone, Default)]
pub struct ActivityQuery {
    /// Only this dataset (local id).
    pub dataset: Option<String>,
    /// Only at or after this time.
    pub since: Option<i64>,
    /// At most this many (default 100, cap 10 000).
    pub limit: Option<u64>,
}

debug_fields!(ActivityQuery { since, limit });
