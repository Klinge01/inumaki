//! One rmcp `ServerHandler` per dataset (M4 spec §5.2, §5.3): listings
//! come from the sanitized catalog; calls are routed to the owning upstream
//! after strict, contract-driven rehydration; every result goes through the
//! content path under the dataset's resource limits. Counters feed
//! `status`, and every content verdict leaves an activity record (M4 spec
//! §16.4). Every error the agent sees is one of the fixed classes.
//!
//! The upstream vector, each upstream's contract state, and the catalog
//! built over them live in one [`Snapshot`] swapped as a whole, and a
//! request reads one snapshot from routing to dispatch; an index the
//! catalog hands out is additionally checked against the owner its lists
//! came from before anything is sent (review carry: routing safety).

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use inumaki_core::span::EntityKind;
use inumaki_vault::{
    CheckLabel, Digest, Direction, FrontDoor, KindCount, KindLabel, NewActivity, OpaqueId, Vault,
    Verdict,
};
use rmcp::model::{
    CacheScope, CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ErrorCode,
    ErrorData, GetPromptRequestParams, GetPromptResponse, Implementation, InitializeResult,
    JsonObject, ListPromptsResult, ListResourceTemplatesResult, ListResourcesResult,
    ListToolsResult, PaginatedRequestParams, PromptsCapability, ProtocolVersion,
    ReadResourceRequestParams, ReadResourceResponse, ResourcesCapability, ResultType,
    ServerCapabilities, ServerConfig, SubscriptionFilter, ToolsCapability,
};
use rmcp::service::{NotificationContext, RequestContext, SubscriptionContext, SubscriptionSink};
use rmcp::{Peer, RoleClient, RoleServer, ServerHandler};
use serde_json::{Value, json};

use crate::activity::{ActivitySink, Hop};
use crate::aggregate::{Catalog, RawLists, UpstreamLists, fetch_lists};
use crate::config::{GatewayConfig, TripwireMode};
use crate::content::{
    ContentError, SanitizeStats, blocked_text, check_names, kind_labels, percent_decode,
    rehydrate_arguments, rehydrate_prompt_arguments, rehydrate_template_params,
    sanitize_call_result, sanitize_prompt_result, sanitize_read_result, string_leaves,
    upstream_error, withheld_text,
};
use crate::contract::{Contract, ContractError, schema_fingerprint};
use crate::discovery::{DiscoveryError, sanitize_lists};
use crate::handles::{HandleStore, Owner};
use crate::limits::{Limits, Refusal};
use crate::service::{Blocks, BlocksError};
use crate::status::{ContractState, DatasetStatus};
use crate::upstream::{UpstreamHandle, UpstreamState};

/// An MCP error from the fixed vocabulary (M4 spec, Global Constraints):
/// `unknown_*`, `unresolved_token`, and `unsupported_content` are
/// `INVALID_PARAMS`, everything else `INTERNAL_ERROR`. `data` must carry
/// only `class`, `kinds`, `checks`, `unknown_tokens`, `removed_markers`,
/// `limit`, or `code`; `null` means none.
pub fn mcp_error(message: &'static str, data: Value) -> ErrorData {
    let code = match message {
        "unknown_tool"
        | "unknown_prompt"
        | "unknown_resource"
        | "unresolved_token"
        | "unsupported_content" => ErrorCode::INVALID_PARAMS,
        _ => ErrorCode::INTERNAL_ERROR,
    };
    ErrorData::new(
        code,
        message,
        if data.is_null() { None } else { Some(data) },
    )
}

fn blocks_error(e: &BlocksError) -> ErrorData {
    match e {
        BlocksError::DatasetNotFound => {
            mcp_error("vault_unavailable", json!({ "class": "dataset_not_found" }))
        }
        BlocksError::ModelUnavailable => mcp_error("model_unavailable", Value::Null),
        BlocksError::VaultUnavailable => {
            mcp_error("vault_unavailable", json!({ "class": "vault" }))
        }
        BlocksError::Unresolved { unknown, removed } => mcp_error(
            "unresolved_token",
            json!({ "unknown_tokens": unknown, "removed_markers": removed }),
        ),
        BlocksError::Unsupported(c) => mcp_error("unsupported_content", json!({ "class": c })),
        BlocksError::Internal(c) => mcp_error("vault_unavailable", json!({ "class": c })),
    }
}

/// A listing that could not be exposed, as the agent sees it.
fn discovery_error(e: &DiscoveryError) -> ErrorData {
    match e {
        DiscoveryError::Unsupported(c) => mcp_error("unsupported_content", json!({ "class": c })),
        DiscoveryError::Blocks(b) => blocks_error(b),
    }
}

/// A content-path failure outside a tool result (a read, a prompt, a
/// refused request), as the agent sees it. A tool call answers `Blocked`
/// and `Uncertain` as tool errors instead.
fn content_error(e: &ContentError) -> ErrorData {
    match e {
        ContentError::Blocked { kinds, checks } => mcp_error(
            "privacy_block",
            json!({ "kinds": kind_labels(kinds), "checks": check_names(checks) }),
        ),
        ContentError::Uncertain { kinds, checks } => mcp_error(
            "privacy_block",
            json!({ "class": "uncertain", "kinds": kind_labels(kinds), "checks": check_names(checks) }),
        ),
        ContentError::Unsupported(class) => {
            mcp_error("unsupported_content", json!({ "class": class }))
        }
        ContentError::Unresolved { unknown, removed } => mcp_error(
            "unresolved_token",
            json!({ "unknown_tokens": unknown, "removed_markers": removed }),
        ),
        ContentError::Blocks(b) => blocks_error(b),
    }
}

fn worker_failed() -> ErrorData {
    mcp_error("upstream_unavailable", json!({ "class": "worker" }))
}

/// First wait before a listing that failed for a transient reason is
/// rebuilt again; doubled per failed attempt up to [`RETRY_MAX`].
const RETRY_BASE: Duration = Duration::from_millis(500);
/// Longest wait between two retries.
const RETRY_MAX: Duration = Duration::from_secs(30);
/// How long one session's list-change notifications may take. A session
/// whose transport is full (an open stream nobody reads) is skipped.
const NOTIFY_TIMEOUT: Duration = Duration::from_secs(2);
/// Open `subscriptions/listen` streams per dataset. Each holds a
/// connection, an rmcp task, and a notification task per catalog change;
/// one more is refused as `resource_limit` (`limit: subscriptions`).
pub const MAX_SUBSCRIPTIONS: usize = 64;

/// An engine failure that can clear up by itself (models loading, the
/// vault briefly unavailable), as opposed to content or contract failures,
/// which stay until an upstream or a row changes.
fn transient(e: &BlocksError) -> bool {
    matches!(
        e,
        BlocksError::ModelUnavailable | BlocksError::VaultUnavailable
    )
}

/// What one rebuild did, for the work done after the lock is released.
#[derive(Default)]
struct Rebuilt {
    /// The exposed catalog changed: tell the sessions.
    changed: bool,
    /// A listing failed, or the profile could not be read, for a
    /// [`transient`] reason: rebuild again later.
    transient: bool,
}

/// Per-upstream contract state. `Debug` prints states and counts: raw
/// schemas are upstream metadata.
#[derive(Clone)]
pub struct UpstreamContract {
    /// The parsed policy, or why it did not parse.
    pub contract: Result<Contract, ContractError>,
    /// The reviewed fingerprint from the vault row.
    pub reviewed: Option<String>,
    /// Readiness after the last rebuild.
    pub state: ContractState,
    /// The upstream's current fingerprint after the last rebuild.
    pub current: Option<String>,
    /// Raw input schemas by original tool name (argument type restoration).
    pub raw_tools: HashMap<String, Arc<JsonObject>>,
    /// Declared argument names by original prompt name.
    pub prompt_args: HashMap<String, Vec<String>>,
}

impl std::fmt::Debug for UpstreamContract {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamContract")
            .field("parsed", &self.contract.is_ok())
            .field("reviewed", &self.reviewed.is_some())
            .field("state", &self.state)
            .field("current", &self.current.is_some())
            .field("tools", &self.raw_tools.len())
            .field("prompts", &self.prompt_args.len())
            .finish()
    }
}

impl UpstreamContract {
    /// From a vault row's policy text and reviewed fingerprint.
    pub fn from_row(policy: &str, reviewed: Option<String>) -> Self {
        let contract = Contract::parse(policy);
        let state = match &contract {
            Err(_) => ContractState::Invalid,
            Ok(c) if is_empty(c) => ContractState::None,
            Ok(_) => ContractState::Ready,
        };
        UpstreamContract {
            contract,
            reviewed,
            state,
            current: None,
            raw_tools: HashMap::new(),
            prompt_args: HashMap::new(),
        }
    }

    /// Whether the upstream may be listed and called.
    fn visible(&self) -> bool {
        matches!(self.state, ContractState::Ready | ContractState::None)
    }
}

/// The fingerprint a contract is bound to: the schemas of the tools,
/// prompts, and templates it reviews. A change there hides the upstream
/// until the change is accepted (M4 spec §5.3: schema changes invalidate
/// the contract until revalidated); an item the contract does not name
/// only ever gets the unreviewed treatment (text sanitized as free text,
/// structured content refused), so one appearing or changing (a
/// `list_changed` adding a tool) leaves the binding intact.
fn contract_fingerprint(raw: &RawLists, contract: &Contract) -> String {
    let tools: Vec<_> = raw
        .tools
        .iter()
        .filter(|t| contract.tools.contains_key(t.name.as_ref()))
        .cloned()
        .collect();
    let prompts: Vec<_> = raw
        .prompts
        .iter()
        .filter(|p| contract.prompts.contains_key(&p.name))
        .cloned()
        .collect();
    let templates: Vec<_> = raw
        .templates
        .iter()
        .filter(|t| contract.templates.contains_key(&t.uri_template))
        .cloned()
        .collect();
    schema_fingerprint(&tools, &prompts, &templates)
}

fn is_empty(c: &Contract) -> bool {
    c.tools.is_empty() && c.prompts.is_empty() && c.templates.is_empty()
}

struct Counters {
    calls: AtomicU64,
    blocked: AtomicU64,
    uncertain: AtomicU64,
    unresolved: AtomicU64,
    unsupported: AtomicU64,
    limited: AtomicU64,
    uncertain_checks: Mutex<BTreeMap<String, u64>>,
    clear_value_hits: AtomicU64,
}

/// One consistent view of a dataset's upstreams: swapped as a whole, so an
/// index from `catalog` always means the same upstream in `upstreams`.
struct Snapshot {
    /// Upstreams in creation order; identity marks one upstream set.
    upstreams: Arc<Vec<Arc<UpstreamHandle>>>,
    /// Contract state per upstream, same order.
    contracts: Vec<Arc<UpstreamContract>>,
    /// Per index, the owner whose lists the catalog was built from.
    owners: Vec<Option<Owner>>,
    catalog: Arc<Catalog>,
    /// Set when the last rebuild could not expose a listing.
    listing_error: Option<ErrorData>,
}

impl Snapshot {
    fn new(upstreams: Vec<(Arc<UpstreamHandle>, UpstreamContract)>) -> Snapshot {
        let n = upstreams.len();
        let (handles, contracts): (Vec<_>, Vec<_>) =
            upstreams.into_iter().map(|(h, c)| (h, Arc::new(c))).unzip();
        Snapshot {
            upstreams: Arc::new(handles),
            contracts,
            owners: vec![None; n],
            catalog: Arc::new(Catalog::empty()),
            listing_error: None,
        }
    }
}

struct Inner {
    dataset: String,
    label: String,
    /// The dataset's opaque label as an activity-record id.
    dataset_ref: OpaqueId,
    vault: Vault,
    blocks: Arc<dyn Blocks>,
    config: GatewayConfig,
    limits: Limits,
    snapshot: RwLock<Arc<Snapshot>>,
    /// One rebuild at a time: each one reads the snapshot it replaces.
    rebuild_lock: tokio::sync::Mutex<()>,
    /// A retry of a transiently failed rebuild is scheduled.
    retry_pending: AtomicBool,
    /// Transiently failed rebuilds in a row (the retry backoff exponent).
    retry_attempt: AtomicU32,
    /// Locked only briefly (minting, resolving, retaining): a sanitization
    /// runs against a [`HandleStore::scoped`] copy, never under this lock.
    handles: Arc<Mutex<HandleStore>>,
    /// Connected agent sessions, told when the catalog changes.
    sessions: Mutex<Vec<Peer<RoleServer>>>,
    /// Open `subscriptions/listen` streams of 2026-07-28 clients (which
    /// have no session), told when the catalog changes; each removes
    /// itself when its request ends.
    subscriptions: Mutex<Vec<(u64, SubscriptionSink)>>,
    /// The id of the next subscription.
    next_subscription: AtomicU64,
    counters: Counters,
    /// Set when the dataset is removed or reloaded: new requests fail.
    closed: AtomicBool,
    /// Requests between routing and their answer.
    inflight: AtomicUsize,
    /// Notified when `inflight` drops to zero.
    idle: tokio::sync::Notify,
    /// Activity records (M4 spec §16.4), written off the request path.
    activity: ActivitySink,
}

/// Removes an open subscription from [`Inner::subscriptions`] when its
/// `subscriptions/listen` request ends, however it ends.
struct Subscribed<'a>(&'a Inner, u64);

impl Drop for Subscribed<'_> {
    fn drop(&mut self) {
        self.0
            .subscriptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|(id, _)| *id != self.1);
    }
}

/// Counts one request in flight until dropped.
struct Entered<'a>(&'a Inner);

impl Drop for Entered<'_> {
    fn drop(&mut self) {
        if self.0.inflight.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.idle.notify_waiters();
        }
    }
}

/// The per-dataset MCP server. Cheap to clone (shared inner). `Debug`
/// prints the opaque dataset label and counts.
#[derive(Clone)]
pub struct DatasetHandler {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for DatasetHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatasetHandler")
            .field("dataset", &self.inner.label)
            .field("tools", &self.catalog().tools().len())
            .finish()
    }
}

/// A request's target: the upstream at a catalog index, verified.
struct Target {
    handle: Arc<UpstreamHandle>,
    contract: Arc<UpstreamContract>,
    peer: Peer<RoleClient>,
}

impl DatasetHandler {
    /// A handler with no upstreams yet. `label` is the opaque log label;
    /// every served call leaves a record in `activity`.
    pub fn new(
        dataset: &str,
        label: &str,
        vault: Vault,
        blocks: Arc<dyn Blocks>,
        config: GatewayConfig,
        activity: ActivitySink,
    ) -> Self {
        DatasetHandler {
            inner: Arc::new(Inner {
                dataset: dataset.to_string(),
                label: label.to_string(),
                dataset_ref: vault.opaque_ref(dataset),
                vault,
                blocks,
                limits: Limits::new(&config),
                config,
                snapshot: RwLock::new(Arc::new(Snapshot::new(Vec::new()))),
                rebuild_lock: tokio::sync::Mutex::new(()),
                retry_pending: AtomicBool::new(false),
                retry_attempt: AtomicU32::new(0),
                handles: Arc::new(Mutex::new(HandleStore::new())),
                sessions: Mutex::new(Vec::new()),
                subscriptions: Mutex::new(Vec::new()),
                next_subscription: AtomicU64::new(0),
                closed: AtomicBool::new(false),
                inflight: AtomicUsize::new(0),
                idle: tokio::sync::Notify::new(),
                activity,
                counters: Counters {
                    calls: AtomicU64::new(0),
                    blocked: AtomicU64::new(0),
                    uncertain: AtomicU64::new(0),
                    unresolved: AtomicU64::new(0),
                    unsupported: AtomicU64::new(0),
                    limited: AtomicU64::new(0),
                    uncertain_checks: Mutex::new(BTreeMap::new()),
                    clear_value_hits: AtomicU64::new(0),
                },
            }),
        }
    }

    /// The dataset id.
    pub fn dataset(&self) -> &str {
        &self.inner.dataset
    }

    fn snapshot(&self) -> Arc<Snapshot> {
        Arc::clone(
            &self
                .inner
                .snapshot
                .read()
                .unwrap_or_else(PoisonError::into_inner),
        )
    }

    /// Replace the upstream set (creation order) with their contracts. The
    /// catalog is emptied in the same swap (nothing routes by an index into
    /// the old set); [`DatasetHandler::rebuild`] fills it again.
    pub fn set_upstreams(&self, upstreams: Vec<(Arc<UpstreamHandle>, UpstreamContract)>) {
        *self
            .inner
            .snapshot
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Arc::new(Snapshot::new(upstreams));
    }

    /// Refuse new requests (`context_unavailable`); requests already in
    /// flight continue and fail on their own once the upstreams stop.
    pub fn close(&self) {
        self.inner.closed.store(true, Ordering::Release);
    }

    /// Wait until no request is in flight, at most `grace`. The gateway
    /// calls it after [`DatasetHandler::close`] and stopping the upstreams,
    /// so an in-flight call answers with an error before its session ends
    /// (M4 Review Focus 6) instead of leaving the agent waiting on a stream
    /// that closed without a response.
    pub async fn drain(&self, grace: Duration) {
        let deadline = tokio::time::Instant::now() + grace;
        loop {
            let idle = self.inner.idle.notified();
            tokio::pin!(idle);
            idle.as_mut().enable();
            if self.inner.inflight.load(Ordering::Acquire) == 0 {
                return;
            }
            if tokio::time::timeout_at(deadline, idle).await.is_err() {
                tracing::warn!(dataset = %self.inner.label, "requests still in flight after the grace period");
                return;
            }
        }
    }

    /// Count a request in flight, or refuse it when the handler is closed.
    fn enter(&self) -> Result<Entered<'_>, ErrorData> {
        self.inner.inflight.fetch_add(1, Ordering::AcqRel);
        let entered = Entered(&self.inner);
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(mcp_error(
                "context_unavailable",
                json!({ "class": "dataset_closed" }),
            ));
        }
        Ok(entered)
    }

    /// The upstream handles (the gateway stops them on removal).
    pub fn upstream_handles(&self) -> Vec<Arc<UpstreamHandle>> {
        self.snapshot().upstreams.iter().cloned().collect()
    }

    /// The current catalog.
    pub fn catalog(&self) -> Arc<Catalog> {
        Arc::clone(&self.snapshot().catalog)
    }

    /// Fetch every running upstream's lists (bounded in time and pages),
    /// check each contract against the dataset's profile, bind it to the
    /// upstream's schema (trust on first use, then drift detection),
    /// sanitize the discovery metadata, and rebuild the catalog over every
    /// configured upstream in creation order: one that is down, or whose
    /// listing failed this time, keeps its last-known lists so its names
    /// keep their owner. An upstream whose contract is invalid, refused by
    /// the profile, or drifted is hidden; a listing that cannot be
    /// sanitized fails the dataset's listings.
    ///
    /// A failure that can clear up by itself (models or vault unavailable,
    /// the profile unreadable) schedules another rebuild with backoff.
    /// Sessions hear about a changed catalog after the rebuild lock is
    /// released, each with a time limit, so a session that does not read
    /// never holds up this or a later rebuild.
    pub async fn rebuild(&self) {
        let done = {
            let _one = self.inner.rebuild_lock.lock().await;
            self.rebuild_locked().await
        };
        if done.transient {
            self.schedule_retry();
        } else {
            self.inner.retry_attempt.store(0, Ordering::Relaxed);
        }
        if done.changed {
            self.notify_sessions();
        }
    }

    /// Rebuild again after a backoff, unless a retry is already scheduled
    /// or the handler is closed. The task holds the handler weakly: a
    /// removed dataset is not kept alive by its retry.
    fn schedule_retry(&self) {
        if self.inner.closed.load(Ordering::Acquire)
            || self.inner.retry_pending.swap(true, Ordering::AcqRel)
        {
            return;
        }
        let attempt = self
            .inner
            .retry_attempt
            .fetch_add(1, Ordering::Relaxed)
            .min(16);
        let delay = RETRY_BASE.saturating_mul(1 << attempt).min(RETRY_MAX);
        tracing::info!(dataset = %self.inner.label, delay_ms = delay.as_millis() as u64, "listing failed for a transient reason; rebuilding again later");
        let weak = Arc::downgrade(&self.inner);
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let Some(inner) = weak.upgrade() else {
                return;
            };
            inner.retry_pending.store(false, Ordering::Release);
            if inner.closed.load(Ordering::Acquire) {
                return;
            }
            DatasetHandler { inner }.rebuild().await;
        });
    }

    /// [`DatasetHandler::rebuild`] under the rebuild lock.
    async fn rebuild_locked(&self) -> Rebuilt {
        let mut done = Rebuilt::default();
        let snap = self.snapshot();
        let blocks = Arc::clone(&self.inner.blocks);
        let dataset = self.inner.dataset.clone();
        let profile = tokio::task::spawn_blocking(move || blocks.profile(&dataset))
            .await
            .map_err(|_| BlocksError::Internal("worker"))
            .and_then(|r| r);
        let n = snap.upstreams.len();
        let mut contracts: Vec<UpstreamContract> =
            snap.contracts.iter().map(|c| (**c).clone()).collect();
        let mut owners: Vec<Option<Owner>> = vec![None; n];
        let mut lists: Vec<UpstreamLists> = Vec::new();
        let mut listing_error: Option<ErrorData> = None;
        for (index, u) in snap.upstreams.iter().enumerate() {
            let uc = &mut contracts[index];
            let contract = match &uc.contract {
                Ok(c) => c.clone(),
                Err(_) => {
                    uc.state = ContractState::Invalid;
                    tracing::warn!(dataset = %self.inner.label, upstream = %u.name, "content policy invalid; upstream hidden");
                    continue;
                }
            };
            // Carry 9: every load, and every rebuild after it, checks the
            // contract against the dataset's profile (a typed identifier
            // always tokenizes, which a Block/Remove kind forbids).
            let allowed = match &profile {
                Ok(p) => contract.check_profile(p).map_err(|_| "profile_kind"),
                Err(e) => {
                    done.transient |= transient(e);
                    Err("profile_unavailable")
                }
            };
            if let Err(class) = allowed {
                uc.state = ContractState::Invalid;
                tracing::warn!(dataset = %self.inner.label, upstream = %u.name, class, "content policy refused for the dataset's profile; upstream hidden");
                continue;
            }
            let fetched = match u.peer() {
                Some(peer) => fetch_lists(&peer, self.inner.config.call_timeout)
                    .await
                    .map_err(|e| {
                        tracing::warn!(dataset = %self.inner.label, upstream = %u.name, error = %e, "upstream lists unavailable; keeping its last-known lists");
                    })
                    .ok(),
                None => None,
            };
            let Some(raw) = fetched else {
                // Down (or its listing failed): keep its names with it.
                if uc.visible() {
                    if let Some(mut l) = u.last_lists() {
                        l.index = index;
                        owners[index] = Some(u.owner());
                        lists.push(l);
                    }
                }
                continue;
            };
            let fp = contract_fingerprint(&raw, &contract);
            uc.current = Some(fp.clone());
            uc.raw_tools = raw
                .tools
                .iter()
                .map(|t| (t.name.to_string(), Arc::clone(&t.input_schema)))
                .collect();
            uc.prompt_args = raw
                .prompts
                .iter()
                .map(|p| {
                    (
                        p.name.clone(),
                        p.arguments
                            .iter()
                            .flatten()
                            .map(|a| a.name.clone())
                            .collect(),
                    )
                })
                .collect();
            match &uc.reviewed {
                None => {
                    // Trust on first use: bind the contract to what we see now.
                    let vault = self.inner.vault.clone();
                    let (dataset, name, f) =
                        (self.inner.dataset.clone(), u.name.clone(), fp.clone());
                    let recorded = tokio::task::spawn_blocking(move || {
                        vault.set_upstream_fingerprint(&dataset, &name, Some(&f))
                    })
                    .await;
                    if !matches!(recorded, Ok(Ok(()))) {
                        tracing::warn!(dataset = %self.inner.label, upstream = %u.name, "could not record the schema fingerprint");
                    }
                    uc.reviewed = Some(fp.clone());
                }
                Some(r) if *r != fp => {
                    uc.state = ContractState::Drift;
                    tracing::warn!(dataset = %self.inner.label, upstream = %u.name, "upstream schema drifted from the reviewed fingerprint; upstream hidden until accepted");
                    continue;
                }
                Some(_) => {}
            }
            uc.state = if is_empty(&contract) {
                ContractState::None
            } else {
                ContractState::Ready
            };
            let blocks = Arc::clone(&self.inner.blocks);
            let dataset = self.inner.dataset.clone();
            let owner = u.owner();
            let resources: Vec<&str> = raw.resources.iter().map(|r| r.uri.as_str()).collect();
            let templates: Vec<&str> = raw
                .templates
                .iter()
                .map(|t| t.uri_template.as_str())
                .filter(|t| contract.templates.contains_key(*t))
                .collect();
            let scoped = self.scoped_handles(&owner, &resources, &templates);
            let outcome = tokio::task::spawn_blocking(move || {
                let mut h = scoped;
                let r = sanitize_lists(&*blocks, &dataset, &owner, index, &raw, &contract, &mut h);
                (r, h)
            })
            .await
            .map(|(r, h)| {
                self.absorb_handles(h);
                r
            });
            match outcome {
                Ok(Ok(l)) => {
                    u.set_last_lists(l.clone());
                    owners[index] = Some(u.owner());
                    lists.push(l);
                }
                Ok(Err(e)) => {
                    let err = discovery_error(&e);
                    tracing::warn!(dataset = %self.inner.label, upstream = %u.name, class = %err.message, "listing could not be sanitized; dataset listings fail");
                    done.transient |= matches!(&e, DiscoveryError::Blocks(b) if transient(b));
                    listing_error = Some(err);
                }
                Err(_) => {
                    done.transient = true;
                    listing_error = Some(worker_failed());
                }
            }
        }
        // Handles of every configured upstream stay, running or not.
        let configured: Vec<Owner> = snap.upstreams.iter().map(|u| u.owner()).collect();
        self.inner
            .handles
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(&configured);
        let catalog = if listing_error.is_some() {
            Catalog::empty()
        } else {
            Catalog::build(&lists)
        };
        tracing::info!(dataset = %self.inner.label, upstreams = lists.len(), tools = catalog.tools().len(), prompts = catalog.prompts().len(), resources = catalog.resources().len(), listing_failed = listing_error.is_some(), "catalog rebuilt");
        done.changed = listed(&catalog) != listed(&snap.catalog);
        let next = Arc::new(Snapshot {
            upstreams: Arc::clone(&snap.upstreams),
            contracts: contracts.into_iter().map(Arc::new).collect(),
            owners,
            catalog: Arc::new(catalog),
            listing_error,
        });
        {
            let mut cur = self
                .inner
                .snapshot
                .write()
                .unwrap_or_else(PoisonError::into_inner);
            // A new upstream set arrived meanwhile: this rebuild is stale
            // (the rebuild that follows the new set does the work).
            if !Arc::ptr_eq(&cur.upstreams, &snap.upstreams) {
                return Rebuilt::default();
            }
            *cur = next;
        }
        done
    }

    /// Mint the handles a listing or result needs under a short lock and
    /// return a store holding them, for the sanitization to use unlocked.
    fn scoped_handles(&self, owner: &Owner, resources: &[&str], templates: &[&str]) -> HandleStore {
        self.inner
            .handles
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .scoped(owner, resources, templates)
    }

    /// Take back what a sanitization minted in its scoped store.
    fn absorb_handles(&self, scoped: HandleStore) {
        self.inner
            .handles
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .absorb(scoped);
    }

    /// Tell every connected session and every open subscription that the
    /// lists changed; forget closed sessions. Each is told on its own task
    /// within [`NOTIFY_TIMEOUT`]: a send waits until the transport took
    /// the message, and one that is full (an open stream nobody reads)
    /// would otherwise stall the caller and every session after it. A
    /// notification names no list item: nothing to sanitize.
    fn notify_sessions(&self) {
        let sinks: Vec<SubscriptionSink> = self
            .inner
            .subscriptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(_, sink)| sink.clone())
            .collect();
        for sink in sinks {
            let label = self.inner.label.clone();
            tokio::spawn(async move {
                // The sink refuses the kinds the client did not ask for.
                let sent = tokio::time::timeout(NOTIFY_TIMEOUT, async {
                    let _ = sink.notify_tool_list_changed().await;
                    let _ = sink.notify_prompt_list_changed().await;
                    let _ = sink.notify_resource_list_changed().await;
                })
                .await;
                if sent.is_err() {
                    tracing::debug!(dataset = %label, "a subscription did not take list-change notifications in time; skipped");
                }
            });
        }
        let peers: Vec<Peer<RoleServer>> = {
            let mut s = self
                .inner
                .sessions
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            s.retain(|p| !p.is_transport_closed());
            s.clone()
        };
        for p in peers {
            let label = self.inner.label.clone();
            tokio::spawn(async move {
                let sent = tokio::time::timeout(NOTIFY_TIMEOUT, async {
                    let _ = p.notify_tool_list_changed().await;
                    let _ = p.notify_prompt_list_changed().await;
                    let _ = p.notify_resource_list_changed().await;
                })
                .await;
                if sent.is_err() {
                    tracing::debug!(dataset = %label, "a session did not take list-change notifications in time; skipped");
                }
            });
        }
    }

    /// For `status`.
    pub fn status(&self) -> DatasetStatus {
        let snap = self.snapshot();
        let c = &self.inner.counters;
        DatasetStatus {
            id: self.inner.dataset.clone(),
            upstreams: snap
                .upstreams
                .iter()
                .zip(&snap.contracts)
                .map(|(h, c)| {
                    let mut s = h.status(c.state);
                    s.schema_fingerprint = c.current.clone();
                    s
                })
                .collect(),
            calls: c.calls.load(Ordering::Relaxed),
            blocked: c.blocked.load(Ordering::Relaxed),
            uncertain: c.uncertain.load(Ordering::Relaxed),
            unresolved: c.unresolved.load(Ordering::Relaxed),
            unsupported: c.unsupported.load(Ordering::Relaxed),
            limited: c.limited.load(Ordering::Relaxed),
            clear_value_hits: c.clear_value_hits.load(Ordering::Relaxed),
        }
    }

    /// Check ids seen on withheld uncertain results, with counts.
    pub fn uncertain_checks(&self) -> BTreeMap<String, u64> {
        self.inner
            .counters
            .uncertain_checks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The catalog of `snap`, or the listing failure (counted).
    fn listing(&self, snap: &Snapshot) -> Result<Arc<Catalog>, ErrorData> {
        match &snap.listing_error {
            Some(e) => {
                if e.message == "unsupported_content" {
                    self.inner
                        .counters
                        .unsupported
                        .fetch_add(1, Ordering::Relaxed);
                }
                Err(e.clone())
            }
            None => Ok(Arc::clone(&snap.catalog)),
        }
    }

    /// The upstream at a catalog `index` of `snap`, only when it is the
    /// owner the catalog's lists for that index came from, its contract is
    /// usable, and it is connected.
    fn target(&self, snap: &Snapshot, index: usize) -> Result<Target, ErrorData> {
        let not_running = || mcp_error("upstream_unavailable", json!({ "class": "not_running" }));
        let handle = snap.upstreams.get(index).ok_or_else(not_running)?;
        let contract = snap.contracts.get(index).ok_or_else(not_running)?;
        let expected = snap.owners.get(index).and_then(Option::as_ref);
        if expected != Some(&handle.owner()) || !contract.visible() {
            tracing::warn!(dataset = %self.inner.label, "route does not match its owner; refused");
            return Err(not_running());
        }
        let peer = handle.peer().ok_or_else(|| {
            let class = if handle.state() == UpstreamState::Starting {
                "starting"
            } else {
                "not_running"
            };
            mcp_error("upstream_unavailable", json!({ "class": class }))
        })?;
        Ok(Target {
            handle: Arc::clone(handle),
            contract: Arc::clone(contract),
            peer,
        })
    }

    /// The upstream owning a handle minted from a result (a resource link
    /// or an embedded resource), when that owner is still configured and
    /// visible; the handle store alone knows these.
    fn target_by_owner(&self, snap: &Snapshot, owner: &Owner) -> Result<Target, ErrorData> {
        let index = snap
            .upstreams
            .iter()
            .position(|u| u.owner() == *owner)
            .ok_or_else(|| mcp_error("unknown_resource", Value::Null))?;
        if snap.listing_error.is_some() || !snap.contracts[index].visible() {
            return Err(mcp_error("unknown_resource", Value::Null));
        }
        let handle = &snap.upstreams[index];
        let peer = handle
            .peer()
            .ok_or_else(|| mcp_error("upstream_unavailable", json!({ "class": "not_running" })))?;
        Ok(Target {
            handle: Arc::clone(handle),
            contract: Arc::clone(&snap.contracts[index]),
            peer,
        })
    }

    /// Map a content-path failure to what the agent sees for a tool call:
    /// a tool error for `Blocked`/`Uncertain` (`Ok`), an MCP error otherwise.
    fn call_failure(&self, e: ContentError) -> Result<CallToolResult, ErrorData> {
        match e {
            ContentError::Blocked { kinds, checks } => {
                self.inner.counters.blocked.fetch_add(1, Ordering::Relaxed);
                tracing::info!(dataset = %self.inner.label, kinds = kinds.len(), checks = checks.len(), "result blocked");
                Ok(CallToolResult::error(vec![ContentBlock::text(
                    blocked_text(&kinds, &checks),
                )]))
            }
            ContentError::Uncertain { kinds, checks } => {
                self.count_uncertain(&checks);
                tracing::info!(dataset = %self.inner.label, kinds = kinds.len(), checks = checks.len(), "uncertain result withheld");
                Ok(CallToolResult::error(vec![ContentBlock::text(
                    withheld_text(&kinds, &checks),
                )]))
            }
            other => Err(self.request_failure(other)),
        }
    }

    fn count_uncertain(&self, checks: &[CheckLabel]) {
        self.inner
            .counters
            .uncertain
            .fetch_add(1, Ordering::Relaxed);
        let mut m = self
            .inner
            .counters
            .uncertain_checks
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for c in checks {
            *m.entry(c.as_str().to_string()).or_insert(0) += 1;
        }
    }

    /// Map a content-path failure to an MCP error (counting it).
    fn request_failure(&self, e: ContentError) -> ErrorData {
        let c = &self.inner.counters;
        match &e {
            ContentError::Blocked { .. } => {
                c.blocked.fetch_add(1, Ordering::Relaxed);
            }
            ContentError::Uncertain { checks, .. } => self.count_uncertain(checks),
            ContentError::Unsupported(_) => {
                c.unsupported.fetch_add(1, Ordering::Relaxed);
            }
            ContentError::Unresolved { .. } => {
                c.unresolved.fetch_add(1, Ordering::Relaxed);
            }
            ContentError::Blocks(_) => {}
        }
        content_error(&e)
    }

    /// An upstream failure: its error becomes `upstream_error` with the
    /// JSON-RPC code only (the message may echo rehydrated arguments); a
    /// connection the transport ended on an oversized message is
    /// `resource_limit`; other transport failures are `upstream_unavailable`
    /// with a class.
    fn upstream_failure(&self, t: &Target, e: rmcp::ServiceError) -> ErrorData {
        // The transport refused a message over the size limit and ended
        // the connection: the answer was too large, not unavailable.
        if !matches!(e, rmcp::ServiceError::McpError(_)) && t.handle.oversized() {
            tracing::info!(dataset = %self.inner.label, upstream = %t.handle.name, "upstream message over the size limit; connection ended");
            return self.too_large();
        }
        let err = match e {
            rmcp::ServiceError::McpError(data) => upstream_error(&data),
            rmcp::ServiceError::TransportClosed => {
                mcp_error("upstream_unavailable", json!({ "class": "closed" }))
            }
            rmcp::ServiceError::TransportSend(_) => {
                mcp_error("upstream_unavailable", json!({ "class": "transport" }))
            }
            rmcp::ServiceError::Timeout { .. } => {
                mcp_error("upstream_unavailable", json!({ "class": "timeout" }))
            }
            _ => mcp_error("upstream_unavailable", json!({ "class": "failed" })),
        };
        tracing::info!(dataset = %self.inner.label, upstream = %t.handle.name, class = %err.message, "upstream call failed");
        err
    }

    fn timed_out(&self, t: &Target) -> ErrorData {
        tracing::warn!(dataset = %self.inner.label, upstream = %t.handle.name, "upstream call timed out");
        mcp_error("upstream_unavailable", json!({ "class": "timeout" }))
    }

    async fn slot(&self) -> Result<tokio::sync::OwnedSemaphorePermit, ErrorData> {
        match self.inner.limits.acquire().await {
            Some(p) => Ok(p),
            None => {
                self.inner.counters.limited.fetch_add(1, Ordering::Relaxed);
                Err(mcp_error("resource_limit", json!({ "limit": "inflight" })))
            }
        }
    }

    /// A result refused before any sanitization work (counted; an unknown
    /// content kind is also recorded as `unsupported`).
    fn within_limits(&self, hop: &Hop, check: Result<(), Refusal>) -> Result<(), ErrorData> {
        match check {
            Ok(()) => Ok(()),
            Err(Refusal::TooLarge) => Err(self.too_large()),
            Err(Refusal::UnknownKind) => {
                Err(self.request_failed(hop, ContentError::Unsupported("content_type")))
            }
        }
    }

    fn too_large(&self) -> ErrorData {
        self.inner.counters.limited.fetch_add(1, Ordering::Relaxed);
        mcp_error("resource_limit", json!({ "limit": "response_bytes" }))
    }

    fn record(&self, stats: &SanitizeStats, what: &'static str, t0: Instant) {
        tracing::info!(dataset = %self.inner.label, what, blocks = stats.blocks, cached = stats.cached, latency_ms = t0.elapsed().as_millis() as u64, "tool call served");
    }

    /// Where a call's records happened: the upstream it was dispatched to
    /// (its opaque label, never the name) and the direction.
    fn hop(&self, t: &Target, direction: Direction) -> Hop {
        Hop {
            upstream: Some(
                self.inner
                    .vault
                    .opaque_upstream(&self.inner.dataset, &t.handle.name),
            ),
            direction,
        }
    }

    /// One activity record for this dataset.
    fn activity_record(
        &self,
        hop: &Hop,
        verdict: Verdict,
        kinds: Vec<KindCount>,
        checks: Vec<CheckLabel>,
        tripwire: bool,
        released: Option<&Released>,
    ) -> NewActivity {
        NewActivity {
            dataset: self.inner.dataset_ref.clone(),
            front_door: FrontDoor::Gateway,
            upstream: hop.upstream.clone(),
            direction: hop.direction,
            verdict,
            checks,
            kinds,
            tripwire,
            bytes: released.map_or(0, |r| r.bytes),
            released: released.map(|r| r.digest.clone()),
        }
    }

    /// Queue one activity record without a released payload; never blocks.
    fn emit(
        &self,
        hop: &Hop,
        verdict: Verdict,
        kinds: Vec<KindCount>,
        checks: Vec<CheckLabel>,
        tripwire: bool,
    ) {
        self.inner
            .activity
            .emit(self.activity_record(hop, verdict, kinds, checks, tripwire, None));
    }

    /// A failure's record: the verdict follows the error class; kinds and
    /// checks come typed from the content path.
    fn emit_failure(&self, hop: &Hop, e: &ContentError) {
        let typed = |kinds: &[EntityKind]| -> Vec<KindCount> {
            kinds
                .iter()
                .map(|k| KindCount {
                    kind: KindLabel::of(k),
                    count: 1,
                })
                .collect()
        };
        let (verdict, kinds, checks) = match e {
            ContentError::Blocked { kinds, checks } => {
                (Verdict::Blocked, typed(kinds), checks.clone())
            }
            ContentError::Uncertain { kinds, checks } => {
                (Verdict::Uncertain, typed(kinds), checks.clone())
            }
            ContentError::Unresolved { .. } => (Verdict::Unresolved, Vec::new(), Vec::new()),
            ContentError::Unsupported(_) => (Verdict::Unsupported, Vec::new(), Vec::new()),
            // Vault or model unavailable: an availability failure, not a
            // privacy verdict; status counters and logs cover it.
            ContentError::Blocks(_) => return,
        };
        self.emit(hop, verdict, kinds, checks, false);
    }

    /// [`DatasetHandler::call_failure`] plus its activity record.
    fn call_failed(&self, hop: &Hop, e: ContentError) -> Result<CallToolResult, ErrorData> {
        self.emit_failure(hop, &e);
        self.call_failure(e)
    }

    /// [`DatasetHandler::request_failure`] plus its activity record.
    fn request_failed(&self, hop: &Hop, e: ContentError) -> ErrorData {
        self.emit_failure(hop, &e);
        self.request_failure(e)
    }

    /// A released result's record: kinds with the blocks they were
    /// replaced in, the byte count, and the keyed digest; with it, for the
    /// egress journal, the bytes exactly as digested (M4 spec §16.3).
    fn emit_released(&self, hop: &Hop, stats: &SanitizeStats, released: Option<Released>) {
        let kinds = stats
            .replaced
            .iter()
            .map(|(k, n)| KindCount {
                kind: KindLabel::of(k),
                count: *n,
            })
            .collect();
        match released {
            Some(r) => {
                let rec = self.activity_record(
                    hop,
                    Verdict::Released,
                    kinds,
                    Vec::new(),
                    false,
                    Some(&r),
                );
                self.inner
                    .activity
                    .emit_released(&self.inner.dataset, rec, r.payload);
            }
            // Did not serialize: a record without a digest, nothing to journal.
            None => self.emit(hop, Verdict::Released, kinds, Vec::new(), false),
        }
    }

    /// Run the tripwire over model-written strings (M4 spec §16.1). `Ok`
    /// means proceed; in block mode a hit is a `privacy_block` error.
    async fn tripwire(&self, hop: &Hop, texts: Vec<String>) -> Result<(), ErrorData> {
        if texts.is_empty() {
            return Ok(());
        }
        let blocks = Arc::clone(&self.inner.blocks);
        let dataset = self.inner.dataset.clone();
        let found = tokio::task::spawn_blocking(move || blocks.scan_clear(&dataset, &texts))
            .await
            .map_err(|_| worker_failed())?
            .map_err(|e| self.request_failed(hop, ContentError::from(e)))?;
        if found.is_empty() {
            return Ok(());
        }
        self.inner
            .counters
            .clear_value_hits
            .fetch_add(1, Ordering::Relaxed);
        // `Blocks::scan_clear` returns kind labels as plain strings;
        // `EntityKind::from_label` is the existing, total way back to a kind.
        let kinds: Vec<KindCount> = found
            .iter()
            .map(|(k, n)| KindCount {
                kind: KindLabel::of(&EntityKind::from_label(k)),
                count: *n,
            })
            .collect();
        let labels: Vec<String> = found.iter().map(|(k, _)| k.clone()).collect();
        let block = self.inner.config.tripwire == TripwireMode::Block;
        tracing::info!(dataset = %self.inner.label, kinds = labels.len(), block, "clear value in arguments");
        self.emit(
            hop,
            if block {
                Verdict::Blocked
            } else {
                Verdict::Released
            },
            kinds,
            vec![CheckLabel::ClearValue],
            true,
        );
        if block {
            return Err(mcp_error(
                "privacy_block",
                json!({ "kinds": labels, "checks": check_names(&[CheckLabel::ClearValue]) }),
            ));
        }
        Ok(())
    }

    fn info(&self) -> ServerConfig {
        // Every list is announced (the catalog changes while a session
        // lives); each can change.
        let mut caps = ServerCapabilities::default();
        let mut tools = ToolsCapability::default();
        tools.list_changed = Some(true);
        caps.tools = Some(tools);
        let mut prompts = PromptsCapability::default();
        prompts.list_changed = Some(true);
        caps.prompts = Some(prompts);
        let mut resources = ResourcesCapability::default();
        resources.list_changed = Some(true);
        caps.resources = Some(resources);
        InitializeResult::new(caps).with_server_info(Implementation::new(
            // Model-visible: the opaque label, never the dataset slug.
            format!("inumaki/{}", self.inner.label),
            env!("CARGO_PKG_VERSION"),
        ))
    }
}

/// Size and keyed digest of a released result, and the serialized bytes
/// they were computed over (journaled as they are).
struct Released {
    bytes: u64,
    digest: Digest,
    payload: Vec<u8>,
}

/// Measure and digest a released result. Runs on the blocking pool with
/// the sanitization it follows, never on an async worker; `None` if it
/// does not serialize (then the record carries no digest).
fn released<T: serde::Serialize>(vault: &Vault, out: &T) -> Option<Released> {
    let bytes = serde_json::to_vec(out).ok()?;
    Some(Released {
        bytes: bytes.len() as u64,
        digest: vault.released_digest(&bytes),
        payload: bytes,
    })
}

/// URIs the content path turns into handles: embedded text resources and
/// resource links (other kinds are refused before any handle is minted).
fn item_uris(items: &[ContentBlock]) -> Vec<&str> {
    items
        .iter()
        .filter_map(|c| match c {
            ContentBlock::Resource(e) => match &e.resource {
                rmcp::model::ResourceContents::TextResourceContents { uri, .. } => {
                    Some(uri.as_str())
                }
                _ => None,
            },
            ContentBlock::ResourceLink(r) => Some(r.uri.as_str()),
            _ => None,
        })
        .collect()
}

/// rmcp 3.4.x behaviour this relies on (re-check on an rmcp upgrade; the
/// `gateway_lifecycle` tests exercise each one): a modern request's
/// [`RequestContext::protocol_version`] is the version in its `_meta`;
/// list and read results go out as the handler returns them (only
/// `resultType` is stripped for 2025 peers); the version gate compares
/// ISO dates as strings.
///
/// Cache hints for a list or read result to a 2026-07-28 peer, whose
/// schema requires `ttlMs` and `cacheScope` there (SEP-2549; a client
/// validating against it rejects the result without them). Stale at once,
/// since the catalog changes while a client is connected and a read is the
/// upstream's content of the moment; private, since every result is
/// sanitized for this dataset and its token namespace. Peers on older
/// versions keep the 2025 wire shape.
fn cache_hints(context: &RequestContext<RoleServer>) -> Option<(u64, CacheScope)> {
    context
        .protocol_version()
        .is_some_and(|v| v.as_str() >= ProtocolVersion::V_2026_07_28.as_str())
        .then_some((0, CacheScope::Private))
}

/// Mark a `tools/call`, `prompts/get`, or `resources/read` result
/// `resultType: "complete"`, which the 2026-07-28 schema requires on every
/// result. One built from an upstream's reply has none (the reply was
/// deserialized from an upstream that may speak an older version), so it is
/// set at the single exit of each of those methods; lists get it from
/// rmcp's `with_all_items`. rmcp 3.4.x removes it again for peers on older
/// versions (`strip_result_type_for_legacy_peer`), so their wire bytes do
/// not change.
macro_rules! complete {
    ($result:expr) => {{
        let mut r = $result;
        r.result_type = Some(ResultType::COMPLETE);
        r
    }};
}

/// Set [`cache_hints`] on a list or read result.
macro_rules! with_cache_hints {
    ($result:expr, $context:expr) => {{
        let mut r = $result;
        if let Some((ttl, scope)) = cache_hints($context) {
            r.ttl_ms = Some(ttl);
            r.cache_scope = Some(scope);
        }
        r
    }};
}

/// What a catalog exposes, for change detection.
fn listed(c: &Catalog) -> String {
    serde_json::to_string(&(c.tools(), c.prompts(), c.resources(), c.templates()))
        .unwrap_or_default()
}

impl ServerHandler for DatasetHandler {
    fn get_info(&self) -> ServerConfig {
        self.info()
    }

    async fn on_initialized(&self, context: NotificationContext<RoleServer>) {
        let mut s = self
            .inner
            .sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        s.retain(|p| !p.is_transport_closed());
        s.push(context.peer);
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let catalog = self.listing(&self.snapshot())?;
        Ok(with_cache_hints!(
            ListToolsResult::with_all_items(catalog.tools().to_vec()),
            &context
        ))
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        let catalog = self.listing(&self.snapshot())?;
        Ok(with_cache_hints!(
            ListPromptsResult::with_all_items(catalog.prompts().to_vec()),
            &context
        ))
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        let catalog = self.listing(&self.snapshot())?;
        Ok(with_cache_hints!(
            ListResourcesResult::with_all_items(catalog.resources().to_vec()),
            &context
        ))
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        let catalog = self.listing(&self.snapshot())?;
        Ok(with_cache_hints!(
            ListResourceTemplatesResult::with_all_items(catalog.templates().to_vec()),
            &context
        ))
    }

    /// `subscriptions/listen` (2026-07-28): list changes only, the same
    /// three a session is told about. Resource update subscriptions are
    /// not served (none is advertised), so they are dropped from the
    /// accepted filter rather than failing the stream.
    fn accepted_subscription_filter(
        &self,
        requested: &SubscriptionFilter,
    ) -> Option<SubscriptionFilter> {
        let mut accepted = SubscriptionFilter::new();
        accepted.tools_list_changed = requested.tools_list_changed;
        accepted.prompts_list_changed = requested.prompts_list_changed;
        accepted.resources_list_changed = requested.resources_list_changed;
        Some(accepted)
    }

    /// Hold an acknowledged subscription open until its request ends (the
    /// client cancels or disconnects, or the dataset's service stops); it
    /// is told about catalog changes meanwhile. Not counted in flight:
    /// draining a removed dataset does not wait for listeners. A closed
    /// handler refuses like [`DatasetHandler::enter`]; past
    /// [`MAX_SUBSCRIPTIONS`] the stream is refused as a resource limit.
    ///
    /// rmcp 3.4.x behaviour this relies on (re-check on an rmcp upgrade;
    /// the `gateway_lifecycle` tests exercise each one): rmcp sends the
    /// acknowledgment before calling this, so a refusal here ends an
    /// acknowledged stream with a JSON-RPC error (HTTP 200, not the 404
    /// a refused filter would give); the request is cancelled when the
    /// client disconnects (`CancelOnDisconnect`) and when the service's
    /// `cancellation_token` fires on dataset removal or reload, which
    /// ends this future and unregisters the sink.
    async fn listen(&self, subscription: SubscriptionContext) -> Result<(), ErrorData> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(mcp_error(
                "context_unavailable",
                json!({ "class": "dataset_closed" }),
            ));
        }
        let id = self.inner.next_subscription.fetch_add(1, Ordering::Relaxed);
        {
            let mut subs = self
                .inner
                .subscriptions
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if subs.len() >= MAX_SUBSCRIPTIONS {
                drop(subs);
                self.inner.counters.limited.fetch_add(1, Ordering::Relaxed);
                return Err(mcp_error(
                    "resource_limit",
                    json!({ "limit": "subscriptions" }),
                ));
            }
            subs.push((id, subscription.sink().clone()));
        }
        let _subscribed = Subscribed(&self.inner, id);
        subscription.cancelled().await;
        Ok(())
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let _entered = self.enter()?;
        let t0 = Instant::now();
        self.inner.counters.calls.fetch_add(1, Ordering::Relaxed);
        let snap = self.snapshot();
        let (index, original) = snap
            .catalog
            .route_tool(&request.name)
            .ok_or_else(|| mcp_error("unknown_tool", Value::Null))?;
        let original = original.to_string();
        let t = self.target(&snap, index)?;
        let args_hop = self.hop(&t, Direction::Arguments);
        let result_hop = self.hop(&t, Direction::Result);
        self.tripwire(
            &args_hop,
            request
                .arguments
                .as_ref()
                .map(|a| string_leaves(&Value::Object(a.clone())))
                .unwrap_or_default(),
        )
        .await?;
        let tool_contract = t
            .contract
            .contract
            .as_ref()
            .ok()
            .and_then(|c| c.tools.get(&original).cloned());
        let schema = t
            .contract
            .raw_tools
            .get(&original)
            .cloned()
            .unwrap_or_default();
        let _slot = self.slot().await?;
        let blocks = Arc::clone(&self.inner.blocks);
        let dataset = self.inner.dataset.clone();
        let raw_args = request.arguments;
        let tc = tool_contract.clone();
        let arguments = tokio::task::spawn_blocking(move || {
            rehydrate_arguments(&*blocks, &dataset, tc.as_ref(), &schema, raw_args)
        })
        .await
        .map_err(|_| worker_failed())?
        .map_err(|e| self.request_failed(&args_hop, e))?;
        let mut params = CallToolRequestParams::new(original);
        params.arguments = arguments;
        let result =
            match tokio::time::timeout(self.inner.config.call_timeout, t.peer.call_tool(params))
                .await
            {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => return Err(self.upstream_failure(&t, e)),
                Err(_) => return Err(self.timed_out(&t)),
            };
        self.within_limits(&result_hop, self.inner.limits.check_call(&result))?;
        let blocks = Arc::clone(&self.inner.blocks);
        let dataset = self.inner.dataset.clone();
        let vault = self.inner.vault.clone();
        let owner = t.handle.owner();
        let scoped = self.scoped_handles(&owner, &item_uris(&result.content), &[]);
        let (sanitized, h) = tokio::task::spawn_blocking(move || {
            let mut h = scoped;
            let r = sanitize_call_result(
                &*blocks,
                &dataset,
                tool_contract.as_ref(),
                &mut h,
                &owner,
                result,
            )
            .map(|(r, stats)| {
                let rel = released(&vault, &r);
                (r, stats, rel)
            });
            (r, h)
        })
        .await
        .map_err(|_| worker_failed())?;
        self.absorb_handles(h);
        let out = match sanitized {
            Ok((r, stats, rel)) => {
                self.record(&stats, "tools/call", t0);
                self.emit_released(&result_hop, &stats, rel);
                r
            }
            Err(e) => self.call_failed(&result_hop, e)?,
        };
        Ok(CallToolResponse::Complete(complete!(out)))
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResponse, ErrorData> {
        let _entered = self.enter()?;
        let t0 = Instant::now();
        self.inner.counters.calls.fetch_add(1, Ordering::Relaxed);
        let snap = self.snapshot();
        let (index, original) = snap
            .catalog
            .route_prompt(&request.name)
            .ok_or_else(|| mcp_error("unknown_prompt", Value::Null))?;
        let original = original.to_string();
        let t = self.target(&snap, index)?;
        let args_hop = self.hop(&t, Direction::Arguments);
        let result_hop = self.hop(&t, Direction::Result);
        self.tripwire(
            &args_hop,
            request
                .arguments
                .as_ref()
                .map(|a| string_leaves(&Value::Object(a.clone())))
                .unwrap_or_default(),
        )
        .await?;
        let pc = t
            .contract
            .contract
            .as_ref()
            .ok()
            .and_then(|c| c.prompts.get(&original).cloned());
        let declared = t
            .contract
            .prompt_args
            .get(&original)
            .cloned()
            .unwrap_or_default();
        let _slot = self.slot().await?;
        let blocks = Arc::clone(&self.inner.blocks);
        let dataset = self.inner.dataset.clone();
        let raw_args = request.arguments;
        let arguments = tokio::task::spawn_blocking(move || {
            rehydrate_prompt_arguments(&*blocks, &dataset, pc.as_ref(), &declared, raw_args)
        })
        .await
        .map_err(|_| worker_failed())?
        .map_err(|e| self.request_failed(&args_hop, e))?;
        let mut params = GetPromptRequestParams::new(original);
        params.arguments = arguments;
        let result =
            match tokio::time::timeout(self.inner.config.call_timeout, t.peer.get_prompt(params))
                .await
            {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => return Err(self.upstream_failure(&t, e)),
                Err(_) => return Err(self.timed_out(&t)),
            };
        self.within_limits(&result_hop, self.inner.limits.check_prompt(&result))?;
        let blocks = Arc::clone(&self.inner.blocks);
        let dataset = self.inner.dataset.clone();
        let vault = self.inner.vault.clone();
        let owner = t.handle.owner();
        let contents: Vec<ContentBlock> =
            result.messages.iter().map(|m| m.content.clone()).collect();
        let scoped = self.scoped_handles(&owner, &item_uris(&contents), &[]);
        let (sanitized, h) = tokio::task::spawn_blocking(move || {
            let mut h = scoped;
            let r = sanitize_prompt_result(&*blocks, &dataset, &mut h, &owner, result).map(
                |(r, stats)| {
                    let rel = released(&vault, &r);
                    (r, stats, rel)
                },
            );
            (r, h)
        })
        .await
        .map_err(|_| worker_failed())?;
        self.absorb_handles(h);
        match sanitized {
            Ok((r, stats, rel)) => {
                self.record(&stats, "prompts/get", t0);
                self.emit_released(&result_hop, &stats, rel);
                Ok(GetPromptResponse::Complete(complete!(r)))
            }
            Err(e) => Err(self.request_failed(&result_hop, e)),
        }
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        let _entered = self.enter()?;
        let t0 = Instant::now();
        self.inner.counters.calls.fetch_add(1, Ordering::Relaxed);
        let snap = self.snapshot();
        let exposed = request.uri;
        // Route first (no work for an unknown handle), then take a slot.
        let mut template = None;
        let (t, uri) = if let Some((i, original)) = snap.catalog.route_resource(&exposed) {
            (self.target(&snap, i)?, original.to_string())
        } else if let Some((i, route, values)) = snap.catalog.route_template(&exposed) {
            let t = self.target(&snap, i)?;
            let tc = t
                .contract
                .contract
                .as_ref()
                .ok()
                .and_then(|c| c.templates.get(&route.original).cloned())
                .ok_or_else(|| mcp_error("unknown_resource", Value::Null))?;
            template = Some((tc, route.clone(), values));
            (t, String::new())
        } else {
            // A handle a result minted (a link or an embedded resource).
            let resolved = self
                .inner
                .handles
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .resolve_resource(&exposed)
                .map(|(o, u)| (o.clone(), u.to_string()));
            let (owner, uri) =
                resolved.ok_or_else(|| mcp_error("unknown_resource", Value::Null))?;
            (self.target_by_owner(&snap, &owner)?, uri)
        };
        let args_hop = self.hop(&t, Direction::Arguments);
        let result_hop = self.hop(&t, Direction::Result);
        if let Some((_, _, values)) = &template {
            // `values` are still percent-encoded (RFC 6570), same as what
            // `rehydrate_template_params` decodes below; a raw scan would
            // miss an encoded value entirely (review I1).
            let decoded = values
                .iter()
                .map(|v| percent_decode(v))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| {
                    self.request_failed(&args_hop, ContentError::Unsupported("template_values"))
                })?;
            self.tripwire(&args_hop, decoded).await?;
        }
        let _slot = self.slot().await?;
        let uri = match template {
            None => uri,
            Some((tc, route, values)) => {
                let blocks = Arc::clone(&self.inner.blocks);
                let dataset = self.inner.dataset.clone();
                tokio::task::spawn_blocking(move || {
                    rehydrate_template_params(&*blocks, &dataset, &tc, &route, values)
                })
                .await
                .map_err(|_| worker_failed())?
                .map_err(|e| self.request_failed(&args_hop, e))?
            }
        };
        let result = match tokio::time::timeout(
            self.inner.config.call_timeout,
            t.peer.read_resource(ReadResourceRequestParams::new(uri)),
        )
        .await
        {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => return Err(self.upstream_failure(&t, e)),
            Err(_) => return Err(self.timed_out(&t)),
        };
        self.within_limits(&result_hop, self.inner.limits.check_read(&result))?;
        let blocks = Arc::clone(&self.inner.blocks);
        let dataset = self.inner.dataset.clone();
        let vault = self.inner.vault.clone();
        let sanitized = tokio::task::spawn_blocking(move || {
            sanitize_read_result(&*blocks, &dataset, &exposed, result).map(|(r, stats)| {
                let rel = released(&vault, &r);
                (r, stats, rel)
            })
        })
        .await
        .map_err(|_| worker_failed())?;
        match sanitized {
            Ok((r, stats, rel)) => {
                self.record(&stats, "resources/read", t0);
                self.emit_released(&result_hop, &stats, rel);
                Ok(ReadResourceResponse::Complete(with_cache_hints!(
                    complete!(r),
                    &context
                )))
            }
            Err(e) => Err(self.request_failed(&result_hop, e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VOCABULARY: &[&str] = &[
        "model_unavailable",
        "vault_unavailable",
        "privacy_block",
        "upstream_unavailable",
        "unsupported_content",
        "unresolved_token",
        "context_unavailable",
        "resource_limit",
        "upstream_error",
        "unknown_tool",
        "unknown_prompt",
        "unknown_resource",
    ];
    const DATA_KEYS: &[&str] = &[
        "class",
        "kinds",
        "checks",
        "unknown_tokens",
        "removed_markers",
        "limit",
        "code",
    ];

    fn assert_fixed(e: &ErrorData) {
        assert!(VOCABULARY.contains(&e.message.as_ref()), "{e:?}");
        if let Some(d) = &e.data {
            let o = d.as_object().expect("data is an object");
            assert!(o.keys().all(|k| DATA_KEYS.contains(&k.as_str())), "{e:?}");
        }
    }

    #[test]
    fn every_failure_maps_to_the_fixed_vocabulary() {
        let blocks = [
            BlocksError::DatasetNotFound,
            BlocksError::ModelUnavailable,
            BlocksError::VaultUnavailable,
            BlocksError::Unresolved {
                unknown: 1,
                removed: 0,
            },
            BlocksError::Unsupported("x"),
            BlocksError::Internal("x"),
        ];
        let kinds = vec![EntityKind::Person];
        let checks = vec![CheckLabel::Leak];
        let mut content = vec![
            ContentError::Blocked {
                kinds: kinds.clone(),
                checks: checks.clone(),
            },
            ContentError::Uncertain { kinds, checks },
            ContentError::Unsupported("binary"),
            ContentError::Unresolved {
                unknown: 1,
                removed: 2,
            },
        ];
        content.extend(blocks.iter().cloned().map(ContentError::Blocks));
        for e in &content {
            assert_fixed(&content_error(e));
        }
        for b in &blocks {
            assert_fixed(&discovery_error(&DiscoveryError::Blocks(b.clone())));
        }
        assert_fixed(&discovery_error(&DiscoveryError::Unsupported(
            "blocked_metadata",
        )));
        assert_fixed(&worker_failed());
        let upstream = upstream_error(&ErrorData::new(
            ErrorCode::INTERNAL_ERROR,
            "lookup failed for Zyxwuria Quolnath",
            Some(json!({ "query": "Zyxwuria Quolnath" })),
        ));
        assert_fixed(&upstream);
        assert!(!format!("{upstream:?}").contains("Zyxwuria"));
        assert_eq!(
            mcp_error("unknown_tool", Value::Null).code,
            ErrorCode::INVALID_PARAMS
        );
        assert_eq!(
            mcp_error("resource_limit", Value::Null).code,
            ErrorCode::INTERNAL_ERROR
        );
    }

    #[test]
    fn contract_debug_prints_no_schema() {
        let mut c = UpstreamContract::from_row("{}", Some("sha256:ab".into()));
        c.raw_tools.insert(
            "lookup".into(),
            Arc::new(
                json!({ "description": "Zyxwuria Quolnath" })
                    .as_object()
                    .cloned()
                    .unwrap(),
            ),
        );
        let d = format!("{c:?}");
        assert!(!d.contains("Zyxwuria") && !d.contains("sha256"), "{d}");
        assert_eq!(c.state, ContractState::None);
        assert_eq!(
            UpstreamContract::from_row("[]", None).state,
            ContractState::Invalid
        );
    }
}
