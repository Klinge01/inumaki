//! The gateway: one handler and one Streamable HTTP service per dataset,
//! rebuilt when a dataset's rows change, all stopped at shutdown.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use inumaki_vault::{DatasetKind, UpstreamKind, Vault, VaultError};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use tokio::sync::{RwLock, mpsc};
use tokio_util::sync::CancellationToken;

use crate::activity::ActivitySink;
use crate::config::GatewayConfig;
use crate::handler::{DatasetHandler, UpstreamContract};
use crate::service::Blocks;
use crate::status::GatewayStatus;
use crate::upstream::{
    BuiltinUpstreams, ResolvedUpstream, Supervision, UpstreamEvent, UpstreamHandle,
};

/// Why a dataset could not be (re)loaded. Classes only.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GatewayError {
    /// The vault failed.
    #[error("vault unavailable")]
    Vault,
    /// No such dataset.
    #[error("dataset not found")]
    DatasetNotFound,
}

impl From<VaultError> for GatewayError {
    fn from(e: VaultError) -> Self {
        match e {
            VaultError::DatasetNotFound(_) => GatewayError::DatasetNotFound,
            _ => GatewayError::Vault,
        }
    }
}

/// The rmcp service type for one dataset.
pub type DatasetService = StreamableHttpService<DatasetHandler, LocalSessionManager>;

/// Host names the Streamable HTTP services accept (the shim sends `inumakid`).
const ALLOWED_HOSTS: [&str; 4] = ["localhost", "127.0.0.1", "::1", "inumakid"];

struct DatasetGateway {
    handler: DatasetHandler,
    service: DatasetService,
    /// Ends every rmcp session of this dataset.
    cancel: CancellationToken,
    events_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

/// How long a stopping dataset waits for its in-flight requests.
const DRAIN_GRACE: Duration = Duration::from_secs(5);
/// Longest wait for the activity queue to drain at shutdown.
const ACTIVITY_FLUSH: Duration = Duration::from_secs(2);
/// Time for the last error responses to reach their streams before the
/// sessions end.
const SETTLE: Duration = Duration::from_millis(100);

impl DatasetGateway {
    /// Refuse new requests, stop the upstreams (an in-flight call fails),
    /// let in-flight requests answer, then end every session.
    async fn stop(&self, grace: Duration) {
        let t = self
            .events_task
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(t) = t {
            t.abort();
        }
        self.handler.close();
        for u in self.handler.upstream_handles() {
            u.stop().await;
        }
        self.handler.drain(grace).await;
        if !self.cancel.is_cancelled() {
            tokio::time::sleep(SETTLE).await;
            self.cancel.cancel();
        }
        self.handler.set_upstreams(Vec::new());
    }
}

struct Inner {
    blocks: Arc<dyn Blocks>,
    vault: Vault,
    builtin: Arc<dyn BuiltinUpstreams>,
    config: GatewayConfig,
    datasets: RwLock<HashMap<String, Arc<DatasetGateway>>>,
    /// One load or removal at a time, so rows read later never lose to rows
    /// read earlier.
    reload_lock: tokio::sync::Mutex<()>,
    /// The one activity writer every dataset handler shares.
    activity: ActivitySink,
}

/// The gateway. Cheap to clone.
#[derive(Clone)]
pub struct Gateway {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Gateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gateway")
            .field("listen", &self.inner.config.listen)
            .finish()
    }
}

/// Merge a JSON-object secret into `into` (secret values win). Logs the
/// opaque dataset label only: a secret's name embeds the dataset slug.
fn merge_secret(vault: &Vault, label: &str, name: &str, into: &mut BTreeMap<String, String>) {
    match vault.get_secret(name) {
        Ok(Some(bytes)) => match serde_json::from_slice::<BTreeMap<String, String>>(&bytes) {
            Ok(map) => into.extend(map),
            Err(_) => {
                tracing::warn!(dataset = %label, "an upstream secret is not a JSON object of strings; ignored")
            }
        },
        Ok(None) => {
            tracing::warn!(dataset = %label, "a secret named by an upstream does not exist")
        }
        Err(e) => {
            tracing::warn!(dataset = %label, error = %e, "an upstream secret could not be read")
        }
    }
}

/// An enabled upstream row with its secrets merged in, and its contract.
struct LoadedRow {
    resolved: ResolvedUpstream,
    contract: UpstreamContract,
}

/// Read a dataset's enabled upstream rows and their secrets. Blocking.
fn load_rows(vault: &Vault, id: &str, label: &str) -> Result<Vec<LoadedRow>, GatewayError> {
    let dataset = vault.dataset(id)?;
    let mut out = Vec::new();
    for row in vault.upstreams(id)?.into_iter().filter(|u| u.spec.enabled) {
        if row.spec.kind == UpstreamKind::Mail && dataset.kind != DatasetKind::Mailbox {
            tracing::warn!(dataset = %label, upstream = %row.spec.name, "mail upstream on a non-mailbox dataset; skipped");
            continue;
        }
        let mut env = row.spec.env.clone();
        let mut headers = row.spec.headers.clone();
        if let Some(s) = &row.spec.env_secret {
            merge_secret(vault, label, s, &mut env);
        }
        if let Some(s) = &row.spec.headers_secret {
            merge_secret(vault, label, s, &mut headers);
        }
        let contract = UpstreamContract::from_row(
            &row.spec.content_policy,
            row.spec.schema_fingerprint.clone(),
        );
        out.push(LoadedRow {
            resolved: ResolvedUpstream {
                name: row.spec.name,
                kind: row.spec.kind,
                command: row.spec.command,
                args: row.spec.args,
                cwd: row.spec.cwd,
                url: row.spec.url,
                env,
                headers,
            },
            contract,
        });
    }
    Ok(out)
}

impl Gateway {
    /// A gateway over `vault`, reaching the engine through `blocks` and
    /// built-in upstreams through `builtin`. Installs the process-wide
    /// rustls provider HTTP upstreams need and starts the activity writer.
    pub fn new(
        blocks: Arc<dyn Blocks>,
        vault: Vault,
        builtin: Arc<dyn BuiltinUpstreams>,
        config: GatewayConfig,
    ) -> Gateway {
        crate::ensure_crypto_provider();
        Gateway {
            inner: Arc::new(Inner {
                blocks,
                activity: ActivitySink::spawn(vault.clone(), config.journal),
                vault,
                builtin,
                config,
                datasets: RwLock::new(HashMap::new()),
                reload_lock: tokio::sync::Mutex::new(()),
            }),
        }
    }

    /// The settings.
    pub fn config(&self) -> &GatewayConfig {
        &self.inner.config
    }

    /// The one activity writer (a clone), so other front doors in the
    /// daemon (the model-API proxy, M8 spec §3) append to the same chain.
    pub fn activity(&self) -> ActivitySink {
        self.inner.activity.clone()
    }

    /// Load every dataset in the vault; returns how many loaded.
    pub async fn start(&self) -> usize {
        let vault = self.inner.vault.clone();
        let ids: Vec<String> = match tokio::task::spawn_blocking(move || vault.datasets()).await {
            Ok(Ok(d)) => d.into_iter().map(|d| d.id).collect(),
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "gateway could not list datasets");
                return 0;
            }
            Err(_) => return 0,
        };
        let mut n = 0;
        for id in ids {
            match self.reload_dataset(&id).await {
                Ok(()) => n += 1,
                Err(e) => {
                    tracing::warn!(dataset = %self.inner.vault.opaque_id(&id), error = %e, "gateway could not load dataset")
                }
            }
        }
        n
    }

    /// Build (or rebuild) the handler, upstreams, and service for `id` from
    /// the vault's current rows. The previous one, if any, is stopped: its
    /// sessions end and its upstreams are stopped.
    pub async fn reload_dataset(&self, id: &str) -> Result<(), GatewayError> {
        let _one = self.inner.reload_lock.lock().await;
        let label = self.inner.vault.opaque_id(id);
        let vault = self.inner.vault.clone();
        let (id_owned, label_owned) = (id.to_string(), label.clone());
        let rows = tokio::task::spawn_blocking(move || load_rows(&vault, &id_owned, &label_owned))
            .await
            .map_err(|_| GatewayError::Vault)??;
        let handler = DatasetHandler::new(
            id,
            &label,
            self.inner.vault.clone(),
            Arc::clone(&self.inner.blocks),
            self.inner.config.clone(),
            self.inner.activity.clone(),
        );
        let (tx, mut rx) = mpsc::unbounded_channel::<UpstreamEvent>();
        let upstreams: Vec<(Arc<UpstreamHandle>, UpstreamContract)> = rows
            .into_iter()
            .map(|r| {
                let h = UpstreamHandle::spawn(
                    label.clone(),
                    id.to_string(),
                    r.resolved,
                    tx.clone(),
                    Arc::clone(&self.inner.builtin),
                    Supervision::from_config(&self.inner.config),
                );
                (h, r.contract)
            })
            .collect();
        drop(tx);
        handler.set_upstreams(upstreams);
        let cancel = CancellationToken::new();
        let h = handler.clone();
        let events_task = tokio::spawn(async move {
            while let Some(ev) = rx.recv().await {
                // Events that queued up meanwhile need no rebuild of their own.
                let mut exited = matches!(ev, UpstreamEvent::Exited { .. });
                while let Ok(more) = rx.try_recv() {
                    exited |= matches!(more, UpstreamEvent::Exited { .. });
                }
                tracing::debug!(exited, "upstream event");
                h.rebuild().await;
            }
        });
        let http_config = StreamableHttpServerConfig::default()
            .with_allowed_hosts(ALLOWED_HOSTS)
            .with_cancellation_token(cancel.clone());
        let factory_handler = handler.clone();
        let service = StreamableHttpService::new(
            move || Ok(factory_handler.clone()),
            Arc::new(LocalSessionManager::default()),
            http_config,
        );
        let dg = Arc::new(DatasetGateway {
            handler,
            service,
            cancel,
            events_task: Mutex::new(Some(events_task)),
        });
        let old = self.inner.datasets.write().await.insert(id.to_string(), dg);
        if let Some(old) = old {
            old.stop(DRAIN_GRACE).await;
        }
        tracing::info!(dataset = %label, "gateway dataset loaded");
        Ok(())
    }

    /// Stop and forget a dataset (deleted): its sessions end, in-flight
    /// calls fail, and later requests find no service.
    pub async fn remove_dataset(&self, id: &str) {
        let _one = self.inner.reload_lock.lock().await;
        let old = self.inner.datasets.write().await.remove(id);
        if let Some(old) = old {
            old.stop(DRAIN_GRACE).await;
            tracing::info!(dataset = %self.inner.vault.opaque_id(id), "gateway dataset removed");
        }
    }

    /// The HTTP service for a dataset, when it has one.
    pub async fn service(&self, id: &str) -> Option<DatasetService> {
        self.inner
            .datasets
            .read()
            .await
            .get(id)
            .map(|d| d.service.clone())
    }

    /// The handler for a dataset, when it has one.
    pub async fn handler(&self, id: &str) -> Option<DatasetHandler> {
        self.inner
            .datasets
            .read()
            .await
            .get(id)
            .map(|d| d.handler.clone())
    }

    /// The status block. `listen` and `tokens` come from the daemon.
    pub async fn status(&self, listen: String, tokens: usize) -> GatewayStatus {
        let map = self.inner.datasets.read().await;
        let mut datasets: Vec<_> = map.values().map(|d| d.handler.status()).collect();
        datasets.sort_by(|a, b| a.id.cmp(&b.id));
        let mut uncertain_checks: BTreeMap<String, u64> = BTreeMap::new();
        for d in map.values() {
            for (k, v) in d.handler.uncertain_checks() {
                *uncertain_checks.entry(k).or_insert(0) += v;
            }
        }
        GatewayStatus {
            listen,
            datasets,
            tokens,
            uncertain_checks,
            qualification: "unqualified".into(),
            activity_dropped: self.inner.activity.dropped(),
            journal_dropped: self.inner.activity.journal_dropped(),
        }
    }

    /// Stop every dataset, each the way a removed one stops: new requests
    /// refused, upstreams stopped, in-flight requests given up to 5 s to
    /// answer, then sessions ended. Then the activity queue gets a bounded
    /// time to drain; what is left is counted in `activity_dropped`.
    pub async fn shutdown(&self) {
        self.shutdown_within(DRAIN_GRACE).await;
    }

    /// [`Gateway::shutdown`] with in-flight requests given `grace` (all
    /// datasets drain together). The daemon calls it as soon as a shutdown
    /// is requested, with a grace inside its own HTTP drain period, so open
    /// MCP streams end before that period runs out.
    pub async fn shutdown_within(&self, grace: Duration) {
        let _one = self.inner.reload_lock.lock().await;
        let all: Vec<Arc<DatasetGateway>> = self
            .inner
            .datasets
            .write()
            .await
            .drain()
            .map(|(_, d)| d)
            .collect();
        if !all.is_empty() {
            futures::future::join_all(all.iter().map(|d| d.stop(grace))).await;
            tracing::info!("gateway stopped");
        }
        // After the handlers stopped: no call emits a record any more.
        self.inner.activity.flush(grace.min(ACTIVITY_FLUSH)).await;
    }
}
