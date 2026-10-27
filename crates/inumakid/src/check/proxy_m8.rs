//! [`ProxyCheckRoutes`] for M8's `CheckRoutes` (M6 spec §9.6, M8 spec
//! §12.2). The check routes live on the proxy listener under
//! `/check/<id>/<upstream>/…`; `server.rs` registers one [`M8Routes`] with
//! the check slot when the proxy is bound.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use inumaki_proxy::{CheckId, CheckRoutes, Script, Step, ToolCall};

use super::proxy::{ProxyCheckRoutes, RecordedBody, ScriptStep};

/// M8's routes plus the proxy's bound address.
pub struct M8Routes {
    routes: Arc<CheckRoutes>,
    listen: SocketAddr,
}

impl M8Routes {
    /// Wrap M8's instance; `listen` is the proxy's bound address.
    pub fn new(routes: Arc<CheckRoutes>, listen: SocketAddr) -> Self {
        M8Routes { routes, listen }
    }
}

/// The upstreams whose check routes M8 serves (Codex streams through its own).
const UPSTREAMS: [&str; 3] = ["anthropic", "openai", "openai-codex"];

impl ProxyCheckRoutes for M8Routes {
    fn register(
        &self,
        id: &str,
        dataset: &str,
        script: Vec<ScriptStep>,
        ttl: Duration,
    ) -> Vec<(String, String)> {
        let Some(cid) = CheckId::from_hex(id) else {
            return Vec::new();
        };
        let steps = script
            .into_iter()
            .map(|s| match s {
                ScriptStep::CallTools(calls) => Step::CallTools(
                    calls
                        .into_iter()
                        .map(|(name_suffix, arguments)| ToolCall {
                            name_suffix,
                            arguments,
                        })
                        .collect(),
                ),
                ScriptStep::EchoToolResults => Step::EchoToolResults,
                ScriptStep::EchoUserText => Step::EchoUserText,
            })
            .collect();
        self.routes.register(cid, dataset, Script(steps), ttl);
        UPSTREAMS
            .iter()
            .map(|u| {
                (
                    u.to_string(),
                    format!("http://{}/check/{id}/{u}", self.listen),
                )
            })
            .collect()
    }

    fn recorded(&self, id: &str) -> Vec<RecordedBody> {
        let Some(cid) = CheckId::from_hex(id) else {
            return Vec::new();
        };
        self.routes
            .recorded(&cid)
            .into_iter()
            .map(|r| RecordedBody {
                upstream: r.upstream.to_string(),
                body: r.body,
            })
            .collect()
    }

    fn remove(&self, id: &str) {
        if let Some(cid) = CheckId::from_hex(id) {
            self.routes.remove(&cid);
        }
    }

    /// Bodies M8 did not keep for `id`: refused over its caps, or discarded
    /// by a re-registration or an expiry (M8 spec §12.2). The trait's
    /// default is 0, so without this override the check could not fail closed.
    fn dropped(&self, id: &str) -> u64 {
        CheckId::from_hex(id).map_or(0, |c| self.routes.dropped(&c))
    }
}
