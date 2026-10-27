//! The gateway direct check's MCP client: connect to the gateway over TCP
//! with the check's token, list the tools, call the one whose name ends in
//! `lookup_record`, and return the tool result as JSON text (what a model
//! would receive). A trait so a test can substitute a leaking gateway.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use rmcp::ServiceExt;
use rmcp::model::{
    CallToolRequestParams, ClientCapabilities, Implementation, InitializeRequestParams,
};
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;

use super::canary_mcp::TOOL;

/// The real probe's overall limit; a probe that returns nothing after at
/// least this long is reported as `timeout`.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(30);

/// The tool result as JSON text, or `None` when the call did not complete.
pub type ProbeFuture = Pin<Box<dyn Future<Output = Option<String>> + Send>>;

/// Calls `lookup_record` through the gateway.
pub trait GatewayProbe: Send + Sync {
    /// Call the tool at `url` with bearer `token`.
    fn lookup(&self, url: String, token: String) -> ProbeFuture;
}

/// The real probe: rmcp's streamable-HTTP client, 30 s overall.
pub struct RmcpProbe;

impl GatewayProbe for RmcpProbe {
    fn lookup(&self, url: String, token: String) -> ProbeFuture {
        Box::pin(async move {
            tokio::time::timeout(PROBE_TIMEOUT, call(url, token))
                .await
                .ok()
                .flatten()
        })
    }
}

async fn call(url: String, token: String) -> Option<String> {
    let mut cfg = StreamableHttpClientTransportConfig::with_uri(url);
    cfg.auth_header = Some(token);
    let client = InitializeRequestParams::new(
        ClientCapabilities::default(),
        Implementation::new("inumaki-check", env!("CARGO_PKG_VERSION")),
    )
    .serve(StreamableHttpClientTransport::from_config(cfg))
    .await
    .ok()?;
    let tools = client.peer().list_all_tools().await.ok()?;
    let name = tools.iter().find(|t| t.name.ends_with(TOOL))?.name.clone();
    let result = client
        .peer()
        .call_tool(CallToolRequestParams::new(name))
        .await
        .ok()?;
    let _ = client.cancel().await;
    serde_json::to_string(&result).ok()
}
