//! `inumaki-mcp DATASET`: an MCP server on stdio that relays every request
//! to `inumakid`'s `/mcp/<dataset>` over the control socket (no bearer
//! token: the socket's file mode is the authorization), and relays the
//! daemon's list-changed notifications back. Sanitization happens in the
//! daemon; this binary never sees the models or the vault. Prints nothing
//! but clap's usage and a one-line startup failure; MCP goes through rmcp's
//! stdio transport.
#![allow(clippy::print_stderr)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, OnceLock};

use clap::Parser;
use inumaki_client::{default_data_dir, resolve_socket};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, ClientCapabilities, ClientConfig, ErrorCode,
    ErrorData, GetPromptRequestParams, GetPromptResponse, Implementation, InitializeRequestParams,
    InitializeResult, ListPromptsResult, ListResourceTemplatesResult, ListResourcesResult,
    ListToolsResult, PaginatedRequestParams, ReadResourceRequestParams, ReadResourceResponse,
    ServerConfig,
};
use rmcp::service::{NotificationContext, RequestContext};
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::{ClientHandler, Peer, RoleClient, RoleServer, ServerHandler, ServiceExt};

/// Relay stdio MCP to a local inumakid dataset.
#[derive(Parser)]
#[command(name = "inumaki-mcp", version, about)]
struct Args {
    /// Dataset id.
    dataset: String,
    /// Control socket (default: `[daemon] socket` in the data directory's `inumaki.toml`, else `inumakid.sock` there).
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Data directory (default: INUMAKI_DATA_DIR or the platform data dir).
    #[arg(long)]
    data_dir: Option<PathBuf>,
}

/// The daemon-side client: forwards the daemon's list-changed
/// notifications to the agent once the stdio side is up.
#[derive(Clone, Default)]
struct Forward {
    agent: Arc<OnceLock<Peer<RoleServer>>>,
}

impl ClientHandler for Forward {
    fn get_info(&self) -> ClientConfig {
        InitializeRequestParams::new(
            ClientCapabilities::default(),
            Implementation::new("inumaki-mcp", env!("CARGO_PKG_VERSION")),
        )
    }

    async fn on_tool_list_changed(&self, _context: NotificationContext<RoleClient>) {
        if let Some(p) = self.agent.get() {
            let _ = p.notify_tool_list_changed().await;
        }
    }

    async fn on_prompt_list_changed(&self, _context: NotificationContext<RoleClient>) {
        if let Some(p) = self.agent.get() {
            let _ = p.notify_prompt_list_changed().await;
        }
    }

    async fn on_resource_list_changed(&self, _context: NotificationContext<RoleClient>) {
        if let Some(p) = self.agent.get() {
            let _ = p.notify_resource_list_changed().await;
        }
    }
}

/// Forwards every request to the daemon's dataset server.
#[derive(Clone)]
struct Relay {
    peer: Peer<RoleClient>,
    info: InitializeResult,
}

/// The daemon's errors are already from the fixed vocabulary; a transport
/// failure becomes `upstream_unavailable`.
fn relay_err(e: rmcp::ServiceError) -> ErrorData {
    match e {
        rmcp::ServiceError::McpError(d) => d,
        _ => ErrorData::new(ErrorCode::INTERNAL_ERROR, "upstream_unavailable", None),
    }
}

impl ServerHandler for Relay {
    fn get_info(&self) -> ServerConfig {
        self.info.clone()
    }

    async fn list_tools(
        &self,
        _r: Option<PaginatedRequestParams>,
        _c: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::with_all_items(
            self.peer.list_all_tools().await.map_err(relay_err)?,
        ))
    }

    async fn call_tool(
        &self,
        r: CallToolRequestParams,
        _c: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        Ok(CallToolResponse::Complete(
            self.peer.call_tool(r).await.map_err(relay_err)?,
        ))
    }

    async fn list_prompts(
        &self,
        _r: Option<PaginatedRequestParams>,
        _c: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        Ok(ListPromptsResult::with_all_items(
            self.peer.list_all_prompts().await.map_err(relay_err)?,
        ))
    }

    async fn get_prompt(
        &self,
        r: GetPromptRequestParams,
        _c: RequestContext<RoleServer>,
    ) -> Result<GetPromptResponse, ErrorData> {
        Ok(GetPromptResponse::Complete(
            self.peer.get_prompt(r).await.map_err(relay_err)?,
        ))
    }

    async fn list_resources(
        &self,
        _r: Option<PaginatedRequestParams>,
        _c: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        Ok(ListResourcesResult::with_all_items(
            self.peer.list_all_resources().await.map_err(relay_err)?,
        ))
    }

    async fn list_resource_templates(
        &self,
        _r: Option<PaginatedRequestParams>,
        _c: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        Ok(ListResourceTemplatesResult::with_all_items(
            self.peer
                .list_all_resource_templates()
                .await
                .map_err(relay_err)?,
        ))
    }

    async fn read_resource(
        &self,
        r: ReadResourceRequestParams,
        _c: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        Ok(ReadResourceResponse::Complete(
            self.peer.read_resource(r).await.map_err(relay_err)?,
        ))
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let a = Args::parse();
    let data_dir = a.data_dir.clone().unwrap_or_else(default_data_dir);
    let socket = match resolve_socket(a.socket.as_deref(), &data_dir) {
        Ok(s) => s,
        Err(e) => {
            // Names the config file; never its content.
            eprintln!("inumaki-mcp: {e}");
            return ExitCode::from(2);
        }
    };
    let cfg =
        StreamableHttpClientTransportConfig::with_uri(format!("http://inumakid/mcp/{}", a.dataset));
    let transport =
        StreamableHttpClientTransport::from_unix_socket_with_config(&socket.to_string_lossy(), cfg);
    let forward = Forward::default();
    let running = match forward.clone().serve(transport).await {
        Ok(r) => r,
        Err(e) => {
            // The dataset id is local configuration the user typed; the
            // socket path is theirs too. Nothing else is printed.
            let why = if e.is_authorization_required() {
                "unauthorized"
            } else {
                "daemon not running or dataset unknown (run `inumaki daemon`, `inumaki dataset list`)"
            };
            eprintln!(
                "inumaki-mcp: cannot reach dataset {} at {}: {why}",
                a.dataset,
                socket.display()
            );
            return ExitCode::from(2);
        }
    };
    let info = running.peer().peer_info().map(|i| {
        let mut r = InitializeResult::new(i.capabilities.clone());
        if let Some(si) = &i.server_info {
            r = r.with_server_info(si.clone());
        }
        r
    });
    let Some(info) = info else {
        eprintln!("inumaki-mcp: no server info from the daemon");
        return ExitCode::from(2);
    };
    let relay = Relay {
        peer: running.peer().clone(),
        info,
    };
    match rmcp::serve_server(relay, rmcp::transport::stdio()).await {
        Ok(server) => {
            let _ = forward.agent.set(server.peer().clone());
            let _ = server.waiting().await;
            let _ = running.cancel().await;
            ExitCode::SUCCESS
        }
        Err(_) => ExitCode::from(2),
    }
}
