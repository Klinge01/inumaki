//! `inumakid canary-mcp --fixture FILE`: a minimal MCP server on stdio with
//! one tool, `lookup_record`, that returns the check's canary identity as
//! text and as `structuredContent` (M6 spec §8.1). It reads the identity
//! from a 0600 file the check writes, refuses a file others can read, and
//! writes nothing but MCP frames to stdout.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ErrorCode, ErrorData,
    Implementation, InitializeResult, ListToolsResult, PaginatedRequestParams, ServerCapabilities,
    ServerConfig, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{RoleServer, ServerHandler};
use serde_json::json;

use super::canary::Canary;

/// The one tool.
pub const TOOL: &str = "lookup_record";

struct CanaryServer {
    canary: Canary,
}

fn object(v: serde_json::Value) -> Arc<serde_json::Map<String, serde_json::Value>> {
    Arc::new(v.as_object().cloned().unwrap_or_default())
}

impl ServerHandler for CanaryServer {
    fn get_info(&self) -> ServerConfig {
        let mut caps = ServerCapabilities::default();
        caps.tools = Some(rmcp::model::ToolsCapability::default());
        InitializeResult::new(caps).with_server_info(Implementation::new(
            "inumaki-check",
            env!("CARGO_PKG_VERSION"),
        ))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let mut tool = Tool::new(
            TOOL,
            "look up the check record",
            object(json!({ "type": "object", "properties": {} })),
        );
        tool.output_schema = Some(object(json!({ "type": "object", "properties": {
            "name": { "type": "string" }, "iban": { "type": "string" }, "email": { "type": "string" } } })));
        Ok(ListToolsResult::with_all_items(vec![tool]))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        if request.name.as_ref() != TOOL {
            return Err(ErrorData::new(
                ErrorCode::INVALID_PARAMS,
                "unknown tool",
                None,
            ));
        }
        let c = &self.canary;
        let mut r = CallToolResult::success(vec![ContentBlock::text(format!(
            "Record: {}, IBAN {}, email {}",
            c.full_name(),
            c.iban,
            c.email
        ))]);
        r.structured_content =
            Some(json!({ "name": c.full_name(), "iban": c.iban, "email": c.email }));
        Ok(CallToolResponse::Complete(r))
    }
}

fn load(fixture: &Path) -> Option<Canary> {
    let meta = std::fs::metadata(fixture).ok()?;
    if meta.permissions().mode() & 0o077 != 0 {
        return None;
    }
    serde_json::from_slice(&std::fs::read(fixture).ok()?).ok()
}

/// Serve until stdin closes. Exit code 0 on a clean end, 2 when the fixture
/// is missing, unreadable, readable by others, or malformed.
pub fn run(fixture: &Path) -> u8 {
    let Some(canary) = load(fixture) else {
        return 2;
    };
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return 2;
    };
    rt.block_on(async move {
        match rmcp::serve_server(CanaryServer { canary }, rmcp::transport::stdio()).await {
            Ok(running) => {
                let _ = running.waiting().await;
                0
            }
            Err(_) => 2,
        }
    })
}
