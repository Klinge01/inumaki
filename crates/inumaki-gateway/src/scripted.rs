//! A scripted MCP server for the gateway tests (M4 spec §13): tools that
//! echo arguments, return a canary identity in text and structured content
//! (with a numeric customer id), take a numeric identifier argument, return
//! dynamic keys, binary content, an argument-echoing error, hang, crash,
//! read the environment, link an unlisted resource, and change their own
//! tool list (add a tool, or change a reviewed tool's schema or prose). Also serves over
//! HTTP and, through `inumakid`'s `inumaki-test-upstream` binary, as a
//! child process. Built only with the `test-fixtures` feature; never part
//! of a user-facing binary.

use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ErrorCode, ErrorData,
    GetPromptRequestParams, GetPromptResponse, GetPromptResult, Implementation, InitializeResult,
    ListPromptsResult, ListResourceTemplatesResult, ListResourcesResult, ListToolsResult,
    PaginatedRequestParams, Prompt, PromptArgument, PromptMessage, ReadResourceRequestParams,
    ReadResourceResponse, ReadResourceResult, Resource, ResourceContents, ResourceTemplate, Role,
    ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{RoleServer, ServerHandler};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

/// The canary person every test looks for.
pub const IDENTITY: &str = "Zyxwuria Quolnath";
/// The canary IBAN.
pub const IBAN: &str = "AT61 1904 3002 3457 3201";
/// The numeric customer id the `record` tool returns and `lookup` expects.
pub const CUSTOMER_ID: u64 = 8_439_271;

/// The scripted server. Cheap to clone; clones share the tool-list toggle.
#[derive(Clone)]
pub struct ScriptedUpstream {
    name: String,
    identity: String,
    log: Option<PathBuf>,
    allow_crash: bool,
    iban_description: bool,
    extra_tool: Arc<AtomicBool>,
    /// `lookup` gains an input property (a reviewed schema changes).
    lookup_schema_v2: Arc<AtomicBool>,
    /// `lookup` gets another description (prose, not schema).
    lookup_description_v2: Arc<AtomicBool>,
    stop: Arc<std::sync::Mutex<Option<CancellationToken>>>,
}

impl std::fmt::Debug for ScriptedUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScriptedUpstream")
            .field("name", &self.name)
            .field("has_log", &self.log.is_some())
            .finish()
    }
}

impl Default for ScriptedUpstream {
    fn default() -> Self {
        ScriptedUpstream {
            name: "scripted".into(),
            identity: IDENTITY.into(),
            log: None,
            allow_crash: false,
            iban_description: false,
            extra_tool: Arc::new(AtomicBool::new(false)),
            lookup_schema_v2: Arc::new(AtomicBool::new(false)),
            lookup_description_v2: Arc::new(AtomicBool::new(false)),
            stop: Arc::new(std::sync::Mutex::new(None)),
        }
    }
}

impl ScriptedUpstream {
    /// Settings from `INUMAKI_TEST_UPSTREAM_NAME`, `_IDENTITY`, `_LOG`,
    /// `_ALLOW_CRASH=1`, `_IBAN_DESC=1` (the child-process binary).
    pub fn from_env() -> Self {
        let mut s = Self::default();
        if let Ok(n) = std::env::var("INUMAKI_TEST_UPSTREAM_NAME") {
            s.name = n;
        }
        if let Ok(i) = std::env::var("INUMAKI_TEST_UPSTREAM_IDENTITY") {
            s.identity = i;
        }
        if let Ok(l) = std::env::var("INUMAKI_TEST_UPSTREAM_LOG") {
            s.log = Some(PathBuf::from(l));
        }
        s.allow_crash = std::env::var("INUMAKI_TEST_UPSTREAM_ALLOW_CRASH").as_deref() == Ok("1");
        s.iban_description = std::env::var("INUMAKI_TEST_UPSTREAM_IBAN_DESC").as_deref() == Ok("1");
        s
    }

    /// Server name reported in `initialize`.
    #[must_use]
    pub fn with_name(mut self, name: &str) -> Self {
        self.name = name.into();
        self
    }

    /// The identity the tools embed.
    #[must_use]
    pub fn with_identity(mut self, identity: &str) -> Self {
        self.identity = identity.into();
        self
    }

    /// Append every received request as a JSON line to this file.
    #[must_use]
    pub fn with_log(mut self, path: PathBuf) -> Self {
        self.log = Some(path);
        self
    }

    /// The token `crash` cancels when the server runs in-process.
    #[must_use]
    pub fn with_stop(self, ct: CancellationToken) -> Self {
        *self
            .stop
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(ct);
        self
    }

    /// Add a tool whose description carries the canary IBAN (a profile that
    /// blocks IBANs then fails the whole listing).
    #[must_use]
    pub fn with_iban_description(mut self, on: bool) -> Self {
        self.iban_description = on;
        self
    }

    fn log_call(&self, what: &str, args: &Value) {
        if let Some(p) = &self.log {
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
            {
                let _ = writeln!(f, "{}", json!({ "what": what, "args": args }));
            }
        }
    }

    fn schema(props: Value, required: &[&str]) -> serde_json::Map<String, Value> {
        json!({ "type": "object", "properties": props, "required": required })
            .as_object()
            .cloned()
            .unwrap_or_default()
    }

    /// The tool list `tools/list` answers with (tests compare contracts
    /// against it).
    pub fn tools(&self) -> Vec<Tool> {
        let s = Self::schema;
        let mut record = Tool::new(
            "record",
            format!("the customer record of {}", self.identity),
            s(json!({}), &[]),
        );
        record.output_schema = Some(Arc::new(
            json!({ "type": "object", "properties": { "customer": { "type": "object", "properties": {
                "id": { "type": "integer", "description": "customer number" },
                "name": { "type": "string" }, "iban": { "type": "string" }, "count": { "type": "integer" },
                "tags": { "type": "array", "items": { "type": "string" } }, "active": { "type": "boolean" } } } } })
            .as_object().cloned().unwrap_or_default(),
        ));
        let mut v = vec![
            Tool::new(
                "echo",
                "echo the query",
                s(
                    json!({ "query": { "type": "string", "description": "free text" } }),
                    &["query"],
                ),
            ),
            record,
            Tool::new(
                "lookup",
                if self.lookup_description_v2.load(Ordering::SeqCst) {
                    "look a customer up by their number"
                } else {
                    "look a customer up by number"
                },
                if self.lookup_schema_v2.load(Ordering::SeqCst) {
                    s(
                        json!({ "customer_id": { "type": "integer" }, "note": { "type": "string" }, "region": { "type": "string" } }),
                        &["customer_id"],
                    )
                } else {
                    s(
                        json!({ "customer_id": { "type": "integer" }, "note": { "type": "string" } }),
                        &["customer_id"],
                    )
                },
            ),
            Tool::new(
                "dynamic",
                "counts keyed by customer name",
                s(json!({}), &[]),
            ),
            Tool::new("binary", "an image plus a caption", s(json!({}), &[])),
            Tool::new(
                "fail",
                "an error that echoes its argument",
                s(json!({ "query": { "type": "string" } }), &["query"]),
            ),
            Tool::new(
                "slow",
                "sleep ms then answer",
                s(json!({ "ms": { "type": "integer" } }), &["ms"]),
            ),
            Tool::new("crash", "end the server", s(json!({}), &[])),
            Tool::new(
                "env",
                "the value of an environment variable",
                s(json!({ "name": { "type": "string" } }), &["name"]),
            ),
            Tool::new(
                "headers",
                "the value of a request header (HTTP only)",
                s(json!({ "name": { "type": "string" } }), &["name"]),
            ),
            Tool::new(
                "change_tools",
                "add the extra tool (default), or change lookup's schema or description, and notify",
                s(
                    json!({ "what": { "type": "string", "enum": ["extra", "lookup_schema", "lookup_description"] } }),
                    &[],
                ),
            ),
            Tool::new(
                "linked",
                "a text plus a link to a resource that is not listed",
                s(json!({}), &[]),
            ),
            Tool::new(
                "long",
                "a text of about `bytes` bytes naming the identity",
                s(json!({ "bytes": { "type": "integer" } }), &["bytes"]),
            ),
            Tool::new(
                "nested",
                "echo nested arguments as structured content",
                s(
                    json!({ "filter": { "type": "object", "properties": { "names": { "type": "array", "items": { "type": "string" } }, "n": { "type": "integer" } } } }),
                    &[],
                ),
            ),
            Tool::new(
                "qwxzvk_tool",
                "a tool whose name is a canary for log tests",
                s(json!({}), &[]),
            ),
        ];
        if self.iban_description {
            v.push(Tool::new(
                "iban_desc",
                format!("account {IBAN}"),
                s(json!({}), &[]),
            ));
        }
        if self.extra_tool.load(Ordering::SeqCst) {
            v.push(Tool::new(
                "extra",
                "appears after change_tools",
                s(json!({}), &[]),
            ));
        }
        v
    }

    /// The prompt list `prompts/list` answers with.
    pub fn prompts(&self) -> Vec<Prompt> {
        vec![Prompt::new(
            "greet",
            Some("greet someone"),
            Some(vec![PromptArgument::new("name")]),
        )]
    }

    /// The template list `resources/templates/list` answers with.
    pub fn templates(&self) -> Vec<ResourceTemplate> {
        vec![ResourceTemplate::new("mem://note/{id}", "note")]
    }

    fn str_arg(args: &Option<rmcp::model::JsonObject>, key: &str) -> String {
        args.as_ref()
            .and_then(|a| a.get(key))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    }

    fn num_arg(args: &Option<rmcp::model::JsonObject>, key: &str) -> u64 {
        args.as_ref()
            .and_then(|a| a.get(key))
            .and_then(Value::as_u64)
            .unwrap_or(0)
    }
}

impl ServerHandler for ScriptedUpstream {
    fn get_info(&self) -> ServerConfig {
        let mut caps = ServerCapabilities::default();
        let mut tools = rmcp::model::ToolsCapability::default();
        tools.list_changed = Some(true);
        caps.tools = Some(tools);
        caps.prompts = Some(rmcp::model::PromptsCapability::default());
        caps.resources = Some(rmcp::model::ResourcesCapability::default());
        InitializeResult::new(caps)
            .with_server_info(Implementation::new(self.name.clone(), "0.0.0"))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::with_all_items(self.tools()))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let args_value = request
            .arguments
            .as_ref()
            .map(|a| Value::Object(a.clone()))
            .unwrap_or(Value::Null);
        self.log_call(&request.name, &args_value);
        let r = match request.name.as_ref() {
            "echo" => {
                let q = Self::str_arg(&request.arguments, "query");
                let mut r = CallToolResult::success(vec![ContentBlock::text(format!("echo: {q}"))]);
                r.structured_content = Some(json!({ "received": q }));
                r
            }
            "record" => {
                let mut r = CallToolResult::success(vec![ContentBlock::text(format!(
                    "Kunde: {} IBAN {IBAN}",
                    self.identity
                ))]);
                r.structured_content = Some(
                    json!({ "customer": { "id": CUSTOMER_ID, "name": self.identity, "iban": IBAN, "count": 3, "tags": ["tier-2", self.identity], "active": true } }),
                );
                r
            }
            "lookup" => {
                let id = request
                    .arguments
                    .as_ref()
                    .and_then(|a| a.get("customer_id"))
                    .cloned()
                    .unwrap_or(Value::Null);
                let mut r = CallToolResult::success(vec![ContentBlock::text(format!(
                    "customer {id} is {}",
                    self.identity
                ))]);
                r.structured_content =
                    Some(json!({ "customer": { "id": id, "name": self.identity } }));
                r
            }
            "dynamic" => {
                let mut r = CallToolResult::success(vec![ContentBlock::text("counts")]);
                r.structured_content =
                    Some(json!({ "by_name": { self.identity.clone(): 3, "Muster GmbH": 1 } }));
                r
            }
            "binary" => CallToolResult::success(vec![
                ContentBlock::image("iVBORw0KGgo=", "image/png"),
                ContentBlock::text(format!("caption {}", self.identity)),
            ]),
            "fail" => {
                let q = Self::str_arg(&request.arguments, "query");
                return Err(ErrorData::new(
                    ErrorCode::INTERNAL_ERROR,
                    format!("lookup failed for {q}"),
                    Some(json!({ "query": q, "identity": self.identity })),
                ));
            }
            "slow" => {
                tokio::time::sleep(std::time::Duration::from_millis(Self::num_arg(
                    &request.arguments,
                    "ms",
                )))
                .await;
                CallToolResult::success(vec![ContentBlock::text("done")])
            }
            "crash" => {
                if self.allow_crash {
                    std::process::exit(3);
                }
                let ct = self
                    .stop
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone();
                if let Some(ct) = ct {
                    ct.cancel();
                }
                CallToolResult::success(vec![ContentBlock::text("ending")])
            }
            "env" => {
                let n = Self::str_arg(&request.arguments, "name");
                CallToolResult::success(vec![ContentBlock::text(
                    std::env::var(n).unwrap_or_else(|_| "<unset>".into()),
                )])
            }
            "headers" => {
                let n = Self::str_arg(&request.arguments, "name");
                let value = context
                    .extensions
                    .get::<http::request::Parts>()
                    .and_then(|p| p.headers.get(n.as_str()))
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("<none>")
                    .to_string();
                CallToolResult::success(vec![ContentBlock::text(value)])
            }
            "change_tools" => {
                let flag = match Self::str_arg(&request.arguments, "what").as_str() {
                    "lookup_schema" => &self.lookup_schema_v2,
                    "lookup_description" => &self.lookup_description_v2,
                    _ => &self.extra_tool,
                };
                flag.store(true, Ordering::SeqCst);
                let _ = context.peer.notify_tool_list_changed().await;
                CallToolResult::success(vec![ContentBlock::text("changed")])
            }
            "long" => {
                let bytes = Self::num_arg(&request.arguments, "bytes") as usize;
                let unit = format!(
                    "Sehr geehrte Frau {}, Ihre Rechnung RE-2026-0042 zur Neubaugasse 22, 1070 Wien ist offen. ",
                    self.identity
                );
                let text: String = unit
                    .repeat(bytes / unit.len() + 1)
                    .chars()
                    .take(bytes)
                    .collect();
                CallToolResult::success(vec![ContentBlock::text(text)])
            }
            "nested" => {
                let mut r = CallToolResult::success(vec![ContentBlock::text("nested")]);
                r.structured_content = Some(json!({ "echo": args_value }));
                r
            }
            "linked" => CallToolResult::success(vec![
                ContentBlock::text("see the note"),
                ContentBlock::resource_link(Resource::new(
                    format!("mem://note/{}", self.identity),
                    "note",
                )),
            ]),
            "qwxzvk_tool" | "iban_desc" => CallToolResult::success(vec![ContentBlock::text("ok")]),
            "extra" if self.extra_tool.load(Ordering::SeqCst) => {
                CallToolResult::success(vec![ContentBlock::text("extra")])
            }
            _ => {
                return Err(ErrorData::new(
                    ErrorCode::METHOD_NOT_FOUND,
                    "unknown tool",
                    Some(json!({ "tool": request.name })),
                ));
            }
        };
        Ok(CallToolResponse::Complete(r))
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        Ok(ListPromptsResult::with_all_items(self.prompts()))
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResponse, ErrorData> {
        if request.name != "greet" {
            return Err(ErrorData::invalid_params("unknown prompt", None));
        }
        let name = Self::str_arg(&request.arguments, "name");
        self.log_call("prompts/get", &json!({ "name": name }));
        Ok(GetPromptResponse::Complete(GetPromptResult::new(vec![
            PromptMessage::new_text(Role::User, format!("Hello {name}, from {}", self.identity)),
        ])))
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        Ok(ListResourcesResult::with_all_items(vec![
            Resource::new(format!("mem://customer/{}", self.identity), "customer"),
            Resource::new("mem://logo", "logo"),
        ]))
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        Ok(ListResourceTemplatesResult::with_all_items(
            self.templates(),
        ))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        self.log_call("resources/read", &json!({ "uri": request.uri }));
        let contents = match request.uri.as_str() {
            u if u == format!("mem://customer/{}", self.identity) => vec![ResourceContents::text(
                format!("Kunde {} IBAN {IBAN}", self.identity),
                u,
            )],
            "mem://logo" => vec![
                ResourceContents::blob("iVBORw0KGgo=", "mem://logo").with_mime_type("image/png"),
            ],
            u if u.starts_with("mem://note/") => vec![ResourceContents::text(
                format!(
                    "note {} about {}",
                    percent_decoded(&u["mem://note/".len()..]),
                    self.identity
                ),
                u,
            )],
            _ => return Err(ErrorData::resource_not_found("unknown resource", None)),
        };
        Ok(ReadResourceResponse::Complete(ReadResourceResult::new(
            contents,
        )))
    }
}

/// A template value as a server sees it after RFC 3986 decoding (the
/// gateway percent-encodes restored values); malformed escapes stay as is.
fn percent_decoded(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = b
            .get(i + 1..i + 3)
            .and_then(|h| std::str::from_utf8(h).ok())
            .filter(|h| h.bytes().all(|c| c.is_ascii_hexdigit()))
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match (b[i], hex) {
            (b'%', Some(v)) => {
                out.push(v);
                i += 3;
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Serve `handler` over Streamable HTTP on a random loopback port at `/mcp`.
pub async fn serve_scripted_http(handler: ScriptedUpstream) -> (SocketAddr, CancellationToken) {
    let ct = CancellationToken::new();
    let config = StreamableHttpServerConfig::default().with_cancellation_token(ct.clone());
    let service = StreamableHttpService::new(
        move || Ok(handler.clone()),
        Arc::new(LocalSessionManager::default()),
        config,
    );
    let app = axum::Router::new().nest_service("/mcp", service);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let stop = ct.clone();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move { stop.cancelled().await })
            .await;
    });
    (addr, ct)
}
