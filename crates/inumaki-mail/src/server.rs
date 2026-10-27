//! The mail upstream (M4 spec §6.2): an rmcp `ServerHandler` with four
//! tools. One IMAP session per server, opened on the first call, dropped
//! on connection errors, reconnected on the next call, kept alive with
//! NOOP; an authentication failure is remembered for a while so an agent
//! loop cannot hammer a locked account. Every mail-domain failure is a
//! tool error with a fixed class and sentence; the gateway sanitizes every
//! result and strictly rehydrates every argument before it gets here.
//!
//! Draft-only: there is no send tool and no SMTP code anywhere in this
//! crate. The only write the connector performs is `APPEND` to the Drafts
//! folder (plus `CREATE` of that folder when the server has none); reads
//! use `EXAMINE` and `BODY.PEEK`, so nothing is marked read.

use std::sync::{Arc, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ErrorCode, ErrorData,
    Implementation, InitializeResult, JsonObject, ListToolsResult, PaginatedRequestParams,
    ServerCapabilities, ServerConfig, Tool, ToolsCapability,
};
use rmcp::service::RequestContext;
use rmcp::{RoleServer, ServerHandler};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::account::{MailAccount, MailCredentials};
use crate::draft::{
    MAX_BODY_BYTES, ReplyDraft, build_reply, new_message_id, parse_cc, reply_subject,
    valid_addr_spec,
};
use crate::error::MailError;
use crate::handles::{MailHandles, MessageRef, Resolved};
use crate::imap::{DraftsFolder, Imap};
use crate::query::{build_search, quote_search};
use crate::render::{MailAddress, parse_message, parse_summary, render_markdown};

/// The upstream name the daemon registers the connector under.
pub const UPSTREAM_NAME: &str = "mail";
/// The four tools, in listing order.
pub const TOOL_NAMES: [&str; 4] = [
    "mail_list_folders",
    "mail_search",
    "mail_read",
    "mail_draft_reply",
];
/// The shipped field contract (plan 2 contract format plus the `handle` rule).
pub const CONTRACT_JSON: &str = include_str!("../contract.json");
/// The fixed confirmation text of a created draft.
pub const DRAFT_TEXT: &str = "Draft created in your Drafts folder. Review and send it from your mail client; inumaki does not send mail.";

/// Settings (`[mail]` in the daemon configuration).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailConfig {
    /// NOOP interval while idle.
    pub keepalive: Duration,
    /// Timeout per IMAP command (connect, login, fetch, append, …).
    pub command_timeout: Duration,
    /// Largest message `mail_read` fetches.
    pub max_message_bytes: usize,
    /// Snippet length in characters.
    pub snippet_chars: usize,
    /// Bytes of `BODY[TEXT]` fetched per search result for the snippet.
    pub summary_text_bytes: usize,
    /// How long an authentication failure is remembered before the server is asked again.
    pub auth_retry_after: Duration,
    /// `mail_search` default `limit`.
    pub default_limit: usize,
    /// `mail_search` maximum `limit`.
    pub max_limit: usize,
}

impl Default for MailConfig {
    fn default() -> Self {
        MailConfig {
            keepalive: Duration::from_secs(300),
            command_timeout: Duration::from_secs(30),
            max_message_bytes: 4 * 1024 * 1024,
            snippet_chars: 200,
            summary_text_bytes: 4096,
            auth_retry_after: Duration::from_secs(60),
            default_limit: 20,
            max_limit: 100,
        }
    }
}

struct Conn {
    imap: Option<Imap>,
    /// The account of the live session, password cleared after login.
    account: Option<MailAccount>,
    drafts: Option<String>,
    last_used: Instant,
    auth_failed_at: Option<Instant>,
}

impl Conn {
    /// Drop the session on connection-class failures; return the error.
    fn fail(&mut self, e: MailError) -> MailError {
        if e.is_connection() {
            self.drop_session();
        }
        e
    }

    fn drop_session(&mut self) {
        self.imap = None;
        self.drafts = None;
        self.account = None;
    }
}

struct Inner {
    creds: Arc<dyn MailCredentials>,
    handles: Arc<dyn MailHandles>,
    config: MailConfig,
    label: String,
    conn: Mutex<Conn>,
    stop: CancellationToken,
}

impl Drop for Inner {
    // the last clone is gone: end the keepalive task
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

/// The connector. Cheap to clone (shared session).
#[derive(Clone)]
pub struct MailServer {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for MailServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MailServer")
            .field("label", &self.inner.label)
            .field("config", &self.inner.config)
            .finish()
    }
}

fn tool_error(e: &MailError) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(format!(
        "{}: {}",
        e.class(),
        e.hint()
    ))])
}

fn schema(props: Value, required: &[&str]) -> JsonObject {
    json!({ "type": "object", "properties": props, "required": required })
        .as_object()
        .cloned()
        .unwrap_or_default()
}

fn output(props: Value) -> Arc<JsonObject> {
    Arc::new(
        json!({ "type": "object", "properties": props })
            .as_object()
            .cloned()
            .unwrap_or_default(),
    )
}

fn str_arg<'a>(
    args: &'a Option<JsonObject>,
    key: &'static str,
) -> Result<Option<&'a str>, MailError> {
    match args.as_ref().and_then(|a| a.get(key)) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.as_str())),
        Some(_) => Err(MailError::InvalidArgument(key)),
    }
}

fn required<'a>(args: &'a Option<JsonObject>, key: &'static str) -> Result<&'a str, MailError> {
    str_arg(args, key)?.ok_or(MailError::InvalidArgument(key))
}

/// Control characters (CR, LF, ESC, NUL, …) become spaces in anything the
/// agent sees outside the message body.
fn no_controls(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// One Markdown table cell or list item.
fn cell(s: &str) -> String {
    no_controls(&s.replace('|', "¦"))
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// NOOP while idle. Holds only a weak reference, so dropping the last
/// [`MailServer`] clone ends the task and closes the session.
async fn keepalive(inner: Weak<Inner>, stop: CancellationToken, every: Duration) {
    let every = every.max(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = stop.cancelled() => return,
            _ = tokio::time::sleep(every) => {}
        }
        let Some(inner) = inner.upgrade() else {
            return;
        };
        let mut conn = inner.conn.lock().await;
        if conn.last_used.elapsed() < every {
            continue;
        }
        let r = match conn.imap.as_mut() {
            Some(imap) => imap.noop().await,
            None => continue,
        };
        match r {
            Ok(()) => conn.last_used = Instant::now(),
            Err(e) => {
                tracing::debug!(dataset = %inner.label, class = e.class(), "keepalive failed; session dropped");
                // any NOOP failure leaves the session in an unknown state
                conn.drop_session();
            }
        }
    }
}

impl MailServer {
    /// Start the connector (needs a Tokio runtime: the keepalive task is
    /// spawned here). `label` is the opaque dataset label for logs.
    pub fn start(
        creds: Arc<dyn MailCredentials>,
        handles: Arc<dyn MailHandles>,
        config: MailConfig,
        label: &str,
    ) -> MailServer {
        let stop = CancellationToken::new();
        let every = config.keepalive;
        let inner = Arc::new(Inner {
            creds,
            handles,
            config,
            label: label.to_string(),
            conn: Mutex::new(Conn {
                imap: None,
                account: None,
                drafts: None,
                last_used: Instant::now(),
                auth_failed_at: None,
            }),
            stop: stop.clone(),
        });
        tokio::spawn(keepalive(Arc::downgrade(&inner), stop, every));
        MailServer { inner }
    }

    /// Stop the keepalive and log out.
    pub async fn shutdown(&self) {
        self.inner.stop.cancel();
        let mut conn = self.inner.conn.lock().await;
        if let Some(imap) = conn.imap.take() {
            imap.logout().await;
        }
        conn.drop_session();
    }

    /// The tool definitions (static names and schemas; descriptions are
    /// free text the gateway sanitizes). There is no send tool.
    pub fn tools() -> Vec<Tool> {
        let mut list = Tool::new(
            TOOL_NAMES[0],
            "List the mailbox folders. Returns a folder handle per folder; pass a handle as the folder argument of mail_search.",
            schema(json!({}), &[]),
        );
        list.output_schema = Some(output(json!({
            "folders": { "type": "array", "items": { "type": "object", "properties": {
                "id": { "type": "string" }, "name": { "type": "string" } } } }
        })));
        let mut search = Tool::new(
            TOOL_NAMES[1],
            "Search a folder (INBOX when no folder handle is given) by words in the sender, subject, or text, and/or a date window. Returns message handles for mail_read and mail_draft_reply, newest first.",
            schema(
                json!({
                    "query": { "type": "string", "description": "words to match in From, Subject, or the text" },
                    "folder": { "type": "string", "description": "a folder handle from mail_list_folders" },
                    "since": { "type": "string", "format": "date", "description": "ISO date, inclusive; compares the date the message was received by the mailbox (IMAP INTERNALDATE), not the Date header" },
                    "before": { "type": "string", "format": "date", "description": "ISO date, exclusive; received date as for since" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 100, "description": "at most this many results (default 20)" }
                }),
                &[],
            ),
        );
        search.output_schema = Some(output(json!({
            "messages": { "type": "array", "items": { "type": "object", "properties": {
                "id": { "type": "string" }, "folder": { "type": "string" }, "from": { "type": "string" },
                "subject": { "type": "string" }, "date": { "type": "string" }, "snippet": { "type": "string" } } } },
            "truncated": { "type": "boolean" }
        })));
        let read = Tool::new(
            TOOL_NAMES[2],
            "Read one message as Markdown: headers, body text, quoted history, and an attachment list (names and types only).",
            schema(
                json!({
                    "id": { "type": "string", "description": "a message handle" },
                    "folder": { "type": "string", "description": "the folder handle the message was found in" }
                }),
                &["id", "folder"],
            ),
        );
        let mut draft = Tool::new(
            TOOL_NAMES[3],
            "Store a reply to a message as a draft in the Drafts folder for the user to review and send in their mail client. Nothing is sent.",
            schema(
                json!({
                    "id": { "type": "string", "description": "a message handle" },
                    "folder": { "type": "string", "description": "the folder handle the message was found in" },
                    "body": { "type": "string", "description": "the reply text" },
                    "cc": { "type": "string", "description": "optional comma-separated extra recipients" }
                }),
                &["id", "folder", "body"],
            ),
        );
        draft.output_schema = Some(output(json!({
            "draft": { "type": "object", "properties": {
                "id": { "type": "string", "description": "the draft's message handle; absent when the stored draft could not be located" },
                "folder": { "type": "string" } }, "required": ["folder"] },
            "status": { "type": "string" }
        })));
        vec![list, search, read, draft]
    }

    /// Run a handle-store call off the async workers (the vault store does
    /// SQLite and crypto).
    async fn handles<T: Send + 'static>(
        &self,
        f: impl FnOnce(&dyn MailHandles) -> Result<T, MailError> + Send + 'static,
    ) -> Result<T, MailError> {
        let h = Arc::clone(&self.inner.handles);
        tokio::task::spawn_blocking(move || f(&*h))
            .await
            .map_err(|_| MailError::Handles("worker"))?
    }

    /// The session, connecting when needed. A refused login is remembered
    /// for `auth_retry_after`: no second LOGIN inside that window.
    async fn ensure<'a>(&self, conn: &'a mut Conn) -> Result<&'a mut Imap, MailError> {
        if conn.imap.is_none() {
            if let Some(t) = conn.auth_failed_at {
                if t.elapsed() < self.inner.config.auth_retry_after {
                    return Err(MailError::AuthFailed);
                }
            }
            // the vault read (SQLite + decrypt) runs off the async workers
            let creds = Arc::clone(&self.inner.creds);
            let mut account = tokio::task::spawn_blocking(move || creds.account())
                .await
                .map_err(|_| MailError::Credentials("worker"))??;
            match Imap::connect(&account, self.inner.config.command_timeout).await {
                Ok(imap) => {
                    conn.imap = Some(imap);
                    conn.drafts = None;
                    conn.auth_failed_at = None;
                    // the password is not needed after login
                    account.password = zeroize::Zeroizing::new(String::new());
                    conn.account = Some(account);
                    tracing::info!(dataset = %self.inner.label, "mail session connected");
                }
                Err(MailError::AuthFailed) => {
                    conn.auth_failed_at = Some(Instant::now());
                    tracing::warn!(dataset = %self.inner.label, "mail login refused; not retried for a while");
                    return Err(MailError::AuthFailed);
                }
                Err(e) => return Err(e),
            }
        }
        conn.last_used = Instant::now();
        conn.imap.as_mut().ok_or(MailError::Protocol("session"))
    }

    /// Resolve a message handle and its folder handle together; the message
    /// must belong to that folder.
    async fn resolve_pair(
        &self,
        id: &str,
        folder: &str,
    ) -> Result<(String, MessageRef), MailError> {
        let (id, folder) = (id.to_string(), folder.to_string());
        let (m, f) = self
            .handles(move |h| Ok((h.resolve(&id)?, h.resolve(&folder)?)))
            .await?;
        match (m, f) {
            (Some(Resolved::Message(m)), Some(Resolved::Folder(f))) if m.folder == f => Ok((f, m)),
            _ => Err(MailError::ContextUnavailable),
        }
    }

    /// EXAMINE the folder and compare its live UIDVALIDITY with the
    /// handle's, on every use (a store whose resolve is not atomic with
    /// invalidation may still hand out a just-invalidated handle once); on a
    /// mismatch drop the folder's message handles and fail, so a UID that
    /// now names another message is never read.
    async fn examine_for(
        &self,
        conn: &mut Conn,
        folder: &str,
        r: &MessageRef,
    ) -> Result<(), MailError> {
        let validity = match self.ensure(conn).await?.examine(folder).await {
            Ok(v) => v,
            Err(e) => return Err(conn.fail(e)),
        };
        if validity != r.uid_validity {
            let f = folder.to_string();
            let n = self.handles(move |h| h.invalidate_folder(&f)).await?;
            tracing::info!(dataset = %self.inner.label, handles = n, "uidvalidity changed; message handles invalidated");
            return Err(MailError::ContextUnavailable);
        }
        Ok(())
    }

    /// The stored draft by its Message-ID in the drafts folder; `None` on
    /// any failure (a connection-class failure drops the session).
    async fn locate_draft(
        &self,
        conn: &mut Conn,
        drafts: &str,
        message_id: &str,
    ) -> Option<MessageRef> {
        let crit = format!("HEADER Message-ID {}", quote_search(message_id).ok()?);
        let validity = match self.ensure(conn).await.ok()?.examine(drafts).await {
            Ok(v) => v,
            Err(e) => {
                let _ = conn.fail(e);
                return None;
            }
        };
        match self.ensure(conn).await.ok()?.uid_search(&crit).await {
            Ok(uids) if uids.len() == 1 => Some(MessageRef {
                folder: drafts.to_string(),
                uid_validity: validity,
                uid: uids[0],
            }),
            Ok(_) => None,
            Err(e) => {
                let _ = conn.fail(e);
                None
            }
        }
    }

    async fn list_folders(&self) -> Result<CallToolResult, MailError> {
        let mut conn = self.inner.conn.lock().await;
        let folders = match self.ensure(&mut conn).await?.folders().await {
            Ok(v) => v,
            Err(e) => return Err(conn.fail(e)),
        };
        drop(conn);
        let mut rows = Vec::new();
        let mut text = String::from("Folders:\n");
        for f in folders.into_iter().filter(|f| f.selectable) {
            let raw = f.raw.clone();
            let h = self.handles(move |hs| hs.folder_handle(&raw)).await?;
            let name = no_controls(&f.display);
            text.push_str(&format!("- {} (id {h})\n", cell(&name)));
            rows.push(json!({ "id": h, "name": name }));
        }
        tracing::info!(dataset = %self.inner.label, tool = TOOL_NAMES[0], folders = rows.len(), "served");
        let mut r = CallToolResult::success(vec![ContentBlock::text(text)]);
        r.structured_content = Some(json!({ "folders": rows }));
        Ok(r)
    }

    async fn search(&self, args: &Option<JsonObject>) -> Result<CallToolResult, MailError> {
        let query = str_arg(args, "query")?;
        let since = str_arg(args, "since")?;
        let before = str_arg(args, "before")?;
        let limit = match args.as_ref().and_then(|a| a.get("limit")) {
            None | Some(Value::Null) => self.inner.config.default_limit,
            Some(Value::Number(n)) => match n.as_u64() {
                Some(l) if l >= 1 && l as usize <= self.inner.config.max_limit => l as usize,
                _ => return Err(MailError::InvalidArgument("limit")),
            },
            Some(_) => return Err(MailError::InvalidArgument("limit")),
        };
        // validate the criteria before touching the network (the literal form depends on the server)
        build_search(query, since, before, true)?;
        let folder = match str_arg(args, "folder")? {
            None => "INBOX".to_string(),
            Some(h) => {
                let h = h.to_string();
                match self.handles(move |hs| hs.resolve(&h)).await? {
                    Some(Resolved::Folder(f)) => f,
                    _ => return Err(MailError::ContextUnavailable),
                }
            }
        };
        let mut conn = self.inner.conn.lock().await;
        let literal_plus = self.ensure(&mut conn).await?.literal_plus();
        let criteria = build_search(query, since, before, literal_plus)?;
        let validity = match self.ensure(&mut conn).await?.examine(&folder).await {
            Ok(v) => v,
            Err(e) => return Err(conn.fail(e)),
        };
        let uids = match self.ensure(&mut conn).await?.uid_search(&criteria).await {
            Ok(v) => v,
            Err(e) => return Err(conn.fail(e)),
        };
        let truncated = uids.len() > limit;
        let uids: Vec<u32> = uids.into_iter().take(limit).collect();
        let mut sums = match self
            .ensure(&mut conn)
            .await?
            .fetch_summaries(&uids, self.inner.config.summary_text_bytes)
            .await
        {
            Ok(v) => v,
            Err(e) => return Err(conn.fail(e)),
        };
        drop(conn);
        sums.sort_by(|a, b| b.uid.cmp(&a.uid));
        let f = folder.clone();
        let folder_handle = self.handles(move |hs| hs.folder_handle(&f)).await?;
        let mut rows = Vec::with_capacity(sums.len());
        let mut text =
            String::from("| id | from | date | subject | snippet |\n|---|---|---|---|---|\n");
        for s in &sums {
            let r = MessageRef {
                folder: folder.clone(),
                uid_validity: validity,
                uid: s.uid,
            };
            let h = self.handles(move |hs| hs.message_handle(&r)).await?;
            let sm = parse_summary(&s.header, &s.text_head, self.inner.config.snippet_chars);
            let (from, subject, snippet) = (
                no_controls(&sm.from),
                no_controls(&sm.subject),
                no_controls(&sm.snippet),
            );
            text.push_str(&format!(
                "| {h} | {} | {} | {} | {} |\n",
                cell(&from),
                cell(&sm.date),
                cell(&subject),
                cell(&snippet)
            ));
            rows.push(json!({ "id": h, "folder": folder_handle, "from": from, "subject": subject, "date": sm.date, "snippet": snippet }));
        }
        if truncated {
            text.push_str("\n(more results exist; narrow the query or the dates)\n");
        }
        tracing::info!(dataset = %self.inner.label, tool = TOOL_NAMES[1], results = rows.len(), truncated, "served");
        let mut r = CallToolResult::success(vec![ContentBlock::text(text)]);
        r.structured_content = Some(json!({ "messages": rows, "truncated": truncated }));
        Ok(r)
    }

    async fn read(&self, args: &Option<JsonObject>) -> Result<CallToolResult, MailError> {
        let id = required(args, "id")?;
        let folder_h = required(args, "folder")?;
        let (folder, mref) = self.resolve_pair(id, folder_h).await?;
        let mut conn = self.inner.conn.lock().await;
        self.examine_for(&mut conn, &folder, &mref).await?;
        // the size first: an oversized message's body is never fetched
        let size = match self.ensure(&mut conn).await?.fetch_size(mref.uid).await {
            Ok(Some(s)) => s,
            Ok(None) => return Err(MailError::ContextUnavailable),
            Err(e) => return Err(conn.fail(e)),
        };
        if size as usize > self.inner.config.max_message_bytes {
            tracing::info!(dataset = %self.inner.label, bytes = size, "message over the size limit");
            return Err(MailError::TooLarge);
        }
        let raw = match self.ensure(&mut conn).await?.fetch_message(mref.uid).await {
            Ok(Some(b)) => b,
            Ok(None) => return Err(MailError::ContextUnavailable),
            Err(e) => return Err(conn.fail(e)),
        };
        drop(conn);
        // the server's size can lie; the limit holds on what actually arrived
        if raw.len() > self.inner.config.max_message_bytes {
            return Err(MailError::TooLarge);
        }
        let parsed = parse_message(&raw).ok_or(MailError::Protocol("message_parse"))?;
        let md = render_markdown(&parsed);
        tracing::info!(dataset = %self.inner.label, tool = TOOL_NAMES[2], bytes = raw.len(), attachments = parsed.attachments.len(), "served");
        Ok(CallToolResult::success(vec![ContentBlock::text(md)]))
    }

    async fn draft_reply(&self, args: &Option<JsonObject>) -> Result<CallToolResult, MailError> {
        // every argument is validated before anything touches the server
        let id = required(args, "id")?;
        let folder_h = required(args, "folder")?;
        let body = required(args, "body")?;
        if body.trim().is_empty() || body.len() > MAX_BODY_BYTES || body.contains('\u{0}') {
            return Err(MailError::InvalidArgument("body"));
        }
        let cc = parse_cc(str_arg(args, "cc")?.unwrap_or(""))?;
        let (folder, mref) = self.resolve_pair(id, folder_h).await?;
        let mut conn = self.inner.conn.lock().await;
        self.examine_for(&mut conn, &folder, &mref).await?;
        let sums = match self
            .ensure(&mut conn)
            .await?
            .fetch_summaries(&[mref.uid], 1)
            .await
        {
            Ok(v) => v,
            Err(e) => return Err(conn.fail(e)),
        };
        let Some(orig_raw) = sums.into_iter().find(|s| s.uid == mref.uid) else {
            return Err(MailError::ContextUnavailable);
        };
        let orig = parse_message(&orig_raw.header).ok_or(MailError::Protocol("message_parse"))?;
        // To = Reply-To when it is exactly one valid address, else the first valid From (M4 spec §6.2 as built)
        let to: MailAddress = match orig.reply_to.as_slice() {
            [single] if single.address.as_deref().is_some_and(valid_addr_spec) => single.clone(),
            _ => orig
                .from
                .iter()
                .find(|a| a.address.as_deref().is_some_and(valid_addr_spec))
                .cloned()
                .ok_or(MailError::DraftRejected("recipient"))?,
        };
        let account = conn
            .account
            .clone()
            .ok_or(MailError::Credentials("account"))?;
        let from = account.draft_from()?;
        let domain = from
            .rsplit('@')
            .next()
            .unwrap_or("inumaki.local")
            .to_string();
        let message_id = new_message_id(&domain)?;
        let subject = reply_subject(orig.subject.as_deref());
        let bytes = build_reply(&ReplyDraft {
            from: &from,
            to: &to,
            cc: &cc,
            subject: &subject,
            in_reply_to: orig.message_id.as_deref(),
            references: &orig.references,
            body,
            message_id: &message_id,
            date_unix: now_unix(),
        })?;
        // where drafts go (resolved once per session)
        let drafts = match conn.drafts.clone() {
            Some(d) => d,
            None => {
                let resolved = match self
                    .ensure(&mut conn)
                    .await?
                    .resolve_drafts_folder(account.drafts_folder.as_deref())
                    .await
                {
                    Ok(r) => r,
                    Err(e) => return Err(conn.fail(e)),
                };
                let name = match resolved {
                    DraftsFolder::Existing(n) => n,
                    DraftsFolder::Create(n) => {
                        if let Err(e) = self.ensure(&mut conn).await?.create(&n).await {
                            return Err(conn.fail(e));
                        }
                        tracing::info!(dataset = %self.inner.label, "drafts folder created");
                        n
                    }
                };
                conn.drafts = Some(name.clone());
                name
            }
        };
        // minted before the write, so a store failure cannot follow a stored draft
        let d = drafts.clone();
        let folder_handle = self.handles(move |hs| hs.folder_handle(&d)).await?;
        // One flagged attempt; one retry without the flag only when nothing
        // can have been stored: the server refused after the literal (`NO`,
        // session in step, same session), or never took the literal at all
        // (`append_desync`: a `NO` or unsolicited data instead of the `+`
        // continuation; the session is out of step, so it is dropped and the
        // retry runs on a fresh one). Never a retry after an ambiguous
        // outcome (connection lost or timeout after the literal):
        // `draft_status_unknown` is reported once.
        let first = self
            .ensure(&mut conn)
            .await?
            .append(&drafts, Some("(\\Draft)"), None, &bytes)
            .await;
        let retry_unflagged = match first {
            Ok(()) => false,
            Err(MailError::DraftRejected(_)) => {
                tracing::info!(dataset = %self.inner.label, "flagged append refused; retrying once without the Draft flag");
                true
            }
            Err(MailError::Protocol("append_desync")) => {
                conn.drop_session();
                tracing::info!(dataset = %self.inner.label, "append refused before the literal; retrying once on a fresh session");
                true
            }
            Err(e) => return Err(conn.fail(e)),
        };
        if retry_unflagged {
            if let Err(e) = self
                .ensure(&mut conn)
                .await?
                .append(&drafts, None, None, &bytes)
                .await
            {
                return Err(conn.fail(e));
            }
        }
        // The draft is stored: from here on nothing may turn into an error
        // (an agent would retry and store it twice). Find it for its handle,
        // best effort; EXAMINE keeps flags untouched.
        let located = self.locate_draft(&mut conn, &drafts, &message_id).await;
        drop(conn);
        let handle = match located {
            Some(r) => match self.handles(move |hs| hs.message_handle(&r)).await {
                Ok(h) => Some(h),
                Err(e) => {
                    tracing::warn!(dataset = %self.inner.label, class = e.class(), "draft stored; its handle could not be minted");
                    None
                }
            },
            None => None,
        };
        tracing::info!(dataset = %self.inner.label, tool = TOOL_NAMES[3], bytes = bytes.len(), cc = cc.len(), located = handle.is_some(), "draft stored");
        let mut text = DRAFT_TEXT.to_string();
        if let Some(h) = &handle {
            text.push_str(&format!(" Draft id: {h}."));
        }
        let mut r = CallToolResult::success(vec![ContentBlock::text(text)]);
        // an unlocated draft has no `id` at all (never JSON null: the output
        // schema says string, and a strict client rejects a mismatch)
        let mut draft = json!({ "folder": folder_handle });
        if let Some(h) = handle {
            draft["id"] = Value::String(h);
        }
        r.structured_content = Some(json!({ "draft": draft, "status": "created" }));
        Ok(r)
    }
}

impl ServerHandler for MailServer {
    fn get_info(&self) -> ServerConfig {
        let mut caps = ServerCapabilities::default();
        caps.tools = Some(ToolsCapability::default());
        InitializeResult::new(caps).with_server_info(Implementation::new(
            "inumaki-mail",
            env!("CARGO_PKG_VERSION"),
        ))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::with_all_items(Self::tools()))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let t0 = Instant::now();
        let (tool, outcome) = match request.name.as_ref() {
            n if n == TOOL_NAMES[0] => (TOOL_NAMES[0], self.list_folders().await),
            n if n == TOOL_NAMES[1] => (TOOL_NAMES[1], self.search(&request.arguments).await),
            n if n == TOOL_NAMES[2] => (TOOL_NAMES[2], self.read(&request.arguments).await),
            n if n == TOOL_NAMES[3] => (TOOL_NAMES[3], self.draft_reply(&request.arguments).await),
            // the agent-supplied name is never echoed or logged
            _ => {
                return Err(ErrorData::new(
                    ErrorCode::METHOD_NOT_FOUND,
                    "unknown tool",
                    None,
                ));
            }
        };
        let result = match outcome {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(dataset = %self.inner.label, tool, class = e.class(), latency_ms = t0.elapsed().as_millis() as u64, "mail tool failed");
                tool_error(&e)
            }
        };
        Ok(CallToolResponse::Complete(result))
    }
}
