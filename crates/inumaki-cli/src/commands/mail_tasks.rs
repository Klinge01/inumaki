//! `inumaki mail-tasks`: the scripted mail-task harness (M4 spec §13.1).
//!
//! The runner plays the agent against a TEST mailbox: it wipes INBOX and the
//! drafts folder, seeds the deterministic fixture mails, drives
//! search, read, and draft through the dataset's gateway over the daemon's
//! control socket, then reads the Drafts folder back over IMAP and checks
//! every stored draft. Plan 4 runs it against GreenMail and reads the report.
//!
//! Nothing a mailbox or the gateway said reaches stdout, stderr, or the
//! report: failures are reduced to fixed class names (the gateway's error
//! vocabulary, the connector's class words), and the report holds counts,
//! indices, and entity-kind labels only. The password is read from a file
//! and never printed.
//!
//! The runner WIPES the INBOX and the drafts folder of the account it logs
//! into. It only starts when the target is loopback (or `--allow-remote`),
//! the dataset's mailbox has the same host, port, and login name, and the
//! drafts folder is not the INBOX and matches the dataset's when that is
//! configured. Point it at a dedicated test account, never a real mailbox.
//!
//! The runner and the connector read no environment variables.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use clap::ValueEnum;
use hyper::Method;
use inumaki_core::config::TokenSettings;
use inumaki_core::rehydrate::Rehydrator;
use inumaki_eval::mail_fixture::{
    DEFAULT_FIXTURE_COUNT, DEFAULT_FIXTURE_SEED, FixtureMail, FixtureOptions, fixture_digest,
    generate_mailbox,
};
use inumaki_eval::{GenFamily, find_residue};
use inumaki_mail::draft::reply_subject;
use inumaki_mail::harness::{SeedMail, clear_folder, list_folder_messages, seed_mailbox};
use inumaki_mail::render::parse_message;
use inumaki_mail::{MailAccount, Preset, is_loopback_host};
use rmcp::ServiceExt;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ClientCapabilities, Implementation,
    InitializeRequestParams,
};
use rmcp::service::ServiceError;
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use serde::Serialize;
use serde_json::{Value, json};

use crate::client::{call, connect, error_line, resolve_socket};
use crate::commands::mailbox::read_password;
use crate::commands::valid_dataset;
use crate::exit;

/// The completion target of M4 spec §13.1.
pub const GATE_TARGET: f64 = 0.9;
/// Timeout of every IMAP command of the harness.
const TIMEOUT: Duration = Duration::from_secs(30);
/// Timeout of one gateway call (a model-backed profile can take a while).
const CALL_TIMEOUT: Duration = Duration::from_secs(120);

/// Fixture family (`--family`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum FamilyArg {
    /// The tuning family.
    Tuning,
    /// The held-out family (never used for tuning).
    HeldOut,
}

impl FamilyArg {
    fn family(self) -> GenFamily {
        match self {
            FamilyArg::Tuning => GenFamily::Tuning,
            FamilyArg::HeldOut => GenFamily::HeldOut,
        }
    }
}

/// Arguments of `mail-tasks`.
#[derive(clap::Args)]
pub struct Args {
    /// Mailbox dataset (configured with `dataset add-mailbox` for the same account).
    #[arg(long)]
    dataset: String,
    /// IMAP host of the test mailbox.
    #[arg(long)]
    imap_host: String,
    /// IMAP port.
    #[arg(long)]
    imap_port: u16,
    /// Plaintext IMAP to loopback only.
    #[arg(long)]
    imap_plaintext_loopback: bool,
    /// Allow a non-loopback host (the mailbox WILL be wiped).
    #[arg(long)]
    allow_remote: bool,
    /// Login name of the dedicated TEST account of the dataset's mailbox. The runner wipes
    /// this account's INBOX and drafts folder, and refuses a name that differs from the one
    /// the dataset's mailbox was configured with.
    #[arg(long)]
    user: String,
    /// File holding the password (mode 0600).
    #[arg(long, value_name = "FILE")]
    password_file: PathBuf,
    /// Drafts folder to wipe and verify: never INBOX, and equal to the dataset mailbox's
    /// configured drafts folder when it has one.
    #[arg(long, default_value = "Drafts")]
    drafts_folder: String,
    /// Fixture count.
    #[arg(long, default_value_t = DEFAULT_FIXTURE_COUNT)]
    count: usize,
    /// Fixture seed.
    #[arg(long, default_value_t = DEFAULT_FIXTURE_SEED)]
    seed: u64,
    /// Fixture family.
    #[arg(long, value_enum, default_value_t = FamilyArg::Tuning)]
    family: FamilyArg,
    /// Write the report as JSON.
    #[arg(long, value_name = "FILE")]
    report_json: Option<PathBuf>,
    /// Exit 5 when the completion gate (90 %) is missed.
    #[arg(long)]
    require_gate: bool,
}

#[derive(Debug, Serialize)]
struct Gate {
    target: f64,
    pass: bool,
}

/// One task's result. `outcome` is one of [`OUTCOMES`]; `step` names the
/// step that decided it (`null` for `completed`); `detail` is a fixed class
/// word (a gateway error name or a connector class), never server text.
#[derive(Debug, Serialize)]
struct TaskOutcome {
    index: usize,
    outcome: &'static str,
    step: Option<&'static str>,
    detail: Option<&'static str>,
    residue_kinds: Vec<String>,
}

/// What the run was measured against (M4 spec §13.1 pinning). Taken from
/// `/v1/status`; `config_fingerprint` is `null` until status exposes it.
#[derive(Debug, Serialize)]
struct Provenance {
    daemon_version: String,
    profile: String,
    models: Value,
    config_fingerprint: Option<String>,
    runner_version: &'static str,
}

/// The report (the plan-4 interface). The keys are frozen; new keys may be
/// added, none renamed or removed.
///
/// Every task has exactly one outcome and every outcome has a counter of the
/// same name, so the counters sum to `tasks`. A failed step is classified:
/// - `unresolved_token`: the gateway answered an MCP `unresolved_token`
///   error (a token the vault does not know, or a removed marker, in a
///   call or result). Not to be confused with `unresolved_tokens`, which
///   counts stored drafts that still hold a placeholder.
/// - `privacy_block`: the gateway blocked or withheld a call or result.
/// - `mail_error`: the connector answered a tool error (`mail_*`,
///   `context_unavailable`, `draft_rejected`, ...); `detail` has the class.
/// - `search_blocked`, `read_blocked`, `draft_failed`: any other gateway or
///   transport failure of that step (`detail` has the gateway's error name).
#[derive(Debug, Serialize)]
struct Report {
    dataset: String,
    seed: u64,
    count: usize,
    family: &'static str,
    fixture_digest: String,
    provenance: Provenance,
    tasks: usize,
    completed: usize,
    search_blocked: usize,
    search_miss: usize,
    read_blocked: usize,
    read_residue: usize,
    draft_failed: usize,
    draft_missing: usize,
    wrong_recipient: usize,
    wrong_thread: usize,
    wrong_restoration: usize,
    unresolved_tokens: usize,
    unresolved_token: usize,
    privacy_block: usize,
    mail_error: usize,
    /// Not measured by a scripted run (`null`); a human-in-the-loop run fills it in.
    interventions: Option<u32>,
    completion_rate: f64,
    gate: Gate,
    per_task: Vec<TaskOutcome>,
}

/// Every outcome a task can have; each is also a counter in the report.
const OUTCOMES: [&str; 14] = [
    "completed",
    "search_blocked",
    "search_miss",
    "read_blocked",
    "read_residue",
    "draft_failed",
    "draft_missing",
    "wrong_recipient",
    "wrong_thread",
    "wrong_restoration",
    "unresolved_tokens",
    "unresolved_token",
    "privacy_block",
    "mail_error",
];

/// The three steps of a task, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Search,
    Read,
    Draft,
}

impl Step {
    fn name(self) -> &'static str {
        match self {
            Step::Search => "search",
            Step::Read => "read",
            Step::Draft => "draft",
        }
    }
}

/// Why a gateway call failed, reduced to a class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    /// MCP `unresolved_token` from the gateway.
    UnresolvedToken,
    /// The gateway blocked or withheld the call or result.
    PrivacyBlock,
    /// The connector's own tool error; carries its class word.
    Mail(&'static str),
    /// Anything else (other gateway errors, transport); carries a fixed word.
    Blocked(&'static str),
}

/// The connector's class words (`MailError::class`), as they open a tool error.
const MAIL_CLASSES: [&str; 13] = [
    "mail_unreachable",
    "mail_timeout",
    "mail_tls_failed",
    "mail_auth_failed",
    "mail_protocol",
    "context_unavailable",
    "invalid_argument",
    "draft_rejected",
    "draft_status_unknown",
    "drafts_folder_missing",
    "resource_limit",
    "mail_handles",
    "mail_credentials",
];

/// The gateway's other MCP error names (`inumaki-gateway` `handler.rs`).
const GATEWAY_ERRORS: [&str; 9] = [
    "model_unavailable",
    "vault_unavailable",
    "upstream_unavailable",
    "unsupported_content",
    "resource_limit",
    "upstream_error",
    "unknown_tool",
    "unknown_prompt",
    "unknown_resource",
];

fn mail_class(word: &str) -> Option<&'static str> {
    MAIL_CLASSES.iter().copied().find(|c| *c == word)
}

/// Classify an MCP error message (always one of the gateway's fixed names).
fn classify_mcp_message(message: &str) -> Failure {
    match message {
        "unresolved_token" => Failure::UnresolvedToken,
        "privacy_block" => Failure::PrivacyBlock,
        // the connector's own class can also come back as a protocol error
        m if mail_class(m).is_some() && m != "resource_limit" => {
            Failure::Mail(mail_class(m).unwrap_or("mail_protocol"))
        }
        m => Failure::Blocked(
            GATEWAY_ERRORS
                .iter()
                .copied()
                .find(|g| *g == m)
                .unwrap_or("other_error"),
        ),
    }
}

/// Classify a tool result that has `isError`: the gateway's block text, or
/// the connector's `class: hint`. Anything else is a generic tool error.
fn classify_tool_text(text: &str) -> Failure {
    let t = text.trim_start();
    if t.starts_with("blocked by inumaki") || t.starts_with("withheld by inumaki") {
        return Failure::PrivacyBlock;
    }
    let word = t.split(':').next().unwrap_or("").trim();
    match mail_class(word) {
        Some(c) => Failure::Mail(c),
        None => Failure::Blocked("tool_error"),
    }
}

fn classify_service_error(e: &ServiceError) -> Failure {
    match e {
        ServiceError::McpError(d) => classify_mcp_message(d.message.as_ref()),
        ServiceError::Timeout { .. } => Failure::Blocked("timeout"),
        _ => Failure::Blocked("transport"),
    }
}

/// The outcome name and detail of a failed step.
fn failure_outcome(step: Step, f: Failure) -> (&'static str, Option<&'static str>) {
    match f {
        Failure::UnresolvedToken => ("unresolved_token", None),
        Failure::PrivacyBlock => ("privacy_block", None),
        Failure::Mail(class) => ("mail_error", Some(class)),
        Failure::Blocked(word) => (
            match step {
                Step::Search => "search_blocked",
                Step::Read => "read_blocked",
                Step::Draft => "draft_failed",
            },
            Some(word),
        ),
    }
}

fn text_of(r: &CallToolResult) -> String {
    r.content
        .iter()
        .filter_map(|c| c.as_text().map(|t| t.text.clone()))
        .collect::<Vec<_>>()
        .join("\n")
}

/// One gateway call: the result, or the class of its failure.
async fn gateway_call(
    client: &rmcp::service::RunningService<rmcp::RoleClient, InitializeRequestParams>,
    name: &str,
    args: Value,
) -> std::result::Result<CallToolResult, Failure> {
    let params = CallToolRequestParams::new(name.to_string())
        .with_arguments(args.as_object().cloned().unwrap_or_default());
    match tokio::time::timeout(CALL_TIMEOUT, client.peer().call_tool(params)).await {
        Err(_) => Err(Failure::Blocked("timeout")),
        Ok(Err(e)) => Err(classify_service_error(&e)),
        Ok(Ok(r)) if r.is_error == Some(true) => Err(classify_tool_text(&text_of(&r))),
        Ok(Ok(r)) => Ok(r),
    }
}

/// True when `s` contains a token-shaped placeholder, by the engine's own
/// grammar (`<KIND_hex>` and `<KIND_REMOVED>`), never by a copy of it.
fn has_placeholder(tokens: &Rehydrator, s: &str) -> bool {
    !tokens.tokens_in(s).is_empty()
}

/// The sender's `<PERSON_…>` token on the first line (the `From` line) of a read result.
fn sender_token(tokens: &Rehydrator, read_text: &str) -> Option<String> {
    let first = read_text.lines().next().unwrap_or_default();
    tokens
        .tokens_in(first)
        .into_iter()
        .find(|t| t.starts_with("<PERSON_"))
}

/// True when the body restored the person: it contains the whole name or
/// any name part of three letters or more. Plan 4a (M4 spec §16.2) restores
/// a linked mention to its own surface form, so a salutation token may come
/// back as `Frau Leitner` rather than the full gold name; the part check
/// keeps this measure valid across that change.
fn restored(body: &str, name: &str) -> bool {
    body.contains(name)
        || name
            .split_whitespace()
            .any(|part| part.chars().count() >= 3 && body.contains(part))
}

/// A draft the connector stored, waiting for the IMAP check.
struct Pending<'a> {
    fixture: &'a FixtureMail,
    used_token: bool,
}

/// Verify one stored draft against its fixture; `completed` or the first
/// thing that is wrong with it.
fn verify_draft(tokens: &Rehydrator, check: &Pending<'_>, raw: &[u8]) -> &'static str {
    let Some(d) = parse_message(raw) else {
        return "draft_failed";
    };
    let f = check.fixture;
    let to_ok = d.to.len() == 1
        && d.to[0].address.as_deref() == Some(f.expected_recipient())
        && d.cc.is_empty();
    if !to_ok {
        return "wrong_recipient";
    }
    let thread_ok = d.references.iter().any(|r| r == &f.message_id)
        && d.subject.as_deref() == Some(reply_subject(Some(&f.subject)).as_str());
    if !thread_ok {
        return "wrong_thread";
    }
    if has_placeholder(tokens, &d.body)
        || d.to
            .iter()
            .chain(&d.cc)
            .any(|a| has_placeholder(tokens, &a.display()))
    {
        return "unresolved_tokens";
    }
    if check.used_token {
        if let Some(n) = &f.from_name {
            if !restored(&d.body, n) {
                return "wrong_restoration";
            }
        }
    }
    "completed"
}

fn done(index: usize, outcome: &'static str, step: Option<Step>) -> TaskOutcome {
    TaskOutcome {
        index,
        outcome,
        step: step.map(Step::name),
        detail: None,
        residue_kinds: Vec::new(),
    }
}

fn failed(index: usize, step: Step, f: Failure) -> TaskOutcome {
    let (outcome, detail) = failure_outcome(step, f);
    TaskOutcome {
        detail,
        ..done(index, outcome, Some(step))
    }
}

/// Wipe and seed the mailbox, then play every task through the gateway.
async fn run_async(
    socket: &Path,
    a: &Args,
    account: &MailAccount,
    mails: &[FixtureMail],
) -> Result<Vec<TaskOutcome>> {
    let tokens = Rehydrator::new(&TokenSettings::default());
    // wipe and seed the test mailbox (with each fixture's day as INTERNALDATE)
    let cleared_inbox = clear_folder(account, TIMEOUT, "INBOX")
        .await
        .map_err(|e| anyhow::anyhow!("clearing INBOX: {}", e.class()))?;
    let cleared_drafts = clear_folder(account, TIMEOUT, &a.drafts_folder)
        .await
        .map_err(|e| anyhow::anyhow!("clearing the drafts folder: {}", e.class()))?;
    let seed: Vec<SeedMail> = mails
        .iter()
        .map(|m| SeedMail {
            folder: m.folder.clone(),
            internal_date: Some(m.internal_date.clone()),
            eml: m.eml.clone(),
        })
        .collect();
    let seeded = seed_mailbox(account, TIMEOUT, &seed)
        .await
        .map_err(|e| anyhow::anyhow!("seeding: {}", e.class()))?;
    println!(
        "mailbox prepared: cleared {cleared_inbox} inbox and {cleared_drafts} draft messages, seeded {seeded}"
    );
    // the agent: an rmcp client over the control socket
    let cfg =
        StreamableHttpClientTransportConfig::with_uri(format!("http://inumakid/mcp/{}", a.dataset));
    let transport =
        StreamableHttpClientTransport::from_unix_socket_with_config(&socket.to_string_lossy(), cfg);
    let client = InitializeRequestParams::new(
        ClientCapabilities::default(),
        Implementation::new("inumaki-mail-tasks", env!("CARGO_PKG_VERSION")),
    )
    .serve(transport)
    .await
    .context("connecting to the dataset's gateway over the control socket")?;
    // the mail upstream may still be connecting after add-mailbox
    let mut inbox: Option<String> = None;
    for _ in 0..100 {
        if let Ok(r) = gateway_call(&client, "mail_list_folders", json!({})).await {
            inbox = r
                .structured_content
                .as_ref()
                .and_then(|s| s["folders"].as_array())
                .and_then(|f| f.iter().find(|x| x["name"] == "INBOX"))
                .and_then(|x| x["id"].as_str())
                .map(str::to_string);
            if inbox.is_some() {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let inbox = inbox.context(
        "the gateway did not list an INBOX folder handle; is the mail upstream running (inumaki status)?",
    )?;
    let mut per_task: Vec<TaskOutcome> = Vec::with_capacity(mails.len());
    let mut pending: Vec<Pending<'_>> = Vec::new();
    for m in mails {
        // search: the day's mail, exactly one hit
        let found = match gateway_call(
            &client,
            "mail_search",
            json!({ "folder": inbox, "since": m.day, "before": m.next_day }),
        )
        .await
        {
            Ok(r) => r,
            Err(f) => {
                per_task.push(failed(m.index, Step::Search, f));
                continue;
            }
        };
        let hits = found
            .structured_content
            .as_ref()
            .and_then(|s| s["messages"].as_array())
            .cloned()
            .unwrap_or_default();
        if hits.len() != 1 {
            per_task.push(done(m.index, "search_miss", Some(Step::Search)));
            continue;
        }
        let id = hits[0]["id"].as_str().unwrap_or_default().to_string();
        // read: released, with no labeled residue
        let md =
            match gateway_call(&client, "mail_read", json!({ "id": id, "folder": inbox })).await {
                Ok(r) => text_of(&r),
                Err(f) => {
                    per_task.push(failed(m.index, Step::Read, f));
                    continue;
                }
            };
        let mut residue_kinds: Vec<String> = Vec::new();
        for s in m.doc.spans.iter().filter(|s| s.sensitive) {
            if find_residue(&s.kind, &m.doc.text[s.start..s.end], &md).is_some()
                && !residue_kinds.contains(&s.kind)
            {
                residue_kinds.push(s.kind.clone());
            }
        }
        if !residue_kinds.is_empty() {
            per_task.push(TaskOutcome {
                residue_kinds,
                ..done(m.index, "read_residue", Some(Step::Read))
            });
            continue;
        }
        // draft: greet the sender by the token the read showed
        let token = sender_token(&tokens, &md);
        let body = match &token {
            Some(t) => format!(
                "Sehr geehrte/r {t},\n\nvielen Dank f\u{fc}r Ihre Nachricht. Wir melden uns.\n"
            ),
            None => "Sehr geehrte Damen und Herren,\n\nvielen Dank f\u{fc}r Ihre Nachricht. Wir melden uns.\n"
                .to_string(),
        };
        // the draft id is optional (the connector omits it when it cannot locate the draft):
        // success is the tool result, the draft itself is checked over IMAP below
        match gateway_call(
            &client,
            "mail_draft_reply",
            json!({ "id": id, "folder": inbox, "body": body }),
        )
        .await
        {
            Ok(_) => pending.push(Pending {
                fixture: m,
                used_token: token.is_some(),
            }),
            Err(f) => per_task.push(failed(m.index, Step::Draft, f)),
        }
    }
    client.cancel().await.ok();
    // verify the drafts over IMAP
    let drafts = list_folder_messages(account, TIMEOUT, &a.drafts_folder)
        .await
        .map_err(|e| anyhow::anyhow!("reading the drafts folder: {}", e.class()))?;
    let mut by_reply: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
    for raw in drafts {
        if let Some(p) = parse_message(&raw) {
            if let Some(irt) = p.in_reply_to {
                by_reply.entry(irt).or_default().push(raw);
            }
        }
    }
    for check in &pending {
        let found = by_reply
            .get(&check.fixture.message_id)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let t = match found {
            [] => done(check.fixture.index, "draft_missing", Some(Step::Draft)),
            [raw] => {
                let outcome = verify_draft(&tokens, check, raw);
                done(
                    check.fixture.index,
                    outcome,
                    (outcome != "completed").then_some(Step::Draft),
                )
            }
            // one task, two stored drafts: an agent would send both
            _ => TaskOutcome {
                detail: Some("duplicate_draft"),
                ..done(check.fixture.index, "draft_failed", Some(Step::Draft))
            },
        };
        per_task.push(t);
    }
    per_task.sort_by_key(|t| t.index);
    Ok(per_task)
}

fn build_report(
    a: &Args,
    digest: String,
    provenance: Provenance,
    per_task: Vec<TaskOutcome>,
) -> Report {
    let count = |o: &str| per_task.iter().filter(|t| t.outcome == o).count();
    debug_assert!(per_task.iter().all(|t| OUTCOMES.contains(&t.outcome)));
    let completed = count("completed");
    let tasks = per_task.len();
    let completion_rate = if tasks == 0 {
        0.0
    } else {
        completed as f64 / tasks as f64
    };
    Report {
        dataset: a.dataset.clone(),
        seed: a.seed,
        count: a.count,
        family: a.family.family().name(),
        fixture_digest: digest,
        provenance,
        tasks,
        completed,
        search_blocked: count("search_blocked"),
        search_miss: count("search_miss"),
        read_blocked: count("read_blocked"),
        read_residue: count("read_residue"),
        draft_failed: count("draft_failed"),
        draft_missing: count("draft_missing"),
        wrong_recipient: count("wrong_recipient"),
        wrong_thread: count("wrong_thread"),
        wrong_restoration: count("wrong_restoration"),
        unresolved_tokens: count("unresolved_tokens"),
        unresolved_token: count("unresolved_token"),
        privacy_block: count("privacy_block"),
        mail_error: count("mail_error"),
        interventions: None,
        completion_rate,
        gate: Gate {
            target: GATE_TARGET,
            pass: tasks > 0 && completion_rate >= GATE_TARGET,
        },
        per_task,
    }
}

/// Refuse what would wipe the wrong mailbox or send a password in clear.
fn check_target(a: &Args) -> Result<()> {
    if !is_loopback_host(&a.imap_host) && !a.allow_remote {
        bail!(
            "the IMAP host is not a loopback host; mail-tasks wipes INBOX and the drafts folder of the account, so pass --allow-remote only for a throwaway test mailbox"
        );
    }
    if a.imap_plaintext_loopback && !is_loopback_host(&a.imap_host) {
        bail!("--imap-plaintext-loopback is only accepted for 127.0.0.1, ::1, or localhost");
    }
    if !valid_dataset(&a.dataset) {
        bail!("--dataset must be 1 to 64 characters of [a-z0-9-]");
    }
    if a.count == 0 {
        bail!("--count must be at least 1");
    }
    // the drafts folder is wiped too: an empty name or the INBOX would wipe the wrong thing
    let drafts = a.drafts_folder.trim();
    if drafts.is_empty() || drafts.eq_ignore_ascii_case("INBOX") {
        bail!("--drafts-folder must name a drafts folder, not the INBOX or an empty name");
    }
    Ok(())
}

/// The dataset's mailbox must be the one the flags name: the runner wipes
/// the account of `--user`, so a dataset configured for another host, port,
/// login, or drafts folder is refused before anything is touched. Messages
/// name flags, never values (a host or a folder can name a customer).
fn check_mailbox_matches(a: &Args, mailbox: &Value) -> Result<()> {
    if mailbox["imap_host"] != a.imap_host.as_str() || mailbox["imap_port"] != a.imap_port {
        bail!(
            "dataset {} points at a different IMAP host or port than --imap-host and --imap-port; the runner would wipe one mailbox and read another",
            a.dataset
        );
    }
    if mailbox["username"] != a.user.as_str() {
        bail!(
            "dataset {} was configured with a different login than --user; the runner would wipe one account and read another",
            a.dataset
        );
    }
    if let Some(configured) = mailbox["drafts_folder"].as_str() {
        if !configured.is_empty() && configured != a.drafts_folder {
            bail!(
                "dataset {} has a configured drafts folder that differs from --drafts-folder; pass --drafts-folder with the configured one",
                a.dataset
            );
        }
    }
    Ok(())
}

/// Entry point.
pub fn run(
    socket: Option<&Path>,
    data_dir: Option<&Path>,
    config: Option<&Path>,
    a: Args,
) -> Result<u8> {
    check_target(&a)?;
    let password = read_password(Some(&a.password_file), "")?;
    let account = MailAccount {
        preset: Preset::Generic,
        host: a.imap_host.clone(),
        port: a.imap_port,
        tls: !a.imap_plaintext_loopback,
        username: zeroize::Zeroizing::new(a.user.clone()),
        password,
        drafts_folder: Some(a.drafts_folder.clone()),
        from_address: None,
    };
    // the dataset must point at the same account
    let c = connect(socket, data_dir, config)?;
    let r = call(
        &c,
        Method::GET,
        &format!("/v1/datasets/{}/mailbox", a.dataset),
        None,
    )?;
    if !r.status.is_success() {
        bail!(
            "dataset {} has no mailbox ({}); run `inumaki dataset add-mailbox` first",
            a.dataset,
            error_line(&r)
        );
    }
    check_mailbox_matches(&a, &r.body)?;
    // what the run is measured against (§13.1 pinning)
    let st = call(&c, Method::GET, "/v1/status", None)?;
    if !st.status.is_success() {
        bail!("reading daemon status: {}", error_line(&st));
    }
    let profile = st.body["datasets"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|d| d["id"] == a.dataset.as_str())
        .and_then(|d| d["profile"].as_str())
        .unwrap_or("?")
        .to_string();
    let provenance = Provenance {
        daemon_version: st.body["version"].as_str().unwrap_or("?").to_string(),
        profile,
        models: st.body["models"].clone(),
        config_fingerprint: st.body["config_fingerprint"].as_str().map(str::to_string),
        runner_version: env!("CARGO_PKG_VERSION"),
    };
    let mails = generate_mailbox(&FixtureOptions {
        seed: a.seed,
        count: a.count,
        family: a.family.family(),
        ..FixtureOptions::default()
    });
    let socket_path = resolve_socket(socket, data_dir, config)?;
    let rt = tokio::runtime::Runtime::new().context("tokio runtime")?;
    let per_task = rt.block_on(run_async(&socket_path, &a, &account, &mails))?;
    let report = build_report(&a, fixture_digest(&mails), provenance, per_task);
    println!(
        "mail-tasks: tasks {} completed {} ({:.1} %) search_blocked {} search_miss {} read_blocked {} read_residue {} draft_failed {} draft_missing {} wrong_recipient {} wrong_thread {} wrong_restoration {} unresolved_tokens {} unresolved_token {} privacy_block {} mail_error {} interventions {} gate {}",
        report.tasks,
        report.completed,
        report.completion_rate * 100.0,
        report.search_blocked,
        report.search_miss,
        report.read_blocked,
        report.read_residue,
        report.draft_failed,
        report.draft_missing,
        report.wrong_recipient,
        report.wrong_thread,
        report.wrong_restoration,
        report.unresolved_tokens,
        report.unresolved_token,
        report.privacy_block,
        report.mail_error,
        report
            .interventions
            .map_or("not-measured".to_string(), |n| n.to_string()),
        if report.gate.pass { "PASS" } else { "MISSED" }
    );
    if let Some(p) = &a.report_json {
        std::fs::write(p, serde_json::to_string_pretty(&report)?)
            .with_context(|| format!("writing {}", p.display()))?;
        println!("report written to {}", p.display());
    }
    if a.require_gate && !report.gate.pass {
        return Ok(exit::TARGET_MISSED);
    }
    Ok(exit::OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens() -> Rehydrator {
        Rehydrator::new(&TokenSettings::default())
    }

    #[test]
    fn placeholders_and_the_sender_token_come_from_the_engines_grammar() {
        let t = tokens();
        assert!(has_placeholder(&t, "Hallo <PERSON_a7f2>,"));
        assert!(has_placeholder(&t, "re <CUSTOMER_ID_abc123> done"));
        assert!(
            has_placeholder(&t, "<IBAN_REMOVED>"),
            "a removed marker is a token too: it must never reach a draft"
        );
        assert!(!has_placeholder(
            &t,
            "Sehr geehrte Frau Leitner, <b>fett</b> 1 < 2 > 0"
        ));
        assert!(!has_placeholder(&t, "<PERSON_>"));
        assert_eq!(
            sender_token(&t, "**From:** <PERSON_a7f2> <<EMAIL_00ff>>\n**To:** x\n").as_deref(),
            Some("<PERSON_a7f2>")
        );
        // a person mentioned in the body is not the sender
        assert_eq!(
            sender_token(&t, "**From:** <EMAIL_00ff>\n\nHallo <PERSON_b8e3>"),
            None
        );
    }

    #[test]
    fn failures_are_classified_into_distinct_outcomes() {
        // the landed gateway's MCP errors
        assert_eq!(
            classify_mcp_message("unresolved_token"),
            Failure::UnresolvedToken
        );
        assert_eq!(classify_mcp_message("privacy_block"), Failure::PrivacyBlock);
        assert_eq!(
            classify_mcp_message("upstream_unavailable"),
            Failure::Blocked("upstream_unavailable")
        );
        assert_eq!(
            classify_mcp_message("unsupported_content"),
            Failure::Blocked("unsupported_content")
        );
        assert_eq!(
            classify_mcp_message("resource_limit"),
            Failure::Blocked("resource_limit")
        );
        assert_eq!(
            classify_mcp_message("context_unavailable"),
            Failure::Mail("context_unavailable")
        );
        // server text never becomes a detail
        assert_eq!(
            classify_mcp_message("Zyxwuria Quolnath"),
            Failure::Blocked("other_error")
        );
        // the gateway's block text and the connector's tool errors
        assert_eq!(
            classify_tool_text("blocked by inumaki (kinds: PERSON; checks: ClearValue)"),
            Failure::PrivacyBlock
        );
        assert_eq!(
            classify_tool_text("withheld by inumaki (uncertain; kinds: DATE; checks: Combination)"),
            Failure::PrivacyBlock
        );
        assert_eq!(
            classify_tool_text("mail_timeout: the mail server did not answer in time"),
            Failure::Mail("mail_timeout")
        );
        assert_eq!(
            classify_tool_text(
                "context_unavailable: the folder or message handle is unknown or stale"
            ),
            Failure::Mail("context_unavailable")
        );
        assert_eq!(
            classify_tool_text("draft_rejected: the draft could not be built"),
            Failure::Mail("draft_rejected")
        );
        assert_eq!(
            classify_tool_text("something else: Zyxwuria"),
            Failure::Blocked("tool_error")
        );
        // each class is its own outcome; the generic ones keep their step
        let cases = [
            (
                Step::Read,
                Failure::UnresolvedToken,
                "unresolved_token",
                None,
            ),
            (Step::Search, Failure::PrivacyBlock, "privacy_block", None),
            (
                Step::Draft,
                Failure::Mail("mail_timeout"),
                "mail_error",
                Some("mail_timeout"),
            ),
            (
                Step::Search,
                Failure::Blocked("transport"),
                "search_blocked",
                Some("transport"),
            ),
            (
                Step::Read,
                Failure::Blocked("tool_error"),
                "read_blocked",
                Some("tool_error"),
            ),
            (
                Step::Draft,
                Failure::Blocked("timeout"),
                "draft_failed",
                Some("timeout"),
            ),
        ];
        for (step, f, outcome, detail) in cases {
            assert_eq!(failure_outcome(step, f), (outcome, detail));
            assert!(OUTCOMES.contains(&outcome));
        }
    }

    #[test]
    fn restoration_accepts_the_whole_name_or_a_part_of_three_letters() {
        assert!(restored("Sehr geehrte/r Sarah Leitner,", "Sarah Leitner"));
        assert!(restored("Sehr geehrte Frau Leitner,", "Sarah Leitner"));
        assert!(!restored("Sehr geehrte/r <PERSON_a7f2>,", "Sarah Leitner"));
        assert!(
            !restored("Hallo Al", "Al Bo"),
            "parts under three letters do not count"
        );
    }

    fn fixture(index: usize) -> FixtureMail {
        generate_mailbox(&FixtureOptions {
            count: index + 1,
            ..FixtureOptions::default()
        })
        .remove(index)
    }

    /// A stored draft as the connector would write it: replying to `f`.
    fn stored(f: &FixtureMail, to: &str, subject: &str, refs: &[&str], body: &str) -> Vec<u8> {
        let refs = refs
            .iter()
            .map(|r| format!("<{r}>"))
            .collect::<Vec<_>>()
            .join(" ");
        format!(
            "From: agent@example.test\r\nTo: {to}\r\nSubject: {subject}\r\nMessage-ID: <d1@example.test>\r\nIn-Reply-To: <{}>\r\nReferences: {refs}\r\nDate: Mon, 5 Jan 2026 09:00:00 +0000\r\n\r\n{body}\r\n",
            f.message_id
        )
        .into_bytes()
    }

    #[test]
    fn a_draft_is_verified_for_recipient_thread_placeholders_and_restoration() {
        let t = tokens();
        // index 2 carries a Reply-To: the right recipient is that address
        let f = fixture(2);
        let reply_to = f.reply_to.clone().expect("every third mail has Reply-To");
        let subject = reply_subject(Some(&f.subject));
        let name = f.from_name.clone().unwrap_or_else(|| "Kunde".to_string());
        let check = Pending {
            fixture: &f,
            used_token: f.from_name.is_some(),
        };
        let good = stored(
            &f,
            &reply_to,
            &subject,
            &[&f.message_id],
            &format!("Sehr geehrte/r {name},"),
        );
        assert_eq!(verify_draft(&t, &check, &good), "completed");
        // to the sender instead of Reply-To
        let wrong_to = stored(
            &f,
            &f.from_address,
            &subject,
            &[&f.message_id],
            &format!("Hallo {name}"),
        );
        assert_eq!(verify_draft(&t, &check, &wrong_to), "wrong_recipient");
        // not in the thread, or with another subject
        let no_refs = stored(&f, &reply_to, &subject, &[], &format!("Hallo {name}"));
        assert_eq!(verify_draft(&t, &check, &no_refs), "wrong_thread");
        let other_subject = stored(
            &f,
            &reply_to,
            "Etwas anderes",
            &[&f.message_id],
            &format!("Hallo {name}"),
        );
        assert_eq!(verify_draft(&t, &check, &other_subject), "wrong_thread");
        // a placeholder that survived into the stored draft
        let placeholder = stored(
            &f,
            &reply_to,
            &subject,
            &[&f.message_id],
            "Hallo <PERSON_a7f2>",
        );
        assert_eq!(verify_draft(&t, &check, &placeholder), "unresolved_tokens");
        let removed = stored(
            &f,
            &reply_to,
            &subject,
            &[&f.message_id],
            &format!("Hallo {name} <IBAN_REMOVED>"),
        );
        assert_eq!(verify_draft(&t, &check, &removed), "unresolved_tokens");
        // the greeting token was not restored to the sender
        if f.from_name.is_some() {
            let not_restored = stored(&f, &reply_to, &subject, &[&f.message_id], "Hallo Unbekannt");
            assert_eq!(verify_draft(&t, &check, &not_restored), "wrong_restoration");
        }
        // unparseable bytes
        assert_eq!(verify_draft(&t, &check, b""), "draft_failed");
    }

    fn args(host: &str, plaintext: bool, allow_remote: bool, count: usize) -> Args {
        Args {
            dataset: "mt".into(),
            imap_host: host.into(),
            imap_port: 143,
            imap_plaintext_loopback: plaintext,
            allow_remote,
            user: "agent".into(),
            password_file: PathBuf::from("/nonexistent"),
            drafts_folder: "Drafts".into(),
            count,
            seed: 1,
            family: FamilyArg::Tuning,
            report_json: None,
            require_gate: false,
        }
    }

    #[test]
    fn a_non_loopback_host_is_refused_without_allow_remote() {
        let e = check_target(&args("imap.example.test", false, false, 5)).unwrap_err();
        assert!(e.to_string().contains("--allow-remote"));
        assert!(
            !e.to_string().contains("imap.example.test"),
            "a host can name a customer"
        );
        assert!(check_target(&args("imap.example.test", false, true, 5)).is_ok());
        assert!(check_target(&args("127.0.0.1", true, false, 5)).is_ok());
        // plaintext off loopback stays refused, allow-remote or not
        assert!(check_target(&args("imap.example.test", true, true, 5)).is_err());
        assert!(check_target(&args("127.0.0.1", true, false, 0)).is_err());
    }

    #[test]
    fn the_runner_refuses_to_wipe_what_the_dataset_does_not_read() {
        let mut a = args("127.0.0.1", true, false, 5);
        // the drafts folder is wiped: INBOX (any case) and an empty name are refused
        for bad in ["INBOX", "inbox", "", "  "] {
            a.drafts_folder = bad.into();
            let e = check_target(&a).unwrap_err().to_string();
            assert!(e.contains("--drafts-folder"), "{e}");
        }
        a.drafts_folder = "Drafts".into();
        assert!(check_target(&a).is_ok());
        let ok = json!({ "imap_host": "127.0.0.1", "imap_port": 143, "username": "agent", "drafts_folder": null });
        assert!(check_mailbox_matches(&a, &ok).is_ok());
        let mut other = ok.clone();
        other["imap_port"] = json!(144);
        assert!(
            check_mailbox_matches(&a, &other)
                .unwrap_err()
                .to_string()
                .contains("--imap-host")
        );
        // another login on the same server: refused, and the value is not echoed
        other = ok.clone();
        other["username"] = json!("someone-else");
        let e = check_mailbox_matches(&a, &other).unwrap_err().to_string();
        assert!(
            e.contains("--user") && !e.contains("someone-else") && !e.contains("agent"),
            "{e}"
        );
        // a configured drafts folder must be the one named
        other = ok.clone();
        other["drafts_folder"] = json!("Entw\u{fc}rfe");
        let e = check_mailbox_matches(&a, &other).unwrap_err().to_string();
        assert!(e.contains("--drafts-folder") && !e.contains("Entw"), "{e}");
        a.drafts_folder = "Entw\u{fc}rfe".into();
        assert!(check_mailbox_matches(&a, &other).is_ok());
    }

    #[test]
    fn the_report_keys_are_frozen() {
        let a = args("127.0.0.1", true, false, 2);
        let per_task = vec![
            done(0, "completed", None),
            failed(1, Step::Read, Failure::PrivacyBlock),
        ];
        let r = build_report(
            &a,
            "d".repeat(64),
            Provenance {
                daemon_version: "0.1.0".into(),
                profile: "offline".into(),
                models: json!([]),
                config_fingerprint: None,
                runner_version: "0.1.0",
            },
            per_task,
        );
        let v = serde_json::to_value(&r).unwrap();
        let keys = |v: &Value| -> Vec<String> { v.as_object().unwrap().keys().cloned().collect() };
        let mut expect = [
            "completed",
            "completion_rate",
            "count",
            "dataset",
            "draft_failed",
            "draft_missing",
            "family",
            "fixture_digest",
            "gate",
            "interventions",
            "mail_error",
            "per_task",
            "privacy_block",
            "provenance",
            "read_blocked",
            "read_residue",
            "search_blocked",
            "search_miss",
            "seed",
            "tasks",
            "unresolved_token",
            "unresolved_tokens",
            "wrong_recipient",
            "wrong_restoration",
            "wrong_thread",
        ]
        .map(String::from);
        expect.sort();
        let mut got = keys(&v);
        got.sort();
        assert_eq!(got, expect);
        let mut prov = keys(&v["provenance"]);
        prov.sort();
        assert_eq!(
            prov,
            [
                "config_fingerprint",
                "daemon_version",
                "models",
                "profile",
                "runner_version"
            ]
        );
        assert_eq!(keys(&v["gate"]), ["pass", "target"]);
        let mut task = keys(&v["per_task"][0]);
        task.sort();
        assert_eq!(
            task,
            ["detail", "index", "outcome", "residue_kinds", "step"]
        );
        // every outcome is a counter, and the counters sum to the tasks
        let sum: u64 = OUTCOMES.iter().map(|o| v[*o].as_u64().unwrap()).sum();
        assert_eq!(sum, v["tasks"].as_u64().unwrap());
        assert_eq!(v["privacy_block"], 1);
        assert_eq!(v["family"], "tuning");
        assert!(v["interventions"].is_null());
        assert_eq!(v["gate"]["target"], 0.9);
        assert_eq!(v["gate"]["pass"], false);
    }
}
