//! `inumaki-hook claude-code|codex [--socket PATH]` (M6 spec §5, §9.7 as
//! amended 2026-09-29): reads a `PostToolUse` payload, sends every key,
//! string, and number of the tool output to `POST /v1/hook` in one request,
//! and prints the harness's replacement. Every failure prints the block
//! replacement, never the original. Writes nothing to disk; stderr carries
//! fixed strings only; a block carries fixed words and entity kind labels,
//! never a part of the tool output, a path, a command, or a daemon message.

#[cfg(panic = "abort")]
compile_error!(
    "inumaki-hook must be built with panic = \"unwind\": fail_closed turns a panic into the block output"
);

pub mod leaves;
pub mod output;
pub mod payload;

use std::time::Duration;

use inumaki_client::{Client, ClientError, HookRequest, HookResponse};
use serde_json::Value;

/// The hook's own deadline, below every harness's hook timeout (spec §5.1;
/// the adapters write `timeout: 30`).
pub const DEADLINE: Duration = Duration::from_secs(10);
/// Total bytes of one request's texts: the control API's 16 MiB
/// `BODY_LIMIT` minus room for the JSON envelope and escaping. Over it the
/// hook blocks (it never truncates); an output whose escaping still pushes
/// the body over `BODY_LIMIT` gets the daemon's `413`, also a block.
pub const MAX_TOTAL: usize = 12 * 1024 * 1024;
/// Bytes read from stdin.
pub const MAX_STDIN: usize = 32 * 1024 * 1024;

/// Which harness format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Harness {
    /// Claude Code.
    ClaudeCode,
    /// Codex.
    Codex,
}

impl Harness {
    /// `claude-code` or `codex`.
    pub fn parse(s: &str) -> Option<Harness> {
        match s {
            "claude-code" => Some(Harness::ClaudeCode),
            "codex" => Some(Harness::Codex),
            _ => None,
        }
    }
}

/// Why an output was blocked (fixed words in the replacement).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockClass {
    /// No service on the socket.
    DaemonUnreachable,
    /// The deadline passed.
    Timeout,
    /// Verification blocked it, or a key, number, or discriminator would
    /// change, or the output holds data that cannot be sanitized in place.
    PrivacyBlock,
    /// Over the size limits.
    TooLarge,
    /// The payload lacked the needed fields.
    UnparsablePayload,
    /// Any other daemon answer (a non-200 status, an unreadable body, a
    /// `replace` with a different number of texts).
    DaemonError,
    /// A panic or setup failure.
    Internal,
}

impl BlockClass {
    /// The class word in the block message.
    pub fn as_str(self) -> &'static str {
        match self {
            BlockClass::DaemonUnreachable => "daemon_unreachable",
            BlockClass::Timeout => "timeout",
            BlockClass::PrivacyBlock => "privacy_block",
            BlockClass::TooLarge => "too_large",
            BlockClass::UnparsablePayload => "unparsable_payload",
            BlockClass::DaemonError => "daemon_error",
            BlockClass::Internal => "internal",
        }
    }
}

/// A block with its kinds.
#[derive(Debug, Clone)]
pub struct Blocked {
    /// Class.
    pub class: BlockClass,
    /// Entity kind labels.
    pub kinds: Vec<String>,
}

/// An entity kind label as the daemon sends it (`PERSON`, `CUSTOMER_ID`).
/// Anything else is printed as `OTHER`: the block text holds fixed words only.
fn safe_kind(k: &str) -> &str {
    let ok = !k.is_empty()
        && k.len() <= 40
        && k.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
    if ok { k } else { "OTHER" }
}

/// The fixed sentence a [`BlockClass::DaemonUnreachable`] block ends with
/// (ruling L97): the hook stays fail-closed while the service is down, so
/// the model and the user learn the recovery. Fixed words only: no socket,
/// path, or other value.
pub const DAEMON_UNREACHABLE_RECOVERY: &str =
    "inumaki is not running; start it to restore tool output.";

/// `blocked by inumaki (<class>; kinds: …)`; a
/// [`BlockClass::DaemonUnreachable`] block adds `. ` and
/// [`DAEMON_UNREACHABLE_RECOVERY`].
pub fn block_message(b: &Blocked) -> String {
    let mut kinds: Vec<&str> = Vec::new();
    for k in &b.kinds {
        let k = safe_kind(k);
        if !kinds.contains(&k) {
            kinds.push(k);
        }
    }
    let kinds = if kinds.is_empty() {
        "none".to_string()
    } else {
        kinds.join(", ")
    };
    let msg = format!("blocked by inumaki ({}; kinds: {kinds})", b.class.as_str());
    match b.class {
        BlockClass::DaemonUnreachable => format!("{msg}. {DAEMON_UNREACHABLE_RECOVERY}"),
        _ => msg,
    }
}

fn classify(e: &ClientError) -> BlockClass {
    match e {
        ClientError::Connect(_) => BlockClass::DaemonUnreachable,
        ClientError::Timeout => BlockClass::Timeout,
        ClientError::Status { status: 451, .. } => BlockClass::PrivacyBlock,
        ClientError::Status { status: 413, .. } => BlockClass::TooLarge,
        _ => BlockClass::DaemonError,
    }
}

/// [`run_with_deadline`] with [`DEADLINE`].
pub async fn run(h: Harness, stdin: &[u8], client: &Client) -> Option<String> {
    run_with_deadline(h, stdin, client, DEADLINE).await
}

/// Decode a payload: strict JSON, else once more after
/// [`payload::fix_lone_surrogates`] (a lone surrogate escape from a
/// JavaScript harness). `None` when it still does not decode.
pub fn decode(stdin: &[u8]) -> Option<Value> {
    serde_json::from_slice(stdin).ok().or_else(|| {
        let fixed = payload::fix_lone_surrogates(stdin)?;
        serde_json::from_slice(&fixed).ok()
    })
}

/// The block for stdin that does not decode, in the template of the tool
/// name [`payload::recover_tool_name`] finds (a bare string only when none
/// is found, which Claude Code would refuse for a built-in tool).
pub fn undecodable(h: Harness, stdin: &[u8], class: BlockClass) -> String {
    let name = payload::recover_tool_name(stdin);
    output::block(
        h,
        name.as_deref(),
        &Blocked {
            class,
            kinds: Vec::new(),
        },
    )
}

/// The output to print: `None` passes the original unchanged (the daemon
/// said `pass`, or the output has no text); `Some` is a replacement or a block.
pub async fn run_with_deadline(
    h: Harness,
    stdin: &[u8],
    client: &Client,
    deadline: Duration,
) -> Option<String> {
    match decode(stdin) {
        Some(v) => run_payload(h, v, client, deadline).await,
        None => Some(undecodable(h, stdin, BlockClass::UnparsablePayload)),
    }
}

/// [`run_with_deadline`] on an already decoded payload. The binary decodes
/// first so that it knows the tool name, and with it the block template,
/// should a later step panic.
pub async fn run_payload(
    h: Harness,
    v: Value,
    client: &Client,
    deadline: Duration,
) -> Option<String> {
    let block = |name: Option<&str>, class: BlockClass, kinds: Vec<String>| {
        Some(output::block(h, name, &Blocked { class, kinds }))
    };
    let name = payload::tool_name(&v).map(str::to_string);
    let call = match payload::parse(h, v) {
        Ok(c) => c,
        Err(class) => return block(name.as_deref(), class, Vec::new()),
    };
    let name = Some(call.name.as_str());
    let texts = leaves::texts(&call.response);
    if texts.iter().all(String::is_empty) {
        return None;
    }
    if texts.iter().map(String::len).sum::<usize>() > MAX_TOTAL {
        return block(name, BlockClass::TooLarge, Vec::new());
    }
    let sent = texts.len();
    let req = HookRequest {
        harness: call.harness,
        tool: call.tool,
        cwd: call.cwd.clone(),
        paths: call.paths.clone(),
        texts,
    };
    match client.clone().with_timeout(deadline).hook(&req).await {
        Ok(HookResponse::Pass) => None,
        Ok(HookResponse::Replace { texts, kinds }) => {
            if texts.len() != sent {
                return block(name, BlockClass::DaemonError, Vec::new());
            }
            if call.binary {
                // Base64 data cannot be sanitized in place.
                return block(name, BlockClass::PrivacyBlock, kinds);
            }
            let mut response = call.response.clone();
            if !leaves::write_back(&mut response, &texts) {
                // A key, number, or discriminator had a hit: its shape cannot hold a token.
                return block(name, BlockClass::PrivacyBlock, kinds);
            }
            Some(output::replace(h, response, &kinds))
        }
        Err(e) => {
            let kinds = e.detail().map(|d| d.kinds.clone()).unwrap_or_default();
            block(name, classify(&e), kinds)
        }
    }
}

/// Run `f`; a panic becomes the block replacement (spec §5.1), in the
/// template of `tool_name` when known (a bare string would be refused by a
/// Claude Code built-in tool, and the original used). The binary installs a
/// panic hook that prints a fixed line, so the panic message (which can
/// hold `Debug` of values) never reaches stderr.
pub fn fail_closed(
    h: Harness,
    tool_name: Option<&str>,
    f: impl FnOnce() -> Option<String> + std::panic::UnwindSafe,
) -> Option<String> {
    std::panic::catch_unwind(f).unwrap_or_else(|_| {
        let b = Blocked {
            class: BlockClass::Internal,
            kinds: Vec::new(),
        };
        Some(output::block(h, tool_name, &b))
    })
}
