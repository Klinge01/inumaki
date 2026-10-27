//! Forwarding (M8 spec §4, §5.8, §20 amendment of 2026-10-12): the request
//! header allowlist, the OAuth move, bounded decompression, and the HTTP/1.1
//! client.
//!
//! Privacy: header values carry credentials and client identity, so nothing
//! here prints, logs, or returns one. A header that is dropped is reported by
//! a label from a closed set of `&'static str` constants, never by the name or
//! value received. Errors are the fixed classes of [`Fail`] and
//! [`UpstreamError`]; `HttpUpstream`'s `Debug` prints its name.

use std::fmt;
use std::io::Read;

use bytes::Bytes;
use futures::{StreamExt, TryStreamExt};
use http::{HeaderMap, HeaderName, HeaderValue};
use subtle::ConstantTimeEq;

use crate::config::{BaseUrls, ProxyConfig};
use crate::error::Fail;
use crate::routes::UpstreamId;
use crate::session::ClientMode;
use crate::status::OauthUse;
use crate::upstream::{Upstream, UpstreamError, UpstreamRequest, UpstreamResponse};

/// Never forwarded either way: hop-by-hop headers (RFC 9110 §7.6.1), `host`,
/// and the headers that describe the body we re-encode (`content-length`,
/// `content-encoding`, `accept-encoding`). Removed by rule, not counted.
const HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
    "content-encoding",
    "accept-encoding",
];

/// Never forwarded on any upstream, not even through `extra_headers` (ruling
/// L58, spec §5.8 amendment 2026-10-10). The request allowlist already drops
/// them; the list stays so that nobody can re-enable one by configuration,
/// and so that a drop is not counted. Every name here carries a recorded
/// reason:
///
/// - `x-codex-turn-metadata` (Codex): a JSON object whose `workspaces` member
///   is keyed by the absolute repository root path (which holds the login
///   name and the project directory names) and holds the git remote's
///   host/org/repo names and the latest commit hash. No detector tokenizes
///   a header, and the header duplicates the body's
///   `client_metadata["x-codex-turn-metadata"]` (dropped as well, see
///   `walk::removal`). Codex's sticky routing uses `x-codex-turn-state`,
///   which still passes.
const STRIPPED: &[&str] = &["x-codex-turn-metadata"];

/// How a header value is checked before it is forwarded (spec §20 amendment
/// of 2026-10-12, "Value rules").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rule {
    /// Forwarded unchanged, marked sensitive, never inspected.
    Credential,
    /// 1 to 128 bytes of `A-Z a-z 0-9 . _ : -`.
    Id,
    /// 1 to 1024 bytes of `A-Z a-z 0-9 . _ : - + =`: no `/`, `\`, `~`, or space.
    Opaque,
    /// 1 to 64 bytes of `A-Z a-z 0-9 . _ : + -`.
    Token,
    /// Up to 2048 bytes of comma-separated items of 1 to 128 token bytes or `=`.
    List,
    /// Up to 256 bytes of comma-separated `type/subtype;key=value` items; the
    /// type is a registered top-level type or `*`.
    Media,
    /// Up to 256 bytes of an RFC 9110 `User-Agent`: products (`token` or
    /// `token/token`) and `(...)` comments, no `@`, `\`, `~`, and no path in
    /// a comment.
    Agent,
}

/// The ids Codex sends on `openai` and `openai-codex`.
fn codex_rule(n: &str) -> Option<Rule> {
    match n {
        "session-id"
        | "thread-id"
        | "x-client-request-id"
        | "x-codex-window-id"
        | "session_id"
        | "conversation_id" => Some(Rule::Id),
        "x-codex-turn-state" => Some(Rule::Opaque),
        "originator"
        | "x-openai-internal-codex-responses-lite"
        | "version"
        | "x-openai-subagent" => Some(Rule::Token),
        "x-codex-beta-features" => Some(Rule::List),
        _ => None,
    }
}

/// The value rule of header `name` (lowercase) on upstream `up`, or `None`
/// when the upstream does not list it. A named row wins over a prefix row.
/// Static: one `match` per upstream, no allocation.
fn rule(up: UpstreamId, name: &str) -> Option<Rule> {
    match name {
        "authorization" => return Some(Rule::Credential),
        "accept" | "content-type" => return Some(Rule::Media),
        "user-agent" => return Some(Rule::Agent),
        _ => {}
    }
    match up {
        UpstreamId::Anthropic => match name {
            "x-api-key" => Some(Rule::Credential),
            "anthropic-version" | "anthropic-dangerous-direct-browser-access" | "x-app" => {
                Some(Rule::Token)
            }
            "anthropic-beta" => Some(Rule::List),
            "x-claude-code-session-id" | "idempotency-key" => Some(Rule::Id),
            _ if name.starts_with("x-stainless-") => Some(Rule::Token),
            _ if name.starts_with("anthropic-") => Some(Rule::List),
            _ => None,
        },
        UpstreamId::Openai => match name {
            "openai-organization" | "openai-project" | "idempotency-key" => Some(Rule::Id),
            _ if name.starts_with("x-stainless-") => Some(Rule::Token),
            _ => codex_rule(name).or_else(|| name.starts_with("openai-").then_some(Rule::List)),
        },
        UpstreamId::OpenaiCodex => match name {
            "chatgpt-account-id" => Some(Rule::Credential),
            // Their row says `-` here, and a named row wins over the prefix row.
            "openai-organization" | "openai-project" => None,
            _ => codex_rule(name).or_else(|| name.starts_with("openai-").then_some(Rule::List)),
        },
    }
}

fn id_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-')
}

fn token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'+' | b'-')
}

fn opaque_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-' | b'+' | b'=')
}

/// `b` without leading and trailing spaces (and tabs, when `tabs`).
fn trim(mut b: &[u8], tabs: bool) -> &[u8] {
    let ws = |c: u8| c == b' ' || (tabs && c == b'\t');
    while let [first, rest @ ..] = b {
        if !ws(*first) {
            break;
        }
        b = rest;
    }
    while let [rest @ .., last] = b {
        if !ws(*last) {
            break;
        }
        b = rest;
    }
    b
}

fn list_ok(b: &[u8]) -> bool {
    b.len() <= 2048
        && b.split(|c| *c == b',').all(|item| {
            let item = trim(item, false);
            (1..=128).contains(&item.len()) && item.iter().all(|c| token_byte(*c) || *c == b'=')
        })
}

/// The top-level media types a `content-type` or `accept` value may name.
const MEDIA_TYPES: &[&str] = &[
    "application",
    "text",
    "multipart",
    "image",
    "audio",
    "video",
];

fn media_ok(b: &[u8]) -> bool {
    let tok = |x: &[u8]| !x.is_empty() && x.iter().all(|c| token_byte(*c));
    let star = |x: &[u8]| !x.is_empty() && x.iter().all(|c| token_byte(*c) || *c == b'*');
    !b.is_empty()
        && b.len() <= 256
        && b.split(|c| *c == b',').all(|item| {
            let mut parts = item.split(|c| *c == b';');
            let kind = trim(parts.next().unwrap_or_default(), true);
            let Some(slash) = kind.iter().position(|c| *c == b'/') else {
                return false;
            };
            let top = &kind[..slash];
            let top_ok = top == b"*"
                || MEDIA_TYPES
                    .iter()
                    .any(|t| t.as_bytes().eq_ignore_ascii_case(top));
            top_ok
                && star(&kind[slash + 1..])
                && parts.all(|p| {
                    let Some(eq) = p.iter().position(|c| *c == b'=') else {
                        return false;
                    };
                    tok(trim(&p[..eq], true)) && tok(trim(&p[eq + 1..], true))
                })
        })
}

/// RFC 9110 `token` characters, without `~` (refused in a `User-Agent`).
fn product_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
        )
}

/// `token/token`; a bare `token` only when `bare_ok`. Every `token` is a
/// valid RFC 9110 product, which would let free words through, so a bare
/// token is accepted only directly after a comment, where Codex puts the
/// terminal name (`(Ubuntu 24.04; x86_64) xterm-256color`), or, when it
/// starts with a digit, directly after a product, where the OpenAI and
/// Anthropic SDKs put the runtime version (`OpenAI/Python 1.54.0`).
fn product_ok(p: &[u8], bare_ok: bool) -> bool {
    let tok = |x: &[u8]| !x.is_empty() && x.iter().all(|c| product_byte(*c));
    match p.iter().position(|c| *c == b'/') {
        None => bare_ok && tok(p),
        Some(i) => tok(&p[..i]) && tok(&p[i + 1..]),
    }
}

/// A word inside a comment: at most one `/`, and none after only punctuation
/// (`/home`, `"/home`, `[/Users`), whatever opens the word.
fn comment_word_ok(w: &[u8]) -> bool {
    let lead = w.iter().take_while(|c| !c.is_ascii_alphanumeric());
    lead.clone().all(|c| *c != b'/') && w.iter().filter(|c| **c == b'/').count() <= 1
}

/// RFC 9110 §10.1.5: products and comments separated by spaces. A comment is
/// `(` to the first `)` with no nesting. A product is `token/token`, or a
/// bare `token` right after a comment or, if it starts with a digit, right
/// after a product (see [`product_ok`]). A `%` anywhere is refused: it would
/// carry a percent-encoded identifier past the character checks.
fn agent_ok(b: &[u8]) -> bool {
    if !(1..=256).contains(&b.len())
        || !b
            .iter()
            .all(|c| (0x20..=0x7e).contains(c) && !matches!(c, b'@' | b'\\' | b'~' | b'%'))
    {
        return false;
    }
    let mut rest = b;
    let mut elements = 0;
    let mut after_comment = false;
    let mut after_product = false;
    loop {
        while let [b' ', r @ ..] = rest {
            rest = r;
        }
        if rest.is_empty() {
            return elements > 0;
        }
        elements += 1;
        if rest[0] == b'(' {
            let Some(end) = rest.iter().position(|c| *c == b')') else {
                return false;
            };
            let body = &rest[1..end];
            rest = &rest[end + 1..];
            after_comment = true;
            after_product = false;
            if body.contains(&b'(')
                || !body.split(|c| *c == b' ').all(comment_word_ok)
                || !(rest.is_empty() || rest[0] == b' ')
            {
                return false;
            }
        } else {
            let end = rest.iter().position(|c| *c == b' ').unwrap_or(rest.len());
            let word = &rest[..end];
            let version = after_product && word[0].is_ascii_digit();
            if !product_ok(word, after_comment || version) {
                return false;
            }
            after_product = word.contains(&b'/');
            after_comment = false;
            rest = &rest[end..];
        }
    }
}

/// Whether `v` meets `rule` (spec §20 amendment of 2026-10-12). Byte loops
/// over the value; nothing is copied or logged.
fn value_ok(rule: Rule, v: &HeaderValue) -> bool {
    let b = v.as_bytes();
    match rule {
        Rule::Credential => true,
        Rule::Id => (1..=128).contains(&b.len()) && b.iter().all(|c| id_byte(*c)),
        Rule::Opaque => (1..=1024).contains(&b.len()) && b.iter().all(|c| opaque_byte(*c)),
        Rule::Token => (1..=64).contains(&b.len()) && b.iter().all(|c| token_byte(*c)),
        Rule::List => list_ok(b),
        Rule::Media => media_ok(b),
        Rule::Agent => agent_ok(b),
    }
}

/// The closed label set of the dropped-header log line: every name in the
/// spec's table (whichever upstream allows it), then the names a harness or
/// gateway adds that identify the client or the network path.
const LABELS: &[&str] = &[
    "authorization",
    "x-api-key",
    "chatgpt-account-id",
    "openai-organization",
    "openai-project",
    "accept",
    "content-type",
    "user-agent",
    "anthropic-version",
    "anthropic-beta",
    "anthropic-dangerous-direct-browser-access",
    "x-app",
    "openai-beta",
    "x-claude-code-session-id",
    "x-stainless-arch",
    "x-stainless-async",
    "x-stainless-helper-method",
    "x-stainless-lang",
    "x-stainless-os",
    "x-stainless-package-version",
    "x-stainless-read-timeout",
    "x-stainless-retry-count",
    "x-stainless-runtime",
    "x-stainless-runtime-version",
    "x-stainless-timeout",
    "idempotency-key",
    "session-id",
    "thread-id",
    "x-client-request-id",
    "x-codex-window-id",
    "session_id",
    "conversation_id",
    "x-codex-turn-state",
    "originator",
    "x-openai-internal-codex-responses-lite",
    "version",
    "x-openai-subagent",
    "x-codex-beta-features",
    "cookie",
    "traceparent",
    "tracestate",
    "baggage",
    "forwarded",
    "x-forwarded-for",
    "x-real-ip",
    "referer",
];

/// Labels for the provider namespaces, used when the name is not in [`LABELS`].
/// A trailing `*` stands for any suffix.
const PREFIX_LABELS: &[&str] = &[
    "anthropic-*",
    "openai-*",
    "x-stainless-*",
    "x-codex-*",
    "x-openai-*",
    "x-claude-code-*",
];

// `Dropped::known` is a 64-bit mask over `LABELS`; `prefixes` is an 8-bit
// mask over `PREFIX_LABELS`.
const _: () = assert!(LABELS.len() <= 64);
const _: () = assert!(PREFIX_LABELS.len() <= 8);

/// What a request's header filtering dropped (not counting the headers that
/// are removed by rule). It holds counts and bit masks over [`LABELS`] only:
/// no received name and no value, so `Debug` and `Display` cannot leak one.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Dropped {
    /// Bit `i` set: a value under `LABELS[i]` was dropped.
    known: u64,
    /// Bit `i` set: a value under `PREFIX_LABELS[i]` was dropped.
    prefixes: u8,
    /// Dropped values whose name matched no label.
    other: u16,
    /// Dropped values that failed their value rule.
    shape: u16,
    /// All dropped values.
    total: u16,
}

impl Dropped {
    /// Record one dropped value of header `name`; `shape` when its name was
    /// listed and the value failed the rule.
    fn note(&mut self, name: &str, shape: bool) {
        self.total = self.total.saturating_add(1);
        if shape {
            self.shape = self.shape.saturating_add(1);
        }
        if let Some(i) = LABELS.iter().position(|l| *l == name) {
            self.known |= 1 << i;
        } else if let Some(i) = PREFIX_LABELS
            .iter()
            .position(|p| name.starts_with(p.trim_end_matches('*')))
        {
            self.prefixes |= 1 << i;
        } else {
            self.other = self.other.saturating_add(1);
        }
    }

    /// The number of dropped values (saturating).
    pub(crate) fn count(&self) -> u16 {
        self.total
    }
}

/// The distinct labels, comma-separated, in table order, then the prefix
/// labels, then `other`.
impl fmt::Display for Dropped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        let mut put = |f: &mut fmt::Formatter<'_>, label: &str| {
            let r = if first {
                f.write_str(label)
            } else {
                write!(f, ",{label}")
            };
            first = false;
            r
        };
        for (i, l) in LABELS.iter().enumerate() {
            if self.known >> i & 1 == 1 {
                put(f, l)?;
            }
        }
        for (i, l) in PREFIX_LABELS.iter().enumerate() {
            if self.prefixes >> i & 1 == 1 {
                put(f, l)?;
            }
        }
        if self.other > 0 {
            put(f, "other")?;
        }
        Ok(())
    }
}

/// Whether `name` may be listed in `[proxy.upstreams.<id>] extra_headers`:
/// 1 to 128 bytes of lowercase RFC 9110 token characters, and not a name
/// that is never forwarded (hop-by-hop and body-framing headers, `x-inumaki-*`,
/// the [`STRIPPED`] names). Shared by `inumakid` (at load) and [`filter`].
pub fn extra_header_allowed(name: &str) -> bool {
    (1..=128).contains(&name.len())
        && name.bytes().all(|b| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
        && !HOP.contains(&name)
        && !STRIPPED.contains(&name)
        && !name.starts_with("x-inumaki-")
}

/// The headers a `Connection` header names are hop-by-hop too.
fn connection_listed(h: &HeaderMap) -> Vec<String> {
    h.get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect()
}

/// The allowlist (spec §20 amendment of 2026-10-12): the request headers that
/// go upstream on `up`, and what was dropped. In order:
///
/// 1. Hop-by-hop headers, `x-inumaki-*`, the [`STRIPPED`] names, and the
///    headers a `Connection` header names are skipped, not counted.
/// 2. A name in `extra` (configured, this upstream only) is kept unchanged and
///    marked sensitive, with no value rule.
/// 3. A name with a [`Rule`] on `up` is kept when the value meets it
///    (`Credential` values are marked sensitive).
/// 4. Everything else is counted.
pub(crate) fn filter(
    inbound: &HeaderMap,
    up: UpstreamId,
    extra: &[HeaderName],
) -> (HeaderMap, Dropped) {
    let named = connection_listed(inbound);
    let mut out = HeaderMap::with_capacity(inbound.len());
    let mut dropped = Dropped::default();
    for (k, v) in inbound {
        let n = k.as_str();
        if HOP.contains(&n)
            || n.starts_with("x-inumaki-")
            || STRIPPED.contains(&n)
            || named.iter().any(|t| t == n)
        {
            continue;
        }
        if extra.contains(k) {
            let mut v = v.clone();
            v.set_sensitive(true);
            out.append(k.clone(), v);
        } else if let Some(rule) = rule(up, n) {
            if value_ok(rule, v) {
                let mut v = v.clone();
                if rule == Rule::Credential {
                    v.set_sensitive(true);
                }
                out.append(k.clone(), v);
            } else {
                dropped.note(n, true);
            }
        } else {
            dropped.note(n, false);
        }
    }
    (out, dropped)
}

/// The headers sent upstream (spec §5.8, §20 amendment of 2026-10-12): the
/// [`filter`]ed allowlist plus `accept-encoding: identity` so answers can be
/// rewritten. A request that dropped something logs one counts-and-labels
/// line. On `Anthropic`, an `sk-ant-oat…` `x-api-key` moves to
/// `authorization: Bearer`. Also reports which OAuth counter the request
/// feeds.
pub fn outbound_headers(
    inbound: &HeaderMap,
    up: UpstreamId,
    extra: &[HeaderName],
) -> (HeaderMap, OauthUse) {
    let (mut out, dropped) = filter(inbound, up, extra);
    if dropped.count() > 0 {
        tracing::info!(
            route = up.prefix(),
            dropped = dropped.total,
            shape = dropped.shape,
            names = %dropped,
            "proxy dropped request headers"
        );
    }
    out.insert(
        http::header::ACCEPT_ENCODING,
        HeaderValue::from_static("identity"),
    );
    let oauth = match up {
        UpstreamId::Anthropic => {
            let moved = out
                .get("x-api-key")
                .and_then(|v| v.to_str().ok())
                .filter(|v| v.starts_with("sk-ant-oat"))
                .and_then(|v| {
                    // The credential string is wiped once the header holds it.
                    let bearer = zeroize::Zeroizing::new(format!("Bearer {v}"));
                    HeaderValue::from_str(&bearer).ok()
                })
                .map(|mut b| {
                    b.set_sensitive(true);
                    b
                });
            if let Some(b) = moved {
                out.remove("x-api-key");
                out.insert(http::header::AUTHORIZATION, b);
                OauthUse::Anthropic { translated: true }
            } else if out
                .get(http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.starts_with("Bearer ") && !v.starts_with("Bearer sk-ant-api"))
            {
                OauthUse::Anthropic { translated: false }
            } else {
                OauthUse::None
            }
        }
        UpstreamId::OpenaiCodex => OauthUse::CodexChatgpt,
        UpstreamId::Openai => OauthUse::None,
    };
    (out, oauth)
}

/// The upstream's headers as relayed to the client: hop-by-hop headers,
/// `content-length`, and `content-encoding` dropped (the body is relayed
/// decoded and re-framed), as are any `access-control-*` and any `x-inumaki-*`
/// (the proxy sets its own).
pub fn relay_headers(upstream: &HeaderMap) -> HeaderMap {
    let named = connection_listed(upstream);
    let mut out = HeaderMap::new();
    for (k, v) in upstream {
        let n = k.as_str();
        if HOP.contains(&n)
            || n.starts_with("access-control-")
            || n.starts_with("x-inumaki-")
            || named.iter().any(|t| t == n)
        {
            continue;
        }
        out.append(k.clone(), v.clone());
    }
    out
}

/// Decode `body` per `Content-Encoding` (`gzip`, `deflate`, `identity`, or
/// none) and bound the result: more than `max` bytes after decoding is
/// [`Fail::TooLarge`], and decoding stops at `max + 1` so a decompression
/// bomb never allocates more than that. Any other encoding, or a corrupt
/// stream, is [`Fail::BadRequest`].
pub fn decode(headers: &HeaderMap, body: Bytes, max: usize) -> Result<Bytes, Fail> {
    let enc = headers
        .get(http::header::CONTENT_ENCODING)
        .map(|v| v.to_str().unwrap_or("?").trim().to_ascii_lowercase());
    let bounded = |r: &mut dyn Read| -> Result<Bytes, Fail> {
        let mut out = Vec::new();
        r.take(max as u64 + 1)
            .read_to_end(&mut out)
            .map_err(|_| Fail::BadRequest)?;
        if out.len() > max {
            return Err(Fail::TooLarge);
        }
        Ok(Bytes::from(out))
    };
    match enc.as_deref() {
        None | Some("identity") => {
            if body.len() > max {
                Err(Fail::TooLarge)
            } else {
                Ok(body)
            }
        }
        Some("gzip") => bounded(&mut flate2::read::GzDecoder::new(&body[..])),
        Some("deflate") => bounded(&mut flate2::read::ZlibDecoder::new(&body[..])),
        Some(_) => Err(Fail::BadRequest),
    }
}

/// Whether the request named itself with the right `X-Inumaki-Client` value
/// (constant-time comparison). A wrong or absent value is `Restricted`.
pub fn client_mode(headers: &HeaderMap, value: &str) -> ClientMode {
    match headers.get("x-inumaki-client") {
        Some(v) if !value.is_empty() && bool::from(v.as_bytes().ct_eq(value.as_bytes())) => {
            ClientMode::Trusted
        }
        _ => ClientMode::Restricted,
    }
}

/// Install `ring` as the process-wide rustls provider unless one is set (the
/// same as `inumaki_gateway::ensure_crypto_provider`; `reqwest` is built
/// without a provider of its own and rustls panics without one).
pub fn ensure_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}

/// The `reqwest` upstream: HTTP/1.1, no redirects (a redirect would carry
/// the sanitized body and the credentials to another host), no automatic
/// decompression. `Debug` prints the type name only.
pub struct HttpUpstream {
    client: reqwest::Client,
    base: BaseUrls,
}

impl fmt::Debug for HttpUpstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HttpUpstream")
    }
}

impl HttpUpstream {
    /// Build the client. Fails closed with [`Fail::Internal`].
    pub fn new(cfg: &ProxyConfig) -> Result<HttpUpstream, Fail> {
        ensure_crypto_provider();
        let client = reqwest::Client::builder()
            .http1_only()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(10))
            .read_timeout(std::time::Duration::from_secs(300))
            .build()
            .map_err(|_| Fail::Internal)?;
        Ok(HttpUpstream {
            client,
            base: cfg.base_urls.clone(),
        })
    }

    fn base(&self, up: UpstreamId) -> &str {
        match up {
            UpstreamId::Anthropic => &self.base.anthropic,
            UpstreamId::Openai => &self.base.openai,
            UpstreamId::OpenaiCodex => &self.base.openai_codex,
        }
    }
}

impl Upstream for HttpUpstream {
    fn send(
        &self,
        req: UpstreamRequest,
    ) -> futures::future::BoxFuture<'static, Result<UpstreamResponse, UpstreamError>> {
        let url = format!("{}{}", self.base(req.upstream), req.path_and_query);
        let rb = self
            .client
            .request(req.method, url)
            .headers(req.headers)
            .body(req.body);
        Box::pin(async move {
            let resp = rb.send().await.map_err(|e| {
                if e.is_timeout() {
                    UpstreamError::Timeout
                } else {
                    UpstreamError::Unreachable
                }
            })?;
            let status = resp.status();
            let headers = resp.headers().clone();
            let body = resp.bytes_stream().map_err(|_| UpstreamError::Body).boxed();
            Ok(UpstreamResponse {
                status,
                headers,
                body,
            })
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn inumaki_and_hop_headers_never_leave_and_oauth_moves() {
        let mut h = http::HeaderMap::new();
        h.insert("x-inumaki-client", "secret".parse().unwrap());
        h.insert("x-inumaki-session", "s".parse().unwrap());
        h.insert("x-inumaki-profile", "p".parse().unwrap());
        h.insert("connection", "keep-alive, x-hop-named".parse().unwrap());
        h.insert("x-hop-named", "v".parse().unwrap());
        h.insert("transfer-encoding", "chunked".parse().unwrap());
        h.insert("proxy-connection", "keep-alive".parse().unwrap());
        h.insert("accept-encoding", "gzip".parse().unwrap());
        h.insert("content-encoding", "gzip".parse().unwrap());
        h.insert("host", "127.0.0.1:8787".parse().unwrap());
        h.insert("user-agent", "claude-cli/2".parse().unwrap());
        h.insert("anthropic-beta", "oauth-2025-04-20".parse().unwrap());
        h.insert("x-api-key", "sk-ant-oat01-abc".parse().unwrap());
        let (out, oauth) = outbound_headers(&h, UpstreamId::Anthropic, &[]);
        for gone in [
            "x-inumaki-client",
            "x-inumaki-session",
            "x-inumaki-profile",
            "connection",
            "x-hop-named",
            "transfer-encoding",
            "proxy-connection",
            "content-encoding",
            "host",
            "x-api-key",
        ] {
            assert!(out.get(gone).is_none(), "{gone} left");
        }
        assert_eq!(out["authorization"], "Bearer sk-ant-oat01-abc");
        assert_eq!(out["anthropic-beta"], "oauth-2025-04-20");
        assert_eq!(out["user-agent"], "claude-cli/2");
        assert_eq!(out["accept-encoding"], "identity");
        assert_eq!(oauth, OauthUse::Anthropic { translated: true });

        // An API key stays where it is; a foreign Bearer counts as OAuth
        // without a move; Codex is always the ChatGPT login.
        let mut k = http::HeaderMap::new();
        k.insert("x-api-key", "sk-ant-api03-x".parse().unwrap());
        let (out, oauth) = outbound_headers(&k, UpstreamId::Anthropic, &[]);
        assert_eq!(out["x-api-key"], "sk-ant-api03-x");
        assert_eq!(oauth, OauthUse::None);
        let mut b = http::HeaderMap::new();
        b.insert("authorization", "Bearer eyJ".parse().unwrap());
        assert_eq!(
            outbound_headers(&b, UpstreamId::Anthropic, &[]).1,
            OauthUse::Anthropic { translated: false }
        );
        assert_eq!(
            outbound_headers(&b, UpstreamId::OpenaiCodex, &[]).1,
            OauthUse::CodexChatgpt
        );
    }

    /// Ruling L58: the turn-metadata header (repository path with the login
    /// name, remote org/repo, commit hash) never leaves, on any upstream;
    /// Codex's other headers pass on the upstreams that list them
    /// (`openai`, `openai-codex`) and nowhere else.
    #[test]
    fn codex_turn_metadata_never_leaves_and_the_rest_passes() {
        const CANARY: &str = "/Users/zyxcanary/Clients/ZyxAcme/repo";
        let meta = format!(
            r#"{{"session_id":"s1","workspaces":{{"{CANARY}":{{"associated_remote_urls":{{"origin":"https://github.com/zyxorg/zyxrepo.git"}},"latest_git_commit_hash":"0123abcd","has_changes":true}}}}}}"#
        );
        let mut h = http::HeaderMap::new();
        h.insert("x-codex-turn-metadata", meta.parse().unwrap());
        let codex_only = [
            ("session-id", "019a-s"),
            ("thread-id", "019a-t"),
            ("x-client-request-id", "019a-t"),
            ("x-codex-window-id", "019a-t:0"),
            ("x-codex-turn-state", "opaque-state"),
            ("x-codex-beta-features", "a,b"),
            ("originator", "codex_exec"),
        ];
        for (k, v) in codex_only {
            h.insert(k, v.parse().unwrap());
        }
        h.insert("user-agent", "codex_exec/0.159.2".parse().unwrap());
        for up in [
            UpstreamId::Anthropic,
            UpstreamId::Openai,
            UpstreamId::OpenaiCodex,
        ] {
            let (out, _) = outbound_headers(&h, up, &[]);
            assert!(out.get("x-codex-turn-metadata").is_none(), "{up:?}");
            assert!(
                out.values()
                    .all(|v| !String::from_utf8_lossy(v.as_bytes()).contains("zyx")),
                "{up:?}"
            );
            assert_eq!(out["user-agent"], "codex_exec/0.159.2", "{up:?}");
            for (k, v) in codex_only {
                if up == UpstreamId::Anthropic {
                    assert!(out.get(k).is_none(), "{up:?} {k}");
                } else {
                    assert_eq!(out[k], v, "{up:?} {k}");
                }
            }
        }
    }

    // ---- the request allowlist (spec §20 amendment of 2026-10-12) ----

    pub(crate) const CLAUDE_CODE_2_1_296: &[(&str, &str)] = &[
        ("accept", "application/json"),
        ("content-type", "application/json"),
        ("user-agent", "claude-cli/2.1.296 (external, sdk-cli)"),
        (
            "x-claude-code-session-id",
            "0b7c1a52-93c4-4f0e-8a31-5d2e6f9b7c10",
        ),
        ("x-stainless-arch", "arm64"),
        ("x-stainless-lang", "js"),
        ("x-stainless-os", "MacOS"),
        ("x-stainless-package-version", "0.60.0"),
        ("x-stainless-retry-count", "0"),
        ("x-stainless-runtime", "node"),
        ("x-stainless-runtime-version", "v24.3.0"),
        ("x-stainless-timeout", "600"),
        (
            "anthropic-beta",
            "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,context-management-2025-06-27,prompt-caching-scope-2026-01-05,advanced-tool-use-2025-11-20",
        ),
        ("anthropic-dangerous-direct-browser-access", "true"),
        ("anthropic-version", "2023-06-01"),
        ("x-api-key", "sk-ant-api03-zyxdummy"),
        ("x-app", "cli"),
    ];

    /// Names the SDKs add that the Claude Code recording did not show.
    const SDK_EXTRAS: &[(&str, &str)] = &[
        ("x-stainless-async", "async:asyncio"),
        ("x-stainless-read-timeout", "600.0"),
        (
            "idempotency-key",
            "stainless-python-retry-3f2b8c1e-5d7a-4e1b-9c3d-2a6f8e0b4d71",
        ),
    ];

    pub(crate) const CODEX_0_159_2: &[(&str, &str)] = &[
        ("x-codex-beta-features", "shell_snapshot,unified_exec"),
        (
            "x-codex-window-id",
            "019a4c2e-7b1d-7f3a-9e5c-1d2b3a4f5e6d:0",
        ),
        ("x-openai-internal-codex-responses-lite", "true"),
        (
            "x-client-request-id",
            "019a4c2e-7b1d-7f3a-9e5c-1d2b3a4f5e6d",
        ),
        ("session-id", "019a4c2e-7b1d-7f3a-9e5c-1d2b3a4f5e6d"),
        ("thread-id", "019a4c2e-7b1d-7f3a-9e5c-1d2b3a4f5e6d"),
        ("accept", "text/event-stream"),
        ("content-type", "application/json; charset=utf-8"),
        ("authorization", "Bearer sk-zyxdummy"),
        ("originator", "codex_exec"),
        (
            "user-agent",
            "codex_exec/0.159.2 (Mac OS 26.0.0; arm64) iTerm.app/3.6.5 (codex_exec; 0.159.2)",
        ),
        // Seen in the Codex source, not in the recorded run. The turn state is
        // base64url-style: a standard-base64 `/` is dropped by `opaque` (a
        // documented residual).
        ("openai-beta", "responses=experimental"),
        ("x-codex-turn-state", "gAAAAABo-_Zt8Q==x9+aGVsbG8="),
    ];

    fn map(pairs: &[(&str, &str)]) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    fn framing_and_turn_metadata() -> Vec<(&'static str, &'static str)> {
        vec![
            ("host", "127.0.0.1:8787"),
            ("content-length", "812"),
            ("accept-encoding", "gzip, br"),
            ("x-codex-turn-metadata", "{\"workspaces\":{}}"),
        ]
    }

    #[test]
    fn recorded_harness_headers_pass() {
        let mut claude: Vec<_> = CLAUDE_CODE_2_1_296
            .iter()
            .chain(SDK_EXTRAS)
            .copied()
            .collect();
        claude.extend(framing_and_turn_metadata());
        let mut codex: Vec<_> = CODEX_0_159_2.to_vec();
        codex.extend(framing_and_turn_metadata());
        let mut chatgpt = codex.clone();
        chatgpt.push(("chatgpt-account-id", "0f6c1d9e-2b7a-4c58-9e31-7a5d4b8c2f60"));
        let mut openai_sdk: Vec<_> = SDK_EXTRAS.to_vec();
        openai_sdk.extend([
            ("authorization", "Bearer sk-zyxdummy"),
            ("openai-organization", "org-ZyxDummy1"),
            ("openai-project", "proj_ZyxDummy1"),
            ("content-type", "application/json"),
        ]);

        let cases: [(UpstreamId, &[(&str, &str)]); 4] = [
            (UpstreamId::Anthropic, &claude),
            (UpstreamId::Openai, &codex),
            (UpstreamId::OpenaiCodex, &chatgpt),
            (UpstreamId::Openai, &openai_sdk),
        ];
        for (up, set) in cases {
            let inbound = map(set);
            let (out, dropped) = filter(&inbound, up, &[]);
            assert_eq!(dropped.count(), 0, "{up:?}: {dropped}");
            let mut expected = 0;
            for (k, v) in set {
                if [
                    "host",
                    "content-length",
                    "accept-encoding",
                    "x-codex-turn-metadata",
                ]
                .contains(k)
                {
                    assert!(out.get(*k).is_none(), "{up:?} {k} left");
                    continue;
                }
                assert_eq!(out[*k], *v, "{up:?} {k}");
                assert_eq!(
                    out[*k].is_sensitive(),
                    ["authorization", "x-api-key", "chatgpt-account-id"].contains(k),
                    "{up:?} {k}"
                );
                expected += 1;
            }
            assert_eq!(out.len(), expected, "{up:?}");
            let (full, _) = outbound_headers(&inbound, up, &[]);
            assert_eq!(full["accept-encoding"], "identity");
            assert_eq!(full.len(), expected + 1, "{up:?}");
        }

        // Other realistic values of the same names.
        for (up, name, value) in [
            (
                UpstreamId::Anthropic,
                "user-agent",
                "claude-cli/2.1.296 (external, cli)",
            ),
            (
                UpstreamId::Openai,
                "user-agent",
                "codex_exec/0.159.2 (Ubuntu 24.04; x86_64) xterm-256color (codex_exec; 0.159.2)",
            ),
            (
                UpstreamId::OpenaiCodex,
                "user-agent",
                "codex_cli_rs/0.159.2 (Windows 10.0.26100; x86_64) WindowsTerminal (codex_cli_rs; 0.159.2)",
            ),
        ] {
            let (out, d) = filter(&map(&[(name, value)]), up, &[]);
            assert_eq!(out[name], value, "{up:?}");
            assert_eq!(d.count(), 0, "{up:?}");
        }
    }

    #[test]
    fn upstreams_list_only_their_own_names() {
        let mut codex = CODEX_0_159_2.to_vec();
        codex.push(("x-codex-turn-metadata", "{}"));
        let inbound = map(&codex);

        // Anthropic: the generic four pass; the Codex-specific names do not,
        // and turn metadata is removed by rule, not counted.
        let (out, d) = filter(&inbound, UpstreamId::Anthropic, &[]);
        for k in ["accept", "content-type", "user-agent", "authorization"] {
            assert!(out.get(k).is_some(), "{k}");
        }
        assert_eq!(out.len(), 4);
        assert_eq!(
            d.to_string(),
            "openai-beta,session-id,thread-id,x-client-request-id,x-codex-window-id,\
             x-codex-turn-state,originator,x-openai-internal-codex-responses-lite,\
             x-codex-beta-features"
        );
        assert_eq!(d.count(), 9);

        // `openai-organization` is a named row on `openai` only.
        let org = map(&[
            ("openai-organization", "org-1"),
            ("openai-project", "proj_1"),
        ]);
        assert_eq!(filter(&org, UpstreamId::Openai, &[]).0.len(), 2);
        let (out, d) = filter(&org, UpstreamId::OpenaiCodex, &[]);
        assert!(out.is_empty());
        assert_eq!(d.to_string(), "openai-organization,openai-project");

        // An Anthropic key on OpenAI is dropped under its own label; an
        // unknown name is `other`; unknown names in a provider namespace
        // pass with the list rule and are labelled by the prefix otherwise.
        let k = map(&[("x-api-key", "sk-ant-api03-zyx"), ("x-zyx-canary", "zyxv")]);
        let (out, d) = filter(&k, UpstreamId::Openai, &[]);
        assert!(out.is_empty());
        assert_eq!(d.to_string(), "x-api-key,other");
        let ns = map(&[("openai-future", "a,b"), ("anthropic-future", "a,b")]);
        assert_eq!(filter(&ns, UpstreamId::Openai, &[]).0.len(), 1);
        assert_eq!(filter(&ns, UpstreamId::Anthropic, &[]).0.len(), 1);
        let (_, d) = filter(&ns, UpstreamId::OpenaiCodex, &[]);
        assert_eq!(d.to_string(), "anthropic-*");
        let (_, d) = filter(
            &map(&[("x-stainless-raw-response", "true"), ("x-codex-new", "1")]),
            UpstreamId::OpenaiCodex,
            &[],
        );
        assert_eq!(d.to_string(), "x-stainless-*,x-codex-*");
    }

    fn ok(rule: Rule, v: &[u8]) -> bool {
        value_ok(rule, &HeaderValue::from_bytes(v).unwrap())
    }

    #[test]
    fn value_rules_follow_the_spec() {
        use Rule::*;
        let rules = [Id, Opaque, Token, List, Media, Agent];

        // Passing shapes, per rule.
        for (rule, v) in [
            (Id, "019a4c2e-7b1d:0"),
            (Id, "org-ZyxDummy1"),
            (Opaque, "gAAAAABo-_Zt8Q==x9+"),
            (Token, "v24.3.0"),
            (Token, "async:asyncio"),
            (List, "responses=experimental"),
            (List, "a-2025-04-20, b-2025-05-14 ,c"),
            (Media, "application/json"),
            (Media, "application/json; charset=utf-8"),
            (Media, "application/json , text/plain,*/*"),
            (Media, "text/event-stream;q = 0.5"),
            (Agent, "claude-cli/2.1.296 (external, sdk-cli)"),
            (Agent, "claude-cli/2.1.296 (external, cli)"),
            (
                Agent,
                "codex_exec/0.159.2 (Mac OS 26.0.0; arm64) iTerm.app/3.6.5 (codex_exec; 0.159.2)",
            ),
            // Documented residual (ruling L75): the rule is a shape check, so
            // the bare token after a comment passes even if it is a login name.
            (Agent, "p/1 (x) huber"),
            // Official SDK user agents: a bare version after a product.
            (Agent, "OpenAI/Python 1.54.0"),
            (Agent, "Anthropic/Python 0.40.0"),
            (Agent, "OpenAI/JS 4.104.0"),
        ] {
            assert!(ok(rule, v.as_bytes()), "{rule:?} {v}");
        }

        // Failing under every rule.
        for rule in rules {
            for v in ["", "zyx@example.at", "a\\b", "caf\u{e9}", "\u{1f600}"] {
                assert!(!ok(rule, v.as_bytes()), "{rule:?} {v:?}");
            }
        }
        assert!(!ok(Id, b"a b") && !ok(Id, b"a/b") && !ok(Token, b"a/b") && !ok(Token, b"a,b"));
        for bad in ["/Users/zyx/repo", "a/b", "~x", "a b", "a%b", "a\\b"] {
            assert!(!ok(Opaque, bad.as_bytes()), "{bad}");
        }

        // Length bounds: the longest passes, one more fails.
        let n = |c: u8, len: usize| vec![c; len];
        assert!(ok(Id, &n(b'a', 128)) && !ok(Id, &n(b'a', 129)));
        assert!(ok(Opaque, &n(b'a', 1024)) && !ok(Opaque, &n(b'a', 1025)));
        assert!(ok(Token, &n(b'a', 64)) && !ok(Token, &n(b'a', 65)));
        // 2048 bytes: 20 items of 100 bytes and a last one of 28.
        let items = |last: usize| {
            let mut v = vec![vec![b'a'; 100]; 20];
            v.push(vec![b'a'; last]);
            v.join(&b',')
        };
        assert_eq!(items(28).len(), 2048);
        assert!(ok(List, &items(28)) && !ok(List, &items(29)));
        assert!(ok(List, &n(b'a', 128)) && !ok(List, &n(b'a', 129)));
        assert!(!ok(List, b"a,,b") && !ok(List, b"a, ,b") && !ok(List, b"a b"));
        assert!(ok(Media, format!("text/{}", "b".repeat(251)).as_bytes()));
        assert!(!ok(Media, format!("text/{}", "b".repeat(252)).as_bytes()));
        let product = |len: usize| [b"p/".as_slice(), &n(b'a', len - 2)].concat();
        assert!(ok(Agent, &product(256)) && !ok(Agent, &product(257)));

        // Media structure.
        for bad in [
            "json",
            "Users/zyx",
            "foo/bar",
            "a/b/c",
            "/b",
            "a/",
            "a/b;charset",
            "a/b;=x",
            "a/b;x=",
            "a/b;",
            "a/b,",
            "a /b",
        ] {
            assert!(!ok(Media, bad.as_bytes()), "{bad}");
        }

        // Agent: products and non-nested comments. Free words outside a
        // comment fail; inside one, a word holds at most one `/` and none
        // after only punctuation, whatever opens it.
        for bad in [
            "free text",
            "p/1 (a) free text",
            "p/1 free",
            "x/huber%40acme.at",
            "p/1 (%2FUsers%2Fx)",
            "p/1 (/Users/zyx/r)",
            "p/1 (\"/home)",
            "p/1 ([/Users)",
            "p/1 ('/etc)",
            "p/1 (a/b/c)",
            "p/1 (a (nested))",
            "p/1 (open",
            "p/1 )",
            "p/1(a)",
            "(a)b",
            "/Users/zyx/repo",
            "/a/b",
            "a/b/c",
            "~/repo",
            "zyx@example.invalid",
            "C:\\Users\\zyx",
            " ",
        ] {
            assert!(!ok(Agent, bad.as_bytes()), "{bad}");
        }
        for good in ["p/1 (Users/zyx)", "p/1  (a; b)  y", "(Mac OS)", "Users/x"] {
            assert!(ok(Agent, good.as_bytes()), "{good}");
        }
        // Control characters are not printable ASCII.
        assert!(!ok(Agent, b"a\tb"));

        // A credential is never inspected.
        assert!(ok(Credential, b"") && ok(Credential, "caf\u{e9} @ \\".as_bytes()));
    }

    #[test]
    fn a_bad_value_is_dropped_and_counted_as_shape() {
        let h = map(&[
            ("user-agent", "claude-cli/2.1.296 (external, cli)"),
            ("user-agent", "zyx@example.at"),
            ("x-stainless-os", "MacOS"),
            ("x-stainless-os", "/Users/zyx"),
            ("x-zyx-canary", "v"),
        ]);
        let (out, d) = filter(&h, UpstreamId::Anthropic, &[]);
        let ua: Vec<_> = out.get_all("user-agent").iter().collect();
        assert_eq!(ua, ["claude-cli/2.1.296 (external, cli)"]);
        assert_eq!(out.get_all("x-stainless-os").iter().count(), 1);
        assert_eq!(d.count(), 3);
        assert_eq!(d.shape, 2);
        assert_eq!(d.to_string(), "user-agent,x-stainless-os,other");
    }

    #[test]
    fn a_failing_content_type_is_dropped_and_counted() {
        let (out, d) = filter(
            &map(&[("content-type", "text/plain; note=zyx@example.invalid")]),
            UpstreamId::Openai,
            &[],
        );
        assert!(out.get("content-type").is_none());
        assert_eq!((d.count(), d.shape), (1, 1));
        assert_eq!(d.to_string(), "content-type");
        let (out, d) = filter(
            &map(&[
                ("content-type", "application/json; charset=utf-8"),
                ("accept", "application/json, text/plain, */*"),
            ]),
            UpstreamId::Openai,
            &[],
        );
        assert_eq!(out["content-type"], "application/json; charset=utf-8");
        assert_eq!(out["accept"], "application/json, text/plain, */*");
        assert_eq!(d.count(), 0);
        // One good value among bad ones keeps the good one only.
        let (out, _) = filter(
            &map(&[
                ("content-type", "Users/zyx"),
                ("content-type", "application/json"),
            ]),
            UpstreamId::Openai,
            &[],
        );
        assert_eq!(out.get_all("content-type").iter().count(), 1);
        assert_eq!(out["content-type"], "application/json");
    }

    #[test]
    fn extra_headers_apply_to_their_upstream_only_and_lift_value_rules() {
        let up = http::HeaderName::from_static("x-gateway-key");
        let ua = http::HeaderName::from_static("user-agent");
        let extra = [up, ua];
        let h = map(&[
            ("x-gateway-key", "ZYX gateway/key @ value"),
            ("user-agent", "/Users/zyx/repo zyx@example.at"),
            ("x-zyx-canary", "v"),
        ]);
        let (out, d) = filter(&h, UpstreamId::Openai, &extra);
        assert_eq!(out["x-gateway-key"], "ZYX gateway/key @ value");
        assert_eq!(out["user-agent"], "/Users/zyx/repo zyx@example.at");
        assert!(out["x-gateway-key"].is_sensitive());
        assert!(out["user-agent"].is_sensitive());
        assert_eq!((d.count(), d.shape), (1, 0));
        // Another upstream, with its own (empty) list: the name is dropped.
        let (out, d) = filter(&h, UpstreamId::Anthropic, &[]);
        assert!(out.get("x-gateway-key").is_none());
        assert_eq!(d.count(), 3);
        // A configured name never overrides a never-forwarded one.
        let hop = [http::HeaderName::from_static("x-inumaki-client")];
        let (out, d) = filter(&map(&[("x-inumaki-client", "v")]), UpstreamId::Openai, &hop);
        assert!(out.is_empty() && d.count() == 0);
        // A Connection-named header is dropped even when configured.
        let (out, _) = filter(
            &map(&[("connection", "x-gateway-key"), ("x-gateway-key", "v")]),
            UpstreamId::Openai,
            &extra,
        );
        assert!(out.is_empty());
    }

    #[test]
    fn extra_header_names_are_checked() {
        let (long, too_long) = ("a".repeat(128), "a".repeat(129));
        for name in ["x-gateway-key", "a", "x_y.z~1", long.as_str()] {
            assert!(extra_header_allowed(name), "{name}");
        }
        for bad in [
            "connection",
            "host",
            "accept-encoding",
            "content-length",
            "x-inumaki-client",
            "x-inumaki-",
            "x-codex-turn-metadata",
            "X-Up",
            "",
            "a b",
            "a:b",
            "caf\u{e9}",
            too_long.as_str(),
        ] {
            assert!(!extra_header_allowed(bad), "{bad}");
        }
    }

    #[test]
    fn no_value_or_unlisted_name_in_debug_or_display() {
        let gw = http::HeaderName::from_static("x-gateway-key");
        let h = map(&[
            ("authorization", "Bearer ZYXSECRET"),
            ("x-gateway-key", "ZYXEXTRA"),
            ("user-agent", "zyx@example.at ZYXUA"),
            ("x-zyx-canary", "ZYXCANARY"),
            ("x-stainless-zyx", "ZYX/PREFIX"),
            ("cookie", "ZYXCOOKIE"),
        ]);
        let (out, d) = filter(&h, UpstreamId::Openai, &[gw]);
        assert_eq!(d.count(), 4);
        for text in [format!("{d}"), format!("{d:?}")] {
            let lower = text.to_ascii_lowercase();
            assert!(!lower.contains("zyx"), "{text}");
            assert!(!lower.contains("gateway"), "{text}");
        }
        assert_eq!(d.to_string(), "user-agent,cookie,x-stainless-*,other");
        let dbg = format!("{out:?}");
        assert!(!dbg.contains("ZYX") && !dbg.contains("zyx"), "{dbg}");
        assert!(dbg.contains("Sensitive"));
    }

    #[test]
    fn relayed_headers_drop_framing_and_keep_the_rest() {
        let mut h = http::HeaderMap::new();
        h.insert("content-length", "5".parse().unwrap());
        h.insert("content-encoding", "gzip".parse().unwrap());
        h.insert("transfer-encoding", "chunked".parse().unwrap());
        h.insert("access-control-allow-origin", "*".parse().unwrap());
        h.insert("proxy-connection", "keep-alive".parse().unwrap());
        h.insert("x-inumaki-verdict", "spoof".parse().unwrap());
        h.insert("retry-after", "3".parse().unwrap());
        h.insert("x-request-id", "r".parse().unwrap());
        let out = relay_headers(&h);
        assert_eq!(out.len(), 2);
        assert_eq!(out["retry-after"], "3");
    }

    #[test]
    fn decompression_is_bounded_after_decoding() {
        use std::io::Write;
        let gz = |data: &[u8]| {
            let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            enc.write_all(data).unwrap();
            bytes::Bytes::from(enc.finish().unwrap())
        };
        let small = gz(&vec![b'a'; 4096]);
        let mut h = http::HeaderMap::new();
        h.insert("content-encoding", "gzip".parse().unwrap());
        assert_eq!(decode(&h, small.clone(), 8192).unwrap().len(), 4096);
        assert_eq!(decode(&h, small, 1024).unwrap_err(), Fail::TooLarge);
        // A bomb: 64 MiB of zeros in a few KiB, refused at max + 1 bytes.
        let bomb = gz(&vec![0u8; 64 << 20]);
        assert!(bomb.len() < 128 << 10);
        assert_eq!(decode(&h, bomb, 1 << 20).unwrap_err(), Fail::TooLarge);
        // deflate (zlib) decodes; corrupt data and other codings are bad requests.
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(b"{}").unwrap();
        h.insert("content-encoding", "deflate".parse().unwrap());
        assert_eq!(
            &decode(&h, bytes::Bytes::from(z.finish().unwrap()), 16).unwrap()[..],
            b"{}"
        );
        assert_eq!(
            decode(&h, bytes::Bytes::from_static(b"not zlib"), 16).unwrap_err(),
            Fail::BadRequest
        );
        h.insert("content-encoding", "zstd".parse().unwrap());
        assert_eq!(
            decode(&h, bytes::Bytes::from_static(b"x"), 1024).unwrap_err(),
            Fail::BadRequest
        );
        // Uncompressed bodies are bounded too.
        h.remove("content-encoding");
        assert_eq!(
            decode(&h, bytes::Bytes::from(vec![b' '; 2048]), 1024).unwrap_err(),
            Fail::TooLarge
        );
    }

    #[test]
    fn client_mode_needs_the_exact_value() {
        let mut h = http::HeaderMap::new();
        assert_eq!(client_mode(&h, "v1"), ClientMode::Restricted);
        h.insert("x-inumaki-client", "v2".parse().unwrap());
        assert_eq!(client_mode(&h, "v1"), ClientMode::Restricted);
        h.insert("x-inumaki-client", "v1".parse().unwrap());
        assert_eq!(client_mode(&h, "v1"), ClientMode::Trusted);
        assert_eq!(client_mode(&h, ""), ClientMode::Restricted);
    }
}
