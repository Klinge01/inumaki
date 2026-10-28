//! Non-streaming answers (M8 spec §6.1, §6.4, §5.6): find the restorable
//! fields per wire format, run the tripwire on the model's raw text,
//! restore by column, splice in place, and seed the next turn. The tripwire
//! and seeding helpers are shared with plan M8-2's stream rewriter.
//!
//! Fail closed: any error (host, restoration, a splice that would not be
//! valid JSON) returns a [`Fail`] and no body, so the caller relays nothing
//! of the upstream's answer. Seeding runs last, only for an answer that is
//! relayed.
//!
//! Privacy: fields hold answer text and are never printed; [`Answer`]'s
//! `Debug` prints lengths and counts only.

use std::collections::HashMap;
use std::fmt;
use std::ops::Range;
use std::sync::Arc;

use inumaki_core::TextOrigin;
use inumaki_core::detect::path_names::PathNameDetector;
use inumaki_core::detect::{DetectCtx, Detector};
use inumaki_core::engine::normalize_input;
use inumaki_core::policy::{Action, Profile};
use inumaki_core::span::{DetectorId, EntityKind, Span};
use inumaki_core::token::parse_token;
use zeroize::Zeroizing;

use crate::cache::Cached;
use crate::config::TripwireMode;
use crate::error::Fail;
use crate::host::{ProxyEvent, Scope};
use crate::json::{self, Node, NodeKind, Seg};
use crate::pipeline::{Shared, host_fail, preserved};
use crate::restore::{Column, Restorer};
use crate::routes::{UpstreamId, Wire};
use crate::session::{ClientMode, SeedStamp, Session};
use crate::walk::Class;
use crate::wire::responses::{CODEX_ITEM_FIXED, codex_item};

/// The rewritten answer. `Debug` prints lengths and counts only.
pub(crate) struct Answer {
    /// The body to relay.
    pub body: Vec<u8>,
    /// Fields whose text changed.
    pub restored: usize,
}

impl fmt::Debug for Answer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Answer")
            .field("len", &self.body.len())
            .field("restored", &self.restored)
            .finish()
    }
}

/// What a field of an answer is (spec §6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Use {
    Text,
    /// A key or string of tool arguments (a node, or a literal inside JSON text).
    Args,
    /// Tool input that is plain text (`custom_tool_call`, or arguments that
    /// do not parse as JSON).
    PlainArgs,
    Error,
    /// Reasoning or citation text: never changed, seeded as provider-written.
    Seed,
}

/// One field: a string or key node, or a literal inside a node's JSON text.
struct Field {
    node: usize,
    inner: Option<Range<usize>>,
    text: String,
    used: Use,
}

/// Where a node sits in a known answer shape. Each node's position is its
/// parent's plus one step (parents precede children), so classifying is
/// linear in the node count and needs no per-node path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Pos {
    #[default]
    None,
    Root,
    // Messages: `content[]` blocks and their citations.
    MContent,
    MBlock,
    MCitations,
    MCitation,
    // Responses: `output[]` items, message parts, reasoning summaries.
    ROutput,
    RItem,
    RContent,
    RPart,
    RSummary,
    RSummaryPart,
    // Chat: `choices[].message`, its tool calls and functions.
    CChoices,
    CChoice,
    CMessage,
    CToolCalls,
    CToolCall,
    CFunction,
    /// Inside a Messages tool input: every key and string is an argument.
    Args,
    // Leaf positions.
    Text,
    Seed,
    /// Arguments carried as JSON text.
    InnerArgs,
    PlainArgs,
}

fn step(wire: Wire, parent: Pos, ty: Option<&str>, seg: &Seg) -> Pos {
    use Pos::*;
    let key: Option<&str> = match seg {
        Seg::Key(k) => Some(k),
        Seg::Index(_) => Option::None,
    };
    let index = key.is_none();
    match (wire, parent) {
        (_, Args) => Args,
        // Messages.
        (Wire::Messages, Root) if key == Some("content") => MContent,
        (Wire::Messages, MContent) if index => MBlock,
        (Wire::Messages, MBlock) => match (ty, key) {
            (Some("text"), Some("text")) => Text,
            (Some("text"), Some("citations")) => MCitations,
            (Some("thinking"), Some("thinking")) => Seed,
            (Some("tool_use" | "server_tool_use" | "mcp_tool_use"), Some("input")) => Args,
            _ => None,
        },
        (Wire::Messages, MCitations) if index => MCitation,
        (Wire::Messages, MCitation) if key == Some("cited_text") => Seed,
        // Responses.
        (Wire::Responses, Root) if key == Some("output") => ROutput,
        (Wire::Responses, ROutput) if index => RItem,
        (Wire::Responses, RItem) => match (ty, key) {
            (Some("message"), Some("content")) => RContent,
            (Some("function_call" | "mcp_call" | "mcp_approval_request"), Some("arguments")) => {
                InnerArgs
            }
            // A Codex MCP call's `namespace` (M8 spec §20 amendment
            // 2026-10-10): model-written like the arguments, so tripwired
            // and restored with them; a plain namespace stays as it is.
            (Some("function_call"), Some("namespace")) => Args,
            // Codex items that run locally or call a tool (fix wave 2a,
            // follow-up N4): every key and string of the item except its
            // ids, status, and type is an argument, whatever the shape.
            (Some(t), Some(k)) if codex_item(t) && !CODEX_ITEM_FIXED.contains(&k) => Args,
            (Some("custom_tool_call"), Some("input")) => PlainArgs,
            (Some("reasoning"), Some("summary")) => RSummary,
            _ => None,
        },
        (Wire::Responses, RContent) if index => RPart,
        (Wire::Responses, RPart) if matches!(key, Some("text" | "refusal")) => Text,
        (Wire::Responses, RSummary) if index => RSummaryPart,
        (Wire::Responses, RSummaryPart) if key == Some("text") => Seed,
        // Chat Completions.
        (Wire::Chat, Root) if key == Some("choices") => CChoices,
        (Wire::Chat, CChoices) if index => CChoice,
        (Wire::Chat, CChoice) if key == Some("message") => CMessage,
        (Wire::Chat, CMessage) => match key {
            Some("content" | "refusal") => Text,
            Some("tool_calls") => CToolCalls,
            Some("function_call") => CFunction,
            _ => None,
        },
        (Wire::Chat, CToolCalls) if index => CToolCall,
        (Wire::Chat, CToolCall) if key == Some("function") => CFunction,
        (Wire::Chat, CFunction) if key == Some("arguments") => InnerArgs,
        _ => None,
    }
}

/// Each string and key inside JSON-text arguments; one plain field when they
/// do not parse (the request side treats them the same way).
fn inner_fields(node: usize, text: &str, out: &mut Vec<Field>) {
    match json::scan(text.as_bytes()) {
        Ok(inner) => out.extend(
            inner
                .into_iter()
                .filter(|m| matches!(m.kind, NodeKind::String | NodeKind::Key))
                .map(|m| Field {
                    node,
                    inner: Some(m.range),
                    text: m.text.unwrap_or_default(),
                    used: Use::Args,
                }),
        ),
        Err(_) => out.push(Field {
            node,
            inner: None,
            text: text.to_string(),
            used: Use::PlainArgs,
        }),
    }
}

/// The fields of an answer: every string of an error body, else the
/// positions of spec §6.1 for `wire`.
fn classify(wire: Wire, nodes: &[Node], error: bool) -> Vec<Field> {
    let mut out = Vec::new();
    if error {
        for (i, n) in nodes.iter().enumerate() {
            if n.kind == NodeKind::String {
                out.push(Field {
                    node: i,
                    inner: None,
                    text: n.text.clone().unwrap_or_default(),
                    used: Use::Error,
                });
            }
        }
        return out;
    }
    // Each object's `type` (it may follow the keys it governs).
    let mut ty: Vec<Option<&str>> = vec![None; nodes.len()];
    for n in nodes {
        if let (NodeKind::String, Some(p), Some(Seg::Key(k))) = (n.kind, n.parent, &n.seg) {
            if k == "type" {
                ty[p] = n.text.as_deref();
            }
        }
    }
    let mut pos: Vec<Pos> = vec![Pos::None; nodes.len()];
    for (i, n) in nodes.iter().enumerate() {
        let (Some(p), Some(seg)) = (n.parent, &n.seg) else {
            pos[i] = Pos::Root;
            continue;
        };
        let parent = pos.get(p).copied().unwrap_or_default();
        if n.kind == NodeKind::Key {
            // A key is an argument when the object it sits in is, or when
            // it is a checked field name of a Codex item (follow-up N4).
            let item_key = parent == Pos::RItem
                && ty.get(p).copied().flatten().is_some_and(codex_item)
                && n.text
                    .as_deref()
                    .is_some_and(|k| !CODEX_ITEM_FIXED.contains(&k));
            if parent == Pos::Args || item_key {
                out.push(Field {
                    node: i,
                    inner: None,
                    text: n.text.clone().unwrap_or_default(),
                    used: Use::Args,
                });
            }
            continue;
        }
        let me = step(wire, parent, ty.get(p).copied().flatten(), seg);
        pos[i] = me;
        if n.kind != NodeKind::String {
            continue;
        }
        let text = n.text.clone().unwrap_or_default();
        let used = match me {
            Pos::Text => Use::Text,
            Pos::Seed => Use::Seed,
            Pos::Args => Use::Args,
            Pos::PlainArgs => Use::PlainArgs,
            Pos::InnerArgs => {
                inner_fields(i, &text, &mut out);
                continue;
            }
            _ => continue,
        };
        out.push(Field {
            node: i,
            inner: None,
            text,
            used,
        });
    }
    out
}

/// Kinds the profile does not preserve (a dataset row from `scan_known`
/// carries a kind and a count, no text).
fn kept_kind(policy: &Profile, k: &EntityKind) -> bool {
    policy.action_for(&Span::new(0, 0, k.clone(), 1.0, DetectorId::Dictionary))
        != Some(Action::Preserve)
}

/// Whether a dataset ORGANIZATION row of a profile that preserves the kind
/// still counts: `scan_known` has no text, so the datasets' dictionary is
/// run over the same texts, and the row counts when some ORGANIZATION
/// match is not `pipeline::preserved` (an identifier-shaped one, I2). The
/// dictionary spans every live dataset, so a match from another dataset
/// can make the row count (toward recall). `datasets` is fetched once.
fn unpreserved_organization(
    sh: &Shared,
    policy: &Profile,
    datasets: &mut Option<Arc<dyn Detector>>,
    nfc: &[String],
) -> Result<bool, Fail> {
    if datasets.is_none() {
        *datasets = Some(sh.host.dictionary().map_err(host_fail)?);
    }
    let d = datasets.as_ref().ok_or(Fail::Internal)?;
    for t in nfc {
        for sp in chat_spans(std::slice::from_ref(d), t, &[])? {
            if sp.kind == EntityKind::Organization && !preserved(policy, t, &sp) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Chat hits (session originals, OS identity) at full-match confidence on
/// NFC text; the per-dataset part comes from `ProxyHost::scan_known`. A hit
/// inside a preserved login in a path position (`preserved`, see
/// `ProxyHost::preserved_logins`) is dropped: the model saw it in clear.
fn chat_spans(
    dets: &[Arc<dyn Detector>],
    text: &str,
    preserved: &[String],
) -> Result<Vec<Span>, Fail> {
    let ctx = DetectCtx::for_text(text);
    let mut out = Vec::new();
    for d in dets {
        let found = d.detect(text, &ctx).map_err(|_| Fail::ModelUnavailable)?;
        out.extend(
            found
                .into_iter()
                .filter(|s| s.confidence >= 0.9 && s.start < s.end),
        );
    }
    if !preserved.is_empty() && !out.is_empty() {
        let kept: Vec<std::ops::Range<usize>> = PathNameDetector::new()
            .detect(text, &ctx)
            .map_err(|_| Fail::ModelUnavailable)?
            .into_iter()
            .filter(|p| {
                text.get(p.start..p.end)
                    .is_some_and(|t| preserved.iter().any(|l| l.eq_ignore_ascii_case(t)))
            })
            .map(|p| p.start..p.end)
            .collect();
        out.retain(|s| !kept.iter().any(|r| r.start <= s.start && s.end <= r.end));
    }
    Ok(out)
}

/// The tripwire on model output (spec §6.4), returning whether anything
/// was found. Known originals only (decision 20); kinds the profile
/// preserves are skipped; one `ClearValue` record per dataset and one for
/// chat hits, per column. In block mode a hit in `args` is
/// `Err(AnswerWithheld)` with check `ClearValue`; text never blocks. The
/// stream rewriter calls it once per completed channel.
pub(crate) fn tripwire_hits(
    sh: &Shared,
    session: &Session,
    up: UpstreamId,
    text: &[&str],
    args: &[&str],
) -> Result<bool, Fail> {
    if text.iter().chain(args).all(|t| t.is_empty()) {
        return Ok(false);
    }
    let policy = sh.host.policy(&sh.cfg.profile).map_err(host_fail)?;
    let originals = session.originals().map_err(|_| Fail::VaultUnavailable)?;
    let dets: Vec<Arc<dyn Detector>> = [
        originals.map(|d| d as Arc<dyn Detector>),
        sh.identity.clone().map(|d| d as Arc<dyn Detector>),
    ]
    .into_iter()
    .flatten()
    .collect();
    let block = sh.cfg.tripwire == TripwireMode::Block;
    let mut any = false;
    let mut args_hit: Vec<String> = Vec::new();
    let mut datasets: Option<Arc<dyn Detector>> = None;
    for (texts, is_args) in [(text, false), (args, true)] {
        let nfc: Vec<String> = texts
            .iter()
            .filter(|t| !t.is_empty())
            .map(|t| normalize_input(t).into_owned())
            .collect();
        if nfc.is_empty() {
            continue;
        }
        let blocked = is_args && block;
        for (ds, kind, n) in sh.host.scan_known(&nfc).map_err(host_fail)? {
            let counts = n > 0
                && (kept_kind(&policy, &kind)
                    || (kind == EntityKind::Organization
                        && unpreserved_organization(sh, &policy, &mut datasets, &nfc)?));
            if !counts {
                continue;
            }
            any = true;
            if is_args {
                args_hit.push(kind.label().to_string());
            }
            sh.host.record(ProxyEvent::ClearValue {
                upstream: up,
                dataset: Some(ds),
                kinds: vec![(kind, n)],
                blocked,
            });
        }
        let mut chat: Vec<(EntityKind, u32)> = Vec::new();
        for t in &nfc {
            for sp in chat_spans(&dets, t, &sh.preserved_logins)? {
                if preserved(&policy, t, &sp) {
                    continue;
                }
                match chat.iter_mut().find(|(k, _)| *k == sp.kind) {
                    Some((_, n)) => *n += 1,
                    None => chat.push((sp.kind, 1)),
                }
            }
        }
        if !chat.is_empty() {
            any = true;
            if is_args {
                args_hit.extend(chat.iter().map(|(k, _)| k.label().to_string()));
            }
            sh.host.record(ProxyEvent::ClearValue {
                upstream: up,
                dataset: None,
                kinds: chat,
                blocked,
            });
        }
    }
    if block && !args_hit.is_empty() {
        args_hit.sort();
        args_hit.dedup();
        return Err(Fail::AnswerWithheld {
            kinds: args_hit,
            checks: vec!["ClearValue".into()],
        });
    }
    Ok(any)
}

/// Seed one leaf (spec §5.6): the form the harness resends (`restored`) →
/// what the model wrote (`raw`). The cached tokens exclude removed markers.
/// An entry already there is kept: it is what an earlier request forwarded
/// for these bytes, and replacing it would change that resend. A seed was
/// never scanned, so it is stamped unverified (`Gen::ZERO`, no dataset
/// digests): its first resend scans it against the whole store.
pub(crate) fn seed_leaf(
    sh: &Shared,
    session: &Session,
    wire: Wire,
    class: Class,
    restored: &str,
    raw: &str,
) {
    let mut tokens: Vec<String> = Vec::new();
    for m in sh.tokens.find_iter(raw) {
        let t = m.as_str();
        if parse_token(&sh.cfg.session_tokens, t).is_some_and(|p| !p.removed)
            && !tokens.iter().any(|x| x == t)
        {
            tokens.push(t.to_string());
        }
    }
    // Seeds are assistant text and tool inputs, never `Role::System` leaves:
    // `Free` (a seed resent in a system position misses).
    let key = sh
        .keys
        .leaf(wire, class, TextOrigin::Free, restored.as_bytes());
    let mut cache = session.cache();
    if !cache.contains(&key) {
        cache.insert(
            key,
            Cached {
                text: raw.to_string(),
                tokens,
            },
            crate::closure::Gen::ZERO,
            std::sync::Arc::from([]),
        );
    }
}

/// Seed streamed JSON arguments (the whole JSON text, which arrived in
/// pieces) per key and string leaf, the request side's `ToolInput` blocks,
/// as `non_streaming` seeds them. Arguments that do not scan as JSON are
/// one plain leaf, as `non_streaming` treats them; when the restored and
/// the raw text differ in their leaf counts nothing is seeded.
pub(crate) fn seed_args_json(
    sh: &Shared,
    session: &Session,
    wire: Wire,
    restored: &str,
    raw: &str,
) {
    let Ok(b) = json::scan(raw.as_bytes()) else {
        seed_leaf(sh, session, wire, Class::ToolInput, restored, raw);
        return;
    };
    let Ok(a) = json::scan(restored.as_bytes()) else {
        return;
    };
    // Restored leaves are copies of originals (final review M5).
    let leaves = |n: Vec<Node>| -> Vec<Zeroizing<String>> {
        n.into_iter()
            .filter(|x| matches!(x.kind, NodeKind::String | NodeKind::Key))
            .filter_map(|x| x.text.map(Zeroizing::new))
            .collect()
    };
    let (a, b) = (leaves(a), leaves(b));
    if a.len() != b.len() {
        return;
    }
    for (r, w) in a.iter().zip(&b) {
        seed_leaf(sh, session, wire, Class::ToolInput, r, w);
    }
}

/// Mark provider-written reasoning or citation text (decision 14) with
/// `stamp`: the producing request's claim (`Prepared::seed_stamp`), never
/// the logs' length when the answer arrives (ruling I1, N1). Step 2 checks
/// the text, when resent, against what the stamp does not cover.
pub(crate) fn seed_scan(sh: &Shared, session: &Session, text: &str, stamp: SeedStamp) {
    session.seed(sh.keys.digest("scan", text.as_bytes()), stamp);
}

/// One splice: a byte range and its replacement.
type Edit = (Range<usize>, Vec<u8>);

/// The UTF-8 byte-order mark some servers put before a body.
const BOM: &[u8] = b"\xef\xbb\xbf";

/// A non-streaming answer (blocking).
///
/// A leading byte-order mark is dropped (a harness's parser may strip it,
/// e.g. Node's `fetch().json()`), and the rest is scanned, tripwired,
/// restored, and relayed without it. A 2xx body that does not scan as JSON
/// fails closed with `upstream_unreachable` and none of it is relayed:
/// streaming is never requested here, so an event stream or any other text
/// would reach the harness unchecked (a block-mode bypass). The one
/// exception is an empty 2xx body (204, or only whitespace), relayed as is.
/// An error body (status >= 400) that is not JSON is relayed unchanged: a
/// harness dispatches no tool call from an error, and nothing in it leaves
/// the machine.
///
/// The tripwire runs before restoration (2xx only); seeding runs last, and
/// not at all for a field when the tripwire found a known value in clear
/// anywhere in the answer, so a model-written original is never forwarded
/// from the cache on the next turn (the engine sees it again instead).
///
/// `scope` is [`Scope::Datasets`] on normal routes. On a check route
/// ([`Scope::Check`], spec §12.3) only the check's tokens are restored, and
/// nothing is written: no tripwire (its `ClearValue` records go through the
/// host) and no seeding (session cache, scan digests).
///
/// `seed` is the stamp of the scanned leaves seeded from this answer: the
/// producing request's `Prepared::seed_stamp()` on normal routes;
/// [`SeedStamp::unverified`] where nothing is seeded (check routes) or in
/// tests.
#[allow(clippy::too_many_arguments)]
pub(crate) fn non_streaming(
    sh: &Shared,
    session: &Session,
    wire: Wire,
    up: UpstreamId,
    mode: ClientMode,
    status: http::StatusCode,
    body: &[u8],
    scope: Scope,
    seed: SeedStamp,
) -> Result<Answer, Fail> {
    let check = matches!(scope, Scope::Check(_));
    let error = !status.is_success();
    let body = body.strip_prefix(BOM).unwrap_or(body);
    let nodes = match json::scan(body) {
        Ok(n) => n,
        Err(_)
            if error
                || body
                    .iter()
                    .all(|c| matches!(c, b' ' | b'\t' | b'\n' | b'\r')) =>
        {
            return Ok(Answer {
                body: body.to_vec(),
                restored: 0,
            });
        }
        // Streaming is never requested here (plan M8-1): an event stream or
        // any other non-JSON 2xx text is never relayed unchecked.
        Err(_) => return Err(Fail::UpstreamUnreachable),
    };
    let fields = classify(wire, &nodes, error);
    let mut hits = false;
    if !error && !check {
        let text: Vec<&str> = fields
            .iter()
            .filter(|f| f.used == Use::Text)
            .map(|f| f.text.as_str())
            .collect();
        let args: Vec<&str> = fields
            .iter()
            .filter(|f| matches!(f.used, Use::Args | Use::PlainArgs))
            .map(|f| f.text.as_str())
            .collect();
        hits = tripwire_hits(sh, session, up, &text, &args)?;
    }
    let mut restorer = Restorer::new(session, &*sh.host, &sh.tokens, scope, mode);
    let mut restored: Vec<Option<String>> = Vec::with_capacity(fields.len());
    for f in &fields {
        let col = match f.used {
            Use::Text => Column::Text,
            Use::Args | Use::PlainArgs => Column::Args,
            Use::Error => Column::Error,
            Use::Seed => {
                restored.push(None);
                continue;
            }
        };
        restored.push(Some(restorer.restore(&f.text, col)?));
    }
    drop(restorer);

    let node = |n: usize| nodes.get(n).ok_or(Fail::Internal);
    let mut edits: Vec<Edit> = Vec::new();
    let mut inner: HashMap<usize, Vec<Edit>> = HashMap::new();
    let mut changed = 0usize;
    for (f, r) in fields.iter().zip(&restored) {
        let Some(r) = r else { continue };
        if *r == f.text {
            continue;
        }
        changed += 1;
        match &f.inner {
            None => edits.push((node(f.node)?.range.clone(), json::quote(r).into_bytes())),
            Some(range) => inner
                .entry(f.node)
                .or_default()
                .push((range.clone(), json::quote(r).into_bytes())),
        }
    }
    for (n, e) in inner {
        let nd = node(n)?;
        let decoded = nd.text.as_deref().ok_or(Fail::Internal)?;
        let spliced = json::splice(decoded.as_bytes(), e).map_err(|_| Fail::Internal)?;
        // A restored key may collide with another: never hand out arguments
        // that no longer parse the way they did.
        json::scan(&spliced).map_err(|_| Fail::Internal)?;
        let s = String::from_utf8(spliced).map_err(|_| Fail::Internal)?;
        edits.push((nd.range.clone(), json::quote(&s).into_bytes()));
    }
    let out = if changed == 0 {
        body.to_vec()
    } else {
        let out = json::splice(body, edits).map_err(|_| Fail::Internal)?;
        json::scan(&out).map_err(|_| Fail::Internal)?;
        out
    };
    if !error && !check {
        for (f, r) in fields.iter().zip(&restored) {
            match (f.used, r) {
                (Use::Seed, _) => seed_scan(sh, session, &f.text, seed.clone()),
                (Use::Text, Some(r)) if !hits => {
                    seed_leaf(sh, session, wire, Class::Text, r, &f.text)
                }
                (Use::Args | Use::PlainArgs, Some(r)) if !hits => {
                    seed_leaf(sh, session, wire, Class::ToolInput, r, &f.text);
                }
                _ => {}
            }
        }
    }
    Ok(Answer {
        body: out,
        restored: changed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tripwire's preserve filter is `pipeline::preserved` (controller
    /// ruling, I2): under a profile preserving ORGANIZATION, an
    /// identifier-shaped ORGANIZATION in the answer is a hit, a name is not.
    #[test]
    fn the_tripwire_never_preserves_an_identifier_shaped_organization() {
        use crate::session::{SessionKey, SessionStore};
        use crate::testing::{CFG_ORG_PRESERVED, FakeHost};
        use inumaki_core::config::CoreConfig;
        let mut h = Arc::into_inner(FakeHost::new()).unwrap();
        let cfg = CoreConfig::from_toml(CFG_ORG_PRESERVED).unwrap();
        h.policy = Arc::new(cfg.resolve_profile("fast").unwrap());
        h.identity = vec![
            (EntityKind::Organization, "K-482913".into()),
            (EntityKind::Organization, "Qorvex Holding".into()),
        ];
        let sh = crate::pipeline::test_shared(Arc::new(h));
        let st = SessionStore::new(
            std::time::Duration::from_secs(60),
            4,
            inumaki_core::config::TokenSettings::default(),
            1 << 20,
        );
        let s = st.get(SessionKey([1; 32]));
        let hit = |t: &str| tripwire_hits(&sh, &s, UpstreamId::Anthropic, &[t], &[]).unwrap();
        assert!(hit("Kunde K-482913 angelegt."), "identifier-shaped");
        assert!(!hit("Die Qorvex Holding meldet sich."), "a preserved name");
    }

    /// A preserved login in a path is no tripwire hit (the model saw it in
    /// clear and may write it); the same login in running text still is.
    #[test]
    fn a_preserved_login_in_a_path_is_no_tripwire_hit() {
        use crate::session::{SessionKey, SessionStore};
        use crate::testing::FakeHost;
        let mut h = Arc::into_inner(FakeHost::new()).unwrap();
        h.identity = vec![(EntityKind::Person, "gruber".into())];
        h.preserved = vec!["gruber".into()];
        let sh = crate::pipeline::test_shared(Arc::new(h));
        let st = SessionStore::new(
            std::time::Duration::from_secs(60),
            4,
            inumaki_core::config::TokenSettings::default(),
            1 << 20,
        );
        let s = st.get(SessionKey([3; 32]));
        let hit = |t: &str| tripwire_hits(&sh, &s, UpstreamId::Anthropic, &[t], &[]).unwrap();
        assert!(!hit("cd /Users/gruber/project && ls"), "a path");
        assert!(!hit("see ~gruber/notes"), "a tilde path");
        assert!(hit("Hallo gruber, willkommen"), "running text");
        assert!(
            hit("cd /Users/gruber/project, ask gruber"),
            "a path and a mention"
        );
    }

    /// The same rule for a dataset row, which `scan_known` reports as a
    /// kind and a count (review fix 1): under a profile preserving
    /// ORGANIZATION, a dataset company name is no hit, an identifier-shaped
    /// dataset ORGANIZATION is.
    #[test]
    fn a_dataset_organization_counts_only_when_identifier_shaped() {
        use crate::session::{SessionKey, SessionStore};
        use crate::testing::{CFG_ORG_PRESERVED, FakeHost};
        use inumaki_core::config::CoreConfig;
        let mut h = Arc::into_inner(FakeHost::new()).unwrap();
        let cfg = CoreConfig::from_toml(CFG_ORG_PRESERVED).unwrap();
        h.policy = Arc::new(cfg.resolve_profile("fast").unwrap());
        {
            let mut ds = h.dataset.lock().unwrap();
            ds.insert(
                "<ORGANIZATION_d1d1d1>".into(),
                (EntityKind::Organization, "Qorvex Holding".into()),
            );
            ds.insert(
                "<ORGANIZATION_d2d2d2>".into(),
                (EntityKind::Organization, "K-482913".into()),
            );
        }
        let sh = crate::pipeline::test_shared(Arc::new(h));
        let st = SessionStore::new(
            std::time::Duration::from_secs(60),
            4,
            inumaki_core::config::TokenSettings::default(),
            1 << 20,
        );
        let s = st.get(SessionKey([2; 32]));
        let hit = |t: &str| tripwire_hits(&sh, &s, UpstreamId::Anthropic, &[t], &[]).unwrap();
        assert!(!hit("Die Qorvex Holding meldet sich."), "a preserved name");
        assert!(hit("Kunde K-482913 angelegt."), "identifier-shaped");
    }

    fn used(wire: Wire, body: serde_json::Value) -> Vec<(Use, String)> {
        let b = body.to_string();
        let nodes = json::scan(b.as_bytes()).unwrap();
        classify(wire, &nodes, false)
            .into_iter()
            .map(|f| (f.used, f.text))
            .collect()
    }

    /// Fix wave 2a (B), follow-up N4: every key and string of a Codex
    /// shell, patch, computer, or MCP item is an argument field (keys
    /// included, as in a Messages tool input), except `id`, `call_id`,
    /// `status`, and `type`.
    #[test]
    fn codex_item_strings_are_argument_fields() {
        let r = used(
            Wire::Responses,
            serde_json::json!({"output": [
                {"type": "shell_call", "id": "sh_1", "status": "completed", "action": {"commands": ["ls a"]}},
                {"type": "apply_patch_call", "id": "ap_1", "operation": {"type": "update_file", "path": "p", "diff": "d"}},
                {"type": "mcp_call", "id": "m", "name": "n", "arguments": "{\"k\":\"v\"}", "output": "o"}]}),
        );
        let args = |v: &[&str]| {
            v.iter()
                .map(|t| (Use::Args, t.to_string()))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            r,
            args(&[
                "action",
                "commands",
                "ls a",
                "operation",
                "diff",
                "d",
                "path",
                "p",
                "type",
                "update_file",
                "arguments",
                "k",
                "v",
                "name",
                "n",
                "output",
                "o",
            ])
        );
    }

    /// Spec §6.1's fields per wire format, and nothing else.
    #[test]
    fn fields_are_found_at_their_real_positions_only() {
        let m = used(
            Wire::Messages,
            serde_json::json!({"content": [
                {"type": "text", "text": "t", "citations": [{"cited_text": "c", "title": "x"}]},
                {"type": "thinking", "thinking": "r", "signature": "s"},
                {"type": "tool_use", "id": "i", "name": "n", "input": {"k": ["v"]}}],
              "other": {"text": "no", "input": {"k": "no"}}}),
        );
        assert_eq!(
            m,
            // serde_json sorts keys: `citations` comes before `text`.
            vec![
                (Use::Seed, "c".into()),
                (Use::Text, "t".into()),
                (Use::Seed, "r".into()),
                (Use::Args, "k".into()),
                (Use::Args, "v".into()),
            ]
        );
        let r = used(
            Wire::Responses,
            serde_json::json!({"output": [
                {"type": "reasoning", "summary": [{"type": "summary_text", "text": "r"}]},
                {"type": "message", "content": [{"type": "output_text", "text": "t", "annotations": []}, {"type": "refusal", "refusal": "f"}]},
                {"type": "function_call", "name": "n", "arguments": "{\"k\":\"v\"}"},
                {"type": "custom_tool_call", "name": "n", "input": "plain"}]}),
        );
        assert_eq!(
            r,
            vec![
                (Use::Seed, "r".into()),
                (Use::Text, "t".into()),
                (Use::Text, "f".into()),
                (Use::Args, "k".into()),
                (Use::Args, "v".into()),
                (Use::PlainArgs, "plain".into()),
            ]
        );
        let c = used(
            Wire::Chat,
            serde_json::json!({"choices": [{"message": {"role": "assistant", "content": "t", "refusal": "f",
                "tool_calls": [{"id": "x", "type": "function", "function": {"name": "n", "arguments": "not json"}}],
                "function_call": {"name": "n", "arguments": "[\"a\"]"}}}]}),
        );
        assert_eq!(
            c,
            vec![
                (Use::Text, "t".into()),
                (Use::Args, "a".into()),
                (Use::Text, "f".into()),
                (Use::PlainArgs, "not json".into()),
            ]
        );
    }
}
