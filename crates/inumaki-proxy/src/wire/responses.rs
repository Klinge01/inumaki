//! The Responses stream codec, also used for the Codex backend (M8 spec
//! §6.2 table, second row): deltas for text, refusals, function arguments,
//! and custom tool input; the `done` events and `response.completed` repeat
//! the full text; reasoning passes and its summaries are seeded from
//! completed items.
//!
//! Channels: text and refusal parts are `(output_index, content_index)`; a
//! call's arguments or a custom tool's input are `(output_index, u32::MAX)`.
//!
//! Framing the engine cannot check aborts the stream: a call item added
//! with arguments (or a custom tool item with input, a content part with
//! text, a `response.created` that already carries output) would reach the
//! client unrestored and untripwired.
//!
//! Codex items that run locally or call a tool (fix wave 2a): an `mcp_call`
//! streams its arguments like a function call (`response.mcp_call_arguments.*`).
//! `shell_call`, `local_shell_call`, `apply_patch_call`, `computer_call`,
//! and `mcp_approval_request` items are handled whole wherever they appear
//! (`output_item.added`, `output_item.done`, `response.completed`): every
//! string and key of the item except `id`, `call_id`, `status`, and `type`
//! is an argument ([`Act::Whole`]; the same for an `mcp_call`'s fields
//! other than its `arguments` channel), and block mode withholds the item from its `added`
//! event until its `done` event passed. Any other event of these items
//! (their type prefix, or their `output_index`) that carries more than ids
//! aborts: the engine does not know its shape, so it cannot check it.
//!
//! `sequence_number`: every synthesized delta takes the next number and every
//! later event's number is shifted by the count synthesized so far, so the
//! client sees strictly increasing numbers. Events before the first
//! synthesized delta stay byte-identical.

use std::collections::{HashMap, HashSet};
use std::ops::Range;

use crate::error::Fail;
use crate::json::{self, Node, NodeKind, Seg};
use crate::sse::{self, SseEvent};
use crate::stream::{
    Abort, Act, ChanKey, ChanKind, P, P::I, P::K, abort_message, carries, elements, find, index_at,
    join, num_at, str_at,
};

fn args(oi: u32) -> ChanKey {
    ChanKey { a: oi, b: u32::MAX }
}

/// Item types that arrive whole, with no delta channel the engine knows,
/// and run locally or call a tool.
fn arrives_whole(ty: &str) -> bool {
    matches!(
        ty,
        "shell_call"
            | "local_shell_call"
            | "apply_patch_call"
            | "computer_call"
            | "mcp_approval_request"
    )
}

/// The Codex item types whose model-written strings are arguments: the
/// whole types and `mcp_call` (whose `arguments` stream as a channel).
pub(crate) fn codex_item(ty: &str) -> bool {
    arrives_whole(ty) || ty == "mcp_call"
}

/// The fields of a [`codex_item`] that are never checked (follow-up N4):
/// every other string and key of the item is an argument, whatever its
/// shape.
pub(crate) const CODEX_ITEM_FIXED: &[&str] = &["id", "call_id", "status", "type"];

/// Event-type prefixes of the items above and of `mcp_call`.
const ITEM_EVENTS: &[&str] = &[
    "response.shell_call",
    "response.local_shell_call",
    "response.apply_patch_call",
    "response.computer_call",
    "response.mcp_call",
    "response.mcp_approval_request",
];

/// The top-level keys of an event that only reports an item's status.
const STATUS_KEYS: &[&str] = &["type", "item_id", "output_index", "sequence_number"];

/// Whether every top-level key of the payload is a status key.
fn status_only(nodes: &[Node]) -> bool {
    let Some(root) = nodes.iter().position(|n| n.parent.is_none()) else {
        return true;
    };
    nodes
        .iter()
        .filter(|n| n.parent == Some(root) && n.kind == NodeKind::Key)
        .all(|n| n.text.as_deref().is_some_and(|k| STATUS_KEYS.contains(&k)))
}

/// The string and key nodes at and below node `root` (parents precede
/// children).
fn strings_under(nodes: &[Node], root: usize, kind: ChanKind) -> Vec<(usize, ChanKind)> {
    let mut inside = vec![false; nodes.len()];
    let mut out = Vec::new();
    for i in root..nodes.len() {
        inside[i] = i == root || nodes[i].parent.is_some_and(|p| p >= root && inside[p]);
        if inside[i] && matches!(nodes[i].kind, NodeKind::String | NodeKind::Key) {
            out.push((i, kind));
        }
    }
    out
}

/// The [`Act::Whole`] fields of a [`codex_item`] at `pre`: every string
/// and key of the item except [`CODEX_ITEM_FIXED`] (follow-up N4), as plain
/// arguments; the `arguments` JSON text of an `mcp_approval_request` as JSON
/// arguments; an `mcp_call`'s `arguments` are its channel, not listed here.
///
/// A `function_call`'s `namespace` (how Codex 0.159.2 calls an MCP tool,
/// M8 spec §20 amendment 2026-10-10) arrives whole too: model-written, so
/// tripwired and restored as plain arguments, whatever its shape.
fn whole(nodes: &[Node], pre: &[P<'_>], ty: &str) -> Vec<(usize, ChanKind)> {
    if ty == "function_call" {
        return find(nodes, &join(pre, &[K("namespace")]))
            .map(|n| strings_under(nodes, n, ChanKind::PlainArgs))
            .unwrap_or_default();
    }
    if !codex_item(ty) {
        return Vec::new();
    }
    let Some(item) = find(nodes, pre) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (i, n) in nodes.iter().enumerate().skip(item + 1) {
        if n.parent != Some(item) {
            continue;
        }
        let name = match (n.kind, &n.seg) {
            (NodeKind::Key, _) => n.text.as_deref(),
            (_, Some(Seg::Key(k))) => Some(k.as_str()),
            _ => None,
        };
        let Some(name) = name else { continue };
        if CODEX_ITEM_FIXED.contains(&name) {
            continue;
        }
        if n.kind == NodeKind::Key {
            out.push((i, ChanKind::PlainArgs));
            continue;
        }
        match (ty, name) {
            ("mcp_call", "arguments") => {}
            ("mcp_approval_request", "arguments") if n.kind == NodeKind::String => {
                out.push((i, ChanKind::JsonArgs));
            }
            _ => out.extend(strings_under(nodes, i, ChanKind::PlainArgs)),
        }
    }
    out
}

#[derive(Default)]
pub(crate) struct Codec {
    /// `item_id` of each channel, for synthesized deltas.
    ids: HashMap<ChanKey, String>,
    /// Text channels that are refusals (their synthesized delta says so).
    refusal: HashSet<ChanKey>,
    response_id: Option<String>,
    /// The upstream's last `sequence_number`.
    last: Option<u64>,
    /// How many events this codec added: the offset of later numbers.
    shift: u64,
    /// The `response.output` of a forwarded `response.failed`, replaced by `[]`.
    blank: Option<Range<usize>>,
    /// Argument channels of `mcp_call` items (their synthesized deltas).
    mcp: HashSet<ChanKey>,
    /// `output_index` of the items whose other events must carry ids only.
    local: HashSet<u32>,
}

/// Restorable fields of an output item at `pre`, the channels it ends,
/// its reasoning-summary texts, and its whole argument strings.
type Item = (
    Vec<ChanKey>,
    Vec<(usize, ChanKey, ChanKind)>,
    Vec<usize>,
    Vec<(usize, ChanKind)>,
);

fn item(nodes: &[Node], pre: &[P<'_>], oi: u32) -> Item {
    let at = |tail: &[P<'static>]| join(pre, tail);
    let (mut ends, mut fields, mut reasoning) = (Vec::new(), Vec::new(), Vec::new());
    let ty = str_at(nodes, &at(&[K("type")]));
    if ty.is_some_and(arrives_whole) {
        ends.push(args(oi));
    }
    let whole = ty.map(|t| whole(nodes, pre, t)).unwrap_or_default();
    match ty {
        Some("message") => {
            for k in elements(nodes, &at(&[K("content")])) {
                let Ok(b) = u32::try_from(k) else { continue };
                let ch = ChanKey { a: oi, b };
                ends.push(ch);
                for f in ["text", "refusal"] {
                    if let Some(n) = find(nodes, &at(&[K("content"), I(k), K(f)])) {
                        fields.push((n, ch, ChanKind::Text));
                    }
                }
            }
        }
        Some("function_call" | "mcp_call") => {
            ends.push(args(oi));
            if let Some(n) = find(nodes, &at(&[K("arguments")])) {
                fields.push((n, args(oi), ChanKind::JsonArgs));
            }
        }
        Some("custom_tool_call") => {
            ends.push(args(oi));
            if let Some(n) = find(nodes, &at(&[K("input")])) {
                fields.push((n, args(oi), ChanKind::PlainArgs));
            }
        }
        Some("reasoning") => {
            for k in elements(nodes, &at(&[K("summary")])) {
                if let Some(n) = find(nodes, &at(&[K("summary"), I(k), K("text")])) {
                    reasoning.push(n);
                }
            }
        }
        _ => {}
    }
    (ends, fields, reasoning, whole)
}

impl Codec {
    fn remember(&mut self, ch: ChanKey, nodes: &[Node]) {
        if let Some(id) = str_at(nodes, &[K("item_id")]) {
            self.ids.entry(ch).or_insert_with(|| id.to_string());
        }
    }

    /// The number for an event this codec adds after the upstream's last
    /// one; later upstream numbers move up by one.
    fn next_seq(&mut self) -> Option<u64> {
        let last = self.last?;
        self.shift += 1;
        Some(last + self.shift)
    }

    /// `None` = the event's framing cannot be checked (the caller refuses).
    fn acts(&mut self, data: &[u8], nodes: &[Node]) -> Option<Vec<Act>> {
        let index = |name: &str| index_at(data, nodes, &[K(name)], u32::MAX - 1).ok();
        let field = |name: &str| find(nodes, &[K(name)]);
        Some(match str_at(nodes, &[K("type")]).unwrap_or("") {
            "response.created" | "response.in_progress" | "response.queued" => {
                // The stream starts empty; output carried here is unrestored text.
                if !elements(nodes, &[K("response"), K("output")]).is_empty() {
                    return None;
                }
                if let Some(id) = str_at(nodes, &[K("response"), K("id")]) {
                    self.response_id.get_or_insert_with(|| id.to_string());
                }
                vec![Act::Pass]
            }
            "response.output_item.added" => {
                let oi = index("output_index")?.unwrap_or(0);
                match str_at(nodes, &[K("item"), K("type")]) {
                    Some(t @ ("function_call" | "custom_tool_call" | "mcp_call")) => {
                        let (field, kind) = if t == "custom_tool_call" {
                            ("input", ChanKind::PlainArgs)
                        } else {
                            ("arguments", ChanKind::JsonArgs)
                        };
                        if carries(data, nodes, &[K("item"), K(field)]) {
                            return None;
                        }
                        if let Some(id) = str_at(nodes, &[K("item"), K("id")]) {
                            self.ids.insert(args(oi), id.to_string());
                        }
                        if t == "mcp_call" {
                            self.mcp.insert(args(oi));
                            self.local.insert(oi);
                        }
                        vec![
                            Act::Open { ch: args(oi), kind },
                            Act::Whole(whole(nodes, &[K("item")], t)),
                        ]
                    }
                    // Whole items: withheld in block mode from here until
                    // their `done` event; what this event carries is checked now.
                    Some(t) if arrives_whole(t) => {
                        self.local.insert(oi);
                        vec![
                            Act::Open {
                                ch: args(oi),
                                kind: ChanKind::PlainArgs,
                            },
                            Act::Whole(whole(nodes, &[K("item")], t)),
                        ]
                    }
                    Some("message") => {
                        for k in elements(nodes, &[K("item"), K("content")]) {
                            for f in ["text", "refusal"] {
                                if carries(data, nodes, &[K("item"), K("content"), I(k), K(f)]) {
                                    return None;
                                }
                            }
                        }
                        vec![Act::Pass]
                    }
                    _ => vec![Act::Pass],
                }
            }
            "response.content_part.added" => {
                if str_at(nodes, &[K("part"), K("type")]) != Some("reasoning_text")
                    && ["text", "refusal"]
                        .iter()
                        .any(|f| carries(data, nodes, &[K("part"), K(f)]))
                {
                    return None;
                }
                vec![Act::Pass]
            }
            t @ ("response.output_text.delta" | "response.refusal.delta") => {
                let part = ChanKey {
                    a: index("output_index")?.unwrap_or(0),
                    b: index("content_index")?.unwrap_or(0),
                };
                self.remember(part, nodes);
                if t == "response.refusal.delta" {
                    self.refusal.insert(part);
                }
                field("delta")
                    .map(|n| {
                        vec![Act::Delta {
                            ch: part,
                            kind: ChanKind::Text,
                            node: n,
                        }]
                    })
                    .unwrap_or_default()
            }
            t @ ("response.function_call_arguments.delta"
            | "response.custom_tool_call_input.delta"
            | "response.mcp_call_arguments.delta") => {
                let ch = args(index("output_index")?.unwrap_or(0));
                self.remember(ch, nodes);
                if t.starts_with("response.mcp") {
                    self.mcp.insert(ch);
                }
                let kind = if t.contains("custom") {
                    ChanKind::PlainArgs
                } else {
                    ChanKind::JsonArgs
                };
                field("delta")
                    .map(|n| vec![Act::Delta { ch, kind, node: n }])
                    .unwrap_or_default()
            }
            t @ ("response.output_text.done" | "response.refusal.done") => {
                let part = ChanKey {
                    a: index("output_index")?.unwrap_or(0),
                    b: index("content_index")?.unwrap_or(0),
                };
                let name = if t == "response.refusal.done" {
                    "refusal"
                } else {
                    "text"
                };
                vec![Act::Repeat {
                    end: vec![part],
                    fields: field(name)
                        .map(|n| vec![(n, part, ChanKind::Text)])
                        .unwrap_or_default(),
                }]
            }
            // Reasoning is never changed, tripwired, or seeded from here.
            "response.content_part.done"
                if str_at(nodes, &[K("part"), K("type")]) == Some("reasoning_text") =>
            {
                vec![Act::Pass]
            }
            "response.content_part.done" => {
                let part = ChanKey {
                    a: index("output_index")?.unwrap_or(0),
                    b: index("content_index")?.unwrap_or(0),
                };
                let fields = ["text", "refusal"]
                    .iter()
                    .filter_map(|f| find(nodes, &[K("part"), K(f)]))
                    .map(|n| (n, part, ChanKind::Text))
                    .collect();
                vec![Act::Repeat {
                    end: vec![part],
                    fields,
                }]
            }
            t @ ("response.function_call_arguments.done"
            | "response.custom_tool_call_input.done"
            | "response.mcp_call_arguments.done") => {
                let ch = args(index("output_index")?.unwrap_or(0));
                let (name, kind) = if t.contains("custom") {
                    ("input", ChanKind::PlainArgs)
                } else {
                    ("arguments", ChanKind::JsonArgs)
                };
                vec![Act::Repeat {
                    end: vec![ch],
                    fields: field(name).map(|n| vec![(n, ch, kind)]).unwrap_or_default(),
                }]
            }
            "response.output_item.done" => {
                let oi = index("output_index")?.unwrap_or(0);
                let (end, fields, reasoning, whole) = item(nodes, &[K("item")], oi);
                vec![
                    Act::Reasoned(reasoning),
                    Act::Repeat { end, fields },
                    Act::Whole(whole),
                ]
            }
            "response.completed" | "response.incomplete" => {
                let (mut fields, mut reasoning, mut wholes) = (Vec::new(), Vec::new(), Vec::new());
                for j in elements(nodes, &[K("response"), K("output")]) {
                    let oi = u32::try_from(j).ok()?;
                    let (_, f, r, w) = item(nodes, &[K("response"), K("output"), I(j)], oi);
                    fields.extend(f);
                    reasoning.extend(r);
                    wholes.extend(w);
                }
                vec![
                    Act::Reasoned(reasoning),
                    Act::Whole(wholes),
                    Act::Terminal { fields },
                ]
            }
            "response.failed" | "error" => {
                // Forwarded without the output it carries: a call the provider
                // completed before failing is neither restored nor tripwired.
                if !elements(nodes, &[K("response"), K("output")]).is_empty() {
                    self.blank =
                        find(nodes, &[K("response"), K("output")]).map(|i| nodes[i].range.clone());
                }
                vec![Act::Failed]
            }
            // Another event of a whole item or an MCP call (by type, or by
            // the item's `output_index`): passed when it carries ids only.
            t => {
                let oi = index_at(data, nodes, &[K("output_index")], u32::MAX - 1)
                    .ok()
                    .flatten();
                let of_item = ITEM_EVENTS.iter().any(|p| t.starts_with(p))
                    || oi.is_some_and(|o| self.local.contains(&o));
                if of_item && !status_only(nodes) {
                    return None;
                }
                vec![Act::Pass]
            }
        })
    }
}

impl crate::stream::Codec for Codec {
    fn classify(&mut self, ev: &SseEvent, data: &[u8], nodes: &[Node]) -> Vec<Act> {
        // The SDKs dispatch on the event name and read the payload's
        // `type`: when the two differ, or a named event has no `type`, the
        // engine and the client would disagree on what the event is (final
        // review I1, N2).
        if ev
            .event
            .as_deref()
            .is_some_and(|e| str_at(nodes, &[K("type")]) != Some(e))
        {
            return vec![Act::Refuse];
        }
        self.acts(data, nodes).unwrap_or_else(|| vec![Act::Refuse])
    }

    fn synth(&mut self, ch: ChanKey, kind: ChanKind, text: &str) -> Result<Vec<u8>, Fail> {
        let ty = match kind {
            ChanKind::Text if self.refusal.contains(&ch) => "response.refusal.delta",
            ChanKind::Text => "response.output_text.delta",
            ChanKind::JsonArgs if self.mcp.contains(&ch) => "response.mcp_call_arguments.delta",
            ChanKind::JsonArgs => "response.function_call_arguments.delta",
            ChanKind::PlainArgs => "response.custom_tool_call_input.delta",
        };
        let mut data = serde_json::json!({"type": ty, "output_index": ch.a, "delta": text});
        if kind == ChanKind::Text {
            data["content_index"] = serde_json::json!(ch.b);
            if ty == "response.output_text.delta" {
                data["logprobs"] = serde_json::json!([]);
            }
        }
        if let Some(id) = self.ids.get(&ch) {
            data["item_id"] = serde_json::json!(id);
        }
        if let Some(s) = self.next_seq() {
            data["sequence_number"] = serde_json::json!(s);
        }
        sse::serialize(Some(ty), None, data.to_string().as_bytes()).map_err(|_| Fail::Internal)
    }

    fn rewrite(
        &mut self,
        ev: &SseEvent,
        data: &[u8],
        nodes: &[Node],
        mut edits: Vec<(Range<usize>, Vec<u8>)>,
    ) -> Result<Vec<u8>, Fail> {
        if let Some(r) = self.blank.take() {
            edits.push((r, b"[]".to_vec()));
        }
        if let (Some(n), Some(s)) = (
            find(nodes, &[K("sequence_number")]),
            num_at(data, nodes, &[K("sequence_number")]),
        ) {
            self.last = Some(s);
            if self.shift > 0 {
                edits.push((
                    nodes[n].range.clone(),
                    (s + self.shift).to_string().into_bytes(),
                ));
            }
        }
        if edits.is_empty() {
            return Ok(ev.raw.clone());
        }
        let d = json::splice(data, edits).map_err(|_| Fail::Internal)?;
        sse::serialize(ev.event.as_deref(), ev.id.as_deref(), &d).map_err(|_| Fail::Internal)
    }

    fn abort(&mut self, why: &Abort) -> Option<Vec<u8>> {
        let (code, message) = abort_message(why);
        let id = self
            .response_id
            .clone()
            .unwrap_or_else(|| "resp_inumaki".into());
        let mut data = serde_json::json!({"type": "response.failed", "response": {"id": id, "object": "response", "status": "failed", "error": {"code": code, "message": message}, "output": []}});
        if let Some(s) = self.next_seq() {
            data["sequence_number"] = serde_json::json!(s);
        }
        sse::serialize(Some("response.failed"), None, data.to_string().as_bytes()).ok()
    }
}
