//! The Messages stream codec (M8 spec §6.2 table, first row). Channels are
//! content-block indices; `content_block_stop` and `message_stop` are the
//! flush points; thinking, signature, and citation deltas pass unchanged
//! (thinking and cited text are seeded as provider-written, spec §5.6).

use std::ops::Range;

use crate::error::Fail;
use crate::json::{self, Node, NodeKind};
use crate::sse::{self, SseEvent};
use crate::stream::{
    Abort, Act, ChanKey, ChanKind, P::K, abort_message, elements, find, index_at, str_at,
};

/// Stateless: every Messages event names its block index.
#[derive(Default)]
pub(crate) struct Codec;

/// The node at `pat` when it is a non-empty string.
fn non_empty(nodes: &[Node], pat: &[crate::stream::P<'_>]) -> Option<usize> {
    find(nodes, pat).filter(|&n| nodes[n].text.as_deref().is_some_and(|t| !t.is_empty()))
}

/// Whether node `i` is `{}`.
fn empty_object(nodes: &[Node], i: usize) -> bool {
    nodes[i].kind == NodeKind::Object && !nodes.iter().any(|n| n.parent == Some(i))
}

impl crate::stream::Codec for Codec {
    fn classify(&mut self, ev: &SseEvent, data: &[u8], nodes: &[Node]) -> Vec<Act> {
        let ty = str_at(nodes, &[K("type")]);
        // The SDKs pick events by name and accumulate them by `type`: when
        // the two differ, or a named event has no `type`, what the engine
        // checks is not what the client builds (final review I1, N2).
        if ev.event.as_deref().is_some_and(|e| ty != Some(e)) {
            return vec![Act::Refuse];
        }
        // An index out of range is refused, never truncated onto another block.
        let Ok(index) = index_at(data, nodes, &[K("index")], u32::MAX) else {
            return vec![Act::Refuse];
        };
        let index = index.unwrap_or(0);
        let ch = ChanKey { a: index, b: 0 };
        match ty.unwrap_or("") {
            // The client's message snapshot starts from this message: content
            // carried here would reach it unrestored and untripwired.
            "message_start" if !elements(nodes, &[K("message"), K("content")]).is_empty() => {
                vec![Act::Refuse]
            }
            "content_block_start" => match str_at(nodes, &[K("content_block"), K("type")]) {
                // The arguments arrive as `input_json_delta`s; a start that
                // already carries input would reach the client unrestored
                // and untripwired, so it aborts (review ruling).
                Some("tool_use" | "server_tool_use" | "mcp_tool_use") => {
                    match find(nodes, &[K("content_block"), K("input")]) {
                        Some(i) if !empty_object(nodes, i) => vec![Act::Refuse],
                        _ => vec![Act::Open {
                            ch,
                            kind: ChanKind::JsonArgs,
                        }],
                    }
                }
                Some("text") => match non_empty(nodes, &[K("content_block"), K("text")]) {
                    Some(n) => vec![Act::Delta {
                        ch,
                        kind: ChanKind::Text,
                        node: n,
                    }],
                    None => vec![Act::Pass],
                },
                Some("thinking") => match non_empty(nodes, &[K("content_block"), K("thinking")]) {
                    Some(n) => vec![Act::Thinking { index, node: n }],
                    None => vec![Act::Pass],
                },
                _ => vec![Act::Pass],
            },
            "content_block_delta" => match str_at(nodes, &[K("delta"), K("type")]) {
                Some("text_delta") => find(nodes, &[K("delta"), K("text")])
                    .map(|n| {
                        vec![Act::Delta {
                            ch,
                            kind: ChanKind::Text,
                            node: n,
                        }]
                    })
                    .unwrap_or_default(),
                Some("input_json_delta") => find(nodes, &[K("delta"), K("partial_json")])
                    .map(|n| {
                        vec![Act::Delta {
                            ch,
                            kind: ChanKind::JsonArgs,
                            node: n,
                        }]
                    })
                    .unwrap_or_default(),
                Some("thinking_delta") => find(nodes, &[K("delta"), K("thinking")])
                    .map(|n| vec![Act::Thinking { index, node: n }])
                    .unwrap_or_default(),
                // Passes unchanged; its cited text is seeded like
                // `non_streaming` seeds `content[].citations[].cited_text`.
                Some("citations_delta") => {
                    find(nodes, &[K("delta"), K("citation"), K("cited_text")])
                        .map(|n| vec![Act::Reasoned(vec![n])])
                        .unwrap_or_default()
                }
                _ => vec![Act::Pass], // signature_delta, unknown deltas
            },
            "content_block_stop" => vec![Act::End(vec![ch])],
            "message_stop" => vec![Act::Terminal { fields: Vec::new() }],
            "error" => vec![Act::Failed],
            _ => vec![Act::Pass],
        }
    }

    fn synth(&mut self, ch: ChanKey, kind: ChanKind, text: &str) -> Result<Vec<u8>, Fail> {
        let delta = match kind {
            ChanKind::Text => serde_json::json!({"type": "text_delta", "text": text}),
            _ => serde_json::json!({"type": "input_json_delta", "partial_json": text}),
        };
        let data =
            serde_json::json!({"type": "content_block_delta", "index": ch.a, "delta": delta});
        sse::serialize(
            Some("content_block_delta"),
            None,
            data.to_string().as_bytes(),
        )
        .map_err(|_| Fail::Internal)
    }

    /// A rewritten event is re-serialized in `sse::serialize`'s canonical
    /// form: its comments, `retry:`, and unknown fields are dropped.
    fn rewrite(
        &mut self,
        ev: &SseEvent,
        data: &[u8],
        _nodes: &[Node],
        edits: Vec<(Range<usize>, Vec<u8>)>,
    ) -> Result<Vec<u8>, Fail> {
        if edits.is_empty() {
            return Ok(ev.raw.clone());
        }
        let d = json::splice(data, edits).map_err(|_| Fail::Internal)?;
        sse::serialize(ev.event.as_deref(), ev.id.as_deref(), &d).map_err(|_| Fail::Internal)
    }

    fn abort(&mut self, why: &Abort) -> Option<Vec<u8>> {
        let (class, message) = abort_message(why);
        let ty = if class == "stream_aborted" {
            "api_error"
        } else {
            class
        };
        let data = serde_json::json!({"type": "error", "error": {"type": ty, "message": message}});
        sse::serialize(Some("error"), None, data.to_string().as_bytes()).ok()
    }
}
