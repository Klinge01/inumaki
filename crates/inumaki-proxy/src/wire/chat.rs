//! The Chat Completions stream codec (M8 spec §6.2 table, third row):
//! `delta.content`, `delta.refusal`, `delta.tool_calls[].function.arguments`,
//! and the legacy `delta.function_call.arguments`. A chunk with
//! `finish_reason` ends its choice's channels; `data: [DONE]` ends the stream.
//!
//! Channels: content `(choice, 0)`, refusal `(choice, 1)`, tool call `k`
//! `(choice, 2 + k)`, legacy function call `(choice, u32::MAX)`.
//!
//! A delta of a shape the codec cannot map to a channel (non-string content
//! parts, non-string arguments, `custom` tool calls) aborts the stream: it
//! would reach the client unrestored and untripwired.

use std::collections::BTreeSet;
use std::ops::Range;

use crate::error::Fail;
use crate::json::{self, Node, NodeKind};
use crate::sse::{self, SseEvent};
use crate::stream::num_at;
use crate::stream::{
    Abort, Act, ChanKey, ChanKind, P, P::I, P::K, abort_message, carries, elements, find, index_at,
    is_null, join, str_at,
};

#[derive(Default)]
pub(crate) struct Codec {
    /// `(id, created, model)` of the first chunk, echoed by synthesized chunks.
    head: Option<(String, u64, String)>,
    /// Channels seen, per choice ended by its `finish_reason`.
    open: BTreeSet<ChanKey>,
    choices: BTreeSet<u32>,
    finished: BTreeSet<u32>,
    /// The `choices` of an error chunk, replaced by `[]` when it is forwarded.
    blank: Option<Range<usize>>,
}

impl Codec {
    /// A string field of a delta: `Ok(Some(node))` for a string, `Ok(None)`
    /// for absent or `null`, `Err(())` for any other value.
    fn string(data: &[u8], nodes: &[Node], pat: &[P<'_>]) -> Result<Option<usize>, ()> {
        match find(nodes, pat) {
            None => Ok(None),
            Some(n) if nodes[n].kind == NodeKind::String => Ok(Some(n)),
            Some(_) if is_null(data, nodes, pat) => Ok(None),
            Some(_) => Err(()),
        }
    }

    /// `None` = a shape the codec cannot map (the caller refuses).
    fn acts(&mut self, data: &[u8], nodes: &[Node]) -> Option<Vec<Act>> {
        if carries(data, nodes, &[K("error")]) {
            // The error is forwarded without the choices it came with: they
            // are neither restored nor tripwired.
            if !elements(nodes, &[K("choices")]).is_empty() {
                self.blank = find(nodes, &[K("choices")]).map(|i| nodes[i].range.clone());
            }
            return Some(vec![Act::Failed]);
        }
        if self.head.is_none() {
            self.head = Some((
                str_at(nodes, &[K("id")]).unwrap_or("").to_string(),
                num_at(data, nodes, &[K("created")]).unwrap_or(0),
                str_at(nodes, &[K("model")]).unwrap_or("").to_string(),
            ));
        }
        if find(nodes, &[K("choices")]).is_some_and(|i| nodes[i].kind != NodeKind::Array)
            && !is_null(data, nodes, &[K("choices")])
        {
            return None;
        }
        let mut acts = Vec::new();
        for j in elements(nodes, &[K("choices")]) {
            let idx = index_at(data, nodes, &[K("choices"), I(j), K("index")], u32::MAX)
                .ok()?
                .map_or(u32::try_from(j).ok(), Some)?;
            self.choices.insert(idx);
            let d = |tail: &[P<'static>]| join(&[K("choices"), I(j), K("delta")], tail);
            for (b, f) in [(0u32, "content"), (1, "refusal")] {
                if let Some(n) = Self::string(data, nodes, &d(&[K(f)])).ok()? {
                    let ch = ChanKey { a: idx, b };
                    self.open.insert(ch);
                    acts.push(Act::Delta {
                        ch,
                        kind: ChanKind::Text,
                        node: n,
                    });
                }
            }
            let calls = d(&[K("tool_calls")]);
            if find(nodes, &calls).is_some_and(|i| nodes[i].kind != NodeKind::Array)
                && !is_null(data, nodes, &calls)
            {
                return None;
            }
            for t in elements(nodes, &calls) {
                let call = |tail: &[P<'static>]| join(&join(&calls, &[I(t)]), tail);
                if find(nodes, &call(&[K("custom")])).is_some() {
                    return None;
                }
                let k = index_at(data, nodes, &call(&[K("index")]), u32::MAX - 3)
                    .ok()?
                    .map_or(u32::try_from(t).ok(), Some)?;
                let ch = ChanKey {
                    a: idx,
                    b: k.checked_add(2).filter(|b| *b < u32::MAX)?,
                };
                self.function(data, nodes, &call(&[K("function")]), ch, &mut acts)?;
            }
            let legacy = d(&[K("function_call")]);
            if find(nodes, &legacy).is_some() {
                let ch = ChanKey {
                    a: idx,
                    b: u32::MAX,
                };
                self.function(data, nodes, &legacy, ch, &mut acts)?;
            }
            if str_at(nodes, &[K("choices"), I(j), K("finish_reason")]).is_some() {
                self.finished.insert(idx);
                acts.push(Act::End(
                    self.open.iter().filter(|c| c.a == idx).copied().collect(),
                ));
            }
        }
        Some(acts)
    }

    /// A function object at `at` (a tool call's `function` or the legacy
    /// `function_call`): its `name` opens the channel, its `arguments` are
    /// deltas. `None` when it is not an object or its arguments not a string.
    fn function(
        &mut self,
        data: &[u8],
        nodes: &[Node],
        at: &[P<'_>],
        ch: ChanKey,
        acts: &mut Vec<Act>,
    ) -> Option<()> {
        let Some(f) = find(nodes, at) else {
            // A tool call without `function` opens the channel for its own sake.
            self.open.insert(ch);
            return Some(());
        };
        if is_null(data, nodes, at) {
            self.open.insert(ch);
            return Some(());
        }
        if nodes[f].kind != NodeKind::Object {
            return None;
        }
        let sub = |name: &'static str| join(at, &[K(name)]);
        self.open.insert(ch);
        if find(nodes, &sub("name")).is_some() {
            acts.push(Act::Open {
                ch,
                kind: ChanKind::JsonArgs,
            });
        }
        if let Some(n) = Self::string(data, nodes, &sub("arguments")).ok()? {
            acts.push(Act::Delta {
                ch,
                kind: ChanKind::JsonArgs,
                node: n,
            });
        }
        Some(())
    }
}

impl crate::stream::Codec for Codec {
    fn raw_terminal(&self, data: &[u8]) -> bool {
        data.trim_ascii() == b"[DONE]"
    }

    fn ended_cleanly(&self) -> bool {
        !self.choices.is_empty() && self.choices == self.finished
    }

    fn classify(&mut self, _ev: &SseEvent, data: &[u8], nodes: &[Node]) -> Vec<Act> {
        self.acts(data, nodes).unwrap_or_else(|| vec![Act::Refuse])
    }

    fn synth(&mut self, ch: ChanKey, _kind: ChanKind, text: &str) -> Result<Vec<u8>, Fail> {
        let delta = match ch.b {
            0 => serde_json::json!({"content": text}),
            1 => serde_json::json!({"refusal": text}),
            u32::MAX => serde_json::json!({"function_call": {"arguments": text}}),
            b => {
                serde_json::json!({"tool_calls": [{"index": b - 2, "function": {"arguments": text}}]})
            }
        };
        let (id, created, model) = self.head.clone().unwrap_or_default();
        let data = serde_json::json!({"id": id, "object": "chat.completion.chunk", "created": created, "model": model,
            "choices": [{"index": ch.a, "delta": delta, "finish_reason": null}]});
        sse::serialize(None, None, data.to_string().as_bytes()).map_err(|_| Fail::Internal)
    }

    fn rewrite(
        &mut self,
        ev: &SseEvent,
        data: &[u8],
        _nodes: &[Node],
        mut edits: Vec<(Range<usize>, Vec<u8>)>,
    ) -> Result<Vec<u8>, Fail> {
        if let Some(r) = self.blank.take() {
            edits.push((r, b"[]".to_vec()));
        }
        if edits.is_empty() {
            return Ok(ev.raw.clone());
        }
        let d = json::splice(data, edits).map_err(|_| Fail::Internal)?;
        sse::serialize(ev.event.as_deref(), ev.id.as_deref(), &d).map_err(|_| Fail::Internal)
    }

    fn abort(&mut self, why: &Abort) -> Option<Vec<u8>> {
        match why {
            // Spec §7: Chat streams end without `[DONE]`.
            Abort::Stream => None,
            Abort::Privacy { .. } => {
                let (class, message) = abort_message(why);
                let data = serde_json::json!({"error": {"type": class, "code": class, "message": message, "param": null}});
                sse::serialize(None, None, data.to_string().as_bytes()).ok()
            }
        }
    }
}
