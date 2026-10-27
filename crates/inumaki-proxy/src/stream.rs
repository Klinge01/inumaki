//! Streaming restoration (M8 spec §6.2–§6.4): one holdback per channel,
//! restoration by provenance and column through the `Restorer`, full-text
//! repeats, synthesized flushes, the tripwire on every completed channel,
//! block-mode buffering of tool calls, and seeding when the stream
//! completes. Synchronous: the handler runs it on a blocking thread.
//!
//! Driver contract (plan M8-2 Task 5): feed every parsed event to
//! [`Rewriter::event`] and send what it returns, in order. When it returns
//! `Err(why)`, send [`Rewriter::abort`]`(&why)` and stop; when the upstream
//! ends, send what [`Rewriter::finish`] returns. When the event parser
//! refuses (an oversized event), send `abort(&Abort::Stream)` and stop.
//! The rewriter fails closed if the contract is broken: after an `Err`,
//! every later `event` is refused and `finish` ends with the abort event.
//!
//! Privacy: an aborted stream never forwards a channel's held tail (an
//! unrestored partial token), drops queued tool calls, and seeds nothing.
//! Channel buffers are `Zeroizing`; `Debug` prints counts only.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ops::Range;
use std::sync::Arc;

use zeroize::Zeroizing;

use crate::config::TripwireMode;
use crate::error::Fail;
use crate::holdback::{Grammar, Holdback, push_z};
use crate::host::Scope;
use crate::json::{self, Node, NodeKind, Seg};
use crate::pipeline::Shared;
use crate::respond;
use crate::restore::{Column, Restorer};
use crate::routes::{UpstreamId, Wire};
use crate::session::{ClientMode, SeedStamp, Session};
use crate::sse::SseEvent;
use crate::walk::Class;

/// A channel of one response (spec §6.2 "Channels"); each codec assigns `a`, `b`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ChanKey {
    pub a: u32,
    pub b: u32,
}

/// What a channel carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChanKind {
    /// Model text: `Column::Text`.
    Text,
    /// JSON arguments: `Column::Args`, originals JSON-escaped.
    JsonArgs,
    /// Plain-text tool input (`custom_tool_call`): `Column::Args`, no escaping.
    PlainArgs,
}

impl ChanKind {
    fn column(self) -> Column {
        if self == ChanKind::Text {
            Column::Text
        } else {
            Column::Args
        }
    }
    fn is_args(self) -> bool {
        self != ChanKind::Text
    }
}

/// What a codec found in one event, applied in order.
pub(crate) enum Act {
    Pass,
    /// A tool-call channel opens with this event (block mode queues from here).
    Open {
        ch: ChanKey,
        kind: ChanKind,
    },
    /// The string node `node` is a delta of `ch`.
    Delta {
        ch: ChanKey,
        kind: ChanKind,
        node: usize,
    },
    /// These channels end at this event: flush, then tripwire.
    End(Vec<ChanKey>),
    /// Full-text repeats after ending `end`.
    Repeat {
        end: Vec<ChanKey>,
        fields: Vec<(usize, ChanKey, ChanKind)>,
    },
    /// Reasoning text to accumulate (Messages `thinking_delta`).
    Thinking {
        index: u32,
        node: usize,
    },
    /// Complete provider-written texts in these nodes (Responses reasoning
    /// summaries, Messages citations): never changed, seeded as scanned.
    Reasoned(Vec<usize>),
    /// Complete model-written argument strings (string or key nodes) of an
    /// item that arrives whole, not as deltas (Codex shell, patch, computer,
    /// and MCP approval items): tripwired as arguments, string nodes
    /// restored by the arguments column. Block mode withholds the item
    /// through the channel its codec opens with [`Act::Open`].
    Whole(Vec<(usize, ChanKind)>),
    /// The stream's last event: end every channel, apply the repeats, seed.
    Terminal {
        fields: Vec<(usize, ChanKey, ChanKind)>,
    },
    /// An upstream error event: forwarded; the stream ends without seeding.
    Failed,
    /// A rewritable event the engine cannot check (framing it does not
    /// expect): the stream aborts.
    Refuse,
}

/// Why a stream ends early.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Abort {
    Stream,
    Privacy { kinds: Vec<String> },
}

/// `(class, fixed message)` of an abort (spec §7). A privacy abort carries
/// the withheld-answer text (spec §7 amendment 2026-10-05): the request was
/// sent, the model's answer is what was stopped.
pub(crate) fn abort_message(why: &Abort) -> (&'static str, String) {
    match why {
        Abort::Stream => ("stream_aborted", "inumaki: stream_aborted".to_string()),
        Abort::Privacy { kinds } => (
            "privacy_block",
            Fail::AnswerWithheld {
                kinds: kinds.clone(),
                checks: vec!["ClearValue".into()],
            }
            .message(),
        ),
    }
}

/// One wire format's stream codec.
///
/// Every data payload that is not [`Codec::raw_terminal`] must scan as JSON
/// (`json::scan`: no duplicate keys, no lone surrogates, bounded nesting),
/// whatever its event name; one that does not aborts the stream (final
/// review I1: clients parse more leniently, so a payload the engine cannot
/// check would reach them unrestored and untripwired).
pub(crate) trait Codec: Send {
    /// A non-JSON data payload that ends the stream (Chat's `[DONE]`).
    fn raw_terminal(&self, _data: &[u8]) -> bool {
        false
    }
    /// The upstream ended without a terminal event but the stream is complete
    /// (Chat: every choice sent `finish_reason`; spec §6.2 "stream end").
    fn ended_cleanly(&self) -> bool {
        false
    }
    fn classify(&mut self, ev: &SseEvent, data: &[u8], nodes: &[Node]) -> Vec<Act>;
    /// A delta event carrying `text` for `ch`, placed before a flush point.
    /// An error aborts the stream.
    fn synth(&mut self, ch: ChanKey, kind: ChanKind, text: &str) -> Result<Vec<u8>, Fail>;
    /// `ev` with `edits` spliced into its data (and per-wire bookkeeping);
    /// `ev.raw` when nothing changes. A re-serialized event is in
    /// `sse::serialize`'s canonical form: its comments, `retry:`, and
    /// unknown fields are dropped (only `event:`, `id:`, `data:` remain).
    fn rewrite(
        &mut self,
        ev: &SseEvent,
        data: &[u8],
        nodes: &[Node],
        edits: Vec<(Range<usize>, Vec<u8>)>,
    ) -> Result<Vec<u8>, Fail>;
    /// The terminal error event, or `None` to close without one.
    fn abort(&mut self, why: &Abort) -> Option<Vec<u8>>;
}

pub(crate) fn codec(wire: Wire) -> Box<dyn Codec> {
    match wire {
        Wire::Messages => Box::new(crate::wire::anthropic::Codec),
        // The Codex backend streams the Responses format (no separate codec).
        Wire::Responses => Box::new(crate::wire::responses::Codec::default()),
        Wire::Chat => Box::new(crate::wire::chat::Codec::default()),
    }
}

/// One step of a node path pattern.
#[derive(Clone, Copy)]
pub(crate) enum P<'s> {
    K(&'s str),
    I(usize),
}

/// Whether node `i`'s path (root to node) is exactly `pat`.
fn at(nodes: &[Node], i: usize, pat: &[P<'_>]) -> bool {
    let mut it = json::segs(nodes, i);
    for p in pat.iter().rev() {
        match (it.next(), p) {
            (Some(Seg::Key(k)), P::K(x)) if k == x => {}
            (Some(Seg::Index(n)), P::I(x)) if n == x => {}
            _ => return false,
        }
    }
    it.next().is_none()
}

/// The value node (not a key) at `pat`. A key node and its value share one
/// path; keys are skipped. `json::scan` refuses duplicate keys, so the
/// match is unique.
pub(crate) fn find(nodes: &[Node], pat: &[P<'_>]) -> Option<usize> {
    (0..nodes.len()).find(|&i| nodes[i].kind != NodeKind::Key && at(nodes, i, pat))
}

pub(crate) fn str_at<'n>(nodes: &'n [Node], pat: &[P<'_>]) -> Option<&'n str> {
    let i = find(nodes, pat)?;
    if nodes[i].kind == NodeKind::String {
        nodes[i].text.as_deref()
    } else {
        None
    }
}

pub(crate) fn num_at(data: &[u8], nodes: &[Node], pat: &[P<'_>]) -> Option<u64> {
    let n = &nodes[find(nodes, pat)?];
    if n.kind != NodeKind::Other {
        return None;
    }
    std::str::from_utf8(data.get(n.range.clone())?)
        .ok()?
        .parse()
        .ok()
}

/// `head` followed by `tail`.
pub(crate) fn join<'s>(head: &[P<'s>], tail: &[P<'s>]) -> Vec<P<'s>> {
    let mut p = head.to_vec();
    p.extend_from_slice(tail);
    p
}

/// Whether the value at `pat` is a JSON `null`.
pub(crate) fn is_null(data: &[u8], nodes: &[Node], pat: &[P<'_>]) -> bool {
    find(nodes, pat).is_some_and(|i| {
        nodes[i].kind == NodeKind::Other && data.get(nodes[i].range.clone()) == Some(b"null")
    })
}

/// Whether `pat` holds something other than `null` or the empty string: a
/// value a codec cannot route through a channel, where the provider's
/// framing is expected to leave it empty.
pub(crate) fn carries(data: &[u8], nodes: &[Node], pat: &[P<'_>]) -> bool {
    let Some(i) = find(nodes, pat) else {
        return false;
    };
    match nodes[i].kind {
        NodeKind::String => nodes[i].text.as_deref().is_some_and(|t| !t.is_empty()),
        NodeKind::Other => !is_null(data, nodes, pat),
        _ => true,
    }
}

/// A non-negative index field of at most `max`: `Ok(None)` when absent or
/// `null`, `Err(())` when it is anything else (the codec refuses).
pub(crate) fn index_at(
    data: &[u8],
    nodes: &[Node],
    pat: &[P<'_>],
    max: u32,
) -> Result<Option<u32>, ()> {
    match find(nodes, pat) {
        None => Ok(None),
        Some(_) if is_null(data, nodes, pat) => Ok(None),
        Some(_) => match num_at(data, nodes, pat).map(u32::try_from) {
            Some(Ok(n)) if n <= max => Ok(Some(n)),
            _ => Err(()),
        },
    }
}

/// Indices of the array elements at `pat`, in order.
pub(crate) fn elements(nodes: &[Node], pat: &[P<'_>]) -> Vec<usize> {
    let Some(p) = find(nodes, pat) else {
        return Vec::new();
    };
    nodes
        .iter()
        .filter(|n| n.parent == Some(p) && n.kind != NodeKind::Key)
        .filter_map(|n| match &n.seg {
            Some(Seg::Index(i)) => Some(*i),
            _ => None,
        })
        .collect()
}

struct Channel {
    kind: ChanKind,
    hold: Holdback,
    /// What the model wrote (tokens; possibly a value in clear).
    raw: Zeroizing<String>,
    /// What the client was sent (restored).
    emitted: Zeroizing<String>,
    ended: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Open,
    /// The terminal event was rewritten; the answer was seeded.
    Done,
    /// The upstream sent an error event; it was forwarded.
    Failed,
    /// `event` returned an error and `abort` was not called yet.
    Broken,
    /// The abort event was produced.
    Aborted,
}

/// The texts the tripwire scans for one channel: decoded string and key
/// leaves of JSON arguments (spec §6.4 amendment), else the raw text.
fn tripwire_texts(kind: ChanKind, raw: &str) -> Vec<Zeroizing<String>> {
    if kind == ChanKind::JsonArgs {
        if let Ok(nodes) = json::scan(raw.as_bytes()) {
            return nodes
                .into_iter()
                .filter(|n| matches!(n.kind, NodeKind::String | NodeKind::Key))
                .filter_map(|n| n.text.map(Zeroizing::new))
                .collect();
        }
    }
    vec![Zeroizing::new(raw.to_string())]
}

/// Rewrites one streamed answer. `Debug` prints counts only.
pub(crate) struct Rewriter<'a> {
    sh: &'a Shared,
    session: &'a Session,
    wire: Wire,
    up: UpstreamId,
    /// Normal routes record (tripwire) and seed; check routes do neither.
    record: bool,
    /// The producing request's stamp for seeded scanned leaves.
    seed: SeedStamp,
    restorer: Restorer<'a>,
    codec: Box<dyn Codec>,
    text_g: Arc<Grammar>,
    args_g: Arc<Grammar>,
    channels: BTreeMap<ChanKey, Channel>,
    thinking: BTreeMap<u32, Zeroizing<String>>,
    reasoning: Vec<Zeroizing<String>>,
    /// Block mode: every event from a tool-call channel's opening until all
    /// such channels end cleanly. The only event bytes kept past one
    /// `event` call, and they can hold restored originals: zeroized when
    /// dropped (an abort), moved out unwiped when released to the client.
    queue: Option<Vec<Zeroizing<Vec<u8>>>>,
    queued: usize,
    buffered: BTreeSet<ChanKey>,
    /// The tripwire found a known value in clear somewhere in this answer:
    /// no text or argument leaf of it is seeded (spec §5.6 amendment 2026-10-05).
    tripped: bool,
    /// Keyed digests of the [`Act::Whole`] texts already tripwired, per
    /// kind: an item repeated by later events is recorded once, and a text
    /// seen as plain arguments is still checked as JSON arguments (decoded
    /// leaves) when it appears as such (follow-up N3).
    whole_seen: HashSet<[u8; 32]>,
    /// [`Act::Whole`] string leaves, restored and raw, seeded at the end as
    /// `non_streaming` seeds argument fields.
    whole_seeds: Vec<(ChanKind, Zeroizing<String>, Zeroizing<String>)>,
    /// `false` once the driver could not get scan permits for the
    /// record-only scan of cut-off channels (final re-review N1).
    cut_record: bool,
    /// Bytes this answer holds: every channel's raw text, thinking, and
    /// reasoning. Over `max_request_bytes` the stream aborts, as
    /// `non_streaming` refuses a larger answer (final review I2).
    total: usize,
    state: State,
}

impl std::fmt::Debug for Rewriter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rewriter")
            .field("channels", &self.channels.len())
            .field("queued", &self.queued)
            .field("state", &self.state)
            .finish()
    }
}

/// One splice of an event's data: a byte range and its replacement.
type Edit = (Range<usize>, Vec<u8>);

/// One delta of the current event: its channel, node, and the text to put there.
type Pending = Vec<(ChanKey, usize, Zeroizing<String>)>;

impl<'a> Rewriter<'a> {
    /// `scope` is `Scope::Datasets` on normal routes, `Scope::Check(_)` on a
    /// check route (spec §12.3: check tokens only, no tripwire, no seeding).
    /// `seed` is the producing request's `Prepared::seed_stamp()`, as
    /// `respond::non_streaming` takes it.
    pub(crate) fn new(
        sh: &'a Shared,
        session: &'a Session,
        wire: Wire,
        up: UpstreamId,
        mode: ClientMode,
        scope: Scope,
        seed: SeedStamp,
    ) -> Rewriter<'a> {
        let (text_g, args_g) = Grammar::for_settings(&sh.cfg.session_tokens);
        let record = !matches!(scope, Scope::Check(_));
        Rewriter {
            sh,
            session,
            wire,
            up,
            record,
            seed,
            restorer: Restorer::new(session, &*sh.host, &sh.tokens, scope, mode),
            codec: codec(wire),
            text_g,
            args_g,
            channels: BTreeMap::new(),
            thinking: BTreeMap::new(),
            reasoning: Vec::new(),
            queue: None,
            queued: 0,
            buffered: BTreeSet::new(),
            tripped: false,
            whole_seen: HashSet::new(),
            whole_seeds: Vec::new(),
            cut_record: true,
            total: 0,
            state: State::Open,
        }
    }

    /// The rewriter with another codec (tests of engine paths a wire's
    /// codec does not reach).
    #[cfg(test)]
    pub(crate) fn with_codec(mut self, codec: Box<dyn Codec>) -> Rewriter<'a> {
        self.codec = codec;
        self
    }

    /// Count `n` more bytes held for this answer; over the cap the stream
    /// aborts (the stream's `ResponseTooLarge`).
    fn grow(&mut self, n: usize) -> Result<(), Abort> {
        self.total = self.total.saturating_add(n);
        if self.total > self.sh.cfg.max_request_bytes {
            return Err(Abort::Stream);
        }
        Ok(())
    }

    /// The raw length of the largest argument channel still open: any event
    /// can end it, and ending scans it whole (the driver sizes its scan
    /// permits with it).
    pub(crate) fn largest_open_args(&self) -> usize {
        self.channels
            .values()
            .filter(|c| !c.ended && c.kind.is_args())
            .map(|c| c.raw.len())
            .max()
            .unwrap_or(0)
    }

    /// The raw length the record-only scan of cut-off channels can scan
    /// whole, sized as the driver sizes an event's scan (the largest open
    /// argument channel); 0 where nothing would be recorded.
    pub(crate) fn cut_scan_len(&self) -> usize {
        if self.record && self.cut_record && self.state != State::Aborted {
            self.largest_open_args()
        } else {
            0
        }
    }

    /// Skip the record-only scan of cut-off channels: the driver could not
    /// get scan permits for it in time (the stream ends either way).
    pub(crate) fn skip_cut_record(&mut self) {
        self.cut_record = false;
    }

    fn blocking(&self) -> bool {
        self.record && self.sh.cfg.tripwire == TripwireMode::Block
    }

    fn grammar(&self, kind: ChanKind) -> Arc<Grammar> {
        Arc::clone(if kind == ChanKind::JsonArgs {
            &self.args_g
        } else {
            &self.text_g
        })
    }

    fn emit(&mut self, out: &mut Vec<Vec<u8>>, b: Vec<u8>) {
        match &mut self.queue {
            Some(q) => {
                self.queued += b.len();
                q.push(Zeroizing::new(b));
            }
            None => out.push(b),
        }
    }

    /// Open `ch` (idempotent). A channel never changes its kind: that would
    /// restore arguments with the text column's provenance.
    fn open(&mut self, ch: ChanKey, kind: ChanKind) -> Result<(), Abort> {
        if let Some(c) = self.channels.get(&ch) {
            return if c.kind == kind {
                Ok(())
            } else {
                Err(Abort::Stream)
            };
        }
        let hold = Holdback::new(self.grammar(kind), kind == ChanKind::JsonArgs);
        self.channels.insert(
            ch,
            Channel {
                kind,
                hold,
                raw: Zeroizing::new(String::new()),
                emitted: Zeroizing::new(String::new()),
                ended: false,
            },
        );
        if self.blocking() && kind.is_args() {
            self.buffered.insert(ch);
            self.queue.get_or_insert_with(Vec::new);
        }
        Ok(())
    }

    /// A delta of `ch`; the text to emit now. Text after the channel ended
    /// is refused: it would bypass the tripwire and the block-mode queue.
    fn push(&mut self, ch: ChanKey, text: &str) -> Result<Zeroizing<String>, Abort> {
        match self.channels.get(&ch) {
            None => return Err(Abort::Stream),
            Some(c) if c.ended => {
                return if text.is_empty() {
                    Ok(Zeroizing::new(String::new()))
                } else {
                    Err(Abort::Stream)
                };
            }
            Some(_) => {}
        }
        self.grow(text.len())?;
        let Some(c) = self.channels.get_mut(&ch) else {
            return Err(Abort::Stream);
        };
        push_z(&mut c.raw, text);
        let col = c.kind.column();
        let restorer = &mut self.restorer;
        let mut resolve = |tok: &str| resolve(restorer, col, tok);
        let e = c.hold.push(text, &mut resolve).map_err(|_| Abort::Stream)?;
        push_z(&mut c.emitted, &e);
        Ok(e)
    }

    /// End `ch`: flush its held tail (into this event's last delta of the
    /// channel, else a synthesized delta before the event), then run the
    /// tripwire on what the model wrote.
    fn end(
        &mut self,
        ch: ChanKey,
        deltas: &mut Pending,
        before: &mut Vec<Vec<u8>>,
    ) -> Result<(), Abort> {
        let (kind, tail, raw) = {
            let Some(c) = self.channels.get_mut(&ch) else {
                return Ok(());
            };
            if c.ended {
                return Ok(());
            }
            c.ended = true;
            let col = c.kind.column();
            let restorer = &mut self.restorer;
            let mut resolve = |tok: &str| resolve(restorer, col, tok);
            let tail = c.hold.finish(&mut resolve).map_err(|_| Abort::Stream)?;
            push_z(&mut c.emitted, &tail);
            // Restored arguments must parse as the model's did (a restored
            // key may collide with another), as `non_streaming` requires.
            if c.kind == ChanKind::JsonArgs
                && json::scan(c.raw.as_bytes()).is_ok()
                && json::scan(c.emitted.as_bytes()).is_err()
            {
                return Err(Abort::Stream);
            }
            (c.kind, tail, c.raw.clone())
        };
        if !tail.is_empty() {
            match deltas.iter_mut().rev().find(|(k, _, _)| *k == ch) {
                Some((_, _, e)) => push_z(e, &tail),
                None => before.push(
                    self.codec
                        .synth(ch, kind, &tail)
                        .map_err(|_| Abort::Stream)?,
                ),
            }
        }
        self.tripwire(kind, &raw)?;
        self.buffered.remove(&ch);
        Ok(())
    }

    /// The tripwire on what the model wrote for one channel (or one
    /// repeat field), on record scopes only. A hit sets `tripped`; in
    /// block mode a hit in arguments aborts with the privacy error.
    fn tripwire(&mut self, kind: ChanKind, raw: &str) -> Result<(), Abort> {
        if !self.record {
            return Ok(());
        }
        let texts = tripwire_texts(kind, raw);
        let texts: Vec<&str> = texts.iter().map(|t| t.as_str()).collect();
        let (text, args): (&[&str], &[&str]) = if kind.is_args() {
            (&[], &texts)
        } else {
            (&texts, &[])
        };
        match respond::tripwire_hits(self.sh, self.session, self.up, text, args) {
            Ok(hit) => {
                self.tripped |= hit;
                Ok(())
            }
            Err(Fail::AnswerWithheld { kinds, .. }) => Err(Abort::Privacy { kinds }),
            // Host or vault trouble: the text is unchecked.
            Err(_) => Err(Abort::Stream),
        }
    }

    /// The tripwire's record for channels an abort or an upstream error cut
    /// off (final review M4): in notify mode their bytes already reached
    /// the client, and the `ClearValue` record is the only signal. Record
    /// scopes only; the result is ignored (the stream ends either way).
    fn record_unended(&self) {
        if !self.record || !self.cut_record {
            return;
        }
        for c in self
            .channels
            .values()
            .filter(|c| !c.ended && !c.raw.is_empty())
        {
            let texts = tripwire_texts(c.kind, &c.raw);
            let texts: Vec<&str> = texts.iter().map(|t| t.as_str()).collect();
            let (text, args): (&[&str], &[&str]) = if c.kind.is_args() {
                (&[], &texts)
            } else {
                (&texts, &[])
            };
            let _ = respond::tripwire_hits(self.sh, self.session, self.up, text, args);
        }
    }

    /// A full-text repeat: the channel's emitted text when the field is the
    /// channel's raw deltas (an absent channel counts as empty). Otherwise
    /// an argument field aborts the stream (the tripwire and the block-mode
    /// queue saw only the deltas, and Codex runs tools from the `done`
    /// events), and a text field is tripwired and restored whole.
    /// `None` = unchanged.
    fn repeat(&mut self, node: &Node, ch: ChanKey, kind: ChanKind) -> Result<Option<Edit>, Abort> {
        if node.kind != NodeKind::String {
            return Err(Abort::Stream);
        }
        let v = node.text.as_deref().unwrap_or("");
        let same = match self.channels.get(&ch) {
            Some(c) => c.kind == kind && c.raw.as_str() == v,
            None => v.is_empty(),
        };
        if !same && kind.is_args() {
            return Err(Abort::Stream);
        }
        if !same {
            self.tripwire(kind, v)?;
        }
        let restored: Zeroizing<String> = match self.channels.get(&ch) {
            Some(c) if same => c.emitted.clone(),
            None if same => Zeroizing::new(String::new()),
            _ => self.restore_whole(kind, v)?,
        };
        Ok((restored.as_str() != v)
            .then(|| (node.range.clone(), json::quote(&restored).into_bytes())))
    }

    /// `v` restored whole by `kind`'s column (JSON-escaped originals for
    /// JSON arguments).
    fn restore_whole(&mut self, kind: ChanKind, v: &str) -> Result<Zeroizing<String>, Abort> {
        let mut h = Holdback::new(self.grammar(kind), kind == ChanKind::JsonArgs);
        let restorer = &mut self.restorer;
        let col = kind.column();
        let mut resolve = |tok: &str| resolve(restorer, col, tok);
        let mut out = h.push(v, &mut resolve).map_err(|_| Abort::Stream)?;
        let tail = h.finish(&mut resolve).map_err(|_| Abort::Stream)?;
        push_z(&mut out, &tail);
        Ok(out)
    }

    /// One [`Act::Whole`] field: tripwired as arguments (once per text and
    /// answer; in block mode a hit aborts with the privacy error), then a
    /// string node is restored in place. A key node is tripwired only: a
    /// restored key could collide with another, and the stream engine
    /// splices without re-parsing the event, so a token in a key stays a
    /// token.
    fn whole(&mut self, node: &Node, kind: ChanKind) -> Result<Option<Edit>, Abort> {
        if !matches!(node.kind, NodeKind::String | NodeKind::Key) || !kind.is_args() {
            return Err(Abort::Stream);
        }
        let v = node.text.as_deref().unwrap_or("");
        if v.is_empty() {
            return Ok(None);
        }
        if self.record
            && self
                .whole_seen
                .insert(self.sh.keys.digest(whole_tag(kind), v.as_bytes()))
        {
            self.tripwire(kind, v)?;
        }
        if node.kind == NodeKind::Key {
            return Ok(None);
        }
        let restored = self.restore_whole(kind, v)?;
        if self.record
            && !self
                .whole_seeds
                .iter()
                .any(|(k, _, w)| *k == kind && w.as_str() == v)
        {
            self.grow(v.len().saturating_add(restored.len()))?;
            self.whole_seeds
                .push((kind, restored.clone(), Zeroizing::new(v.to_string())));
        }
        Ok((restored.as_str() != v)
            .then(|| (node.range.clone(), json::quote(&restored).into_bytes())))
    }

    /// One upstream event; the bytes for the client, in order. After an
    /// `Err` the caller sends [`Rewriter::abort`] and stops.
    pub(crate) fn event(&mut self, ev: SseEvent) -> Result<Vec<Vec<u8>>, Abort> {
        match self.state {
            State::Broken | State::Aborted => return Err(Abort::Stream),
            // The stream ended (upstream error, or the terminal event):
            // nothing after it reaches the client, so nothing can bypass
            // the tripwire or the block-mode queue.
            State::Failed | State::Done => return Ok(Vec::new()),
            State::Open => {}
        }
        let r = self.step(ev);
        if r.is_err() {
            self.state = State::Broken;
        }
        r
    }

    fn step(&mut self, ev: SseEvent) -> Result<Vec<Vec<u8>>, Abort> {
        let mut out = Vec::new();
        let Some(data) = ev.data.clone() else {
            self.emit(&mut out, ev.raw);
            return Ok(out);
        };
        let (nodes, acts) = if self.codec.raw_terminal(&data) {
            (Vec::new(), vec![Act::Terminal { fields: Vec::new() }])
        } else {
            match json::scan(&data) {
                Ok(n) => {
                    let a = self.codec.classify(&ev, &data, &n);
                    (n, a)
                }
                // Any unscannable payload, whatever the event name (I1).
                Err(_) => return Err(Abort::Stream),
            }
        };
        let node = |i: usize| nodes.get(i).ok_or(Abort::Stream);
        let mut deltas: Pending = Vec::new();
        let mut before: Vec<Vec<u8>> = Vec::new();
        let mut edits: Vec<Edit> = Vec::new();
        let mut terminal = false;
        for act in acts {
            match act {
                Act::Pass => {}
                Act::Open { ch, kind } => self.open(ch, kind)?,
                Act::Delta { ch, kind, node: i } => {
                    let n = node(i)?;
                    if n.kind != NodeKind::String {
                        return Err(Abort::Stream);
                    }
                    self.open(ch, kind)?;
                    let e = self.push(ch, n.text.as_deref().unwrap_or(""))?;
                    deltas.push((ch, i, e));
                }
                Act::End(chs) => {
                    for ch in chs {
                        self.end(ch, &mut deltas, &mut before)?;
                    }
                }
                Act::Repeat { end, fields } => {
                    for ch in end {
                        self.end(ch, &mut deltas, &mut before)?;
                    }
                    for (i, ch, kind) in fields {
                        edits.extend(self.repeat(node(i)?, ch, kind)?);
                    }
                }
                Act::Thinking { index, node: i } => {
                    let t = node(i)?.text.as_deref().unwrap_or("");
                    self.grow(t.len())?;
                    push_z(self.thinking.entry(index).or_default(), t);
                }
                Act::Whole(fields) => {
                    for (i, kind) in fields {
                        edits.extend(self.whole(node(i)?, kind)?);
                    }
                }
                Act::Reasoned(ns) => {
                    for i in ns {
                        if let Some(t) = &node(i)?.text {
                            self.grow(t.len())?;
                            self.reasoning.push(Zeroizing::new(t.clone()));
                        }
                    }
                }
                Act::Terminal { fields } => {
                    let all: Vec<ChanKey> = self.channels.keys().copied().collect();
                    for ch in all {
                        self.end(ch, &mut deltas, &mut before)?;
                    }
                    for (i, ch, kind) in fields {
                        edits.extend(self.repeat(node(i)?, ch, kind)?);
                    }
                    terminal = true;
                }
                Act::Refuse => return Err(Abort::Stream),
                Act::Failed => {
                    self.record_unended();
                    // An unfinished tool call is never released.
                    self.state = State::Failed;
                    self.queue = None;
                    self.queued = 0;
                    self.buffered.clear();
                }
            }
        }
        for (_, i, e) in deltas {
            let n = node(i)?;
            if n.text.as_deref() != Some(e.as_str()) {
                edits.push((n.range.clone(), json::quote(&e).into_bytes()));
            }
        }
        let bytes = self
            .codec
            .rewrite(&ev, &data, &nodes, edits)
            .map_err(|_| Abort::Stream)?;
        for b in before {
            self.emit(&mut out, b);
        }
        self.emit(&mut out, bytes);
        if self.buffered.is_empty() {
            if let Some(q) = self.queue.take() {
                out.extend(q.into_iter().map(|mut b| std::mem::take(&mut *b)));
                self.queued = 0;
            }
        }
        if self.queued > self.sh.cfg.max_request_bytes {
            return Err(Abort::Stream);
        }
        if terminal && self.state == State::Open {
            self.state = State::Done;
            if self.record {
                self.seed();
            }
        }
        Ok(out)
    }

    /// Seed the next turn (spec §5.6): text and argument leaves as the
    /// request walker keys them (none when the tripwire hit anywhere in the
    /// answer), reasoning and citations as scanned digests with the
    /// producing request's stamp. Exactly as `respond::non_streaming` does.
    fn seed(&self) {
        if !self.tripped {
            for c in self.channels.values() {
                match c.kind {
                    ChanKind::Text => respond::seed_leaf(
                        self.sh,
                        self.session,
                        self.wire,
                        Class::Text,
                        &c.emitted,
                        &c.raw,
                    ),
                    ChanKind::PlainArgs => respond::seed_leaf(
                        self.sh,
                        self.session,
                        self.wire,
                        Class::ToolInput,
                        &c.emitted,
                        &c.raw,
                    ),
                    // No deltas: `input: {}`, which `non_streaming` seeds nothing for.
                    ChanKind::JsonArgs if c.raw.is_empty() => {}
                    ChanKind::JsonArgs => respond::seed_args_json(
                        self.sh,
                        self.session,
                        self.wire,
                        &c.emitted,
                        &c.raw,
                    ),
                }
            }
            for (kind, restored, raw) in &self.whole_seeds {
                if *kind == ChanKind::JsonArgs {
                    respond::seed_args_json(self.sh, self.session, self.wire, restored, raw);
                } else {
                    respond::seed_leaf(
                        self.sh,
                        self.session,
                        self.wire,
                        Class::ToolInput,
                        restored,
                        raw,
                    );
                }
            }
        }
        for t in self.thinking.values().chain(&self.reasoning) {
            let t: &str = t;
            respond::seed_scan(self.sh, self.session, t, self.seed.clone());
        }
    }

    /// The upstream ended. `(bytes, completed)`; an unfinished stream gets the abort event.
    pub(crate) fn finish(&mut self) -> (Vec<Vec<u8>>, bool) {
        match self.state {
            State::Done => (Vec::new(), true),
            State::Failed | State::Aborted => (Vec::new(), false),
            State::Open
                if self.codec.ended_cleanly()
                    && self.channels.values().all(|c| c.ended)
                    && self.queue.is_none() =>
            {
                self.state = State::Done;
                if self.record {
                    self.seed();
                }
                (Vec::new(), true)
            }
            State::Open | State::Broken => (self.abort(&Abort::Stream), false),
        }
    }

    /// End the stream now: held tails and queued tool calls are dropped,
    /// nothing is seeded. The abort event is produced once.
    pub(crate) fn abort(&mut self, why: &Abort) -> Vec<Vec<u8>> {
        if self.state == State::Aborted {
            return Vec::new();
        }
        self.record_unended();
        self.queue = None;
        self.queued = 0;
        self.buffered.clear();
        self.state = State::Aborted;
        self.codec.abort(why).into_iter().collect()
    }
}

/// The digest tag of an [`Act::Whole`] text: one per kind, since a JSON
/// argument text is tripwired on its decoded leaves and a plain one raw.
fn whole_tag(kind: ChanKind) -> &'static str {
    match kind {
        ChanKind::JsonArgs => "whole-json",
        ChanKind::PlainArgs => "whole-plain",
        ChanKind::Text => "whole-text",
    }
}

/// Resolve one complete token for `col`; `None` leaves it as received.
fn resolve(
    restorer: &mut Restorer<'_>,
    col: Column,
    tok: &str,
) -> Result<Option<Zeroizing<String>>, Fail> {
    let r = Zeroizing::new(restorer.restore(tok, col)?);
    Ok((r.as_str() != tok).then_some(r))
}
