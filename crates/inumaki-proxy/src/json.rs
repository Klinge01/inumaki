//! A span-recording JSON scanner and an in-place rewriter (M8 spec §5.7).
//! `scan` validates a body (strict RFC 8259, duplicate keys refused, depth
//! bounded) and reports every value with its path and byte range; strings
//! and keys come with their decoded text. `splice` replaces byte ranges in
//! a copy of the input, so every untouched byte is forwarded as received.
//!
//! This is the hostile-input boundary of the proxy: a body that this module
//! accepts must mean the same thing to the provider as it does here, so
//! anything ambiguous (duplicate keys, lone surrogates, trailing bytes,
//! excessive nesting) is refused. Errors carry no position and no text.
//!
//! Paths are structural: each node stores its parent's index and its own
//! single path segment, so memory grows with the body size only (not with
//! nesting depth times node count). Use `path(nodes, i)` for a root-to-node
//! path, `depth`, or `segs` (leaf to root, no allocation). This replaces the
//! brief's per-node `path: Vec<Seg>`, which a hostile body could amplify to
//! gigabytes (approved deviation, M8-1 Task 4 review).

use std::collections::HashSet;
use std::ops::Range;

/// Deepest nesting accepted: at most this many containers inside one another.
/// One less than the 128 that `serde_json` refuses, so this scanner never
/// accepts a body a downstream `serde_json` parse would reject.
pub const MAX_DEPTH: usize = 127;

/// One step of a JSON path. Keys can be data: `Debug` prints lengths only.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Seg {
    Key(String),
    Index(usize),
}

impl std::fmt::Debug for Seg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Seg::Key(k) => write!(f, "Key({})", k.len()),
            Seg::Index(i) => write!(f, "Index({i})"),
        }
    }
}

/// What a node is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    Object,
    Array,
    String,
    Key,
    Other,
}

/// A value (or an object key) with its byte range.
///
/// `parent` is the index of the enclosing container node (`None` for the
/// document root) and `seg` is the step from that container to this node:
/// `Key(k)` for an object member's key and for its value, `Index(n)` for an
/// array element, `None` for the root. A key node and its value therefore
/// share one path. `Debug` shows the kind only: no keys, values, or positions.
#[derive(Clone)]
pub struct Node {
    pub parent: Option<usize>,
    pub seg: Option<Seg>,
    pub kind: NodeKind,
    pub range: Range<usize>,
    pub text: Option<String>,
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Node")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// The path segments of node `i`, from the node up to the root (no allocation).
/// A parent is followed only when its index is smaller than the current node's,
/// so hand-built cyclic nodes end the walk. An out-of-range `i` has no segments.
pub fn segs(nodes: &[Node], i: usize) -> impl Iterator<Item = &Seg> {
    let mut cur = Some(i);
    std::iter::from_fn(move || {
        while let Some(at) = cur {
            let n = nodes.get(at)?;
            cur = n.parent.filter(|&p| p < at);
            if let Some(seg) = &n.seg {
                return Some(seg);
            }
        }
        None
    })
}

/// The path of node `i`, root to node (empty for an out-of-range index).
pub fn path(nodes: &[Node], i: usize) -> Vec<Seg> {
    let mut out: Vec<Seg> = segs(nodes, i).cloned().collect();
    out.reverse();
    out
}

/// The number of path segments of node `i` (0 for the root).
pub fn depth(nodes: &[Node], i: usize) -> usize {
    segs(nodes, i).count()
}

/// Why a body was refused. No position, no text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JsonError {
    #[error("invalid JSON")]
    Invalid,
    #[error("JSON nested too deeply")]
    TooDeep,
    #[error("duplicate object key")]
    DuplicateKey,
}

use JsonError::{DuplicateKey, Invalid, TooDeep};

/// Scan `src`; nodes in document order, a container before its children.
pub fn scan(src: &[u8]) -> Result<Vec<Node>, JsonError> {
    std::str::from_utf8(src).map_err(|_| Invalid)?;
    let mut p = Parser {
        s: src,
        i: 0,
        nodes: Vec::new(),
    };
    p.ws();
    p.value(0, None, None)?;
    p.ws();
    if p.i != src.len() {
        return Err(Invalid);
    }
    Ok(p.nodes)
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    nodes: Vec<Node>,
}

impl Parser<'_> {
    fn push_node(
        &mut self,
        parent: Option<usize>,
        seg: Option<Seg>,
        kind: NodeKind,
        range: Range<usize>,
        text: Option<String>,
    ) {
        self.nodes.push(Node {
            parent,
            seg,
            kind,
            range,
            text,
        });
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn expect(&mut self, b: u8) -> Result<(), JsonError> {
        if self.peek() == Some(b) {
            self.i += 1;
            Ok(())
        } else {
            Err(Invalid)
        }
    }

    /// `depth` is the number of containers already open around this value;
    /// `parent` and `seg` locate it (see `Node`).
    fn value(
        &mut self,
        depth: usize,
        parent: Option<usize>,
        seg: Option<Seg>,
    ) -> Result<(), JsonError> {
        match self.peek() {
            Some(b'{') => self.container(depth, true, parent, seg),
            Some(b'[') => self.container(depth, false, parent, seg),
            Some(b'"') => {
                let start = self.i;
                let text = self.string()?;
                self.push_node(parent, seg, NodeKind::String, start..self.i, Some(text));
                Ok(())
            }
            Some(_) => {
                let start = self.i;
                self.scalar()?;
                self.push_node(parent, seg, NodeKind::Other, start..self.i, None);
                Ok(())
            }
            None => Err(Invalid),
        }
    }

    fn container(
        &mut self,
        depth: usize,
        object: bool,
        parent: Option<usize>,
        seg: Option<Seg>,
    ) -> Result<(), JsonError> {
        // Checked before anything is recorded: this is also the stack bound,
        // because `container` recurses only through `value`.
        if depth >= MAX_DEPTH {
            return Err(TooDeep);
        }
        let start = self.i;
        let at = self.nodes.len();
        let kind = if object {
            NodeKind::Object
        } else {
            NodeKind::Array
        };
        self.push_node(parent, seg, kind, start..start, None);
        self.i += 1;
        self.ws();
        let close = if object { b'}' } else { b']' };
        let mut keys: HashSet<String> = HashSet::new();
        if self.peek() == Some(close) {
            self.i += 1;
        } else {
            let mut n = 0usize;
            loop {
                self.ws();
                let child_seg = if object {
                    if self.peek() != Some(b'"') {
                        return Err(Invalid);
                    }
                    let kstart = self.i;
                    // Duplicates are compared on the decoded key, so a key
                    // spelled with escapes collides with its plain spelling,
                    // as a provider's parser would see it.
                    let key = self.string()?;
                    if !keys.insert(key.clone()) {
                        return Err(DuplicateKey);
                    }
                    let seg = Seg::Key(key.clone());
                    self.push_node(
                        Some(at),
                        Some(seg.clone()),
                        NodeKind::Key,
                        kstart..self.i,
                        Some(key),
                    );
                    self.ws();
                    self.expect(b':')?;
                    self.ws();
                    seg
                } else {
                    Seg::Index(n)
                };
                self.value(depth + 1, Some(at), Some(child_seg))?;
                n += 1;
                self.ws();
                match self.peek() {
                    Some(b',') => self.i += 1,
                    Some(c) if c == close => {
                        self.i += 1;
                        break;
                    }
                    _ => return Err(Invalid),
                }
            }
        }
        self.nodes[at].range = start..self.i;
        Ok(())
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        let h = self.s.get(self.i..self.i + 4).ok_or(Invalid)?;
        if !h.iter().all(u8::is_ascii_hexdigit) {
            return Err(Invalid);
        }
        let s = std::str::from_utf8(h).map_err(|_| Invalid)?;
        self.i += 4;
        u32::from_str_radix(s, 16).map_err(|_| Invalid)
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let b = self.peek().ok_or(Invalid)?;
            match b {
                b'"' => {
                    self.i += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.i += 1;
                    let e = self.peek().ok_or(Invalid)?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let c = if (0xD800..0xDC00).contains(&hi) {
                                if self.s.get(self.i..self.i + 2) != Some(b"\\u") {
                                    return Err(Invalid);
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(Invalid);
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return Err(Invalid);
                            } else {
                                hi
                            };
                            out.push(char::from_u32(c).ok_or(Invalid)?);
                        }
                        _ => return Err(Invalid),
                    }
                }
                0x00..=0x1f => return Err(Invalid),
                _ => {
                    // The whole input was validated as UTF-8 up front, so a
                    // non-ASCII byte here is the lead byte of a full sequence.
                    let len = match b {
                        0x00..=0x7f => 1,
                        0xc0..=0xdf => 2,
                        0xe0..=0xef => 3,
                        _ => 4,
                    };
                    let ch = std::str::from_utf8(self.s.get(self.i..self.i + len).ok_or(Invalid)?)
                        .map_err(|_| Invalid)?;
                    out.push_str(ch);
                    self.i += len;
                }
            }
        }
    }

    /// Numbers are checked against the RFC 8259 grammar only. A well-formed
    /// number outside the `f64` range (such as `1e400`) is accepted: numbers
    /// are never rewritten, so they are forwarded as received.
    fn scalar(&mut self) -> Result<(), JsonError> {
        for lit in [&b"true"[..], b"false", b"null"] {
            if self.s[self.i..].starts_with(lit) {
                self.i += lit.len();
                return Ok(());
            }
        }
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.i += 1;
                }
            }
            _ => return Err(Invalid),
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(Invalid);
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.i += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(Invalid);
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.i += 1;
            }
        }
        if self.i == start {
            return Err(Invalid);
        }
        Ok(())
    }
}

/// `s` as a JSON string literal: `"`, `\`, and control characters escaped;
/// everything else as UTF-8.
pub fn quote(s: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The byte range whose removal deletes one member (`"key": value`) of the
/// object node `obj`, together with one adjoining comma, so that the rest of
/// the body stays valid JSON and byte-identical:
///
/// - a member followed by another: from its key to the next member's key
///   (`{"a":1, "b":2}` becomes `{"b":2}`);
/// - the last of several: from the previous member's value end to its own
///   value end (`{"a":1, "b":2}` becomes `{"a":1}`);
/// - an only member: its key to its value end (`{"a":1}` becomes `{}`;
///   whitespace around it stays).
///
/// `key` is the member's key node; its value is the node right after it
/// (`scan` pushes them in that order). `None` when the nodes do not
/// describe such a member: the caller then removes nothing.
pub fn member_removal(nodes: &[Node], obj: usize, key: usize) -> Option<Range<usize>> {
    let o = nodes.get(obj)?;
    let k = nodes.get(key)?;
    let v = nodes.get(key.checked_add(1)?)?;
    if o.kind != NodeKind::Object
        || k.kind != NodeKind::Key
        || k.parent != Some(obj)
        || v.kind == NodeKind::Key
        || v.parent != Some(obj)
        || v.seg != k.seg
        || key <= obj
    {
        return None;
    }
    // The object's descendants follow it in document order, inside its range.
    let mut prev_value_end = None;
    let mut next_key_start = None;
    for (i, n) in nodes.iter().enumerate().skip(obj + 1) {
        if n.range.start >= o.range.end {
            break;
        }
        if n.parent != Some(obj) {
            continue;
        }
        if i < key && n.kind != NodeKind::Key {
            prev_value_end = Some(n.range.end);
        } else if i > key + 1 && n.kind == NodeKind::Key {
            next_key_start = Some(n.range.start);
            break;
        }
    }
    let r = match (next_key_start, prev_value_end) {
        (Some(next), _) => k.range.start..next,
        (None, Some(prev)) => prev..v.range.end,
        (None, None) => k.range.start..v.range.end,
    };
    (r.start < r.end && r.end <= o.range.end).then_some(r)
}

/// Replace non-overlapping byte ranges of `src` with raw bytes. Inverted,
/// out-of-bounds, or overlapping ranges are refused (never a panic).
pub fn splice(src: &[u8], mut edits: Vec<(Range<usize>, Vec<u8>)>) -> Result<Vec<u8>, JsonError> {
    edits.sort_by_key(|(r, _)| (r.start, r.end));
    let mut out = Vec::with_capacity(src.len());
    let mut cur = 0usize;
    for (r, bytes) in edits {
        if r.start < cur || r.start > r.end || r.end > src.len() {
            return Err(Invalid);
        }
        out.extend_from_slice(&src[cur..r.start]);
        out.extend_from_slice(&bytes);
        cur = r.end;
    }
    out.extend_from_slice(&src[cur..]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untouched_bytes_are_forwarded_as_received() {
        let src = r#"{ "a" : 1.0 , "b":[true,null,"xé"], "c":{"d":"Zyxwuria"} }"#.as_bytes();
        let nodes = scan(src).unwrap();
        let d = nodes
            .iter()
            .find(|n| n.kind == NodeKind::String && n.text.as_deref() == Some("Zyxwuria"))
            .unwrap();
        let out = splice(
            src,
            vec![(d.range.clone(), quote("<PERSON_ab12>").into_bytes())],
        )
        .unwrap();
        let expect = r#"{ "a" : 1.0 , "b":[true,null,"xé"], "c":{"d":"<PERSON_ab12>"} }"#;
        assert_eq!(out, expect.as_bytes().to_vec());
        assert_eq!(splice(src, Vec::new()).unwrap(), src.to_vec());
    }

    #[test]
    fn strings_decode_escapes_and_surrogates() {
        let nodes = scan(r#"["a\"b\\c\nü😀"]"#.as_bytes()).unwrap();
        assert_eq!(nodes[1].text.as_deref(), Some("a\"b\\c\nü😀"));
        assert_eq!(path(&nodes, 1), vec![Seg::Index(0)]);
    }

    #[test]
    fn keys_are_nodes_with_the_object_path() {
        let nodes = scan(br#"{"input":{"Zyx":"v"}}"#).unwrap();
        let ki = nodes
            .iter()
            .position(|n| n.kind == NodeKind::Key && n.text.as_deref() == Some("Zyx"))
            .unwrap();
        let key = &nodes[ki];
        let expect = vec![Seg::Key("input".into()), Seg::Key("Zyx".into())];
        assert_eq!(path(&nodes, ki), expect);
        assert_eq!(depth(&nodes, ki), 2);
        // The key's value shares its path.
        assert_eq!(path(&nodes, ki + 1), expect);
        assert_eq!(path(&nodes, 0), Vec::<Seg>::new());
        assert_eq!(&br#"{"input":{"Zyx":"v"}}"#[key.range.clone()], br#""Zyx""#);
    }

    #[test]
    fn quote_escapes_what_json_requires() {
        assert_eq!(quote("a\"b\\c\n\t\u{1}ü"), r#""a\"b\\c\n\t\u0001ü""#);
        let round: String = serde_json::from_str(&quote("x\"y\u{7f}\u{2028}")).unwrap();
        assert_eq!(round, "x\"y\u{7f}\u{2028}");
    }

    /// Review Focus 4.
    #[test]
    fn hostile_json_is_refused() {
        assert_eq!(
            scan(br#"{"a":1,"a":2}"#).unwrap_err(),
            JsonError::DuplicateKey
        );
        assert_eq!(scan(br#"["\ud800"]"#).unwrap_err(), JsonError::Invalid);
        assert_eq!(scan(b"[1,]").unwrap_err(), JsonError::Invalid);
        assert_eq!(scan(b"{\"a\":\"\x01\"}").unwrap_err(), JsonError::Invalid);
        assert_eq!(scan(b"[01]").unwrap_err(), JsonError::Invalid);
        assert_eq!(scan(b"{} x").unwrap_err(), JsonError::Invalid);
        let deep = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
        assert_eq!(scan(deep.as_bytes()).unwrap_err(), JsonError::TooDeep);
        assert_eq!(scan(&[b'"', 0xff, b'"']).unwrap_err(), JsonError::Invalid);
        // Escaped spellings of one key are one key.
        assert_eq!(
            scan(br#"{"a":1,"\u0061":2}"#).unwrap_err(),
            JsonError::DuplicateKey
        );
        // A surrogate pair is fine; a low surrogate alone or a broken pair is not.
        assert!(scan(br#"["\ud83d\ude00"]"#).is_ok());
        assert_eq!(scan(br#"["\ude00"]"#).unwrap_err(), JsonError::Invalid);
        assert_eq!(
            scan(br#"["\ud83d\u0041"]"#).unwrap_err(),
            JsonError::Invalid
        );
        // Nesting: exactly MAX_DEPTH containers pass, one more is refused.
        let nest = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
        assert!(scan(nest(MAX_DEPTH).as_bytes()).is_ok());
        assert_eq!(
            MAX_DEPTH + 1,
            128,
            "serde_json refuses 128 nested containers"
        );
        assert_eq!(
            scan(nest(MAX_DEPTH + 1).as_bytes()).unwrap_err(),
            JsonError::TooDeep
        );
        // Unterminated deep input is refused before the stack grows.
        assert_eq!(
            scan("[".repeat(100_000).as_bytes()).unwrap_err(),
            JsonError::TooDeep
        );
        // A byte-order mark is not JSON whitespace.
        assert_eq!(scan(b"\xef\xbb\xbf{}").unwrap_err(), JsonError::Invalid);
    }

    #[test]
    fn malformed_numbers_and_literals_are_refused() {
        for bad in ["-", "1.", "1e", "+1", ".5", "-01", "1e+", "truex"] {
            assert_eq!(
                scan(bad.as_bytes()).unwrap_err(),
                JsonError::Invalid,
                "{bad}"
            );
            let arr = format!("[{bad}]");
            assert_eq!(
                scan(arr.as_bytes()).unwrap_err(),
                JsonError::Invalid,
                "{arr}"
            );
        }
        // Well-formed but out of f64 range: accepted, never rewritten.
        assert!(scan(b"[1e400,-0,0.5E-3]").is_ok());
    }

    /// Memory follows the body, not depth x nodes: one segment and one parent
    /// index per node, so deep nesting followed by a wide array stays cheap.
    #[test]
    fn memory_is_proportional_to_the_body() {
        assert!(
            std::mem::size_of::<Node>() <= 128,
            "{}",
            std::mem::size_of::<Node>()
        );
        let mut body = "[".repeat(126);
        body.push_str(&"0,".repeat(200_000));
        body.push('0');
        body.push_str(&"]".repeat(126));
        let t = std::time::Instant::now();
        let nodes = scan(body.as_bytes()).unwrap();
        assert!(
            t.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            t.elapsed()
        );
        assert_eq!(nodes.len(), 126 + 200_001);
        assert!(nodes.len() <= body.len());
        // The deepest elements still resolve their full path on demand.
        let last = nodes.len() - 1;
        assert_eq!(depth(&nodes, last), 126);
        assert_eq!(segs(&nodes, last).next(), Some(&Seg::Index(200_000)));
    }

    /// Legitimate bodies are never refused for their shape: deep tool
    /// schemas are common (MCP, Claude Code), and so is a large history.
    #[test]
    fn deep_schemas_and_large_bodies_are_accepted() {
        fn schema(level: usize) -> String {
            if level == 0 {
                return r#"{"type":"string","description":"a leaf field"}"#.to_string();
            }
            let inner = schema(level - 1);
            format!(
                r#"{{"type":"object","properties":{{"alpha":{inner},"beta":{inner},"gamma":{inner}}},"required":["alpha"]}}"#
            )
        }
        let one = schema(5);
        assert!(one.len() > 20_000);
        assert!(scan(one.as_bytes()).is_ok());

        let tools = (0..40)
            .map(|i| format!(r#"{{"name":"tool_{i}","parameters":{one}}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let body = format!(r#"{{"model":"m","tools":[{tools}],"messages":[]}}"#);
        assert!(body.len() > 800_000);
        let nodes = scan(body.as_bytes()).unwrap();
        // A deep leaf's path resolves root to leaf.
        let leaf = nodes
            .iter()
            .rposition(|n| n.kind == NodeKind::String && n.text.as_deref() == Some("a leaf field"))
            .unwrap();
        let p = path(&nodes, leaf);
        assert_eq!(p[0], Seg::Key("tools".into()));
        assert_eq!(p[1], Seg::Index(39));
        assert_eq!(p.len(), 2 + 1 + 5 * 2 + 1);

        // {"messages":[{"content":[{"type":"text","text":"..."}, ...]}]}: 10 000 strings at depth 6.
        let parts = (0..10_000)
            .map(|i| format!(r#"{{"type":"text","text":"part {i}"}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let body = format!(r#"{{"messages":[{{"role":"user","content":[{parts}]}}]}}"#);
        let nodes = scan(body.as_bytes()).unwrap();
        assert!(nodes.iter().filter(|n| n.kind == NodeKind::String).count() >= 20_000);
    }

    /// Ruling L58: removing a member keeps valid JSON and every other byte.
    #[test]
    fn member_removal_fixes_commas_and_keeps_other_bytes() {
        let remove = |src: &str, key: &str| -> String {
            let nodes = scan(src.as_bytes()).unwrap();
            let k = nodes
                .iter()
                .rposition(|n| n.kind == NodeKind::Key && n.text.as_deref() == Some(key))
                .unwrap();
            let obj = nodes[k].parent.unwrap();
            let r = member_removal(&nodes, obj, k).unwrap();
            let out = splice(src.as_bytes(), vec![(r, Vec::new())]).unwrap();
            let out = String::from_utf8(out).unwrap();
            assert!(scan(out.as_bytes()).is_ok(), "{out}");
            out
        };
        assert_eq!(
            remove(r#"{"a":1, "x":{"p":[1,2]} ,"b":2}"#, "x"),
            r#"{"a":1, "b":2}"#
        );
        assert_eq!(remove(r#"{"x":"v" , "b":2}"#, "x"), r#"{"b":2}"#);
        assert_eq!(remove(r#"{"a":1 , "x" : "v" }"#, "x"), r#"{"a":1 }"#);
        assert_eq!(remove(r#"{"x":"v"}"#, "x"), r#"{}"#);
        assert_eq!(remove(r#"{ "x" : [] }"#, "x"), r#"{  }"#);
        // Nested: only the named object's member goes.
        assert_eq!(
            remove(r#"{"m":{"x":1,"y":2},"x":3}"#, "y"),
            r#"{"m":{"x":1},"x":3}"#
        );
        // Not a member of that object: nothing.
        let nodes = scan(br#"{"a":{"x":1}}"#).unwrap();
        let k = nodes
            .iter()
            .position(|n| n.text.as_deref() == Some("x"))
            .unwrap();
        assert!(member_removal(&nodes, 0, k).is_none());
        assert!(member_removal(&nodes, 0, 99).is_none());
        let arr = scan(br#"[{"x":1}]"#).unwrap();
        assert!(member_removal(&arr, 0, 2).is_none());
    }

    #[test]
    fn splice_refuses_bad_ranges_without_panicking() {
        let src = b"0123456789";
        let e = |r: std::ops::Range<usize>| (r, b"x".to_vec());
        let inverted = |start, end| std::ops::Range { start, end };
        assert!(splice(src, vec![e(2..4), e(3..5)]).is_err());
        assert!(splice(src, vec![e(8..12)]).is_err());
        assert!(splice(src, vec![e(inverted(20, 4))]).is_err());
        assert!(splice(src, vec![e(inverted(6, 4))]).is_err());
        // Out-of-order input is sorted; adjacent edits are fine.
        assert_eq!(
            splice(src, vec![e(5..7), e(2..5)]).unwrap(),
            b"01xx789".to_vec()
        );
    }

    /// Keys and string values are data: neither `Debug` nor the error text may show them.
    #[test]
    fn debug_and_errors_carry_no_body_text() {
        let nodes = scan(br#"{"SecretKeyZyx":"SecretValueZyx"}"#).unwrap();
        let shown = format!("{nodes:?}");
        assert!(
            !shown.contains("Zyx") && !shown.contains("range"),
            "{shown}"
        );
        for e in [
            JsonError::Invalid,
            JsonError::TooDeep,
            JsonError::DuplicateKey,
        ] {
            assert!(!format!("{e:?} {e}").contains("Zyx"));
        }
        let dup = scan(br#"{"SecretKeyZyx":1,"SecretKeyZyx":2}"#).unwrap_err();
        assert!(!format!("{dup:?} {dup}").contains("Zyx"));
    }
}
