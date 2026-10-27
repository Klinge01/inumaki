//! Server-sent events (M8 spec §6.2): a parser that keeps every event's
//! exact bytes, so events without a rewritable field are forwarded
//! byte-identical, and a serializer for rewritten and synthesized events.

/// Largest event accepted (spec §6.2).
pub const MAX_EVENT: usize = 16 << 20;

/// One event. `raw` includes the terminating empty line. The parsed fields
/// carry stream content, so `Debug` prints lengths only.
#[derive(Clone, PartialEq, Eq)]
pub struct SseEvent {
    pub raw: Vec<u8>,
    pub event: Option<String>,
    pub id: Option<String>,
    pub data: Option<Vec<u8>>,
}

impl std::fmt::Debug for SseEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SseEvent")
            .field("raw_len", &self.raw.len())
            .field("event_len", &self.event.as_ref().map(String::len))
            .field("id_len", &self.id.as_ref().map(String::len))
            .field("data_len", &self.data.as_ref().map(Vec::len))
            .finish()
    }
}

/// Why a stream could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SseError {
    #[error("server-sent event too large")]
    TooLarge,
    /// An event name or id to write holds a line break (CR or LF): written,
    /// it would start another field or event.
    #[error("server-sent event field holds a line break")]
    LineBreak,
}

/// Incremental parser. Lines end with `\r\n`, `\n`, or `\r`; an empty line
/// ends an event.
///
/// Fails closed: after one refusal every later `push` and `finish` is
/// refused too, so the oversized bytes still buffered are never handed out.
///
/// One UTF-8 byte-order mark at the start of the stream is dropped, as a
/// client's decoder drops it (final review I1): kept, it would turn the
/// first line into an unknown field, so the first event would carry no
/// data and pass unchecked while the client still parses it.
pub struct SseParser {
    buf: Vec<u8>,
    pos: usize,
    line_start: usize,
    max: usize,
    failed: bool,
    /// No byte other than a possible start of the byte-order mark was seen yet.
    at_start: bool,
}

const BOM: &[u8] = b"\xEF\xBB\xBF";

impl SseParser {
    pub fn new(max: usize) -> SseParser {
        SseParser {
            buf: Vec::new(),
            pos: 0,
            line_start: 0,
            max,
            failed: false,
            at_start: true,
        }
    }

    /// Append bytes; every event they complete. An event (complete or still
    /// open) larger than `max` bytes is refused.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<SseEvent>, SseError> {
        if self.failed {
            return Err(SseError::TooLarge);
        }
        self.buf.extend_from_slice(chunk);
        if self.at_start {
            if self.buf.starts_with(BOM) {
                self.buf.drain(..BOM.len());
                self.at_start = false;
            } else if !BOM.starts_with(&self.buf) {
                self.at_start = false;
            }
        }
        let mut out = Vec::new();
        while let Some(end) = self.next_end() {
            if end > self.max {
                return Err(self.fail());
            }
            let raw: Vec<u8> = self.buf.drain(..end).collect();
            self.pos = 0;
            self.line_start = 0;
            out.push(parse(raw));
        }
        if self.buf.len() > self.max {
            return Err(self.fail());
        }
        Ok(out)
    }

    /// Bytes left when the stream ended, as a last event, so concatenating
    /// every `raw` still reproduces the input. Refused after a refusal.
    pub fn finish(&mut self) -> Result<Option<SseEvent>, SseError> {
        if self.failed {
            return Err(SseError::TooLarge);
        }
        let raw = std::mem::take(&mut self.buf);
        self.pos = 0;
        self.line_start = 0;
        Ok(if raw.is_empty() {
            None
        } else {
            Some(parse(raw))
        })
    }

    /// Refuse from now on and drop what is buffered.
    fn fail(&mut self) -> SseError {
        self.failed = true;
        self.buf = Vec::new();
        self.pos = 0;
        self.line_start = 0;
        SseError::TooLarge
    }

    /// One past the empty line ending the first buffered event, resuming
    /// where the last call stopped.
    fn next_end(&mut self) -> Option<usize> {
        let b = &self.buf;
        while self.pos < b.len() {
            let eol = match b[self.pos] {
                b'\n' => 1,
                b'\r' if self.pos + 1 < b.len() => {
                    if b[self.pos + 1] == b'\n' {
                        2
                    } else {
                        1
                    }
                }
                b'\r' => return None, // maybe the first half of CRLF
                _ => {
                    self.pos += 1;
                    continue;
                }
            };
            let empty = self.pos == self.line_start;
            self.pos += eol;
            self.line_start = self.pos;
            if empty {
                return Some(self.pos);
            }
        }
        None
    }
}

fn lines(b: &[u8]) -> Vec<&[u8]> {
    let (mut out, mut s, mut i) = (Vec::new(), 0usize, 0usize);
    while i < b.len() {
        match b[i] {
            b'\n' => {
                out.push(&b[s..i]);
                i += 1;
                s = i;
            }
            b'\r' => {
                out.push(&b[s..i]);
                i += if b.get(i + 1) == Some(&b'\n') { 2 } else { 1 };
                s = i;
            }
            _ => i += 1,
        }
    }
    if s < b.len() {
        out.push(&b[s..]);
    }
    out
}

fn parse(raw: Vec<u8>) -> SseEvent {
    let (mut event, mut id, mut data): (Option<String>, Option<String>, Option<Vec<u8>>) =
        (None, None, None);
    for line in lines(&raw) {
        if line.is_empty() || line[0] == b':' {
            continue;
        }
        let (name, value) = match line.iter().position(|b| *b == b':') {
            Some(i) => (
                &line[..i],
                line[i + 1..].strip_prefix(b" ").unwrap_or(&line[i + 1..]),
            ),
            None => (line, &b""[..]),
        };
        match name {
            b"event" => event = Some(String::from_utf8_lossy(value).into_owned()),
            b"id" => id = Some(String::from_utf8_lossy(value).into_owned()),
            b"data" => match data.as_mut() {
                Some(d) => {
                    d.push(b'\n');
                    d.extend_from_slice(value);
                }
                None => data = Some(value.to_vec()),
            },
            _ => {}
        }
    }
    SseEvent {
        raw,
        event,
        id,
        data,
    }
}

/// One event in canonical form (`\n` line ends; one `data:` line per data
/// line).
///
/// Upstream model text and restored originals reach `data`, so every line
/// break in it (`\r\n`, `\r`, or `\n`) ends a `data:` line: a CR can never
/// start another field or event toward the client (the client reads the
/// pieces back joined by `\n`). An `event` or `id` holding CR or LF is
/// refused ([`SseError::LineBreak`]); the caller aborts the stream.
pub fn serialize(event: Option<&str>, id: Option<&str>, data: &[u8]) -> Result<Vec<u8>, SseError> {
    let mut out = Vec::with_capacity(data.len() + 32);
    for (name, value) in [(&b"event: "[..], event), (b"id: ", id)] {
        let Some(v) = value else { continue };
        if v.bytes().any(|b| b == b'\r' || b == b'\n') {
            return Err(SseError::LineBreak);
        }
        out.extend_from_slice(name);
        out.extend_from_slice(v.as_bytes());
        out.push(b'\n');
    }
    let lines = if data.is_empty() {
        vec![data]
    } else {
        let mut v = lines(data);
        // A trailing line break ends one more, empty, line.
        if matches!(data.last(), Some(b'\r' | b'\n')) {
            v.push(&data[data.len()..]);
        }
        v
    };
    for line in lines {
        out.extend_from_slice(b"data: ");
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out.push(b'\n');
    Ok(out)
}

/// A body whose first bytes read as an event stream (engine spec §8.3
/// amendment: detection by content when `Content-Type` is missing).
pub fn looks_like_sse(first: &[u8]) -> bool {
    let s = first.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(first);
    let s = &s[s
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(s.len())..];
    [&b"data:"[..], b"event:", b"id:", b"retry:", b":"]
        .iter()
        .any(|p| s.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    const STREAM: &[u8] = b": keep-alive\r\n\r\nevent: content_block_delta\r\ndata: {\"a\":\r\ndata: 1}\r\n\r\nid: 7\nevent: ping\ndata: {}\n\ndata: [DONE]\n\n";

    #[test]
    fn every_split_yields_the_same_events_and_bytes() {
        let whole = SseParser::new(MAX_EVENT).push(STREAM).unwrap();
        assert_eq!(whole.len(), 4);
        assert_eq!(whole[0].data, None, "a comment-only event");
        assert_eq!(whole[1].event.as_deref(), Some("content_block_delta"));
        assert_eq!(whole[1].data.as_deref(), Some(&b"{\"a\":\n1}"[..]));
        assert_eq!(whole[2].id.as_deref(), Some("7"));
        assert_eq!(whole[3].data.as_deref(), Some(&b"[DONE]"[..]));
        for i in 0..=STREAM.len() {
            let mut p = SseParser::new(MAX_EVENT);
            let mut evs = p.push(&STREAM[..i]).unwrap();
            evs.extend(p.push(&STREAM[i..]).unwrap());
            assert!(p.finish().unwrap().is_none(), "split at {i}");
            assert_eq!(evs, whole, "split at {i}");
            assert_eq!(
                evs.iter().flat_map(|e| e.raw.clone()).collect::<Vec<u8>>(),
                STREAM.to_vec()
            );
        }
        let mut p = SseParser::new(MAX_EVENT);
        let evs: Vec<SseEvent> = STREAM.iter().flat_map(|b| p.push(&[*b]).unwrap()).collect();
        assert_eq!(evs, whole, "one byte at a time");
    }

    /// Final review I1: a leading byte-order mark is dropped, also when it
    /// arrives split, so the first event is parsed (and checked) as the
    /// client parses it. A mark later in the stream is not touched.
    #[test]
    fn a_leading_byte_order_mark_is_dropped() {
        let stream = b"\xEF\xBB\xBFdata: {}\n\n";
        for i in 0..=stream.len() {
            let mut p = SseParser::new(MAX_EVENT);
            let mut evs = p.push(&stream[..i]).unwrap();
            evs.extend(p.push(&stream[i..]).unwrap());
            assert_eq!(evs.len(), 1, "split at {i}");
            assert_eq!(evs[0].data.as_deref(), Some(&b"{}"[..]), "split at {i}");
            assert_eq!(evs[0].raw, b"data: {}\n\n".to_vec());
        }
        let mut p = SseParser::new(MAX_EVENT);
        let evs = p.push(b"data: 1\n\n\xEF\xBB\xBFdata: 2\n\n").unwrap();
        assert_eq!(evs[1].data, None, "only the stream's first bytes");
    }

    #[test]
    fn an_oversized_event_is_refused() {
        let mut p = SseParser::new(64);
        assert_eq!(p.push(&[b'a'; 100]).unwrap_err(), SseError::TooLarge);
    }

    #[test]
    fn sniffing_and_serializing() {
        assert!(looks_like_sse(b"\n\nevent: x\n"));
        assert!(looks_like_sse(b"data: {}"));
        assert!(!looks_like_sse(b"{\"type\":\"message\"}"));
        let out = serialize(Some("ping"), None, b"{}").unwrap();
        assert_eq!(out, b"event: ping\ndata: {}\n\n".to_vec());
        let back = SseParser::new(MAX_EVENT).push(&out).unwrap();
        assert_eq!(back[0].data.as_deref(), Some(&b"{}"[..]));
    }

    /// Fix wave 2a (A): upstream model text and restored text reach
    /// `serialize`, so a line break in the data (CR, LF, or CRLF) never
    /// starts a new field or event toward the client: each piece is its
    /// own `data:` line, and the client reads one event with the same data
    /// (a CR read back as LF).
    #[test]
    fn a_line_break_in_the_data_never_makes_a_field_or_an_event() {
        for (data, back) in [
            (&b"a\rid: 1\revent: x"[..], &b"a\nid: 1\nevent: x"[..]),
            (b"a\r\rdata: b", b"a\n\ndata: b"),
            (b"a\r\nevent: x\r\n", b"a\nevent: x\n"),
            (b"a\n\nevent: x", b"a\n\nevent: x"),
            (b"\r", b"\n"),
        ] {
            let out = serialize(None, None, data).unwrap();
            let evs = SseParser::new(MAX_EVENT).push(&out).unwrap();
            assert_eq!(evs.len(), 1, "{data:?}");
            assert_eq!(evs[0].event, None, "{data:?}");
            assert_eq!(evs[0].id, None, "{data:?}");
            assert_eq!(evs[0].data.as_deref(), Some(back), "{data:?}");
            assert_eq!(evs[0].raw, out);
        }
    }

    /// Fix wave 2a (A): an event name or id with a line break is refused,
    /// never written.
    #[test]
    fn a_line_break_in_the_event_name_or_id_is_refused() {
        for (e, i) in [
            (Some("a\rdata: x"), None),
            (Some("a\n"), None),
            (None, Some("1\r\nevent: x")),
            (Some("ok"), Some("\r")),
        ] {
            assert_eq!(
                serialize(e, i, b"{}").unwrap_err(),
                SseError::LineBreak,
                "{e:?} {i:?}"
            );
        }
        assert_eq!(
            serialize(Some("ok"), Some("7"), b"{}").unwrap(),
            b"event: ok\nid: 7\ndata: {}\n\n".to_vec()
        );
    }

    #[test]
    fn a_completed_oversized_event_is_refused_too() {
        let mut p = SseParser::new(64);
        let mut ev = b"data: ".to_vec();
        ev.extend_from_slice(&[b'a'; 100]);
        ev.extend_from_slice(b"\n\n");
        assert_eq!(p.push(&ev).unwrap_err(), SseError::TooLarge);
    }

    #[test]
    fn a_refused_parser_stays_refused() {
        let mut p = SseParser::new(64);
        assert!(p.push(&[b'a'; 100]).is_err());
        assert_eq!(p.push(b"\n\n").unwrap_err(), SseError::TooLarge);
        assert_eq!(
            p.finish().unwrap_err(),
            SseError::TooLarge,
            "never the buffered bytes"
        );
    }

    #[test]
    fn debug_prints_lengths_only() {
        let evs = SseParser::new(MAX_EVENT)
            .push(b"event: secret-name\nid: secret-id\ndata: secret-value\n\n")
            .unwrap();
        let shown = format!("{:?}", evs[0]);
        assert!(!shown.contains("secret"), "{shown}");
        assert!(shown.contains("data_len"), "{shown}");
    }
}
