//! A tolerant receive path for one known server quirk. RFC 3501 writes a
//! partial body section as `BODY[TEXT]<0> {200}`: origin, then a space,
//! then the literal. GreenMail 2.1 drops the space (`BODY[TEXT]<0>{200}`),
//! and imap-proto (correctly) refuses the response, which would end the
//! session on every partial fetch. [`TolerantStream`] wraps the transport
//! and, on the server-to-client direction only, inserts exactly one space
//! when a response line ends in `<digits>{digits}\r\n`. Nothing else is
//! ever changed, dropped, or added.
//!
//! The filter is a byte-level state machine, correct across any read-chunk
//! split. A line ending in `{N}\r\n` announces a literal; the next `N` bytes
//! are message data and pass through uninspected (a literal may itself hold
//! `<0>{5}\r\n`), then the filter is back in line mode. Only a candidate
//! `{digits}\r\n` tail is ever held back (at most [`MAX_HELD`] bytes), so a
//! long line streams straight through. Anything that does not match exactly
//! (a non-digit, more than 20 digits, an overflowing `N`, a stray byte
//! before CRLF) is released unchanged. `N` is only counted down, never
//! allocated. The partial fetch stays bounded: this is not a fallback to a
//! full-text fetch. Writes pass through untouched.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Most digits accepted in a literal length (`u64::MAX` has 20).
const MAX_DIGITS: usize = 20;

/// Most bytes ever held back: `{`, the digits, `}`, CR.
pub const MAX_HELD: usize = 1 + MAX_DIGITS + 2;

/// Bytes read from the inner stream per poll.
const SCRATCH: usize = 8 * 1024;

/// What the bytes just released in line mode looked like, for the
/// `<digits>` that must precede a quirk literal.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Origin {
    /// Nothing useful.
    None,
    /// Just saw `<`.
    Open,
    /// `<` and at least one digit.
    Digits,
    /// A complete `<digits>`: the last byte released was its `>`.
    Closed,
}

/// Where a held `{digits}\r` candidate is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// After `{` and zero or more digits.
    Digits,
    /// After `}`.
    Brace,
    /// After `}\r`.
    Cr,
}

/// A literal-announcement candidate not yet released.
struct Held {
    bytes: [u8; MAX_HELD],
    len: usize,
    digits: usize,
    n: u64,
    phase: Phase,
    /// `<digits>` came right before the `{`: insert the space on a match.
    insert: bool,
}

/// The byte filter. Feed it with [`Filter::push`], end it with
/// [`Filter::finish`].
struct Filter {
    /// Literal bytes still to pass through uninspected; 0 is line mode.
    literal: u64,
    origin: Origin,
    held: Option<Held>,
}

impl Filter {
    fn new() -> Self {
        Filter {
            literal: 0,
            origin: Origin::None,
            held: None,
        }
    }

    /// Process `input`, appending the filtered bytes to `out`.
    fn push(&mut self, mut input: &[u8], out: &mut Vec<u8>) {
        while !input.is_empty() {
            if self.literal > 0 {
                let take = usize::try_from(self.literal)
                    .unwrap_or(usize::MAX)
                    .min(input.len());
                out.extend_from_slice(&input[..take]);
                // take <= literal, so this never underflows
                self.literal -= take as u64;
                input = &input[take..];
                continue;
            }
            let b = input[0];
            input = &input[1..];
            self.line_byte(b, out);
        }
    }

    /// End of stream: release anything held, unchanged.
    fn finish(&mut self, out: &mut Vec<u8>) {
        if let Some(h) = self.held.take() {
            out.extend_from_slice(&h.bytes[..h.len]);
        }
        self.origin = Origin::None;
    }

    /// One byte in line mode.
    fn line_byte(&mut self, b: u8, out: &mut Vec<u8>) {
        let Some(h) = self.held.as_mut() else {
            self.free_byte(b, out);
            return;
        };
        let accepted = match (h.phase, b) {
            (Phase::Digits, b'0'..=b'9') if h.digits < MAX_DIGITS => {
                match h
                    .n
                    .checked_mul(10)
                    .and_then(|n| n.checked_add(u64::from(b - b'0')))
                {
                    Some(n) => {
                        h.n = n;
                        h.digits += 1;
                        true
                    }
                    None => false,
                }
            }
            (Phase::Digits, b'}') if h.digits > 0 => {
                h.phase = Phase::Brace;
                true
            }
            (Phase::Brace, b'\r') => {
                h.phase = Phase::Cr;
                true
            }
            (Phase::Cr, b'\n') => {
                // a literal announcement: release it (with the tolerated
                // space), then count the literal through
                if h.insert {
                    out.push(b' ');
                }
                out.extend_from_slice(&h.bytes[..h.len]);
                out.push(b);
                self.literal = h.n;
                self.held = None;
                self.origin = Origin::None;
                return;
            }
            _ => false,
        };
        if accepted {
            // a held candidate is at most `{`, 20 digits, `}`, CR
            h.bytes[h.len] = b;
            h.len += 1;
            return;
        }
        // no match: release the held bytes unchanged, then treat `b` afresh
        // (it may open a new candidate)
        out.extend_from_slice(&h.bytes[..h.len]);
        self.held = None;
        self.origin = Origin::None;
        self.free_byte(b, out);
    }

    /// A line-mode byte with nothing held.
    fn free_byte(&mut self, b: u8, out: &mut Vec<u8>) {
        if b == b'{' {
            let mut bytes = [0u8; MAX_HELD];
            bytes[0] = b;
            self.held = Some(Held {
                bytes,
                len: 1,
                digits: 0,
                n: 0,
                phase: Phase::Digits,
                insert: self.origin == Origin::Closed,
            });
            self.origin = Origin::None;
            return;
        }
        out.push(b);
        self.origin = match (self.origin, b) {
            (_, b'<') => Origin::Open,
            (Origin::Open | Origin::Digits, b'0'..=b'9') => Origin::Digits,
            (Origin::Digits, b'>') => Origin::Closed,
            _ => Origin::None,
        };
    }
}

/// A transport whose read side tolerates a missing space before a
/// partial-fetch literal (see the module docs). Writes pass straight
/// through.
pub struct TolerantStream<S> {
    inner: S,
    filter: Filter,
    scratch: Box<[u8]>,
    out: Vec<u8>,
    out_pos: usize,
    eof: bool,
}

impl<S> TolerantStream<S> {
    /// Wrap `inner`.
    pub fn new(inner: S) -> Self {
        TolerantStream {
            inner,
            filter: Filter::new(),
            scratch: vec![0u8; SCRATCH].into_boxed_slice(),
            out: Vec::with_capacity(SCRATCH + MAX_HELD + 1),
            out_pos: 0,
            eof: false,
        }
    }
}

impl<S: std::fmt::Debug> std::fmt::Debug for TolerantStream<S> {
    // never the buffered bytes: they are mail
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TolerantStream")
            .field("inner", &self.inner)
            .field("in_literal", &(self.filter.literal > 0))
            .field("held_len", &self.filter.held.as_ref().map_or(0, |h| h.len))
            .field("pending_len", &(self.out.len() - self.out_pos))
            .finish()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TolerantStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.out_pos < this.out.len() {
                let n = (this.out.len() - this.out_pos).min(buf.remaining());
                buf.put_slice(&this.out[this.out_pos..this.out_pos + n]);
                this.out_pos += n;
                if this.out_pos == this.out.len() {
                    this.out.clear();
                    this.out_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if this.eof || buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            let mut rb = ReadBuf::new(&mut this.scratch[..]);
            match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
            let got = rb.filled().len();
            if got == 0 {
                this.eof = true;
                this.filter.finish(&mut this.out);
            } else {
                this.filter.push(&this.scratch[..got], &mut this.out);
            }
            // everything may have been held back (a read that ended inside
            // `{12`): read again rather than report a zero-length read,
            // which would mean EOF
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TolerantStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
