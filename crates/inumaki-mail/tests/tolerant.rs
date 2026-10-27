//! The partial-fetch quirk filter (tolerant.rs): one space inserted before a
//! `<digits>{digits}\r\n` literal and nothing else changed, the same output
//! for every read-chunk split, literal data never inspected, and malformed
//! or truncated announcements passed through without a panic.

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

use inumaki_mail::tolerant::TolerantStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// Everything the filter yields for `input` written in one go over a duplex.
async fn via_duplex(input: &[u8]) -> Vec<u8> {
    let (mut server, client) = tokio::io::duplex(1 << 20);
    server.write_all(input).await.unwrap();
    drop(server);
    let mut out = Vec::new();
    TolerantStream::new(client)
        .read_to_end(&mut out)
        .await
        .unwrap();
    out
}

/// A reader that yields the given chunks one per poll, returning `Pending`
/// once between chunks, so every split point is exercised deterministically.
struct Chunked {
    chunks: VecDeque<Vec<u8>>,
    ready: bool,
}

impl std::fmt::Debug for Chunked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Chunked")
    }
}

impl AsyncRead for Chunked {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.ready {
            self.ready = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.ready = false;
        if let Some(mut c) = self.chunks.pop_front() {
            let n = c.len().min(buf.remaining());
            buf.put_slice(&c[..n]);
            if n < c.len() {
                self.chunks.push_front(c.split_off(n));
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Chunked {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(data.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// The filter's output for `input` split at the given chunk lengths (the
/// remainder is one last chunk), read back `read_size` bytes at a time.
async fn via_chunks(input: &[u8], lens: &[usize], read_size: usize) -> Vec<u8> {
    let mut chunks = VecDeque::new();
    let mut rest = input;
    for &l in lens {
        if rest.is_empty() {
            break;
        }
        let l = l.clamp(1, rest.len());
        chunks.push_back(rest[..l].to_vec());
        rest = &rest[l..];
    }
    if !rest.is_empty() {
        chunks.push_back(rest.to_vec());
    }
    let mut s = TolerantStream::new(Chunked {
        chunks,
        ready: false,
    });
    let mut out = Vec::new();
    let mut buf = vec![0u8; read_size];
    loop {
        let n = s.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    out
}

/// A tiny deterministic generator (no rand dependency).
fn lcg(seed: &mut u64) -> usize {
    *seed = seed
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    (*seed >> 33) as usize
}

/// Whole-buffer output equals the output of every split checked here.
async fn assert_split_invariant(input: &[u8], expected: &[u8]) {
    assert_eq!(via_duplex(input).await, expected, "whole buffer");
    assert_eq!(
        via_chunks(input, &vec![1; input.len()], 1).await,
        expected,
        "one byte at a time"
    );
    assert_eq!(
        via_chunks(input, &[], 3).await,
        expected,
        "one chunk, tiny reads"
    );
    for seed in 0..64u64 {
        let mut s = seed;
        let lens: Vec<usize> = (0..input.len()).map(|_| 1 + lcg(&mut s) % 17).collect();
        let read = 1 + lcg(&mut s) % 40;
        assert_eq!(
            via_chunks(input, &lens, read).await,
            expected,
            "seed {seed}"
        );
    }
}

const WITH_SPACE: &[u8] =
    b"* 6 FETCH (UID 6 RFC822.SIZE 99 BODY[TEXT]<0> {5}\r\nHallo)\r\nA4 OK done\r\n";
const WITHOUT_SPACE: &[u8] =
    b"* 6 FETCH (UID 6 RFC822.SIZE 99 BODY[TEXT]<0>{5}\r\nHallo)\r\nA4 OK done\r\n";

#[tokio::test]
async fn conforming_response_is_unchanged() {
    assert_split_invariant(WITH_SPACE, WITH_SPACE).await;
    let full = b"* 1 FETCH (BODY[] {3}\r\nabc BODY[HEADER] {0}\r\n)\r\n";
    assert_split_invariant(full, full).await;
}

#[tokio::test]
async fn missing_space_gets_exactly_one() {
    assert_split_invariant(WITHOUT_SPACE, WITH_SPACE).await;
    let big = b"* 1 FETCH (BODY[TEXT]<1024>{12345678}\r\n";
    assert_split_invariant(big, b"* 1 FETCH (BODY[TEXT]<1024> {12345678}\r\n").await;
}

#[tokio::test]
async fn literal_data_is_never_inspected() {
    // the literal itself holds the quirk pattern, CR/LF, and a brace tail
    let data = b"x<0>{5}\r\nab\r\n<7>{1}\r\n{9}\r\n";
    let mut input = format!("* 1 FETCH (BODY[] {{{}}}\r\n", data.len()).into_bytes();
    input.extend_from_slice(data);
    input.extend_from_slice(b" BODY[TEXT]<0>{3}\r\n<1>)\r\nA1 OK\r\n");
    let mut expected = format!("* 1 FETCH (BODY[] {{{}}}\r\n", data.len()).into_bytes();
    expected.extend_from_slice(data);
    expected.extend_from_slice(b" BODY[TEXT]<0> {3}\r\n<1>)\r\nA1 OK\r\n");
    assert_split_invariant(&input, &expected).await;

    // a quirk literal whose data is the pattern again: only the line is fixed
    let input = b"* 2 FETCH (BODY[TEXT]<0>{9}\r\n<0>{5}\r\n)\r\n";
    let expected = b"* 2 FETCH (BODY[TEXT]<0> {9}\r\n<0>{5}\r\n)\r\n";
    assert_split_invariant(input, expected).await;
}

#[tokio::test]
async fn consecutive_literals_and_responses() {
    let input = b"* 1 FETCH (UID 1 BODY[HEADER] {4}\r\nH: x BODY[TEXT]<0>{2}\r\nab)\r\n\
* 2 FETCH (UID 2 BODY[HEADER] {4}\r\nH: y BODY[TEXT]<0>{2}\r\ncd)\r\nA1 OK\r\n";
    let expected = b"* 1 FETCH (UID 1 BODY[HEADER] {4}\r\nH: x BODY[TEXT]<0> {2}\r\nab)\r\n\
* 2 FETCH (UID 2 BODY[HEADER] {4}\r\nH: y BODY[TEXT]<0> {2}\r\ncd)\r\nA1 OK\r\n";
    assert_split_invariant(input, expected).await;
}

#[tokio::test]
async fn near_misses_pass_through_unchanged() {
    for input in [
        &b"* OK <0>{5x}\r\nmore\r\n"[..],
        b"* OK <0>{}\r\n",
        b"* OK <0>{5} \r\n",
        b"* OK <0>{5}\rX\r\n",
        b"* OK <>{5}\r\nabcde\r\n",
        b"* OK 0>{5}\r\nabcde\r\n",
        b"* OK <a>{5}\r\nabcde\r\n",
        b"* OK <0> >{5}\r\nabcde\r\n",
        b"* OK {{{<0>\r\n",
        // overflowing and over-long lengths: never a literal, never a panic
        b"* 1 FETCH (BODY[TEXT]<0>{18446744073709551616}\r\nA1 OK\r\n",
        b"* 1 FETCH (BODY[TEXT]<0>{000000000000000000001}\r\nx\r\n",
        // truncated at EOF inside a candidate
        b"* 1 FETCH (BODY[TEXT]<0>{12",
        b"* 1 FETCH (BODY[TEXT]<0>{12}",
        b"* 1 FETCH (BODY[TEXT]<0>{12}\r",
    ] {
        assert_split_invariant(input, input).await;
    }
}

#[tokio::test]
async fn literal_longer_than_the_stream_passes_through() {
    // the server announces more bytes than it sends before EOF
    let input = b"* 1 FETCH (BODY[TEXT]<0>{100}\r\nshort<0>{5}\r\n";
    let expected = b"* 1 FETCH (BODY[TEXT]<0> {100}\r\nshort<0>{5}\r\n";
    assert_split_invariant(input, expected).await;
    // u64::MAX: counted down, never allocated
    let input = b"* 1 FETCH (BODY[]<0>{18446744073709551615}\r\nabc";
    let expected = b"* 1 FETCH (BODY[]<0> {18446744073709551615}\r\nabc";
    assert_split_invariant(input, expected).await;
}

#[tokio::test]
async fn long_line_streams_through_and_stays_correct() {
    // 200 KiB without CRLF, then the quirk: nothing is buffered up front
    let mut input = b"* 1 FETCH (X \"".to_vec();
    input.extend(std::iter::repeat_n(b'a', 200 * 1024));
    input.extend_from_slice(b"\" BODY[TEXT]<0>{2}\r\nok)\r\n");
    let mut expected = b"* 1 FETCH (X \"".to_vec();
    expected.extend(std::iter::repeat_n(b'a', 200 * 1024));
    expected.extend_from_slice(b"\" BODY[TEXT]<0> {2}\r\nok)\r\n");
    assert_eq!(via_duplex(&input).await, expected);
    assert_eq!(via_chunks(&input, &[7; 4096], 513).await, expected);
}

#[tokio::test]
async fn writes_pass_straight_through_and_debug_holds_no_bytes() {
    const CMD: &[u8] = b"A1 UID FETCH 1 (BODY.PEEK[TEXT]<0.5>{3}\r\n";
    let (client, mut server) = tokio::io::duplex(1024);
    let mut s = TolerantStream::new(client);
    s.write_all(CMD).await.unwrap();
    s.flush().await.unwrap();
    let mut got = vec![0u8; CMD.len()];
    server.read_exact(&mut got).await.unwrap();
    assert_eq!(got, CMD);

    // a canary pending mid-read never appears in Debug
    let mut s = TolerantStream::new(Chunked {
        chunks: VecDeque::from([b"* 1 FETCH (BODY[TEXT]<0>{20}\r\nZyxwuria Quolnath {12".to_vec()]),
        ready: false,
    });
    let mut buf = [0u8; 8];
    s.read_exact(&mut buf).await.unwrap();
    let dbg = format!("{s:?}");
    assert!(!dbg.contains("Zyxwuria"), "{dbg}");
    assert!(!dbg.contains("FETCH"), "{dbg}");
}
