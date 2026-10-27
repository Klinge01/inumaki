//! A scripted IMAP4rev1 server for tests (feature `fake-imap`): LOGIN,
//! CAPABILITY, LIST with special-use attributes, SELECT/EXAMINE with
//! UIDVALIDITY, CREATE, UID SEARCH (SINCE/BEFORE/HEADER/FROM/SUBJECT/TEXT/OR/
//! CHARSET), UID FETCH (UID, RFC822.SIZE, FLAGS, BODY[]/BODY[HEADER]/
//! BODY[TEXT] with partials, PEEK variants), UID STORE, EXPUNGE, APPEND
//! with literals and APPENDUID, NOOP, LOGOUT. Modes script failures: a
//! refused login, a rejected `\Draft` flag (after the literal or instead of
//! the continuation), a connection dropped after the
//! APPEND literal (stored or not), an unparseable APPEND answer, an APPEND
//! that never shows up in the folder, a stall after login, and a partial
//! fetch answered without the space before its literal (GreenMail). Every received
//! command name is recorded so tests can count attempts. Never part of a
//! user-facing binary.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

/// Scripted failure modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FakeMode {
    /// Everything works.
    #[default]
    Normal,
    /// Every LOGIN gets `NO [AUTHENTICATIONFAILED]`.
    RefuseLogin,
    /// An APPEND with `\Draft` in its flags is refused after the literal.
    RejectDraftFlag,
    /// The connection closes right after the APPEND literal; nothing is stored.
    DropAfterLiteral,
    /// The message is stored, then the connection closes without a tagged reply.
    DropAfterLiteralStored,
    /// After LOGIN succeeds, no command is ever answered.
    StallAfterLogin,
    /// An unsolicited `* 1 EXISTS` is sent before the APPEND continuation
    /// (RFC 3501 allows it); a client that reads one line and gives up is
    /// now out of step with a server still waiting for the literal.
    UnsolicitedBeforeContinue,
    /// `LIST` and `UID FETCH` get a tagged `NO` (the other commands work): a
    /// client that reads a refusal as an empty result would see no folders
    /// and no messages.
    RefuseListAndFetch,
    /// An APPEND with `\Draft` in its flags gets a tagged `NO` instead of
    /// the `+` continuation, so the literal is never sent and nothing is
    /// stored; unflagged APPENDs work.
    RefuseDraftBeforeLiteral,
    /// The APPEND is stored, then answered with an unparseable tagged line
    /// (the connection stays open): the client cannot tell what happened.
    GarbledAfterLiteralStored,
    /// The APPEND is stored and answered `OK`, but the message never shows
    /// up in the folder (an eventually consistent server): a later search
    /// cannot find it.
    AppendNotListed,
    /// A partial body section is answered without the space RFC 3501
    /// requires before its literal (`BODY[TEXT]<0>{16}`), as GreenMail 2.1
    /// does; full sections keep the space.
    NoSpaceBeforePartialLiteral,
}

/// A stored message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeMessage {
    /// UID.
    pub uid: u32,
    /// Flags like `\Draft`.
    pub flags: Vec<String>,
    /// INTERNALDATE as (year, month, day): the APPEND date-time when given,
    /// else the day the message arrived. `SINCE`/`BEFORE` compare this, as
    /// real servers do, never the `Date` header.
    pub internal_date: (u32, u32, u32),
    /// Raw RFC 5322 bytes.
    pub raw: Vec<u8>,
}

/// A folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeFolder {
    /// UIDVALIDITY.
    pub uid_validity: u32,
    /// Next UID.
    pub uid_next: u32,
    /// Messages in UID order.
    pub messages: Vec<FakeMessage>,
    /// RFC 6154 attribute such as `\Drafts`.
    pub special_use: Option<String>,
}

/// One APPEND the server accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendRecord {
    /// Target folder.
    pub folder: String,
    /// Flags as sent, e.g. `(\Draft)`.
    pub flags: Option<String>,
    /// The literal.
    pub raw: Vec<u8>,
}

/// The server's mutable state, shared with the test.
#[derive(Debug, Clone)]
pub struct FakeState {
    /// Accepted login.
    pub username: String,
    /// Accepted password.
    pub password: String,
    /// Folders by raw name.
    pub folders: BTreeMap<String, FakeFolder>,
    /// Stored appends, in order.
    pub appends: Vec<AppendRecord>,
    /// Failure mode.
    pub mode: FakeMode,
    /// Successful logins.
    pub logins: u32,
    /// LOGIN commands seen.
    pub login_attempts: u32,
    /// Command names seen (`LOGIN`, `LIST`, `UID SEARCH`, `APPEND`, …).
    pub commands: Vec<String>,
    /// Item lists of every `UID FETCH`, in order (tests check what was fetched).
    pub fetches: Vec<String>,
    /// Advertise `LITERAL+` (GreenMail does); `false` models a server without it.
    pub literal_plus: bool,
}

impl FakeState {
    /// An account with an empty INBOX (UIDVALIDITY 1000).
    pub fn new(user: &str, pass: &str) -> Self {
        let mut folders = BTreeMap::new();
        folders.insert(
            "INBOX".to_string(),
            FakeFolder {
                uid_validity: 1000,
                uid_next: 1,
                messages: Vec::new(),
                special_use: None,
            },
        );
        FakeState {
            username: user.into(),
            password: pass.into(),
            folders,
            appends: Vec::new(),
            mode: FakeMode::Normal,
            logins: 0,
            login_attempts: 0,
            commands: Vec::new(),
            fetches: Vec::new(),
            literal_plus: true,
        }
    }

    /// Add an empty folder.
    pub fn add_folder(&mut self, name: &str, uid_validity: u32) {
        self.folders.entry(name.to_string()).or_insert(FakeFolder {
            uid_validity,
            uid_next: 1,
            messages: Vec::new(),
            special_use: None,
        });
    }

    /// Store a message; returns its UID. Creates the folder when missing. The
    /// INTERNALDATE is taken from the message's `Date` header (else today),
    /// which is what a test that seeds fixtures directly usually wants; a
    /// real server would stamp the arrival time — use [`FakeState::add_with_date`]
    /// or the APPEND date-time argument to model that.
    pub fn add(&mut self, folder: &str, raw: &[u8]) -> u32 {
        let date = message_date(raw).unwrap_or_else(today);
        self.add_with_date(folder, raw, date)
    }

    /// Store a message with an explicit INTERNALDATE (year, month, day).
    pub fn add_with_date(
        &mut self,
        folder: &str,
        raw: &[u8],
        internal_date: (u32, u32, u32),
    ) -> u32 {
        let n = self.folders.len() as u32;
        let f = self
            .folders
            .entry(folder.to_string())
            .or_insert(FakeFolder {
                uid_validity: 1000 + 7 * n,
                uid_next: 1,
                messages: Vec::new(),
                special_use: None,
            });
        let uid = f.uid_next;
        f.uid_next += 1;
        f.messages.push(FakeMessage {
            uid,
            flags: Vec::new(),
            internal_date,
            raw: raw.to_vec(),
        });
        uid
    }

    /// Simulate a rebuilt folder: new UIDVALIDITY, UIDs renumbered from 1.
    pub fn bump_uidvalidity(&mut self, folder: &str) {
        if let Some(f) = self.folders.get_mut(folder) {
            f.uid_validity += 1;
            f.uid_next = 1;
            for m in &mut f.messages {
                m.uid = f.uid_next;
                f.uid_next += 1;
            }
        }
    }

    /// How many times a command was received.
    pub fn count(&self, command: &str) -> usize {
        self.commands
            .iter()
            .filter(|c| c.as_str() == command)
            .count()
    }
}

/// A running fake server.
pub struct FakeImap {
    addr: SocketAddr,
    state: Arc<Mutex<FakeState>>,
    ct: CancellationToken,
}

impl std::fmt::Debug for FakeImap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeImap")
            .field("addr", &self.addr)
            .finish()
    }
}

impl FakeImap {
    /// Bind a random loopback port and serve `state`.
    pub async fn start(state: FakeState) -> FakeImap {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let state = Arc::new(Mutex::new(state));
        let ct = CancellationToken::new();
        let (st, stop) = (Arc::clone(&state), ct.clone());
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = stop.cancelled() => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break };
                        let st = Arc::clone(&st);
                        tokio::spawn(async move {
                            let _ = serve(stream, st).await;
                        });
                    }
                }
            }
        });
        FakeImap { addr, state, ct }
    }

    /// Bound address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Bound port.
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// The shared state.
    pub fn state(&self) -> Arc<Mutex<FakeState>> {
        Arc::clone(&self.state)
    }

    /// Stop accepting connections.
    pub fn stop(&self) {
        self.ct.cancel();
    }
}

impl Drop for FakeImap {
    fn drop(&mut self) {
        self.ct.cancel();
    }
}

fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Tokens of an IMAP command line: atoms, quoted strings (unescaped),
/// parenthesized lists as one token, `{n}` literals as one token.
fn tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            ' ' => i += 1,
            '"' => {
                let mut t = String::new();
                i += 1;
                while i < chars.len() && chars[i] != '"' {
                    if chars[i] == '\\' && i + 1 < chars.len() {
                        i += 1;
                    }
                    t.push(chars[i]);
                    i += 1;
                }
                i += 1;
                out.push(t);
            }
            '(' => {
                let start = i;
                let mut depth = 0;
                while i < chars.len() {
                    if chars[i] == '(' {
                        depth += 1;
                    } else if chars[i] == ')' {
                        depth -= 1;
                        if depth == 0 {
                            i += 1;
                            break;
                        }
                    }
                    i += 1;
                }
                out.push(chars[start..i].iter().collect());
            }
            _ => {
                let start = i;
                while i < chars.len() && chars[i] != ' ' {
                    i += 1;
                }
                out.push(chars[start..i].iter().collect());
            }
        }
    }
    out
}

fn split_message(raw: &[u8]) -> (&[u8], &[u8]) {
    if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
        return (&raw[..i + 4], &raw[i + 4..]);
    }
    if let Some(i) = raw.windows(2).position(|w| w == b"\n\n") {
        return (&raw[..i + 2], &raw[i + 2..]);
    }
    (raw, &[])
}

/// Header value (unfolded) by case-insensitive name.
fn header(raw: &[u8], name: &str) -> Option<String> {
    let (head, _) = split_message(raw);
    let text = String::from_utf8_lossy(head);
    let mut lines: Vec<String> = Vec::new();
    for l in text.lines() {
        if (l.starts_with(' ') || l.starts_with('\t')) && !lines.is_empty() {
            let last = lines.last_mut().expect("non-empty");
            last.push(' ');
            last.push_str(l.trim());
        } else {
            lines.push(l.to_string());
        }
    }
    lines.iter().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case(name)
            .then(|| v.trim().to_string())
    })
}

const MONTHS: [&str; 12] = [
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];

fn month(s: &str) -> Option<u32> {
    s.get(..3)
        .and_then(|p| MONTHS.iter().position(|m| m.eq_ignore_ascii_case(p)))
        .map(|i| i as u32 + 1)
}

/// `27-Sep-2026` → (2026, 9, 27).
fn imap_date(s: &str) -> Option<(u32, u32, u32)> {
    let mut it = s.split('-');
    let d: u32 = it.next()?.parse().ok()?;
    let m = month(it.next()?)?;
    let y: u32 = it.next()?.parse().ok()?;
    Some((y, m, d))
}

/// Days since 1970-01-01 → (year, month, day).
fn civil(days: i64) -> (u32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    ((if m <= 2 { y + 1 } else { y }) as u32, m, d)
}

/// Today (UTC) as (year, month, day): the INTERNALDATE a server stamps.
fn today() -> (u32, u32, u32) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    civil((secs / 86_400) as i64)
}

/// An IMAP date-time argument (`27-Sep-2026 10:00:00 +0000`, quotes already
/// removed by the tokenizer) → (year, month, day).
fn parse_imap_datetime(s: &str) -> Option<(u32, u32, u32)> {
    imap_date(s.trim().split(' ').next()?)
}

/// The `Date:` header's day as (year, month, day).
fn message_date(raw: &[u8]) -> Option<(u32, u32, u32)> {
    let v = header(raw, "Date")?;
    let toks: Vec<&str> = v.split([' ', ',']).filter(|t| !t.is_empty()).collect();
    for w in toks.windows(3) {
        if let (Ok(d), Some(m), Ok(y)) = (w[0].parse::<u32>(), month(w[1]), w[2].parse::<u32>()) {
            if d <= 31 && y > 1900 {
                return Some((y, m, d));
            }
        }
    }
    None
}

#[derive(Debug)]
enum Crit {
    All,
    Since((u32, u32, u32)),
    Before((u32, u32, u32)),
    Header(String, String),
    From(String),
    Subject(String),
    Text(String),
    Or(Box<Crit>, Box<Crit>),
}

fn parse_crit(t: &[String], i: &mut usize) -> Option<Crit> {
    let word = t.get(*i)?.to_ascii_uppercase();
    *i += 1;
    Some(match word.as_str() {
        "ALL" => Crit::All,
        "CHARSET" => {
            *i += 1;
            parse_crit(t, i)?
        }
        "SINCE" => Crit::Since(imap_date(t.get(*i).map(|s| {
            *i += 1;
            s.as_str()
        })?)?),
        "BEFORE" => Crit::Before(imap_date(t.get(*i).map(|s| {
            *i += 1;
            s.as_str()
        })?)?),
        "HEADER" => {
            let name = t.get(*i)?.clone();
            let value = t.get(*i + 1)?.clone();
            *i += 2;
            Crit::Header(name, value)
        }
        "FROM" | "SUBJECT" | "TEXT" => {
            let v = t.get(*i)?.clone();
            *i += 1;
            match word.as_str() {
                "FROM" => Crit::From(v),
                "SUBJECT" => Crit::Subject(v),
                _ => Crit::Text(v),
            }
        }
        "OR" => {
            let a = parse_crit(t, i)?;
            let b = parse_crit(t, i)?;
            Crit::Or(Box::new(a), Box::new(b))
        }
        _ => return None,
    })
}

/// The decoded searchable parts of a message.
struct Decoded {
    subject: Option<String>,
    from: Vec<String>,
    body: Vec<String>,
}

fn decoded(raw: &[u8]) -> Decoded {
    let Some(msg) = mail_parser::MessageParser::default().parse(raw) else {
        return Decoded {
            subject: None,
            from: Vec::new(),
            body: Vec::new(),
        };
    };
    let mut from = Vec::new();
    if let Some(a) = msg.from() {
        for x in a.iter() {
            from.extend(x.name().map(str::to_string));
            from.extend(x.address().map(str::to_string));
        }
    }
    let body = (0..msg.text_body_count())
        .filter_map(|i| msg.body_text(i).map(|t| t.to_string()))
        .collect();
    Decoded {
        subject: msg.subject().map(str::to_string),
        from,
        body,
    }
}

fn contains_ci(hay: &str, needle: &str) -> bool {
    hay.to_lowercase().contains(&needle.to_lowercase())
}

fn matches(c: &Crit, m: &FakeMessage) -> bool {
    match c {
        Crit::All => true,
        Crit::Since(d) => m.internal_date >= *d,
        Crit::Before(d) => m.internal_date < *d,
        Crit::Header(n, v) => header(&m.raw, n).is_some_and(|h| contains_ci(&h, v)),
        // FROM, SUBJECT and TEXT match the decoded values, as real servers do:
        // an encoded-word or quoted-printable body never matches its raw bytes.
        Crit::From(v) => decoded(&m.raw).from.iter().any(|f| contains_ci(f, v)),
        Crit::Subject(v) => decoded(&m.raw).subject.is_some_and(|s| contains_ci(&s, v)),
        Crit::Text(v) => {
            let d = decoded(&m.raw);
            d.subject
                .iter()
                .chain(&d.from)
                .chain(&d.body)
                .any(|t| contains_ci(t, v))
        }
        Crit::Or(a, b) => matches(a, m) || matches(b, m),
    }
}

/// `1`, `1,3`, `2:5`, `1:*`.
fn parse_set(s: &str, max: u32) -> Vec<u32> {
    let mut out = Vec::new();
    for part in s.split(',') {
        if let Some((a, b)) = part.split_once(':') {
            let a: u32 = a.parse().unwrap_or(0);
            let b: u32 = if b == "*" {
                max
            } else {
                b.parse().unwrap_or(0)
            };
            out.extend(a.min(b)..=a.max(b));
        } else if let Ok(v) = part.parse::<u32>() {
            out.push(v);
        }
    }
    out
}

async fn write(wr: &mut OwnedWriteHalf, s: &str) -> std::io::Result<()> {
    wr.write_all(s.as_bytes()).await
}

fn fetch_items(items: &str, m: &FakeMessage, mode: FakeMode) -> Vec<Vec<u8>> {
    let (head, text) = split_message(&m.raw);
    let mut parts: Vec<Vec<u8>> = Vec::new();
    for it in items
        .trim_start_matches('(')
        .trim_end_matches(')')
        .split(' ')
        .filter(|s| !s.is_empty())
    {
        let up = it.to_ascii_uppercase();
        let up = up.replace("BODY.PEEK[", "BODY[");
        if up == "UID" {
            parts.push(format!("UID {}", m.uid).into_bytes());
        } else if up == "RFC822.SIZE" {
            parts.push(format!("RFC822.SIZE {}", m.raw.len()).into_bytes());
        } else if up == "FLAGS" {
            parts.push(format!("FLAGS ({})", m.flags.join(" ")).into_bytes());
        } else if up == "BODY[]" {
            let mut p = format!("BODY[] {{{}}}\r\n", m.raw.len()).into_bytes();
            p.extend_from_slice(&m.raw);
            parts.push(p);
        } else if up == "BODY[HEADER]" {
            let mut p = format!("BODY[HEADER] {{{}}}\r\n", head.len()).into_bytes();
            p.extend_from_slice(head);
            parts.push(p);
        } else if let Some(rest) = up.strip_prefix("BODY[TEXT]") {
            let (slice, label) = match rest.strip_prefix('<').and_then(|r| r.strip_suffix('>')) {
                Some(partial) => {
                    let (a, b) = partial.split_once('.').unwrap_or((partial, "0"));
                    let a: usize = a.parse().unwrap_or(0);
                    let b: usize = b.parse().unwrap_or(text.len());
                    let end = (a + b).min(text.len());
                    let sp = if mode == FakeMode::NoSpaceBeforePartialLiteral {
                        ""
                    } else {
                        " "
                    };
                    (
                        &text[a.min(text.len())..end],
                        format!("BODY[TEXT]<{a}>{sp}"),
                    )
                }
                None => (text, "BODY[TEXT] ".to_string()),
            };
            let mut p = format!("{label}{{{}}}\r\n", slice.len()).into_bytes();
            p.extend_from_slice(slice);
            parts.push(p);
        }
    }
    parts
}

async fn serve(stream: TcpStream, state: Arc<Mutex<FakeState>>) -> std::io::Result<()> {
    let (rd, mut wr) = stream.into_split();
    let mut rd = BufReader::new(rd);
    let caps = if state
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .literal_plus
    {
        "IMAP4rev1 UIDPLUS LITERAL+"
    } else {
        "IMAP4rev1 UIDPLUS"
    };
    write(
        &mut wr,
        &format!("* OK [CAPABILITY {caps}] inumaki fake IMAP ready\r\n"),
    )
    .await?;
    let mut authed = false;
    let mut selected: Option<String> = None;
    loop {
        let mut line = String::new();
        if rd.read_line(&mut line).await? == 0 {
            return Ok(());
        }
        // LITERAL+ (`{n+}`): the client sends the bytes without waiting for a
        // continuation; splice each literal in as a quoted string and keep
        // reading the rest of the command line. Plain `{n}` (APPEND) is not
        // touched here.
        loop {
            let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
            let Some(open) = trimmed.rfind('{') else {
                break;
            };
            let Some(n) = trimmed[open + 1..]
                .strip_suffix("+}")
                .and_then(|s| s.parse::<usize>().ok())
            else {
                break;
            };
            let mut lit = vec![0u8; n];
            rd.read_exact(&mut lit).await?;
            let mut rest = String::new();
            rd.read_line(&mut rest).await?;
            line = format!(
                "{}{}{}",
                &trimmed[..open],
                quote(&String::from_utf8_lossy(&lit)),
                rest
            );
        }
        let line = line.trim_end_matches(['\r', '\n']).to_string();
        let Some((tag, rest)) = line.split_once(' ') else {
            write(&mut wr, "* BAD missing tag\r\n").await?;
            continue;
        };
        let t = tokens(rest);
        let Some(cmd) = t.first().map(|c| c.to_ascii_uppercase()) else {
            write(&mut wr, &format!("{tag} BAD empty\r\n")).await?;
            continue;
        };
        let name = if cmd == "UID" {
            format!(
                "UID {}",
                t.get(1).map(|s| s.to_ascii_uppercase()).unwrap_or_default()
            )
        } else {
            cmd.clone()
        };
        let mode = {
            let mut st = state.lock().unwrap_or_else(PoisonError::into_inner);
            st.commands.push(name.clone());
            st.mode
        };
        if authed && mode == FakeMode::StallAfterLogin {
            // never answer; hold the connection until the client gives up
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            return Ok(());
        }
        match cmd.as_str() {
            "CAPABILITY" => {
                write(
                    &mut wr,
                    &format!("* CAPABILITY {caps}\r\n{tag} OK CAPABILITY completed\r\n"),
                )
                .await?
            }
            "NOOP" => write(&mut wr, &format!("{tag} OK NOOP completed\r\n")).await?,
            "LOGOUT" => {
                write(
                    &mut wr,
                    &format!("* BYE logging out\r\n{tag} OK LOGOUT completed\r\n"),
                )
                .await?;
                return Ok(());
            }
            "LOGIN" => {
                let ok = {
                    let mut st = state.lock().unwrap_or_else(PoisonError::into_inner);
                    st.login_attempts += 1;
                    let ok = mode != FakeMode::RefuseLogin
                        && t.get(1) == Some(&st.username)
                        && t.get(2) == Some(&st.password);
                    if ok {
                        st.logins += 1;
                    }
                    ok
                };
                if ok {
                    authed = true;
                    write(&mut wr, &format!("{tag} OK LOGIN completed\r\n")).await?;
                } else {
                    write(
                        &mut wr,
                        &format!("{tag} NO [AUTHENTICATIONFAILED] Authentication failed\r\n"),
                    )
                    .await?;
                }
            }
            _ if !authed => write(&mut wr, &format!("{tag} NO not authenticated\r\n")).await?,
            "LIST" if mode == FakeMode::RefuseListAndFetch => {
                write(&mut wr, &format!("{tag} NO server busy\r\n")).await?
            }
            "LIST" => {
                let lines: Vec<String> = {
                    let st = state.lock().unwrap_or_else(PoisonError::into_inner);
                    st.folders
                        .iter()
                        .map(|(n, f)| {
                            format!(
                                "* LIST ({}) \"/\" {}\r\n",
                                f.special_use.clone().unwrap_or_default(),
                                quote(n)
                            )
                        })
                        .collect()
                };
                for l in lines {
                    write(&mut wr, &l).await?;
                }
                write(&mut wr, &format!("{tag} OK LIST completed\r\n")).await?;
            }
            "SELECT" | "EXAMINE" => {
                let name = t.get(1).cloned().unwrap_or_default();
                let info = {
                    let st = state.lock().unwrap_or_else(PoisonError::into_inner);
                    st.folders
                        .get(&name)
                        .map(|f| (f.messages.len(), f.uid_validity, f.uid_next))
                };
                match info {
                    Some((n, validity, next)) => {
                        selected = Some(name);
                        write(&mut wr, &format!("* FLAGS (\\Answered \\Deleted \\Draft \\Flagged \\Seen)\r\n* {n} EXISTS\r\n* 0 RECENT\r\n* OK [UIDVALIDITY {validity}] UIDs valid\r\n* OK [UIDNEXT {next}] Predicted next UID\r\n{tag} OK [{}] {cmd} completed\r\n", if cmd == "SELECT" { "READ-WRITE" } else { "READ-ONLY" })).await?;
                    }
                    None => {
                        write(
                            &mut wr,
                            &format!("{tag} NO [TRYCREATE] no such mailbox\r\n"),
                        )
                        .await?
                    }
                }
            }
            "CREATE" => {
                let name = t.get(1).cloned().unwrap_or_default();
                {
                    let mut st = state.lock().unwrap_or_else(PoisonError::into_inner);
                    let n = st.folders.len() as u32;
                    st.add_folder(&name, 1000 + 7 * n);
                }
                write(&mut wr, &format!("{tag} OK CREATE completed\r\n")).await?;
            }
            "CLOSE" => {
                selected = None;
                write(&mut wr, &format!("{tag} OK CLOSE completed\r\n")).await?;
            }
            "EXPUNGE" => {
                let Some(sel) = &selected else {
                    write(&mut wr, &format!("{tag} BAD no mailbox selected\r\n")).await?;
                    continue;
                };
                let removed: Vec<usize> = {
                    let mut st = state.lock().unwrap_or_else(PoisonError::into_inner);
                    let f = st.folders.get_mut(sel).expect("selected folder exists");
                    let mut removed = Vec::new();
                    let mut seq = 0usize;
                    f.messages.retain(|m| {
                        seq += 1;
                        let del = m.flags.iter().any(|fl| fl == "\\Deleted");
                        if del {
                            removed.push(seq - removed.len());
                        }
                        !del
                    });
                    removed
                };
                for seq in removed {
                    write(&mut wr, &format!("* {seq} EXPUNGE\r\n")).await?;
                }
                write(&mut wr, &format!("{tag} OK EXPUNGE completed\r\n")).await?;
            }
            "UID" => {
                let Some(sel) = selected.clone() else {
                    write(&mut wr, &format!("{tag} BAD no mailbox selected\r\n")).await?;
                    continue;
                };
                let sub = t.get(1).map(|s| s.to_ascii_uppercase()).unwrap_or_default();
                match sub.as_str() {
                    "SEARCH" => {
                        let mut i = 2;
                        let mut crits = Vec::new();
                        // anything the parser cannot read is the client's fault: BAD,
                        // not "every message", so a malformed criterion cannot pass
                        let mut valid = true;
                        while i < t.len() {
                            match parse_crit(&t, &mut i) {
                                Some(c) => crits.push(c),
                                None => {
                                    valid = false;
                                    break;
                                }
                            }
                        }
                        if !valid || crits.is_empty() {
                            write(&mut wr, &format!("{tag} BAD invalid search criteria\r\n"))
                                .await?;
                            continue;
                        }
                        let hits: Vec<String> = {
                            let st = state.lock().unwrap_or_else(PoisonError::into_inner);
                            st.folders[&sel]
                                .messages
                                .iter()
                                .filter(|m| crits.iter().all(|c| matches(c, m)))
                                .map(|m| m.uid.to_string())
                                .collect()
                        };
                        let list = if hits.is_empty() {
                            String::new()
                        } else {
                            format!(" {}", hits.join(" "))
                        };
                        write(
                            &mut wr,
                            &format!("* SEARCH{list}\r\n{tag} OK SEARCH completed\r\n"),
                        )
                        .await?;
                    }
                    "FETCH" if mode == FakeMode::RefuseListAndFetch => {
                        write(&mut wr, &format!("{tag} NO server busy\r\n")).await?
                    }
                    "FETCH" => {
                        let set = t.get(2).cloned().unwrap_or_default();
                        let items = t.get(3).cloned().unwrap_or_default();
                        let responses: Vec<Vec<u8>> = {
                            let mut st = state.lock().unwrap_or_else(PoisonError::into_inner);
                            st.fetches.push(items.clone());
                            let f = &st.folders[&sel];
                            let max = f.messages.iter().map(|m| m.uid).max().unwrap_or(0);
                            let wanted = parse_set(&set, max);
                            f.messages
                                .iter()
                                .enumerate()
                                .filter(|(_, m)| wanted.contains(&m.uid))
                                .map(|(idx, m)| {
                                    let mut out = format!("* {} FETCH (", idx + 1).into_bytes();
                                    let parts = fetch_items(&items, m, mode);
                                    for (k, p) in parts.iter().enumerate() {
                                        if k > 0 {
                                            out.push(b' ');
                                        }
                                        out.extend_from_slice(p);
                                    }
                                    out.extend_from_slice(b")\r\n");
                                    out
                                })
                                .collect()
                        };
                        for r in responses {
                            wr.write_all(&r).await?;
                        }
                        write(&mut wr, &format!("{tag} OK FETCH completed\r\n")).await?;
                    }
                    "STORE" => {
                        let set = t.get(2).cloned().unwrap_or_default();
                        let op = t.get(3).map(|s| s.to_ascii_uppercase()).unwrap_or_default();
                        let flags: Vec<String> = t
                            .get(4)
                            .map(|s| {
                                s.trim_matches(['(', ')'])
                                    .split(' ')
                                    .filter(|x| !x.is_empty())
                                    .map(str::to_string)
                                    .collect()
                            })
                            .unwrap_or_default();
                        {
                            let mut st = state.lock().unwrap_or_else(PoisonError::into_inner);
                            let f = st.folders.get_mut(&sel).expect("selected folder exists");
                            let max = f.messages.iter().map(|m| m.uid).max().unwrap_or(0);
                            let wanted = parse_set(&set, max);
                            for m in f.messages.iter_mut().filter(|m| wanted.contains(&m.uid)) {
                                match op.as_str() {
                                    "+FLAGS" | "+FLAGS.SILENT" => {
                                        for fl in &flags {
                                            if !m.flags.contains(fl) {
                                                m.flags.push(fl.clone());
                                            }
                                        }
                                    }
                                    "-FLAGS" | "-FLAGS.SILENT" => {
                                        m.flags.retain(|x| !flags.contains(x))
                                    }
                                    _ => m.flags = flags.clone(),
                                }
                            }
                        }
                        write(&mut wr, &format!("{tag} OK STORE completed\r\n")).await?;
                    }
                    _ => write(&mut wr, &format!("{tag} BAD unknown UID command\r\n")).await?,
                }
            }
            "APPEND" => {
                let folder = t.get(1).cloned().unwrap_or_default();
                let mut flags: Option<String> = None;
                let mut literal: Option<usize> = None;
                let mut internal_date: Option<(u32, u32, u32)> = None;
                for tok in t.get(2..).unwrap_or(&[]) {
                    if tok.starts_with('(') {
                        flags = Some(tok.clone());
                    } else if let Some(n) = tok.strip_prefix('{').and_then(|s| s.strip_suffix('}'))
                    {
                        literal = n.trim_end_matches('+').parse().ok();
                    } else if let Some(d) = parse_imap_datetime(tok) {
                        internal_date = Some(d);
                    }
                }
                let internal_date = internal_date.unwrap_or_else(today);
                let Some(n) = literal else {
                    write(&mut wr, &format!("{tag} BAD missing literal\r\n")).await?;
                    continue;
                };
                // only the draft APPEND: the connector's unflagged retry must go through
                if mode == FakeMode::UnsolicitedBeforeContinue
                    && flags.as_deref().is_some_and(|f| f.contains("\\Draft"))
                {
                    // legal per RFC 3501 §7: untagged data may precede the continuation
                    write(&mut wr, "* 1 EXISTS\r\n").await?;
                }
                if mode == FakeMode::RefuseDraftBeforeLiteral
                    && flags.as_deref().is_some_and(|f| f.contains("\\Draft"))
                {
                    // the client must not send the literal after this
                    write(
                        &mut wr,
                        &format!("{tag} NO [CANNOT] flag not permitted\r\n"),
                    )
                    .await?;
                    continue;
                }
                write(&mut wr, "+ OK\r\n").await?;
                let mut raw = vec![0u8; n];
                rd.read_exact(&mut raw).await?;
                let mut crlf = String::new();
                rd.read_line(&mut crlf).await?;
                let store = |st: &mut FakeState| -> Option<(u32, u32)> {
                    let f = st.folders.get_mut(&folder)?;
                    let uid = f.uid_next;
                    f.uid_next += 1;
                    let parsed: Vec<String> = flags
                        .as_deref()
                        .map(|s| {
                            s.trim_matches(['(', ')'])
                                .split(' ')
                                .filter(|x| !x.is_empty())
                                .map(str::to_string)
                                .collect()
                        })
                        .unwrap_or_default();
                    if mode != FakeMode::AppendNotListed {
                        f.messages.push(FakeMessage {
                            uid,
                            flags: parsed,
                            internal_date,
                            raw: raw.clone(),
                        });
                    }
                    let validity = f.uid_validity;
                    st.appends.push(AppendRecord {
                        folder: folder.clone(),
                        flags: flags.clone(),
                        raw: raw.clone(),
                    });
                    Some((validity, uid))
                };
                match mode {
                    FakeMode::DropAfterLiteral => return Ok(()),
                    FakeMode::DropAfterLiteralStored => {
                        let mut st = state.lock().unwrap_or_else(PoisonError::into_inner);
                        let _ = store(&mut st);
                        return Ok(());
                    }
                    FakeMode::GarbledAfterLiteralStored => {
                        {
                            let mut st = state.lock().unwrap_or_else(PoisonError::into_inner);
                            let _ = store(&mut st);
                        }
                        write(&mut wr, &format!("{tag} \u{1}%%% (\r\n")).await?;
                    }
                    FakeMode::RejectDraftFlag
                        if flags.as_deref().is_some_and(|f| f.contains("\\Draft")) =>
                    {
                        write(
                            &mut wr,
                            &format!("{tag} NO [CANNOT] flag not permitted\r\n"),
                        )
                        .await?;
                    }
                    _ => {
                        let stored = {
                            let mut st = state.lock().unwrap_or_else(PoisonError::into_inner);
                            store(&mut st)
                        };
                        match stored {
                            Some((validity, uid)) => {
                                write(
                                    &mut wr,
                                    &format!(
                                        "{tag} OK [APPENDUID {validity} {uid}] APPEND completed\r\n"
                                    ),
                                )
                                .await?
                            }
                            None => {
                                write(
                                    &mut wr,
                                    &format!("{tag} NO [TRYCREATE] no such mailbox\r\n"),
                                )
                                .await?
                            }
                        }
                    }
                }
            }
            _ => write(&mut wr, &format!("{tag} BAD unknown command\r\n")).await?,
        }
    }
}
