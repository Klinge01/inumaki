//! One IMAP session (M4 spec §6.1): connect and log in, list folders with
//! special-use detection, EXAMINE for reads, UID SEARCH, partial and full
//! UID FETCH with `BODY.PEEK` (nothing is marked read), APPEND with a
//! flag, NOOP, LOGOUT. Every command runs under one timeout; every error
//! becomes a class. Server strings never leave this module.

use std::time::Duration;

use async_imap::Session;
use async_imap::imap_proto::{
    AttributeValue, MailboxDatum, MessageSection, Response, SectionPath, Status,
};
use async_imap::types::NameAttribute;

use crate::account::MailAccount;
use crate::error::MailError;
use crate::query::{decode_utf7, fetch_set};
use crate::stream::{MailStream, connect_stream};
use crate::tolerant::TolerantStream;

/// One listed folder.
#[derive(Clone, PartialEq, Eq)]
pub struct FolderInfo {
    /// The name as the server spells it (modified UTF-7), used in commands.
    pub raw: String,
    /// Decoded for display.
    pub display: String,
    /// Not `\Noselect`.
    pub selectable: bool,
    /// Carries the RFC 6154 `\Drafts` attribute.
    pub drafts_special_use: bool,
}

impl std::fmt::Debug for FolderInfo {
    // a folder name can name a customer: lengths and flags only
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FolderInfo")
            .field("raw_len", &self.raw.len())
            .field("display_len", &self.display.len())
            .field("selectable", &self.selectable)
            .field("drafts_special_use", &self.drafts_special_use)
            .finish()
    }
}

/// Where drafts go.
#[derive(Clone, PartialEq, Eq)]
pub enum DraftsFolder {
    /// An existing folder (raw name).
    Existing(String),
    /// No drafts folder exists; create this one on first use.
    Create(String),
}

impl std::fmt::Debug for DraftsFolder {
    // the folder name is not printed: existing or to-be-created, and its length
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DraftsFolder::Existing(n) => f
                .debug_struct("DraftsFolder::Existing")
                .field("name_len", &n.len())
                .finish(),
            DraftsFolder::Create(n) => f
                .debug_struct("DraftsFolder::Create")
                .field("name_len", &n.len())
                .finish(),
        }
    }
}

/// A search-result row before parsing.
#[derive(Clone, PartialEq, Eq)]
pub struct RawSummary {
    /// UID.
    pub uid: u32,
    /// `RFC822.SIZE`.
    pub size: u32,
    /// `BODY[HEADER]`.
    pub header: Vec<u8>,
    /// A prefix of `BODY[TEXT]`.
    pub text_head: Vec<u8>,
}

impl std::fmt::Debug for RawSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawSummary")
            .field("uid", &self.uid)
            .field("size", &self.size)
            .field("header_len", &self.header.len())
            .field("text_len", &self.text_head.len())
            .finish()
    }
}

/// An authenticated session.
pub struct Imap {
    session: Session<TolerantStream<MailStream>>,
    timeout: Duration,
    literal_plus: bool,
}

impl std::fmt::Debug for Imap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Imap")
            .field("timeout", &self.timeout)
            .finish()
    }
}

fn name_info(attrs: &[NameAttribute<'_>], name: &str) -> FolderInfo {
    FolderInfo {
        raw: name.to_string(),
        display: decode_utf7(name),
        selectable: !attrs.iter().any(|a| matches!(a, NameAttribute::NoSelect)),
        drafts_special_use: attrs.iter().any(|a| matches!(a, NameAttribute::Drafts)),
    }
}

/// One `FETCH` response, reduced to what the wrapper reads.
#[derive(Default)]
struct FetchedRow {
    uid: Option<u32>,
    size: Option<u32>,
    header: Option<Vec<u8>>,
    text: Option<Vec<u8>>,
    body: Option<Vec<u8>>,
}

fn fetched_row(attrs: &[AttributeValue<'_>]) -> FetchedRow {
    let mut row = FetchedRow::default();
    for a in attrs {
        match a {
            AttributeValue::Uid(u) => row.uid = Some(*u),
            AttributeValue::Rfc822Size(n) => row.size = Some(*n),
            AttributeValue::BodySection {
                section,
                data: Some(d),
                ..
            } => match section {
                None => row.body = Some(d.to_vec()),
                Some(SectionPath::Full(MessageSection::Header)) => row.header = Some(d.to_vec()),
                Some(SectionPath::Full(MessageSection::Text)) => row.text = Some(d.to_vec()),
                _ => {}
            },
            _ => {}
        }
    }
    row
}

impl Imap {
    /// Connect, read the greeting, log in.
    pub async fn connect(account: &MailAccount, timeout: Duration) -> Result<Imap, MailError> {
        let stream = connect_stream(&account.host, account.port, account.tls, timeout).await?;
        // every session reads through the quirk filter (tolerant.rs)
        let mut client = async_imap::Client::new(TolerantStream::new(stream));
        match tokio::time::timeout(timeout, client.read_response()).await {
            Ok(Ok(Some(_greeting))) => {}
            Ok(Ok(None)) => {
                return Err(MailError::Unreachable(std::io::ErrorKind::ConnectionReset));
            }
            Ok(Err(e)) => return Err(MailError::Unreachable(e.kind())),
            Err(_) => return Err(MailError::Timeout),
        }
        let mut session = match tokio::time::timeout(
            timeout,
            client.login(&**account.username, &**account.password),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err((e, _client))) => return Err(MailError::from_login(&e)),
            Err(_) => return Err(MailError::Timeout),
        };
        // LITERAL+ decides how non-ASCII search terms travel (query.rs)
        let literal_plus = match tokio::time::timeout(timeout, session.capabilities()).await {
            Ok(Ok(caps)) => caps.has_str("LITERAL+"),
            Ok(Err(_)) | Err(_) => false,
        };
        // no host or port here: a generic host name can name the customer
        tracing::debug!(tls = account.tls, literal_plus, "imap session opened");
        Ok(Imap {
            session,
            timeout,
            literal_plus,
        })
    }

    /// The server advertised `LITERAL+`.
    pub fn literal_plus(&self) -> bool {
        self.literal_plus
    }

    /// Run `command` and feed every untagged response to `on`, then read the
    /// tagged completion ourselves. `Session::{list, uid_search, uid_fetch}`
    /// of async-imap 0.11 stop at the tagged line without looking at its
    /// status, so a refused command would look like an empty result; here
    /// `OK` is data, `BAD` is `invalid_argument` (the client's fault, the
    /// session stays in step), `NO` is a protocol class, IO or EOF is
    /// unreachable, and the whole exchange runs under one timeout. Server
    /// text is never kept.
    async fn tagged<F>(&mut self, command: String, mut on: F) -> Result<(), MailError>
    where
        F: FnMut(&Response<'_>),
    {
        let timeout = self.timeout;
        let session = &mut self.session;
        let outcome = tokio::time::timeout(timeout, async {
            let id = session
                .run_command(command)
                .await
                .map_err(|e| MailError::from_imap(&e, false))?;
            loop {
                let resp = match session.read_response().await {
                    Ok(Some(r)) => r,
                    Ok(None) => {
                        return Err(MailError::Unreachable(std::io::ErrorKind::ConnectionReset));
                    }
                    Err(e) => return Err(MailError::Unreachable(e.kind())),
                };
                match resp.parsed() {
                    Response::Done { tag, status, .. } if *tag == id => {
                        return match status {
                            Status::Ok => Ok(()),
                            Status::Bad => Err(MailError::InvalidArgument("imap_command")),
                            Status::No => Err(MailError::Protocol("no")),
                            _ => Err(MailError::Protocol("imap_status")),
                        };
                    }
                    other => on(other),
                }
            }
        })
        .await;
        match outcome {
            Ok(r) => r,
            Err(_) => Err(MailError::Timeout),
        }
    }

    /// `LIST "" "*"`, sorted by raw name. A refused `LIST` is an error, never
    /// an empty folder list.
    pub async fn folders(&mut self) -> Result<Vec<FolderInfo>, MailError> {
        let mut out: Vec<FolderInfo> = Vec::new();
        self.tagged("LIST \"\" \"*\"".to_string(), |r| {
            if let Response::MailboxData(MailboxDatum::List {
                name_attributes,
                name,
                ..
            }) = r
            {
                out.push(name_info(name_attributes, name));
            }
        })
        .await?;
        out.sort_by(|a, b| a.raw.cmp(&b.raw));
        tracing::debug!(folders = out.len(), "folders listed");
        Ok(out)
    }

    /// `EXAMINE` (read-only); returns UIDVALIDITY.
    pub async fn examine(&mut self, folder: &str) -> Result<u32, MailError> {
        let timeout = self.timeout;
        let mb = match tokio::time::timeout(timeout, self.session.examine(folder)).await {
            Ok(Ok(m)) => m,
            Ok(Err(async_imap::error::Error::No(_))) => return Err(MailError::ContextUnavailable),
            Ok(Err(e)) => return Err(MailError::from_imap(&e, false)),
            Err(_) => return Err(MailError::Timeout),
        };
        mb.uid_validity.ok_or(MailError::Protocol("uidvalidity"))
    }

    /// `SELECT`; returns UIDVALIDITY.
    pub async fn select(&mut self, folder: &str) -> Result<u32, MailError> {
        let timeout = self.timeout;
        let mb = match tokio::time::timeout(timeout, self.session.select(folder)).await {
            Ok(Ok(m)) => m,
            Ok(Err(async_imap::error::Error::No(_))) => return Err(MailError::ContextUnavailable),
            Ok(Err(e)) => return Err(MailError::from_imap(&e, false)),
            Err(_) => return Err(MailError::Timeout),
        };
        mb.uid_validity.ok_or(MailError::Protocol("uidvalidity"))
    }

    /// `UID SEARCH <criteria>` in the examined folder; highest UID first.
    /// `BAD` (malformed criteria) is `invalid_argument` and keeps the session.
    pub async fn uid_search(&mut self, criteria: &str) -> Result<Vec<u32>, MailError> {
        let mut uids: Vec<u32> = Vec::new();
        self.tagged(format!("UID SEARCH {criteria}"), |r| {
            if let Response::MailboxData(MailboxDatum::Search(found)) = r {
                uids.extend_from_slice(found);
            }
        })
        .await?;
        uids.sort_unstable_by(|a, b| b.cmp(a));
        uids.dedup();
        Ok(uids)
    }

    /// `UID FETCH`; a refused fetch is an error, never an empty result.
    async fn fetch(&mut self, set: &str, items: &str) -> Result<Vec<FetchedRow>, MailError> {
        let mut rows: Vec<FetchedRow> = Vec::new();
        self.tagged(format!("UID FETCH {set} {items}"), |r| {
            if let Response::Fetch(_, attrs) = r {
                rows.push(fetched_row(attrs));
            }
        })
        .await?;
        Ok(rows)
    }

    /// Header plus the first `text_bytes` of the text for each UID, in the
    /// server's order. UIDs the server does not return are absent.
    pub async fn fetch_summaries(
        &mut self,
        uids: &[u32],
        text_bytes: usize,
    ) -> Result<Vec<RawSummary>, MailError> {
        if uids.is_empty() {
            return Ok(Vec::new());
        }
        let items = format!("(UID RFC822.SIZE BODY.PEEK[HEADER] BODY.PEEK[TEXT]<0.{text_bytes}>)");
        let fetched = self.fetch(&fetch_set(uids), &items).await?;
        Ok(fetched
            .iter()
            .filter_map(|f| {
                Some(RawSummary {
                    uid: f.uid?,
                    size: f.size.unwrap_or(0),
                    header: f.header.clone().unwrap_or_default(),
                    text_head: f.text.clone().unwrap_or_default(),
                })
            })
            .collect())
    }

    /// `RFC822.SIZE` of one message; `None` when the UID is gone.
    pub async fn fetch_size(&mut self, uid: u32) -> Result<Option<u32>, MailError> {
        let fetched = self.fetch(&uid.to_string(), "(UID RFC822.SIZE)").await?;
        Ok(fetched
            .iter()
            .find(|f| f.uid == Some(uid))
            .and_then(|f| f.size))
    }

    /// The whole message (`BODY.PEEK[]`); `None` when the UID is gone.
    pub async fn fetch_message(&mut self, uid: u32) -> Result<Option<Vec<u8>>, MailError> {
        let fetched = self.fetch(&uid.to_string(), "(UID BODY.PEEK[])").await?;
        Ok(fetched
            .iter()
            .find(|f| f.uid == Some(uid))
            .and_then(|f| f.body.clone()))
    }

    /// `APPEND folder [flags] [date-time] {n}`. `internaldate` is the quoted
    /// IMAP date-time (`"\" 5-Jan-2026 09:00:00 +0000\""`) that becomes the
    /// message's INTERNALDATE, which `SINCE`/`BEFORE` search on; `None` lets
    /// the server stamp now (right for drafts, wrong for seeded fixtures). A
    /// failure after the literal may have stored the message: an IO error or
    /// a timeout is `DraftStatusUnknown`.
    pub async fn append(
        &mut self,
        folder: &str,
        flags: Option<&str>,
        internaldate: Option<&str>,
        bytes: &[u8],
    ) -> Result<(), MailError> {
        let timeout = self.timeout;
        match tokio::time::timeout(
            timeout,
            self.session.append(folder, flags, internaldate, bytes),
        )
        .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(MailError::from_imap(&e, true)),
            Err(_) => Err(MailError::DraftStatusUnknown),
        }
    }

    /// `CREATE folder`.
    pub async fn create(&mut self, folder: &str) -> Result<(), MailError> {
        let timeout = self.timeout;
        match tokio::time::timeout(timeout, self.session.create(folder)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(MailError::from_imap(&e, false)),
            Err(_) => Err(MailError::Timeout),
        }
    }

    /// `UID STORE set query` (harness only: flag messages for deletion). A
    /// tagged `NO` or `BAD` is an error, never a silent success, so a wipe
    /// that did not happen cannot be reported as done.
    #[cfg(feature = "harness")]
    pub async fn uid_store(&mut self, set: &str, query: &str) -> Result<(), MailError> {
        self.tagged(format!("UID STORE {set} {query}"), |_| {})
            .await
    }

    /// `EXPUNGE` (harness only), status-aware like [`Imap::uid_store`].
    #[cfg(feature = "harness")]
    pub async fn expunge(&mut self) -> Result<(), MailError> {
        self.tagged("EXPUNGE".to_string(), |_| {}).await
    }

    /// `NOOP` (keepalive).
    pub async fn noop(&mut self) -> Result<(), MailError> {
        let timeout = self.timeout;
        match tokio::time::timeout(timeout, self.session.noop()).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(MailError::from_imap(&e, false)),
            Err(_) => Err(MailError::Timeout),
        }
    }

    /// `LOGOUT`; errors are ignored (the session is gone either way).
    pub async fn logout(mut self) {
        let _ = tokio::time::timeout(self.timeout, self.session.logout()).await;
    }

    /// The drafts folder: the configured one (must exist; matched against the
    /// raw modified-UTF-7 name or its decoded display name, so a user may
    /// type `[Gmail]/Entwürfe`), else the `\Drafts` special-use folder, else
    /// a folder named `Drafts` in any case, else `Create("Drafts")`.
    pub async fn resolve_drafts_folder(
        &mut self,
        configured: Option<&str>,
    ) -> Result<DraftsFolder, MailError> {
        let folders = self.folders().await?;
        if let Some(c) = configured {
            return match folders
                .iter()
                .find(|f| f.selectable && (f.raw == c || f.display == c))
            {
                Some(f) => Ok(DraftsFolder::Existing(f.raw.clone())),
                None => Err(MailError::DraftsFolderMissing),
            };
        }
        if let Some(f) = folders
            .iter()
            .find(|f| f.drafts_special_use && f.selectable)
        {
            return Ok(DraftsFolder::Existing(f.raw.clone()));
        }
        if let Some(f) = folders
            .iter()
            .find(|f| f.selectable && f.raw.eq_ignore_ascii_case("Drafts"))
        {
            return Ok(DraftsFolder::Existing(f.raw.clone()));
        }
        Ok(DraftsFolder::Create("Drafts".to_string()))
    }
}
