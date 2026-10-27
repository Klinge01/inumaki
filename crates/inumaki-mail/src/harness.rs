//! Test-mailbox helpers for the scripted mail tasks (feature `harness`):
//! seed fixture mails, wipe a folder, read a folder back. Used by
//! `inumaki mail-tasks` against a test mailbox (the scripted fake server or
//! GreenMail); never by the daemon. Every command is status-aware: a
//! refused wipe or a refused append is an error, not a count.

use std::time::Duration;

use crate::account::MailAccount;
use crate::error::MailError;
use crate::imap::Imap;

/// One message to seed.
#[derive(Clone, PartialEq, Eq)]
pub struct SeedMail {
    /// Target folder (created when missing).
    pub folder: String,
    /// Quoted IMAP date-time for the APPEND, so INTERNALDATE (what `SINCE`/
    /// `BEFORE` compare) is the fixture's day and not the seeding day.
    pub internal_date: Option<String>,
    /// RFC 5322 bytes.
    pub eml: Vec<u8>,
}

impl std::fmt::Debug for SeedMail {
    // a fixture mail is a PII look-alike: lengths only
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeedMail")
            .field("folder_len", &self.folder.len())
            .field("has_date", &self.internal_date.is_some())
            .field("eml_len", &self.eml.len())
            .finish()
    }
}

/// APPEND every mail with its internal date; missing folders are created. Returns how many.
pub async fn seed_mailbox(
    account: &MailAccount,
    timeout: Duration,
    mails: &[SeedMail],
) -> Result<usize, MailError> {
    let mut imap = Imap::connect(account, timeout).await?;
    let outcome = seed(&mut imap, mails).await;
    imap.logout().await;
    outcome
}

async fn seed(imap: &mut Imap, mails: &[SeedMail]) -> Result<usize, MailError> {
    let mut known: Vec<String> = imap.folders().await?.into_iter().map(|f| f.raw).collect();
    for m in mails {
        if !known.contains(&m.folder) {
            imap.create(&m.folder).await?;
            known.push(m.folder.clone());
        }
        imap.append(&m.folder, None, m.internal_date.as_deref(), &m.eml)
            .await?;
    }
    Ok(mails.len())
}

/// Delete every message of `folder`. Returns how many were there; a folder
/// that does not exist has none.
pub async fn clear_folder(
    account: &MailAccount,
    timeout: Duration,
    folder: &str,
) -> Result<usize, MailError> {
    let mut imap = Imap::connect(account, timeout).await?;
    let outcome = clear(&mut imap, folder).await;
    imap.logout().await;
    outcome
}

async fn clear(imap: &mut Imap, folder: &str) -> Result<usize, MailError> {
    if !imap.folders().await?.iter().any(|f| f.raw == folder) {
        return Ok(0);
    }
    imap.select(folder).await?;
    let uids = imap.uid_search("ALL").await?;
    if !uids.is_empty() {
        imap.uid_store("1:*", "+FLAGS (\\Deleted)").await?;
        imap.expunge().await?;
    }
    Ok(uids.len())
}

/// Every message of `folder`, oldest first; a folder that does not exist has none.
pub async fn list_folder_messages(
    account: &MailAccount,
    timeout: Duration,
    folder: &str,
) -> Result<Vec<Vec<u8>>, MailError> {
    let mut imap = Imap::connect(account, timeout).await?;
    let outcome = list(&mut imap, folder).await;
    imap.logout().await;
    outcome
}

async fn list(imap: &mut Imap, folder: &str) -> Result<Vec<Vec<u8>>, MailError> {
    if !imap.folders().await?.iter().any(|f| f.raw == folder) {
        return Ok(Vec::new());
    }
    imap.examine(folder).await?;
    let mut uids = imap.uid_search("ALL").await?;
    uids.sort_unstable();
    let mut out = Vec::with_capacity(uids.len());
    for uid in uids {
        if let Some(raw) = imap.fetch_message(uid).await? {
            out.push(raw);
        }
    }
    Ok(out)
}
