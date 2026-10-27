//! Opaque mail handles (M4 spec §6.2): `mf_` + 16 random lowercase letters
//! for folders, `mm_` + 16 for messages. The payload (folder name,
//! UIDVALIDITY, UID) is sealed with AAD `mailhandle:<handle>`; lookups by
//! reference go through HMACs of the same fields, so no folder name is
//! stored readable. Handles are scoped to (dataset, mailbox fingerprint),
//! deleted per folder when its UIDVALIDITY changes, and swept by last use.

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::VaultError;
use crate::vault::{Vault, is_constraint};

/// Length of every handle (`mf_`/`mm_` plus 16 letters).
pub const MAIL_HANDLE_LEN: usize = 19;

/// What a handle names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailHandleKind {
    /// A folder.
    Folder,
    /// A message (folder, UIDVALIDITY, UID).
    Message,
}

impl MailHandleKind {
    /// The handle prefix.
    pub fn prefix(self) -> &'static str {
        match self {
            MailHandleKind::Folder => "mf_",
            MailHandleKind::Message => "mm_",
        }
    }

    /// The stored string.
    pub fn as_str(self) -> &'static str {
        match self {
            MailHandleKind::Folder => "folder",
            MailHandleKind::Message => "message",
        }
    }

    /// Parse the stored string.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "folder" => Some(MailHandleKind::Folder),
            "message" => Some(MailHandleKind::Message),
            _ => None,
        }
    }
}

/// What a handle resolves to. A folder reference has `uid == 0`. `Debug`
/// prints the folder name's length, never the name.
#[derive(Clone, PartialEq, Eq)]
pub struct MailHandleRef {
    /// IMAP folder name as the server spells it (modified UTF-7).
    pub folder: String,
    /// UIDVALIDITY of the folder when the message was seen (0 for folders).
    pub uid_validity: u32,
    /// UID of the message (0 for folders).
    pub uid: u32,
}

impl std::fmt::Debug for MailHandleRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MailHandleRef")
            .field("folder_len", &self.folder.len())
            .field("uid_validity", &self.uid_validity)
            .field("uid", &self.uid)
            .finish()
    }
}

impl MailHandleRef {
    /// A folder reference.
    pub fn folder(name: &str) -> Self {
        MailHandleRef {
            folder: name.to_string(),
            uid_validity: 0,
            uid: 0,
        }
    }

    /// A message reference.
    pub fn message(folder: &str, uid_validity: u32, uid: u32) -> Self {
        MailHandleRef {
            folder: folder.to_string(),
            uid_validity,
            uid,
        }
    }

    /// Folder or message.
    pub fn kind(&self) -> MailHandleKind {
        if self.uid == 0 {
            MailHandleKind::Folder
        } else {
            MailHandleKind::Message
        }
    }
}

/// The kind of a well-formed handle string, `None` for anything else.
/// Shape only: provenance is [`Vault::resolve_mail_handle`].
pub fn is_mail_handle(s: &str) -> Option<MailHandleKind> {
    if s.len() != MAIL_HANDLE_LEN {
        return None;
    }
    let kind = match s.get(..3)? {
        "mf_" => MailHandleKind::Folder,
        "mm_" => MailHandleKind::Message,
        _ => return None,
    };
    s[3..]
        .bytes()
        .all(|b| b.is_ascii_lowercase())
        .then_some(kind)
}

fn random_letters(n: usize) -> Result<String, VaultError> {
    let mut out = String::with_capacity(n);
    while out.len() < n {
        let mut buf = [0u8; 32];
        getrandom::fill(&mut buf).map_err(|_| VaultError::Random)?;
        for b in buf {
            // rejection sampling: 234 = 9 * 26 keeps the letters uniform
            if b < 234 && out.len() < n {
                out.push(char::from(b'a' + b % 26));
            }
        }
    }
    Ok(out)
}

#[derive(Serialize, Deserialize)]
struct Payload {
    f: String,
    v: u32,
    u: u32,
}

fn key_input(fp: &str, r: &MailHandleRef) -> String {
    format!(
        "mailhandle:{}:{fp}:{}:{}:{}",
        r.kind().as_str(),
        r.folder,
        r.uid_validity,
        r.uid
    )
}

fn folder_input(fp: &str, folder: &str) -> String {
    format!("mailfolder:{fp}:{folder}")
}

fn seal_aad(handle: &str) -> Vec<u8> {
    format!("mailhandle:{handle}").into_bytes()
}

const SELECT_BY_KEY: &str =
    "SELECT handle FROM mail_handles WHERE dataset_id = ?1 AND key_hmac = ?2";

impl Vault {
    /// The handle for `r` in this dataset and mailbox: the existing one, or
    /// a freshly minted random one. Minting is refused when `mailbox_fp` is
    /// not the dataset's current mailbox fingerprint: a connector started for
    /// a replaced mailbox must not repopulate the table after `set_mailbox`
    /// emptied it (`InvalidMailbox("fingerprint")`; `MailboxNotFound` without
    /// a row). The check and the insert run under one lock hold, so a
    /// concurrent `set_mailbox` cannot land between them.
    pub fn mail_handle(
        &self,
        dataset_id: &str,
        mailbox_fp: &str,
        r: &MailHandleRef,
    ) -> Result<String, VaultError> {
        let key = self.inner.indexer.mac(key_input(mailbox_fp, r).as_bytes());
        let now = self.inner.now();
        let conn = self.inner.lock();
        let current: Option<String> = conn
            .query_row(
                "SELECT fingerprint FROM mailboxes WHERE dataset_id = ?1",
                params![dataset_id],
                |row| row.get(0),
            )
            .optional()?;
        match current {
            None => return Err(VaultError::MailboxNotFound),
            Some(fp) if fp != mailbox_fp => return Err(VaultError::InvalidMailbox("fingerprint")),
            Some(_) => {}
        }
        let existing: Option<String> = conn
            .query_row(SELECT_BY_KEY, params![dataset_id, key.as_slice()], |row| {
                row.get(0)
            })
            .optional()?;
        if let Some(h) = existing {
            conn.execute(
                "UPDATE mail_handles SET last_used = ?1 WHERE handle = ?2",
                params![now, h],
            )?;
            return Ok(h);
        }
        let handle = format!("{}{}", r.kind().prefix(), random_letters(16)?);
        let payload = Zeroizing::new(
            serde_json::to_vec(&Payload {
                f: r.folder.clone(),
                v: r.uid_validity,
                u: r.uid,
            })
            .map_err(|_| VaultError::Encrypt)?,
        );
        let sealed = self.inner.cipher.seal(&seal_aad(&handle), &payload)?;
        let folder_mac = self
            .inner
            .indexer
            .mac(folder_input(mailbox_fp, &r.folder).as_bytes());
        let inserted = conn.execute(
            "INSERT INTO mail_handles (handle, dataset_id, mailbox_fp, kind, key_hmac, folder_hmac, nonce, value, created_at, last_used) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)",
            params![
                handle,
                dataset_id,
                mailbox_fp,
                r.kind().as_str(),
                key.as_slice(),
                folder_mac.as_slice(),
                sealed.nonce,
                sealed.value,
                now
            ],
        );
        match inserted {
            Ok(_) => Ok(handle),
            Err(e) if is_constraint(&e, "mail_handles.dataset_id, mail_handles.key_hmac") => {
                // minted through another connection: return that one
                Ok(
                    conn.query_row(SELECT_BY_KEY, params![dataset_id, key.as_slice()], |row| {
                        row.get(0)
                    })?,
                )
            }
            Err(rusqlite::Error::SqliteFailure(f, _))
                if f.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_FOREIGNKEY =>
            {
                Err(VaultError::DatasetNotFound(dataset_id.to_string()))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// What a handle names, when it was minted for this dataset and mailbox.
    /// Anything else (wrong shape, other dataset, other mailbox, invalidated,
    /// swept) is `None`. Touches `last_used`; a handle deleted between the
    /// read and the touch (invalidated or swept meanwhile) is `None` too.
    pub fn resolve_mail_handle(
        &self,
        dataset_id: &str,
        mailbox_fp: &str,
        handle: &str,
    ) -> Result<Option<(MailHandleKind, MailHandleRef)>, VaultError> {
        let Some(shape) = is_mail_handle(handle) else {
            return Ok(None);
        };
        let row: Option<(String, String, Vec<u8>, Vec<u8>)> = {
            let conn = self.inner.lock();
            conn.query_row(
                "SELECT mailbox_fp, kind, nonce, value FROM mail_handles WHERE handle = ?1 AND dataset_id = ?2",
                params![handle, dataset_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?
        };
        let Some((fp, kind, nonce, value)) = row else {
            return Ok(None);
        };
        if fp != mailbox_fp {
            return Ok(None);
        }
        let kind = MailHandleKind::parse(&kind)
            .filter(|k| *k == shape)
            .ok_or(VaultError::Decrypt)?;
        let plain = self.inner.cipher.open(&seal_aad(handle), &nonce, &value)?;
        let p: Payload = serde_json::from_slice(&plain).map_err(|_| VaultError::Decrypt)?;
        let now = self.inner.now();
        let touched = {
            let conn = self.inner.lock();
            conn.execute(
                "UPDATE mail_handles SET last_used = ?1 WHERE handle = ?2 AND dataset_id = ?3 AND mailbox_fp = ?4",
                params![now, handle, dataset_id, mailbox_fp],
            )?
        };
        if touched == 0 {
            return Ok(None);
        }
        Ok(Some((
            kind,
            MailHandleRef {
                folder: p.f,
                uid_validity: p.v,
                uid: p.u,
            },
        )))
    }

    /// True when the handle was minted for this dataset and mailbox
    /// (provenance for the field contract); no decryption, no touch.
    pub fn mail_handle_known(
        &self,
        dataset_id: &str,
        mailbox_fp: &str,
        handle: &str,
    ) -> Result<bool, VaultError> {
        if is_mail_handle(handle).is_none() {
            return Ok(false);
        }
        let conn = self.inner.lock();
        let n: i64 = conn.query_row(
            "SELECT count(*) FROM mail_handles WHERE handle = ?1 AND dataset_id = ?2 AND mailbox_fp = ?3",
            params![handle, dataset_id, mailbox_fp],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// Delete the message handles of a folder (its UIDVALIDITY changed);
    /// the folder handle itself stays. Returns how many.
    pub fn invalidate_mail_folder(
        &self,
        dataset_id: &str,
        mailbox_fp: &str,
        folder: &str,
    ) -> Result<usize, VaultError> {
        let folder_mac = self
            .inner
            .indexer
            .mac(folder_input(mailbox_fp, folder).as_bytes());
        let n = {
            let conn = self.inner.lock();
            conn.execute(
                "DELETE FROM mail_handles WHERE dataset_id = ?1 AND folder_hmac = ?2 AND kind = 'message'",
                params![dataset_id, folder_mac.as_slice()],
            )?
        };
        tracing::info!(dataset = %self.inner.opaque(dataset_id), handles = n, "message handles invalidated");
        Ok(n)
    }

    /// Delete handles not used for `retention_days`; returns how many.
    pub fn sweep_mail_handles(&self, retention_days: u32) -> Result<usize, VaultError> {
        let cutoff = self.inner.now() - i64::from(retention_days) * 86_400;
        let conn = self.inner.lock();
        Ok(conn.execute(
            "DELETE FROM mail_handles WHERE last_used < ?1",
            params![cutoff],
        )?)
    }

    /// Handles of a dataset (`status`).
    pub fn mail_handle_count(&self, dataset_id: &str) -> Result<u64, VaultError> {
        self.dataset_profile(dataset_id)?;
        let conn = self.inner.lock();
        let n: i64 = conn.query_row(
            "SELECT count(*) FROM mail_handles WHERE dataset_id = ?1",
            params![dataset_id],
            |r| r.get(0),
        )?;
        Ok(u64::try_from(n).unwrap_or(0))
    }
}
