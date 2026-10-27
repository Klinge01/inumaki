//! The mailbox row of a mailbox dataset (M4 spec §4.4). The username, the
//! drafts folder, and the optional From address are sealed like dataset
//! names; the app password lives in the secrets table under
//! `<dataset>/mail/password`; `fingerprint` is an HMAC label of the account
//! that scopes the dataset's mail handles. Replacing or removing the mailbox
//! deletes every handle of the dataset (spec §6.2).

use rusqlite::{OptionalExtension, params};

use crate::crypto::hex;
use crate::error::VaultError;
use crate::secrets::valid_secret_name;
use crate::vault::{Vault, open_hex, seal_hex};

/// True for the three presets.
pub fn valid_preset(p: &str) -> bool {
    matches!(p, "gmail" | "outlook" | "generic")
}

/// The secrets-table name of a dataset's app password.
pub fn mail_password_secret(dataset_id: &str) -> String {
    format!("{dataset_id}/mail/password")
}

/// True for the loopback names a plaintext IMAP connection is allowed to.
pub fn is_loopback_host(host: &str) -> bool {
    host == "127.0.0.1" || host == "::1" || host.eq_ignore_ascii_case("localhost")
}

fn valid_host(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
}

fn header_safe(s: &str) -> bool {
    !s.is_empty() && s.len() <= 320 && !s.chars().any(|c| c.is_control())
}

/// How to reach one mailbox. `Debug` prints the host, port, TLS, preset,
/// and lengths; never the username or a folder name.
#[derive(Clone, PartialEq, Eq)]
pub struct MailboxSpec {
    /// `gmail`, `outlook`, or `generic`.
    pub preset: String,
    /// IMAP host.
    pub imap_host: String,
    /// IMAP port (993 for implicit TLS).
    pub imap_port: u16,
    /// Implicit TLS; `false` is allowed for loopback hosts only.
    pub imap_tls: bool,
    /// Login name (sealed at rest).
    pub username: String,
    /// Secrets-table name of the app password.
    pub password_secret: String,
    /// Drafts folder; `None` = discover (`\Drafts` attribute, `Drafts`, or create it).
    pub drafts_folder: Option<String>,
    /// `From` of drafts when the username is not an address (sealed at rest).
    pub from_address: Option<String>,
}

impl std::fmt::Debug for MailboxSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MailboxSpec")
            .field("preset", &self.preset)
            .field("imap_host", &self.imap_host)
            .field("imap_port", &self.imap_port)
            .field("imap_tls", &self.imap_tls)
            .field("username_len", &self.username.len())
            .field("has_password_secret", &!self.password_secret.is_empty())
            .field("has_drafts_folder", &self.drafts_folder.is_some())
            .field("has_from_address", &self.from_address.is_some())
            .finish()
    }
}

impl MailboxSpec {
    fn validate(&self) -> Result<(), VaultError> {
        if !valid_preset(&self.preset) {
            return Err(VaultError::InvalidMailbox("preset"));
        }
        if !valid_host(&self.imap_host) {
            return Err(VaultError::InvalidMailbox("imap_host"));
        }
        if self.imap_port == 0 {
            return Err(VaultError::InvalidMailbox("imap_port"));
        }
        if !self.imap_tls && !is_loopback_host(&self.imap_host) {
            return Err(VaultError::InvalidMailbox("imap_tls"));
        }
        if !header_safe(&self.username) {
            return Err(VaultError::InvalidMailbox("username"));
        }
        if !valid_secret_name(&self.password_secret) {
            return Err(VaultError::InvalidSecretName);
        }
        if self
            .drafts_folder
            .as_deref()
            .is_some_and(|d| !header_safe(d))
        {
            return Err(VaultError::InvalidMailbox("drafts_folder"));
        }
        if self
            .from_address
            .as_deref()
            .is_some_and(|a| !header_safe(a) || !a.contains('@'))
        {
            return Err(VaultError::InvalidMailbox("from_address"));
        }
        Ok(())
    }
}

/// A stored mailbox. `Debug` omits the dataset id (a user-chosen slug) and
/// redacts the spec as [`MailboxSpec`] does.
#[derive(Clone, PartialEq, Eq)]
pub struct Mailbox {
    /// Owning dataset.
    pub dataset_id: String,
    /// The settings (decrypted).
    pub spec: MailboxSpec,
    /// HMAC label of (host, port, username): the handle scope.
    pub fingerprint: String,
    /// Unix seconds of the last `set_mailbox`.
    pub created_at: i64,
}

impl std::fmt::Debug for Mailbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mailbox")
            .field("spec", &self.spec)
            .field("fingerprint", &self.fingerprint)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// One `mailboxes` row as stored (sealed fields still hex).
struct MailboxRow {
    preset: String,
    imap_host: String,
    imap_port: i64,
    imap_tls: i64,
    username: String,
    password_secret: String,
    drafts_folder: Option<String>,
    from_address: Option<String>,
    fingerprint: String,
    created_at: i64,
}

fn aad(purpose: &str, dataset_id: &str) -> Vec<u8> {
    format!("{purpose}:{dataset_id}").into_bytes()
}

impl Vault {
    /// The handle scope of an account: 16 hex characters of
    /// `HMAC(index_key, "mailbox:<len>:<host>:<port>:<len>:<username>")`.
    /// The byte lengths make the input unambiguous: a `:` in the host or
    /// the user name cannot make two accounts share a scope.
    pub fn mailbox_fingerprint(&self, host: &str, port: u16, username: &str) -> String {
        let mac = self.inner.indexer.mac(
            format!(
                "mailbox:{}:{host}:{port}:{}:{username}",
                host.len(),
                username.len()
            )
            .as_bytes(),
        );
        hex(&mac[..8])
    }

    /// Configure (or replace) the dataset's mailbox. Every mail handle of
    /// the dataset is deleted: handles belong to one account configuration.
    pub fn set_mailbox(&self, dataset_id: &str, spec: &MailboxSpec) -> Result<Mailbox, VaultError> {
        spec.validate()?;
        self.dataset_profile(dataset_id)?;
        let fingerprint = self.mailbox_fingerprint(&spec.imap_host, spec.imap_port, &spec.username);
        let username = seal_hex(
            &self.inner,
            &aad("mailbox-user", dataset_id),
            &spec.username,
        )?;
        let drafts = spec
            .drafts_folder
            .as_deref()
            .map(|d| seal_hex(&self.inner, &aad("mailbox-drafts", dataset_id), d))
            .transpose()?;
        let from = spec
            .from_address
            .as_deref()
            .map(|a| seal_hex(&self.inner, &aad("mailbox-from", dataset_id), a))
            .transpose()?;
        let now = self.inner.now();
        let replaced = {
            let mut conn = self.inner.lock();
            let tx = conn.transaction()?;
            let previous: Option<String> = tx
                .query_row(
                    "SELECT fingerprint FROM mailboxes WHERE dataset_id = ?1",
                    params![dataset_id],
                    |r| r.get(0),
                )
                .optional()?;
            tx.execute(
                "INSERT INTO mailboxes (dataset_id, preset, imap_host, imap_port, imap_tls, username, password_secret, drafts_folder, from_address, fingerprint, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11) \
                 ON CONFLICT(dataset_id) DO UPDATE SET preset = excluded.preset, imap_host = excluded.imap_host, imap_port = excluded.imap_port, \
                 imap_tls = excluded.imap_tls, username = excluded.username, password_secret = excluded.password_secret, drafts_folder = excluded.drafts_folder, \
                 from_address = excluded.from_address, fingerprint = excluded.fingerprint, created_at = excluded.created_at",
                params![
                    dataset_id,
                    spec.preset,
                    spec.imap_host,
                    i64::from(spec.imap_port),
                    i64::from(spec.imap_tls),
                    username,
                    spec.password_secret,
                    drafts,
                    from,
                    fingerprint,
                    now
                ],
            )?;
            tx.execute(
                "DELETE FROM mail_handles WHERE dataset_id = ?1",
                params![dataset_id],
            )?;
            tx.commit()?;
            previous.is_some()
        };
        tracing::info!(
            dataset = %self.inner.opaque(dataset_id),
            preset = %spec.preset,
            tls = spec.imap_tls,
            replaced,
            "mailbox configured"
        );
        Ok(Mailbox {
            dataset_id: dataset_id.to_string(),
            spec: spec.clone(),
            fingerprint,
            created_at: now,
        })
    }

    /// The dataset's mailbox, decrypted; `None` when none is configured.
    pub fn mailbox(&self, dataset_id: &str) -> Result<Option<Mailbox>, VaultError> {
        let row: Option<MailboxRow> = {
            let conn = self.inner.lock();
            conn.query_row(
                "SELECT preset, imap_host, imap_port, imap_tls, username, password_secret, drafts_folder, from_address, fingerprint, created_at \
                 FROM mailboxes WHERE dataset_id = ?1",
                params![dataset_id],
                |r| {
                    Ok(MailboxRow {
                        preset: r.get(0)?,
                        imap_host: r.get(1)?,
                        imap_port: r.get(2)?,
                        imap_tls: r.get(3)?,
                        username: r.get(4)?,
                        password_secret: r.get(5)?,
                        drafts_folder: r.get(6)?,
                        from_address: r.get(7)?,
                        fingerprint: r.get(8)?,
                        created_at: r.get(9)?,
                    })
                },
            )
            .optional()?
        };
        let Some(row) = row else {
            return Ok(None);
        };
        let username = open_hex(&self.inner, &aad("mailbox-user", dataset_id), &row.username)?;
        let drafts_folder = row
            .drafts_folder
            .map(|d| {
                open_hex(&self.inner, &aad("mailbox-drafts", dataset_id), &d)
                    .map(|z| z.as_str().to_owned())
            })
            .transpose()?;
        let from_address = row
            .from_address
            .map(|a| {
                open_hex(&self.inner, &aad("mailbox-from", dataset_id), &a)
                    .map(|z| z.as_str().to_owned())
            })
            .transpose()?;
        let imap_port =
            u16::try_from(row.imap_port).map_err(|_| VaultError::InvalidMailbox("imap_port"))?;
        Ok(Some(Mailbox {
            dataset_id: dataset_id.to_string(),
            spec: MailboxSpec {
                preset: row.preset,
                imap_host: row.imap_host,
                imap_port,
                imap_tls: row.imap_tls != 0,
                username: username.as_str().to_owned(),
                password_secret: row.password_secret,
                drafts_folder,
                from_address,
            },
            fingerprint: row.fingerprint,
            created_at: row.created_at,
        }))
    }

    /// Remove the mailbox and every handle of the dataset; `false` when none.
    pub fn remove_mailbox(&self, dataset_id: &str) -> Result<bool, VaultError> {
        let n = {
            let mut conn = self.inner.lock();
            let tx = conn.transaction()?;
            let n = tx.execute(
                "DELETE FROM mailboxes WHERE dataset_id = ?1",
                params![dataset_id],
            )?;
            tx.execute(
                "DELETE FROM mail_handles WHERE dataset_id = ?1",
                params![dataset_id],
            )?;
            tx.commit()?;
            n
        };
        if n > 0 {
            tracing::info!(dataset = %self.inner.opaque(dataset_id), "mailbox removed");
        }
        Ok(n > 0)
    }
}
