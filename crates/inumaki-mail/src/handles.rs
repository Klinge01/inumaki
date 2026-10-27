//! What the connector needs from the handle store (M4 spec §6.2). The
//! daemon implements [`MailHandles`] over the vault's `mail_handles`
//! table; [`MemoryHandles`] is the in-process version for tests and the
//! `mail-tasks` runner. Handles are `mf_`/`mm_` plus 16 random lowercase
//! letters; resolution is by provenance, never by shape.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use crate::error::MailError;

/// A message by folder, UIDVALIDITY, and UID.
#[derive(Clone, PartialEq, Eq)]
pub struct MessageRef {
    /// Folder name as the server spells it.
    pub folder: String,
    /// UIDVALIDITY when the message was listed.
    pub uid_validity: u32,
    /// UID.
    pub uid: u32,
}

impl std::fmt::Debug for MessageRef {
    // a folder name can name a customer: its length only
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageRef")
            .field("folder_len", &self.folder.len())
            .field("uid_validity", &self.uid_validity)
            .field("uid", &self.uid)
            .finish()
    }
}

/// What a handle names.
#[derive(Clone, PartialEq, Eq)]
pub enum Resolved {
    /// A folder (raw name).
    Folder(String),
    /// A message.
    Message(MessageRef),
}

impl std::fmt::Debug for Resolved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Resolved::Folder(n) => f
                .debug_struct("Resolved::Folder")
                .field("name_len", &n.len())
                .finish(),
            Resolved::Message(m) => f.debug_tuple("Resolved::Message").field(m).finish(),
        }
    }
}

/// The handle store.
pub trait MailHandles: Send + Sync + 'static {
    /// The handle of a folder (minted once).
    fn folder_handle(&self, folder: &str) -> Result<String, MailError>;
    /// The handle of a message (minted once per folder, UIDVALIDITY, UID).
    fn message_handle(&self, r: &MessageRef) -> Result<String, MailError>;
    /// What a handle names; `None` for anything not minted here.
    fn resolve(&self, handle: &str) -> Result<Option<Resolved>, MailError>;
    /// Drop the message handles of a folder (its UIDVALIDITY changed).
    fn invalidate_folder(&self, folder: &str) -> Result<usize, MailError>;
}

/// `prefix` plus 16 random lowercase letters (rejection sampling, so every
/// letter is equally likely).
pub fn random_handle(prefix: &str) -> Result<String, MailError> {
    let mut out = String::with_capacity(prefix.len() + 16);
    out.push_str(prefix);
    while out.len() < prefix.len() + 16 {
        let mut buf = [0u8; 32];
        getrandom::fill(&mut buf).map_err(|_| MailError::Handles("random"))?;
        for b in buf {
            if b < 234 && out.len() < prefix.len() + 16 {
                out.push((b'a' + b % 26) as char);
            }
        }
    }
    Ok(out)
}

#[derive(Default)]
struct MemoryInner {
    by_key: HashMap<String, String>,
    by_handle: HashMap<String, Resolved>,
}

/// An in-memory handle store.
#[derive(Default)]
pub struct MemoryHandles {
    inner: Mutex<MemoryInner>,
}

impl std::fmt::Debug for MemoryHandles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryHandles")
            .field("handles", &self.len())
            .finish()
    }
}

impl MemoryHandles {
    /// Empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Handles held.
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .by_handle
            .len()
    }

    /// True when nothing is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// True when the handle was minted here.
    pub fn known(&self, handle: &str) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .by_handle
            .contains_key(handle)
    }

    fn mint(&self, key: String, prefix: &str, value: Resolved) -> Result<String, MailError> {
        let mut g = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(h) = g.by_key.get(&key) {
            return Ok(h.clone());
        }
        let h = loop {
            let h = random_handle(prefix)?;
            if !g.by_handle.contains_key(&h) {
                break h;
            }
        };
        g.by_key.insert(key, h.clone());
        g.by_handle.insert(h.clone(), value);
        Ok(h)
    }
}

impl MailHandles for MemoryHandles {
    fn folder_handle(&self, folder: &str) -> Result<String, MailError> {
        self.mint(
            format!("f:{folder}"),
            "mf_",
            Resolved::Folder(folder.to_string()),
        )
    }

    fn message_handle(&self, r: &MessageRef) -> Result<String, MailError> {
        self.mint(
            format!("m:{}:{}:{}", r.uid_validity, r.uid, r.folder),
            "mm_",
            Resolved::Message(r.clone()),
        )
    }

    fn resolve(&self, handle: &str) -> Result<Option<Resolved>, MailError> {
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .by_handle
            .get(handle)
            .cloned())
    }

    fn invalidate_folder(&self, folder: &str) -> Result<usize, MailError> {
        let mut g = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let stale: Vec<String> = g
            .by_handle
            .iter()
            .filter(|(_, v)| matches!(v, Resolved::Message(m) if m.folder == folder))
            .map(|(h, _)| h.clone())
            .collect();
        for h in &stale {
            g.by_handle.remove(h);
        }
        // the keys go too, or the stale message would be re-minted under the same handle
        g.by_key.retain(|_, h| !stale.contains(h));
        Ok(stale.len())
    }
}
