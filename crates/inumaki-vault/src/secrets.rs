//! The secrets table (M4 spec §4.3): named values sealed with the vault's
//! encryption key, AAD `secret:<name>`. Names are the only thing that ever
//! leaves this module in clear. `get_secret` distinguishes a missing entry
//! (`Ok(None)`) from a storage or decryption failure (`Err`).

use rusqlite::{OptionalExtension, params};
use zeroize::Zeroizing;

use crate::error::VaultError;
use crate::vault::Vault;

/// True for `[a-z0-9][a-z0-9/_.-]{0,127}`.
pub fn valid_secret_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 128
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'/' | b'_' | b'.' | b'-')
        })
}

fn aad(name: &str) -> Vec<u8> {
    format!("secret:{name}").into_bytes()
}

/// The dataset slug a secret name starts with (`<dataset>/upstream/<name>/env`,
/// `<dataset>/mail/password`), for the opaque log label only; never logged
/// in clear.
fn owning_dataset(name: &str) -> &str {
    name.split('/').next().unwrap_or(name)
}

impl Vault {
    /// Store or replace a secret. The secret's name is never logged — it
    /// embeds the raw dataset slug (`<dataset>/upstream/<name>/env`); only
    /// the opaque dataset id derived from that slug is.
    pub fn put_secret(&self, name: &str, value: &[u8]) -> Result<(), VaultError> {
        if !valid_secret_name(name) {
            return Err(VaultError::InvalidSecretName);
        }
        let sealed = self.inner.cipher.seal(&aad(name), value)?;
        {
            let conn = self.inner.lock();
            conn.execute(
                "INSERT INTO secrets (name, nonce, value) VALUES (?1, ?2, ?3) \
                 ON CONFLICT(name) DO UPDATE SET nonce = excluded.nonce, value = excluded.value",
                params![name, sealed.nonce, sealed.value],
            )?;
        }
        tracing::info!(dataset = %self.inner.opaque(owning_dataset(name)), "secret stored");
        Ok(())
    }

    /// The decrypted value, zeroized on drop; `None` when no such name.
    pub fn get_secret(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
        let row: Option<(Vec<u8>, Vec<u8>)> = {
            let conn = self.inner.lock();
            conn.query_row(
                "SELECT nonce, value FROM secrets WHERE name = ?1",
                params![name],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
        };
        match row {
            Some((nonce, value)) => Ok(Some(self.inner.cipher.open(&aad(name), &nonce, &value)?)),
            None => Ok(None),
        }
    }

    /// Delete a secret; `false` when there was none.
    pub fn delete_secret(&self, name: &str) -> Result<bool, VaultError> {
        let conn = self.inner.lock();
        let n = conn.execute("DELETE FROM secrets WHERE name = ?1", params![name])?;
        Ok(n > 0)
    }

    /// Every secret name, sorted.
    pub fn list_secret_names(&self) -> Result<Vec<String>, VaultError> {
        let conn = self.inner.lock();
        let mut stmt = conn.prepare("SELECT name FROM secrets ORDER BY name")?;
        let names = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(names)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Metadata, Subscriber};

    use crate::keys::KeySource;
    use crate::vault::{Vault, VaultOptions};

    use super::owning_dataset;

    /// Formats every event this subscriber sees into one line (`name` plus
    /// each field's `Debug`), so a test can assert on what tracing actually
    /// emitted rather than trusting the source.
    struct CapturingSubscriber {
        lines: Arc<Mutex<Vec<String>>>,
    }

    struct LineVisitor(String);

    impl Visit for LineVisitor {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0.push_str(&format!(" {}={value:?}", field.name()));
        }
    }

    impl Subscriber for CapturingSubscriber {
        fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _span: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }
        fn record(&self, _span: &Id, _values: &Record<'_>) {}
        fn record_follows_from(&self, _span: &Id, _follows: &Id) {}
        fn event(&self, event: &Event<'_>) {
            let mut line = LineVisitor(event.metadata().name().to_string());
            event.record(&mut line);
            self.lines.lock().unwrap().push(line.0);
        }
        fn enter(&self, _span: &Id) {}
        fn exit(&self, _span: &Id) {}
    }

    #[test]
    fn owning_dataset_takes_the_first_path_segment() {
        assert_eq!(owning_dataset("crm/upstream/crm/env"), "crm");
        assert_eq!(owning_dataset("mail-work/mail/password"), "mail-work");
        assert_eq!(owning_dataset("no-slash"), "no-slash");
    }

    #[test]
    fn put_secret_logs_the_opaque_dataset_id_never_the_name_or_slug() {
        let dir = tempfile::tempdir().unwrap();
        let v =
            Vault::open(VaultOptions::in_dir(dir.path()).with_key_source(KeySource::File)).unwrap();
        let lines = Arc::new(Mutex::new(Vec::new()));
        let subscriber = CapturingSubscriber {
            lines: Arc::clone(&lines),
        };
        tracing::subscriber::with_default(subscriber, || {
            v.put_secret("crm/upstream/crm/env", b"hunter2-canary")
                .unwrap();
        });
        let captured = lines.lock().unwrap().join("\n");
        assert!(!captured.is_empty(), "the event was captured at all");
        assert!(!captured.contains("crm/upstream/crm/env"), "{captured}");
        assert!(!captured.contains("crm"), "{captured}");
        assert!(!captured.contains("hunter2-canary"), "{captured}");
        // The opaque id is still there, in its usual hex form.
        let expected = v.opaque_id("crm");
        assert!(captured.contains(&expected), "{captured}");
    }
}
