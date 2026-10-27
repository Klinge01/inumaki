//! The two vault keys and where they live: OS secret store or a 0600 file.

use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::error::{VaultError, io_err};

/// Key file name inside the data directory.
pub const KEY_FILE: &str = "vault.key";
/// Service name used in the OS secret store.
pub const KEYRING_SERVICE: &str = "inumaki";

/// How long opening the vault waits for the OS secret store. On macOS the
/// Keychain may first ask the user (an ad hoc signature changes with every
/// build), so the wait has to cover a person answering; elsewhere a hung
/// D-Bus must not stall startup (spec §15).
pub const KEYRING_TIMEOUT: Duration = if cfg!(target_os = "macos") {
    Duration::from_secs(120)
} else {
    Duration::from_secs(2)
};

/// Where the keys live, from `[vault] key_source`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    /// The vault's recorded source; on first run the secret store if
    /// reachable, else a key file.
    Auto,
    /// The OS secret store only.
    Keyring,
    /// The key file only.
    File,
}

impl KeySource {
    /// Parse a config value.
    pub fn parse(s: &str) -> Option<KeySource> {
        match s {
            "auto" => Some(KeySource::Auto),
            "keyring" => Some(KeySource::Keyring),
            "file" => Some(KeySource::File),
            _ => None,
        }
    }
}

/// The encryption key and the index key.
pub struct Keys {
    /// XChaCha20-Poly1305 key.
    pub enc: Zeroizing<[u8; 32]>,
    /// HMAC-SHA256 key.
    pub index: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Keys(64 bytes)")
    }
}

impl Keys {
    /// Fresh keys from the OS CSPRNG.
    pub fn generate() -> Result<Keys, VaultError> {
        let mut enc = Zeroizing::new([0u8; 32]);
        let mut index = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *enc).map_err(|_| VaultError::Random)?;
        getrandom::fill(&mut *index).map_err(|_| VaultError::Random)?;
        Ok(Keys { enc, index })
    }

    /// From 64 bytes (`enc || index`).
    pub fn from_bytes(b: &[u8]) -> Option<Keys> {
        if b.len() != 64 {
            return None;
        }
        let mut enc = Zeroizing::new([0u8; 32]);
        let mut index = Zeroizing::new([0u8; 32]);
        enc.copy_from_slice(&b[..32]);
        index.copy_from_slice(&b[32..]);
        Some(Keys { enc, index })
    }

    /// `enc || index`, zeroized on drop.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 64]> {
        let mut out = Zeroizing::new([0u8; 64]);
        out[..32].copy_from_slice(&*self.enc);
        out[32..].copy_from_slice(&*self.index);
        out
    }
}

/// Somewhere keys can be kept: the OS secret store, or a test double.
pub trait KeyStore: Send + Sync {
    /// The stored keys, `None` when none were stored yet.
    fn load(&self) -> Result<Option<Keys>, VaultError>;
    /// Store keys.
    fn store(&self, keys: &Keys) -> Result<(), VaultError>;
}

/// The OS secret store through the `keyring` crate (macOS Keychain, Linux
/// Secret Service). Every call runs on a helper thread with a timeout so a
/// hung D-Bus cannot stall startup (spec §15).
pub struct OsKeyring {
    user: String,
    timeout: Duration,
}

impl std::fmt::Debug for OsKeyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OsKeyring")
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl OsKeyring {
    /// Keys for the vault identified by `vault_id` (a random id stored in
    /// `meta.vault_id`, review I5): the item is tied to the vault's
    /// identity, not the data directory's path, so moving or renaming the
    /// directory does not lock the vault out of its own keys.
    pub fn new(vault_id: &str, timeout: Duration) -> Self {
        OsKeyring {
            user: format!("vault-{vault_id}"),
            timeout,
        }
    }

    fn with_timeout<T: Send + 'static>(
        &self,
        f: impl FnOnce(keyring::Entry) -> Result<T, VaultError> + Send + 'static,
    ) -> Result<T, VaultError> {
        let user = self.user.clone();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let r = keyring::Entry::new(KEYRING_SERVICE, &user)
                .map_err(|e| VaultError::KeyStore(e.to_string()))
                .and_then(f);
            let _ = tx.send(r);
        });
        match rx.recv_timeout(self.timeout) {
            Ok(r) => r,
            Err(_) => Err(VaultError::KeyStore(format!(
                "no answer from the secret store within {} ms",
                self.timeout.as_millis()
            ))),
        }
    }
}

impl KeyStore for OsKeyring {
    fn load(&self) -> Result<Option<Keys>, VaultError> {
        self.with_timeout(|entry| match entry.get_secret() {
            Ok(bytes) => Keys::from_bytes(&bytes)
                .map(Some)
                .ok_or(VaultError::KeyStore(
                    "stored secret has the wrong length".into(),
                )),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(VaultError::KeyStore(e.to_string())),
        })
    }

    fn store(&self, keys: &Keys) -> Result<(), VaultError> {
        let bytes = keys.to_bytes();
        self.with_timeout(move |entry| {
            entry
                .set_secret(&*bytes)
                .map_err(|e| VaultError::KeyStore(e.to_string()))
        })
    }
}

/// Loaded keys and where they came from.
#[derive(Debug)]
pub struct KeyLoad {
    /// The keys.
    pub keys: Keys,
    /// `"keyring"` or `"file"`, to be recorded in `meta.key_source`.
    pub source: &'static str,
}

fn key_file_path(data_dir: &Path) -> PathBuf {
    data_dir.join(KEY_FILE)
}

fn file_load_or_create(data_dir: &Path) -> Result<Keys, VaultError> {
    let path = key_file_path(data_dir);
    let display = path.display().to_string();
    match std::fs::metadata(&path) {
        Ok(meta) => {
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(VaultError::KeyFile {
                    path: display,
                    reason: "permissions are not 0600",
                });
            }
            let mut f = std::fs::File::open(&path).map_err(|e| io_err(&path, &e))?;
            let mut buf = Zeroizing::new(Vec::with_capacity(64));
            f.read_to_end(&mut buf).map_err(|e| io_err(&path, &e))?;
            Keys::from_bytes(&buf).ok_or(VaultError::KeyFile {
                path: display,
                reason: "wrong length",
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(data_dir).map_err(|e| io_err(data_dir, &e))?;
            let keys = Keys::generate()?;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .map_err(|e| io_err(&path, &e))?;
            f.write_all(&*keys.to_bytes())
                .map_err(|e| io_err(&path, &e))?;
            f.sync_all().map_err(|e| io_err(&path, &e))?;
            Ok(keys)
        }
        Err(e) => Err(io_err(&path, &e)),
    }
}

fn store_load_or_create(store: &dyn KeyStore) -> Result<Keys, VaultError> {
    if let Some(k) = store.load()? {
        return Ok(k);
    }
    let keys = Keys::generate()?;
    store.store(&keys)?;
    Ok(keys)
}

/// Load the vault keys, creating them on first run.
///
/// `stored` is `meta.key_source` of an existing vault. An explicit source
/// that differs from it is [`VaultError::KeySourceChanged`]. `Auto` follows
/// `stored` when present; on a first run it uses `store` when reachable and
/// otherwise writes a key file (logging one warning).
pub fn load_or_create(
    data_dir: &Path,
    source: KeySource,
    stored: Option<&str>,
    store: &dyn KeyStore,
) -> Result<KeyLoad, VaultError> {
    let want: Option<&'static str> = match source {
        KeySource::Keyring => Some("keyring"),
        KeySource::File => Some("file"),
        KeySource::Auto => match stored {
            Some("keyring") => Some("keyring"),
            Some("file") => Some("file"),
            Some(other) => {
                return Err(VaultError::KeySourceChanged {
                    stored: other.to_string(),
                    requested: "auto".into(),
                });
            }
            None => None,
        },
    };
    if let (Some(s), Some(w)) = (stored, want) {
        if s != w {
            return Err(VaultError::KeySourceChanged {
                stored: s.to_string(),
                requested: w.to_string(),
            });
        }
    }
    match want {
        Some("keyring") => Ok(KeyLoad {
            keys: store_load_or_create(store)?,
            source: "keyring",
        }),
        Some(_) => Ok(KeyLoad {
            keys: file_load_or_create(data_dir)?,
            source: "file",
        }),
        None => match store_load_or_create(store) {
            Ok(keys) => Ok(KeyLoad {
                keys,
                source: "keyring",
            }),
            Err(e) => {
                tracing::warn!(error = %e, "no OS secret store reachable; keeping the vault keys in a 0600 key file");
                Ok(KeyLoad {
                    keys: file_load_or_create(data_dir)?,
                    source: "file",
                })
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;

    /// In-memory key store standing in for the OS keyring.
    struct MemStore(Mutex<Option<Vec<u8>>>);
    impl KeyStore for MemStore {
        fn load(&self) -> Result<Option<Keys>, VaultError> {
            Ok(self.0.lock().unwrap().as_deref().and_then(Keys::from_bytes))
        }
        fn store(&self, keys: &Keys) -> Result<(), VaultError> {
            *self.0.lock().unwrap() = Some(keys.to_bytes().to_vec());
            Ok(())
        }
    }

    /// A store that is not reachable (headless Linux, CI).
    struct Unreachable;
    impl KeyStore for Unreachable {
        fn load(&self) -> Result<Option<Keys>, VaultError> {
            Err(VaultError::KeyStore("no secret service".into()))
        }
        fn store(&self, _: &Keys) -> Result<(), VaultError> {
            Err(VaultError::KeyStore("no secret service".into()))
        }
    }

    #[test]
    fn keyring_timeout_leaves_time_to_answer_a_keychain_prompt() {
        // An ad hoc signed build makes macOS ask before the Keychain hands
        // out the key; a daemon that gives up first is restarted by launchd
        // and asks again, a new prompt every ten seconds.
        if cfg!(target_os = "macos") {
            assert!(KEYRING_TIMEOUT >= Duration::from_secs(60));
        } else {
            assert!(KEYRING_TIMEOUT <= Duration::from_secs(5));
        }
    }

    #[test]
    fn file_source_creates_a_0600_key_file_and_reloads_it() {
        let dir = tempfile::tempdir().unwrap();
        let a = load_or_create(dir.path(), KeySource::File, None, &Unreachable).unwrap();
        assert_eq!(a.source, "file");
        let path = dir.path().join(KEY_FILE);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 64);
        let b = load_or_create(dir.path(), KeySource::File, Some("file"), &Unreachable).unwrap();
        assert_eq!(&*a.keys.enc, &*b.keys.enc);
        assert_eq!(&*a.keys.index, &*b.keys.index);
        assert_ne!(&*a.keys.enc, &*a.keys.index);
    }

    /// Review Focus 3.
    #[test]
    fn key_file_with_loose_permissions_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        load_or_create(dir.path(), KeySource::File, None, &Unreachable).unwrap();
        let path = dir.path().join(KEY_FILE);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let e =
            load_or_create(dir.path(), KeySource::File, Some("file"), &Unreachable).unwrap_err();
        assert!(
            matches!(
                e,
                VaultError::KeyFile {
                    reason: "permissions are not 0600",
                    ..
                }
            ),
            "{e}"
        );
    }

    #[test]
    fn key_file_of_wrong_length_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(KEY_FILE);
        std::fs::write(&path, [7u8; 10]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let e = load_or_create(dir.path(), KeySource::File, None, &Unreachable).unwrap_err();
        assert!(
            matches!(
                e,
                VaultError::KeyFile {
                    reason: "wrong length",
                    ..
                }
            ),
            "{e}"
        );
    }

    #[test]
    fn auto_prefers_the_secret_store_and_falls_back_to_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let mem = MemStore(Mutex::new(None));
        let a = load_or_create(dir.path(), KeySource::Auto, None, &mem).unwrap();
        assert_eq!(a.source, "keyring");
        assert!(mem.0.lock().unwrap().is_some(), "keys were stored");
        assert!(!dir.path().join(KEY_FILE).exists());
        let b = load_or_create(dir.path(), KeySource::Auto, Some("keyring"), &mem).unwrap();
        assert_eq!(&*a.keys.enc, &*b.keys.enc);

        let dir2 = tempfile::tempdir().unwrap();
        let c = load_or_create(dir2.path(), KeySource::Auto, None, &Unreachable).unwrap();
        assert_eq!(c.source, "file");
        assert!(dir2.path().join(KEY_FILE).exists());
    }

    #[test]
    fn auto_follows_the_stored_source() {
        let dir = tempfile::tempdir().unwrap();
        let mem = MemStore(Mutex::new(None));
        load_or_create(dir.path(), KeySource::File, None, &mem).unwrap();
        // stored = file, store reachable: auto must still use the file
        let r = load_or_create(dir.path(), KeySource::Auto, Some("file"), &mem).unwrap();
        assert_eq!(r.source, "file");
        assert!(mem.0.lock().unwrap().is_none());
    }

    #[test]
    fn explicit_source_change_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mem = MemStore(Mutex::new(None));
        load_or_create(dir.path(), KeySource::File, None, &mem).unwrap();
        let e = load_or_create(dir.path(), KeySource::Keyring, Some("file"), &mem).unwrap_err();
        assert!(
            matches!(&e, VaultError::KeySourceChanged { stored, requested } if stored == "file" && requested == "keyring"),
            "{e}"
        );
        let e = load_or_create(dir.path(), KeySource::File, Some("keyring"), &mem).unwrap_err();
        assert!(matches!(e, VaultError::KeySourceChanged { .. }));
    }

    #[test]
    fn keyring_requested_but_unreachable_is_an_error_not_a_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let e = load_or_create(dir.path(), KeySource::Keyring, None, &Unreachable).unwrap_err();
        assert!(matches!(e, VaultError::KeyStore(_)), "{e}");
        assert!(!dir.path().join(KEY_FILE).exists());
    }

    #[test]
    fn key_source_parses() {
        assert!(matches!(KeySource::parse("auto"), Some(KeySource::Auto)));
        assert!(matches!(
            KeySource::parse("keyring"),
            Some(KeySource::Keyring)
        ));
        assert!(matches!(KeySource::parse("file"), Some(KeySource::File)));
        assert!(KeySource::parse("vault").is_none());
    }

    #[test]
    fn keys_debug_prints_no_bytes() {
        let k = Keys::generate().unwrap();
        let d = format!("{k:?}");
        assert_eq!(d, "Keys(64 bytes)");
    }
}
