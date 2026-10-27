//! The Protect switch's pure parts (spec §4.5): dataset ids, the credential
//! split, definition identity, and data-source entry names. The caller
//! (app or CLI) makes the control-API calls.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::model::{McpServerEntry, Transport};

/// `mcp-` + the name lowercased, `[a-z0-9-]` only, runs of `-` collapsed,
/// trimmed to 64, `-2`, `-3`, … on a conflict with `taken`.
pub fn dataset_id_for(server: &str, taken: &BTreeSet<String>) -> String {
    let mut s = String::from("mcp-");
    for c in server.to_lowercase().chars() {
        let c = if c.is_ascii_lowercase() || c.is_ascii_digit() {
            c
        } else {
            '-'
        };
        if !(c == '-' && s.ends_with('-')) {
            s.push(c);
        }
    }
    let base: String = s
        .trim_end_matches('-')
        .chars()
        .take(64)
        .collect::<String>()
        .trim_end_matches('-')
        .to_string();
    if !taken.contains(&base) {
        return base;
    }
    (2..)
        .map(|n| {
            let suffix = format!("-{n}");
            let keep = 64 - suffix.len();
            format!(
                "{}{suffix}",
                base.chars()
                    .take(keep)
                    .collect::<String>()
                    .trim_end_matches('-')
            )
        })
        .find(|c| !taken.contains(c))
        .expect("some suffix is free")
}

/// Whether a header or environment variable name reads like a credential
/// (M4 spec §9): such values go to the vault. The CLI's `upstream add`
/// uses this same rule.
pub fn credential_like(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    matches!(
        l.as_str(),
        "authorization" | "cookie" | "proxy-authorization"
    ) || [
        "token",
        "secret",
        "key",
        "password",
        "passwd",
        "credential",
        "auth",
        "api",
    ]
    .iter()
    .any(|w| l.contains(w))
}

/// An upstream to create for a protected entry.
pub struct UpstreamParts {
    /// `stdio` or `http`.
    pub kind: &'static str,
    /// Absolute program.
    pub command: Option<String>,
    /// Arguments.
    pub args: Vec<String>,
    /// Working directory.
    pub cwd: Option<String>,
    /// URL.
    pub url: Option<String>,
    /// Non-secret environment, including the login shell's `PATH`.
    pub env: BTreeMap<String, String>,
    /// Non-secret headers.
    pub headers: BTreeMap<String, String>,
    /// Secret environment.
    pub secret_env: BTreeMap<String, Zeroizing<String>>,
    /// Secret headers.
    pub secret_headers: BTreeMap<String, Zeroizing<String>>,
}

impl std::fmt::Debug for UpstreamParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamParts")
            .field("kind", &self.kind)
            .field("env", &self.env.len())
            .field("secret_env", &self.secret_env.len())
            .field("headers", &self.headers.len())
            .field("secret_headers", &self.secret_headers.len())
            .finish_non_exhaustive()
    }
}

/// The first executable `command` in `path` (a `PATH` string), or `command` if absolute.
pub fn resolve_command(command: &str, path: &str) -> Option<PathBuf> {
    let c = Path::new(command);
    if c.is_absolute() {
        return crate::detect::is_executable(c).then(|| c.to_path_buf());
    }
    path.split(':')
        .map(|d| Path::new(d).join(command))
        .find(|p| crate::detect::is_executable(p))
}

/// Split an entry into an upstream (spec §4.5 steps 1–2). `login_path` is
/// the login shell's `PATH`: the command is resolved with it and it is
/// recorded in the non-secret env, because the service starts with a
/// minimal environment and plan 2c clears the child's.
///
/// A credential-like name never lands in a non-secret field, whichever
/// table it came from.
pub fn split(e: &McpServerEntry, login_path: Option<&str>) -> UpstreamParts {
    let mut parts = UpstreamParts {
        kind: "stdio",
        command: None,
        args: Vec::new(),
        cwd: None,
        url: None,
        env: BTreeMap::new(),
        headers: BTreeMap::new(),
        secret_env: BTreeMap::new(),
        secret_headers: BTreeMap::new(),
    };
    match &e.transport {
        Transport::Stdio { command, args, cwd } => {
            let resolved = login_path
                .and_then(|p| resolve_command(command, p))
                .map(|p| p.to_string_lossy().into_owned());
            parts.command = Some(resolved.unwrap_or_else(|| command.clone()));
            parts.args = args.clone();
            parts.cwd = cwd.clone();
            if let Some(p) = login_path {
                parts.env.insert("PATH".to_string(), p.to_string());
            }
        }
        Transport::Http { url } => {
            parts.kind = "http";
            parts.url = Some(url.clone());
        }
    }
    for (k, v) in &e.values {
        let (table, name) = k.split_once(':').unwrap_or(("env", k));
        let secret = credential_like(name);
        match (table, secret) {
            ("env", true) => {
                parts.secret_env.insert(name.to_string(), v.clone());
            }
            ("env", false) => {
                parts.env.insert(name.to_string(), v.to_string());
            }
            (_, true) => {
                parts.secret_headers.insert(name.to_string(), v.clone());
            }
            (_, false) => {
                parts.headers.insert(name.to_string(), v.to_string());
            }
        }
    }
    parts
}

/// Identity of a definition (spec §4.5 step 3): command, args, cwd, URL,
/// env and header names, and the secret values, so two accounts of one
/// server never share a dataset. Keyed with a per-install key (review
/// minor item): an unsalted hash of a secret stored on disk could be
/// confirmed against a guessed value.
pub fn definition_id(e: &McpServerEntry, key: &[u8]) -> String {
    let mut h = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    let mut put = |s: &str| {
        h.update(&(s.len() as u64).to_be_bytes());
        h.update(s.as_bytes());
    };
    match &e.transport {
        Transport::Stdio { command, args, cwd } => {
            put("stdio");
            put(command);
            for a in args {
                put(a);
            }
            put(cwd.as_deref().unwrap_or(""));
        }
        Transport::Http { url } => {
            put("http");
            put(url);
        }
    }
    let mut names: Vec<&String> = e.env_names.iter().chain(e.header_names.iter()).collect();
    names.sort();
    for n in names {
        put(n);
    }
    for (k, v) in &e.values {
        put(k);
        put(v);
    }
    format!(
        "hmac:{}",
        h.finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

/// `<data_dir>/adapters/definitions.json` (0600): definition id → dataset
/// id, with its key in `<data_dir>/adapters/definition.key` (32 random
/// bytes, 0600, created on first use).
pub struct DefinitionIndex {
    path: PathBuf,
    key: Zeroizing<Vec<u8>>,
    map: BTreeMap<String, String>,
}

impl std::fmt::Debug for DefinitionIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DefinitionIndex")
            .field("entries", &self.map.len())
            .finish_non_exhaustive()
    }
}

/// Write `bytes` to `path` as a 0600 file (temp, fsync, rename), creating a
/// 0700 parent directory when missing.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(d) = path.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(d)?;
    }
    crate::backup::write_private(path, bytes).map_err(|_| std::io::Error::other("write failed"))
}

impl DefinitionIndex {
    /// Load the index (empty when missing) and its key (created when missing).
    ///
    /// Only a missing file is replaced. A key of the wrong length, an
    /// unreadable file, or an unparsable `definitions.json` is an error:
    /// silently starting over would map every known definition to a new
    /// dataset and overwrite the old index on the next save. The
    /// `adapters/` directory is created 0700 and an existing one is tightened.
    pub fn load(data_dir: &Path) -> std::io::Result<Self> {
        use std::io::ErrorKind::{InvalidData, NotFound};
        use std::os::unix::fs::PermissionsExt;
        let dir = data_dir.join("adapters");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        let key_path = dir.join("definition.key");
        let key = match std::fs::read(&key_path) {
            Ok(k) if k.len() == 32 => Zeroizing::new(k),
            Ok(_) => {
                return Err(std::io::Error::new(
                    InvalidData,
                    "adapters/definition.key is corrupt; delete it (and adapters/definitions.json) by hand",
                ));
            }
            Err(e) if e.kind() == NotFound => {
                let mut k = vec![0u8; 32];
                getrandom::fill(&mut k).map_err(|_| std::io::Error::other("no randomness"))?;
                write_private(&key_path, &k)?;
                Zeroizing::new(k)
            }
            Err(e) => return Err(e),
        };
        let path = dir.join("definitions.json");
        let map = match std::fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b).map_err(|_| {
                std::io::Error::new(
                    InvalidData,
                    "adapters/definitions.json is corrupt; delete it by hand",
                )
            })?,
            Err(e) if e.kind() == NotFound => BTreeMap::new(),
            Err(e) => return Err(e),
        };
        Ok(DefinitionIndex { path, key, map })
    }

    /// The keyed identity of `e` ([`definition_id`]).
    pub fn id_for(&self, e: &McpServerEntry) -> String {
        definition_id(e, &self.key)
    }

    /// The dataset of a definition.
    pub fn get(&self, def: &str) -> Option<&str> {
        self.map.get(def).map(String::as_str)
    }

    /// Record a definition's dataset.
    pub fn insert(&mut self, def: String, dataset: String) {
        self.map.insert(def, dataset);
    }

    /// Write (0600).
    pub fn save(&self) -> std::io::Result<()> {
        write_private(
            &self.path,
            &serde_json::to_vec_pretty(&self.map).unwrap_or_default(),
        )
    }
}

/// `inumaki-mail`, `inumaki-mail-2`, … (spec §4.5): the `index`-th mailbox
/// entry (0-based), skipping names the harness already uses for other entries.
pub fn mail_entry_name(index: usize, taken: &BTreeSet<String>) -> String {
    let name = |n: usize| {
        if n == 1 {
            "inumaki-mail".to_string()
        } else {
            format!("inumaki-mail-{n}")
        }
    };
    (1..)
        .map(name)
        .filter(|c| !taken.contains(c))
        .nth(index)
        .expect("some name is free")
}

/// An upstream name for a server name: `[a-z0-9_-]`, at most 64 characters.
pub fn upstream_name(server: &str) -> String {
    let s: String = server
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .take(64)
        .collect();
    if s.is_empty() {
        "server".to_string()
    } else {
        s
    }
}
