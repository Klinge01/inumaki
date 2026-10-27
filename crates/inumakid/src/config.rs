//! The daemon's tables (`[daemon]`, `[vault]`, `[gateway]`, `[journal]`,
//! `[mail]`, `[proxy]`, `[mirror]`) on top of the engine configuration
//! (spec §10.1), all in one file: `--config`, else `<data_dir>/inumaki.toml`
//! when it exists, else the embedded `configs/default.toml`. Unknown keys and
//! tables are refused; errors name the file, table, key, and line, never a
//! value.

use std::path::{Path, PathBuf};
use std::time::Duration;

use inumaki_core::config::CoreConfig;
use inumaki_core::{Error, TokenSettings};
use inumaki_vault::KeySource;
use serde::Deserialize;

/// Default sanitization cache size: 64 MiB.
pub const DEFAULT_CACHE_BYTES: u64 = 67_108_864;

/// `[daemon]` table.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DaemonSection {
    /// Socket path; relative to the data directory.
    pub socket: PathBuf,
    /// Sanitization cache capacity in bytes of sanitized text.
    pub cache_bytes: u64,
    /// Session context TTL, e.g. `15m`.
    pub session_ttl: String,
    /// Maximum live session contexts.
    pub session_cap: usize,
    /// Profile for requests that name none (and no dataset).
    pub default_profile: String,
    /// Session token suffix length; defaults to `[tokens] suffix_len`.
    pub session_suffix_len: Option<usize>,
}

impl Default for DaemonSection {
    fn default() -> Self {
        DaemonSection {
            socket: PathBuf::from("inumakid.sock"),
            cache_bytes: DEFAULT_CACHE_BYTES,
            session_ttl: "15m".into(),
            session_cap: 10_000,
            default_profile: "support-email".into(),
            session_suffix_len: None,
        }
    }
}

/// `[vault]` table.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VaultSection {
    /// SQLite file; relative to the data directory.
    pub path: PathBuf,
    /// `auto`, `keyring`, or `file`.
    pub key_source: String,
    /// Cap on known-entity automaton entries per namespace.
    pub automaton_max_entries: usize,
    /// Namespace token suffix length.
    pub suffix_len: usize,
}

impl Default for VaultSection {
    fn default() -> Self {
        VaultSection {
            path: PathBuf::from("vault.sqlite"),
            key_source: "auto".into(),
            automaton_max_entries: 200_000,
            suffix_len: 6,
        }
    }
}

/// `[gateway]` table (M4 spec §10).
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GatewaySection {
    /// TCP listen address; loopback only.
    pub listen: String,
    /// Cap on the upstream restart backoff, e.g. `30s`.
    pub upstream_restart_max_backoff: String,
    /// Time an upstream gets to answer one call, e.g. `60s`.
    pub upstream_call_timeout: String,
    /// Largest upstream result accepted for sanitization, e.g. `4MiB`.
    pub max_response_bytes: String,
    /// In-flight inference slots per dataset.
    pub max_inflight: usize,
    /// How long a request waits for a slot, e.g. `30s`.
    pub queue_timeout: String,
    /// Obsolete bypass; any value is a configuration error (metadata
    /// sanitization is mandatory, M4 spec §10).
    pub sanitize_descriptions: Option<bool>,
    /// Days an activity record is kept (M4 spec §16.4).
    pub activity_retention_days: u32,
    /// `notify` or `block` (M4 spec §16.1).
    pub tripwire: String,
    /// Browser origins allowed to reach the gateway; empty rejects every
    /// request that carries `Origin` (M4 spec §16.8).
    pub allowed_origins: Vec<String>,
}

impl Default for GatewaySection {
    fn default() -> Self {
        GatewaySection {
            listen: "127.0.0.1:8789".into(),
            upstream_restart_max_backoff: "30s".into(),
            upstream_call_timeout: "60s".into(),
            max_response_bytes: "4MiB".into(),
            max_inflight: 8,
            queue_timeout: "30s".into(),
            sanitize_descriptions: None,
            activity_retention_days: 30,
            tripwire: "notify".into(),
            allowed_origins: Vec::new(),
        }
    }
}

/// `http://host[:port]` or `https://host[:port]`, no path, no wildcard.
/// Also refuses forms that a browser's serialized `Origin` header can never
/// equal byte-for-byte (review round 1 #7): an uppercase scheme or host
/// (browsers always lower-case both), an explicit default port (`:80` for
/// `http`, `:443` for `https`; browsers omit it), an empty host
/// (`http://:`), and an ambiguous unbracketed multi-colon host
/// (`http://a:b:c`). Accepting one of these would silently never match any
/// real request, leaving an operator's intended allow-list entry dead.
pub(crate) fn valid_origin(o: &str) -> bool {
    let (scheme, rest) = if let Some(r) = o.strip_prefix("http://") {
        ("http", r)
    } else if let Some(r) = o.strip_prefix("https://") {
        ("https", r)
    } else {
        return false;
    };
    if rest.is_empty() || rest.contains('/') || rest.contains('*') {
        return false;
    }
    if !rest
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
    {
        return false;
    }
    if rest.chars().any(|c| c.is_ascii_uppercase()) {
        return false;
    }
    let (host, port) = if let Some(after_bracket) = rest.strip_prefix('[') {
        let Some(close) = after_bracket.find(']') else {
            return false;
        };
        let host = &rest[..close + 2];
        let after = &after_bracket[close + 1..];
        if after.is_empty() {
            (host, None)
        } else {
            let Some(p) = after.strip_prefix(':') else {
                return false;
            };
            (host, Some(p))
        }
    } else {
        match rest.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (rest, None),
        }
    };
    if host.is_empty() {
        return false;
    }
    match port {
        None => true,
        Some(p) => {
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                return false;
            }
            let default_port = matches!((scheme, p), ("http", "80") | ("https", "443"));
            !default_port
        }
    }
}

/// `1048576`, `512KiB`, `4MiB`, `1GiB`, or decimal `10KB`, `64MB`, `2GB`.
pub fn parse_bytes(s: &str) -> Option<usize> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: usize = num.parse().ok()?;
    let mult = match unit.trim() {
        "" | "B" => 1,
        "KiB" => 1024,
        "MiB" => 1024 * 1024,
        "GiB" => 1024 * 1024 * 1024,
        "KB" => 1_000,
        "MB" => 1_000_000,
        "GB" => 1_000_000_000,
        _ => return None,
    };
    n.checked_mul(mult)
}

/// The daemon's own tables. The engine's tables share the file and are read
/// by [`CoreConfig`]; [`parse_tables`] reads each daemon table on its own,
/// so an error names its table, and refuses any top-level key that neither
/// side knows.
#[derive(Default)]
struct FileTables {
    daemon: DaemonSection,
    vault: VaultSection,
    gateway: GatewaySection,
    journal: crate::journal::JournalSection,
    mail: crate::mail::MailSection,
    proxy: crate::proxy_config::ProxySection,
    mirror: crate::mirror_config::MirrorSection,
}

/// File name of the configuration `inumakid` and the CLI read from the data
/// directory when no `--config` is given.
pub const DEFAULT_CONFIG_FILE: &str = "inumaki.toml";

/// Where the active configuration came from (`GET /v1/status`
/// `config_source`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSource {
    /// The shipped `configs/default.toml`, compiled in.
    Embedded,
    /// A file: `--config`, or `<data_dir>/inumaki.toml`.
    File(PathBuf),
}

impl ConfigSource {
    /// `embedded`, or the file's absolute path. A path, never content.
    pub fn label(&self) -> String {
        match self {
            ConfigSource::Embedded => "embedded".into(),
            ConfigSource::File(p) => std::path::absolute(p)
                .unwrap_or_else(|_| p.clone())
                .display()
                .to_string(),
        }
    }
}

/// The configuration file to load: `--config` when given, else
/// `<data_dir>/inumaki.toml` when anything exists at that path, else `None`
/// (the embedded default). Fails closed: only a definite "not found" falls
/// back to the embedded default. A path that cannot be inspected
/// (permissions) is an error, and so is one that exists but cannot be read
/// (a dangling symlink, a directory), when it is loaded.
pub fn config_path(cli: Option<&Path>, data_dir: &Path) -> Result<Option<PathBuf>, Error> {
    if let Some(p) = cli {
        return Ok(Some(p.to_path_buf()));
    }
    let p = data_dir.join(DEFAULT_CONFIG_FILE);
    match std::fs::symlink_metadata(&p) {
        Ok(_) => Ok(Some(p)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(Error::ConfigInvalid(format!(
            "config file {}: cannot inspect",
            p.display()
        ))),
    }
}

/// Engine configuration plus the daemon's own tables, validated.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// Engine configuration (profiles, detectors, models).
    pub core: CoreConfig,
    /// `[daemon]`.
    pub daemon: DaemonSection,
    /// `[vault]`.
    pub vault: VaultSection,
    /// `[gateway]`.
    pub gateway: GatewaySection,
    /// Parsed `daemon.session_ttl`.
    pub session_ttl: Duration,
    /// Resolved session suffix length.
    pub session_suffix_len: usize,
    /// Parsed `vault.key_source`.
    pub key_source: KeySource,
    /// Parsed `gateway.upstream_restart_max_backoff`.
    pub gateway_restart_max_backoff: Duration,
    /// Parsed `gateway.upstream_call_timeout`.
    pub gateway_call_timeout: Duration,
    /// Parsed `gateway.max_response_bytes`.
    pub gateway_max_response_bytes: usize,
    /// Parsed `gateway.queue_timeout`.
    pub gateway_queue_timeout: Duration,
    /// `[journal]`.
    pub journal: crate::journal::JournalSection,
    /// Parsed `journal.retention`.
    pub journal_retention: Duration,
    /// Parsed `journal.max_bytes`.
    pub journal_max_bytes: u64,
    /// `[mail]`.
    pub mail: crate::mail::MailSection,
    /// Validated `[mail]` ([`DaemonConfig::mail_config`]).
    pub mail_parsed: inumaki_mail::MailConfig,
    /// Validated `[proxy]` (M8 spec §10).
    pub proxy: inumaki_proxy::ProxyConfig,
    /// `[proxy] definitions_account_values` (read by the proxy host).
    pub proxy_account_values: crate::proxy_config::AccountValues,
    /// `[mirror]`.
    pub mirror: crate::mirror_config::MirrorSection,
    /// Validated `[mirror]`.
    pub mirror_cfg: inumaki_mirror::MirrorConfig,
    /// [`canonical_fingerprint`] of the parsed configuration, every
    /// dictionary file's bytes, and [`BUILD_REVISION`]. Part of every cache
    /// key (M4 spec §5.3: a changed configuration invalidates cached
    /// verdicts) and of the folder mirror's policy fingerprint.
    pub fingerprint: [u8; 32],
}

/// Generation of the code that produces sanitized output. Bump on every
/// change that can change sanitized output (detection, policy, verifier,
/// tokenization, mirror rendering): it is part of
/// [`DaemonConfig::fingerprint`], so the bump re-mirrors every folder once.
/// Without it, a development build or a build without `INUMAKI_BUILD_REV`
/// keeps mirror files sanitized by the old code on disk.
pub const SANITIZER_GENERATION: u32 = 5;

/// Which code a fingerprint was computed by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Revision<'a> {
    /// The crate version.
    pub version: &'a str,
    /// [`SANITIZER_GENERATION`].
    pub generation: u32,
    /// `INUMAKI_BUILD_REV` at build time (the packaging scripts set the
    /// git revision), when set.
    pub build: Option<&'a str>,
}

/// The revision of this binary, part of [`DaemonConfig::fingerprint`].
pub const BUILD_REVISION: Revision<'static> = Revision {
    version: env!("CARGO_PKG_VERSION"),
    generation: SANITIZER_GENERATION,
    build: option_env!("INUMAKI_BUILD_REV"),
};

/// SHA-256 over a canonical encoding of the parsed configuration `config`,
/// the dictionary files' bytes, and the code revision `rev` (every field).
///
/// The encoding is type-tagged and length-prefixed, with table keys sorted
/// by their bytes and arrays kept in order, so the hash follows the values
/// and nothing else: a comment, blank lines, key order inside a table, the
/// position of a table in the file, and the spelling of a value (`'a'` or
/// `"a"`, `0.5` or `0.50`, dotted keys or a table header) do not change it;
/// every changed, added, removed, or renamed value does, including values
/// that affect no output (over-invalidation is safe, under-invalidation
/// would leave stale sanitized output). A file that states a default
/// explicitly hashes differently from one that omits it.
///
/// `dictionaries` holds, per category in a fixed order, each file's bytes
/// in configuration order. Every file is hashed as (category, index,
/// length, bytes), so a line moved to another file or category changes the
/// hash.
pub fn canonical_fingerprint(
    config: &toml::Value,
    dictionaries: &[(&str, Vec<Vec<u8>>)],
    rev: &Revision<'_>,
) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    fn len(h: &mut Sha256, n: usize) {
        h.update((n as u64).to_le_bytes());
    }
    fn bytes(h: &mut Sha256, b: &[u8]) {
        len(h, b.len());
        h.update(b);
    }
    fn value(h: &mut Sha256, v: &toml::Value) {
        use toml::Value as V;
        match v {
            V::String(s) => {
                h.update(b"s");
                bytes(h, s.as_bytes());
            }
            V::Integer(i) => {
                h.update(b"i");
                h.update(i.to_le_bytes());
            }
            // Exact bits: 0.5 and 0.50 are one value, 0.5 and 0.5000001 are not.
            V::Float(f) => {
                h.update(b"f");
                h.update(f.to_bits().to_le_bytes());
            }
            V::Boolean(b) => h.update([b'b', u8::from(*b)]),
            V::Datetime(d) => {
                h.update(b"d");
                bytes(h, d.to_string().as_bytes());
            }
            V::Array(a) => {
                h.update(b"a");
                len(h, a.len());
                for x in a {
                    value(h, x);
                }
            }
            V::Table(t) => {
                h.update(b"t");
                len(h, t.len());
                let mut entries: Vec<_> = t.iter().collect();
                entries.sort_unstable_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
                for (k, x) in entries {
                    bytes(h, k.as_bytes());
                    value(h, x);
                }
            }
        }
    }

    let mut h = Sha256::new();
    bytes(&mut h, b"inumaki config fingerprint v2");
    bytes(&mut h, rev.version.as_bytes());
    h.update(rev.generation.to_le_bytes());
    match rev.build {
        None => h.update([0]),
        Some(b) => {
            h.update([1]);
            bytes(&mut h, b.as_bytes());
        }
    }
    value(&mut h, config);
    len(&mut h, dictionaries.len());
    for (category, files) in dictionaries {
        bytes(&mut h, category.as_bytes());
        len(&mut h, files.len());
        for (index, file) in files.iter().enumerate() {
            len(&mut h, index);
            bytes(&mut h, file);
        }
    }
    h.finalize().into()
}

/// `15m`, `2h`, `1d`, `45s`, or plain seconds.
pub fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: u64 = num.parse().ok()?;
    let mult = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return None,
    };
    Some(Duration::from_secs(n.checked_mul(mult)?))
}

/// 1-based line of a byte offset (never any text).
fn line_of(text: &str, offset: usize) -> usize {
    text[..offset.min(text.len())].matches('\n').count() + 1
}

/// The field names `T` declares to serde as a struct; nothing is parsed.
/// Used to learn the engine's table names from [`CoreConfig`] itself, so a
/// table the engine adds is never refused here.
fn struct_fields<T: serde::de::DeserializeOwned>() -> &'static [&'static str] {
    use serde::de::{self, Visitor};

    struct Probe<'a>(&'a mut &'static [&'static str]);

    impl<'de> de::Deserializer<'de> for Probe<'_> {
        type Error = de::value::Error;

        fn deserialize_any<V: Visitor<'de>>(self, _: V) -> Result<V::Value, Self::Error> {
            Err(de::Error::custom("probe"))
        }

        fn deserialize_struct<V: Visitor<'de>>(
            self,
            _: &'static str,
            fields: &'static [&'static str],
            _: V,
        ) -> Result<V::Value, Self::Error> {
            *self.0 = fields;
            Err(de::Error::custom("probe"))
        }

        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
            bytes byte_buf option unit unit_struct newtype_struct seq tuple
            tuple_struct map enum identifier ignored_any
        }
    }

    let mut fields: &'static [&'static str] = &[];
    let _ = T::deserialize(Probe(&mut fields));
    fields
}

fn bare_key_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

/// `key` when it is a plain bare key spelled exactly so at byte `at` of
/// `text`, safe to print. A quoted key can hold any text (a backtick
/// included, which would cut serde's message short), so a key whose source
/// does not start with exactly that bare key is not printed.
fn printable_key<'k>(key: &'k str, text: &str, at: usize) -> Option<&'k str> {
    let plain = !key.is_empty() && key.len() <= 64 && key.bytes().all(bare_key_byte);
    let spelled = text.get(at..).is_some_and(|src| {
        src.starts_with(key) && !src[key.len()..].bytes().next().is_some_and(bare_key_byte)
    });
    (plain && spelled).then_some(key)
}

/// `Some(key)` for serde's "unknown field" message (`Some(None)` when the
/// key is not printable), `None` for every other message.
fn unknown_key<'m>(message: &'m str, text: &str, at: Option<usize>) -> Option<Option<&'m str>> {
    let rest = message.strip_prefix("unknown field `")?;
    Some(
        rest.split_once('`')
            .zip(at)
            .and_then(|((k, _), at)| printable_key(k, text, at)),
    )
}

/// One table's error: its name, what kind of error, and the line. Never the
/// line's text and never the parser's message, which can quote a value.
fn table_error(table: &str, text: &str, e: &toml::de::Error) -> Error {
    let start = e.span().map(|s| s.start);
    let at = start
        .map(|s| format!(" at line {}", line_of(text, s)))
        .unwrap_or_default();
    Error::ConfigInvalid(match unknown_key(e.message(), text, start) {
        Some(Some(key)) => format!("{table} table: unknown key `{key}`{at}"),
        Some(None) => format!("{table} table: unknown key{at}"),
        None => format!("{table} table: invalid value{at}"),
    })
}

/// One daemon table, deserialized on its own.
fn section<T: serde::de::DeserializeOwned>(
    table: &str,
    value: toml::Spanned<toml::de::DeValue<'_>>,
    text: &str,
) -> Result<T, Error> {
    T::deserialize(toml::de::ValueDeserializer::from(value))
        .map_err(|e| table_error(table, text, &e))
}

fn parse_tables(text: &str) -> Result<FileTables, Error> {
    let doc = toml::de::DeTable::parse(text).map_err(|e| match e.span() {
        Some(span) => Error::ConfigInvalid(format!(
            "toml parse error at line {}",
            line_of(text, span.start)
        )),
        None => Error::ConfigInvalid("toml parse error".into()),
    })?;
    let engine = struct_fields::<CoreConfig>();
    let mut t = FileTables::default();
    for (key, value) in doc.into_inner() {
        let name: &str = key.get_ref();
        match name {
            "daemon" => t.daemon = section(name, value, text)?,
            "vault" => t.vault = section(name, value, text)?,
            "gateway" => t.gateway = section(name, value, text)?,
            "journal" => t.journal = section(name, value, text)?,
            "mail" => t.mail = section(name, value, text)?,
            "proxy" => t.proxy = section(name, value, text)?,
            "mirror" => t.mirror = section(name, value, text)?,
            n if engine.contains(&n) => {}
            n => {
                let at = line_of(text, key.span().start);
                return Err(Error::ConfigInvalid(
                    match printable_key(n, text, key.span().start) {
                        Some(k) => format!("unknown table `{k}` at line {at}"),
                        None => format!("unknown table at line {at}"),
                    },
                ));
            }
        }
    }
    Ok(t)
}

impl DaemonConfig {
    /// Parse and validate. Errors name key paths, never values.
    pub fn from_toml(text: &str) -> Result<Self, Error> {
        let core = CoreConfig::from_toml(text)?;
        let value = toml::from_str::<toml::Table>(text)
            .map_err(|_| Error::ConfigInvalid("toml parse error".into()))?;
        Self::assemble(core, parse_tables(text)?, value)
    }

    /// Read a file and lay it over the embedded default, so a partial file
    /// is enough ([`inumaki_core::config::overlay_on_default`]); dictionary
    /// and model paths resolve relative to it. The daemon's own tables are
    /// read from the file's text, so an error's line is the file's line;
    /// the fingerprint covers the merged result. Every error names the file
    /// (`config file <path>: …`), never its text.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let load = || {
            // One read: the engine, the daemon tables, and the fingerprint
            // all see the same text, even if the file is rewritten meanwhile.
            let text = std::fs::read_to_string(path)
                .map_err(|_| Error::ConfigInvalid("cannot read".into()))?;
            let merged = inumaki_core::config::overlay_on_default(&text)?;
            let core = CoreConfig::from_table_at(merged.clone(), path)?;
            Self::assemble(core, parse_tables(&text)?, merged)
        };
        load().map_err(|e| match e {
            Error::ConfigInvalid(m) => {
                Error::ConfigInvalid(format!("config file {}: {m}", path.display()))
            }
            other => other,
        })
    }

    /// The startup configuration: `--config` when given, else
    /// `<data_dir>/inumaki.toml` when it exists, else the embedded default
    /// (see [`config_path`]). A file that is present but unreadable or
    /// invalid is an error; there is no silent fallback.
    pub fn resolve(cli: Option<&Path>, data_dir: &Path) -> Result<(Self, ConfigSource), Error> {
        match config_path(cli, data_dir)? {
            Some(p) => Ok((Self::load(&p)?, ConfigSource::File(p))),
            None => Ok((Self::embedded(), ConfigSource::Embedded)),
        }
    }

    /// The shipped `configs/default.toml`.
    pub fn embedded() -> Self {
        Self::from_toml(include_str!("../../../configs/default.toml"))
            .expect("embedded config is valid")
    }

    fn assemble(core: CoreConfig, t: FileTables, value: toml::Table) -> Result<Self, Error> {
        let session_ttl = parse_duration(&t.daemon.session_ttl)
            .filter(|d| !d.is_zero())
            .ok_or_else(|| Error::ConfigInvalid("daemon.session_ttl".into()))?;
        if t.daemon.session_cap == 0 {
            return Err(Error::ConfigInvalid("daemon.session_cap".into()));
        }
        let session_suffix_len = t
            .daemon
            .session_suffix_len
            .unwrap_or(core.tokens.suffix_len);
        if !(4..=12).contains(&session_suffix_len) {
            return Err(Error::ConfigInvalid("daemon.session_suffix_len".into()));
        }
        if !(4..=12).contains(&t.vault.suffix_len) {
            return Err(Error::ConfigInvalid("vault.suffix_len".into()));
        }
        if session_suffix_len == t.vault.suffix_len {
            return Err(Error::ConfigInvalid("daemon.session_suffix_len".into()));
        }
        let key_source = KeySource::parse(&t.vault.key_source)
            .ok_or_else(|| Error::ConfigInvalid("vault.key_source".into()))?;
        if t.vault.automaton_max_entries == 0 {
            return Err(Error::ConfigInvalid("vault.automaton_max_entries".into()));
        }
        core.resolve_dataset_profile(&t.daemon.default_profile)
            .map_err(|_| Error::ConfigInvalid("daemon.default_profile".into()))?;
        if t.gateway.sanitize_descriptions.is_some() {
            return Err(Error::ConfigInvalid("gateway.sanitize_descriptions".into()));
        }
        let gateway_restart_max_backoff = parse_duration(&t.gateway.upstream_restart_max_backoff)
            .filter(|d| !d.is_zero())
            .ok_or_else(|| Error::ConfigInvalid("gateway.upstream_restart_max_backoff".into()))?;
        let gateway_call_timeout = parse_duration(&t.gateway.upstream_call_timeout)
            .filter(|d| !d.is_zero())
            .ok_or_else(|| Error::ConfigInvalid("gateway.upstream_call_timeout".into()))?;
        let gateway_queue_timeout = parse_duration(&t.gateway.queue_timeout)
            .filter(|d| !d.is_zero())
            .ok_or_else(|| Error::ConfigInvalid("gateway.queue_timeout".into()))?;
        let gateway_max_response_bytes = parse_bytes(&t.gateway.max_response_bytes)
            .filter(|b| *b >= 64 * 1024)
            .ok_or_else(|| Error::ConfigInvalid("gateway.max_response_bytes".into()))?;
        if t.gateway.max_inflight == 0 {
            return Err(Error::ConfigInvalid("gateway.max_inflight".into()));
        }
        if t.gateway.activity_retention_days == 0 {
            return Err(Error::ConfigInvalid(
                "gateway.activity_retention_days".into(),
            ));
        }
        if !t
            .gateway
            .listen
            .parse::<std::net::SocketAddr>()
            .is_ok_and(|a| a.ip().is_loopback())
        {
            return Err(Error::ConfigInvalid("gateway.listen".into()));
        }
        if !matches!(t.gateway.tripwire.as_str(), "notify" | "block") {
            return Err(Error::ConfigInvalid("gateway.tripwire".into()));
        }
        if !t.gateway.allowed_origins.iter().all(|o| valid_origin(o)) {
            return Err(Error::ConfigInvalid("gateway.allowed_origins".into()));
        }
        let (journal_retention, journal_max_bytes) = crate::journal::parse(&t.journal)?;
        let mail_parsed = crate::mail::parse(&t.mail)?;
        let mirror_cfg = crate::mirror_config::parse(&t.mirror)?;
        let fingerprint = {
            // The merged table: the file over the embedded default, or the
            // whole text when it was not layered.
            let mut dictionaries = Vec::with_capacity(3);
            for (category, paths) in [
                ("persons", &core.dictionary.persons),
                ("addresses", &core.dictionary.addresses),
                ("organizations", &core.dictionary.organizations),
            ] {
                let mut files = Vec::with_capacity(paths.len());
                for path in paths {
                    files.push(std::fs::read(path).map_err(|_| {
                        Error::ConfigInvalid(format!("dictionary file {}", path.display()))
                    })?);
                }
                dictionaries.push((category, files));
            }
            canonical_fingerprint(&toml::Value::Table(value), &dictionaries, &BUILD_REVISION)
        };
        let proxy_account_values = t.proxy.account_values()?;
        let proxy = t.proxy.parse(
            &t.daemon,
            &core,
            TokenSettings {
                suffix_len: session_suffix_len,
                open: core.tokens.open.clone(),
                close: core.tokens.close.clone(),
                surface_form: core.tokens.surface_form,
            },
            fingerprint,
        )?;
        Ok(DaemonConfig {
            core,
            daemon: t.daemon,
            vault: t.vault,
            gateway: t.gateway,
            session_ttl,
            session_suffix_len,
            key_source,
            gateway_restart_max_backoff,
            gateway_call_timeout,
            gateway_max_response_bytes,
            gateway_queue_timeout,
            journal: t.journal,
            journal_retention,
            journal_max_bytes,
            mail: t.mail,
            mail_parsed,
            proxy,
            proxy_account_values,
            mirror: t.mirror,
            mirror_cfg,
            fingerprint,
        })
    }

    /// The gateway crate's settings.
    pub fn gateway_config(&self) -> inumaki_gateway::GatewayConfig {
        inumaki_gateway::GatewayConfig {
            listen: self.gateway.listen.clone(),
            restart_max_backoff: self.gateway_restart_max_backoff,
            call_timeout: self.gateway_call_timeout,
            max_response_bytes: self.gateway_max_response_bytes,
            max_inflight: self.gateway.max_inflight,
            queue_timeout: self.gateway_queue_timeout,
            tripwire: if self.gateway.tripwire == "block" {
                inumaki_gateway::TripwireMode::Block
            } else {
                inumaki_gateway::TripwireMode::Notify
            },
            journal: self.journal.enabled,
        }
    }

    /// Token format for session contexts.
    pub fn session_tokens(&self) -> TokenSettings {
        TokenSettings {
            suffix_len: self.session_suffix_len,
            open: self.core.tokens.open.clone(),
            close: self.core.tokens.close.clone(),
            surface_form: self.core.tokens.surface_form,
        }
    }

    /// Token format for vault namespaces.
    pub fn vault_tokens(&self) -> TokenSettings {
        TokenSettings {
            suffix_len: self.vault.suffix_len,
            open: self.core.tokens.open.clone(),
            close: self.core.tokens.close.clone(),
            surface_form: self.core.tokens.surface_form,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = include_str!("../../../configs/default.toml");

    /// `BASE` plus `extra`. Never append a table `default.toml` already
    /// declares (`[tokens]`, `[dictionary]`, `[ner]`, `[profiles.*]`): a
    /// duplicate table is a TOML parse error, not an override. Edit `BASE`
    /// with `replace` and use `with_text` for those cases (review I1).
    fn with(extra: &str) -> Result<DaemonConfig, inumaki_core::Error> {
        with_text(&format!("{BASE}\n{extra}\n"))
    }

    fn with_text(text: &str) -> Result<DaemonConfig, inumaki_core::Error> {
        DaemonConfig::from_toml(text)
    }

    #[test]
    fn defaults_match_the_spec() {
        let c = with("").unwrap();
        assert_eq!(c.daemon.socket, PathBuf::from("inumakid.sock"));
        assert_eq!(c.daemon.cache_bytes, 67_108_864);
        assert_eq!(c.session_ttl, Duration::from_secs(15 * 60));
        assert_eq!(c.daemon.session_cap, 10_000);
        assert_eq!(c.daemon.default_profile, "support-email");
        assert_eq!(c.vault.path, PathBuf::from("vault.sqlite"));
        assert_eq!(c.key_source, KeySource::Auto);
        assert_eq!(c.vault.automaton_max_entries, 200_000);
        assert_eq!((c.session_suffix_len, c.vault.suffix_len), (4, 6));
        assert_eq!(c.session_tokens().suffix_len, 4);
        assert_eq!(c.vault_tokens().suffix_len, 6);
        assert_eq!(c.vault_tokens().open, "<");
    }

    #[test]
    fn tables_override_defaults() {
        let c = with("[daemon]\nsocket = \"/tmp/x.sock\"\ncache_bytes = 1024\nsession_ttl = \"90s\"\nsession_cap = 5\ndefault_profile = \"offline\"\nsession_suffix_len = 5\n[vault]\npath = \"/tmp/v.sqlite\"\nkey_source = \"file\"\nautomaton_max_entries = 10\nsuffix_len = 8\n").unwrap();
        assert_eq!(c.daemon.socket, PathBuf::from("/tmp/x.sock"));
        assert_eq!(c.daemon.cache_bytes, 1024);
        assert_eq!(c.session_ttl, Duration::from_secs(90));
        assert_eq!(c.daemon.session_cap, 5);
        assert_eq!(c.daemon.default_profile, "offline");
        assert_eq!(c.session_suffix_len, 5);
        assert_eq!(c.key_source, KeySource::File);
        assert_eq!(c.vault.automaton_max_entries, 10);
        assert_eq!(c.vault.suffix_len, 8);
    }

    #[test]
    fn equal_suffix_lengths_are_rejected() {
        for extra in [
            "[daemon]\nsession_suffix_len = 6\n",
            "[vault]\nsuffix_len = 4\n",
        ] {
            let e = with(extra).unwrap_err();
            assert!(
                format!("{e}").contains("daemon.session_suffix_len"),
                "{extra}: {e}"
            );
        }
        // `[tokens]` exists in BASE; edit it instead of appending a second table
        let text = BASE.replace("suffix_len = 4", "suffix_len = 6");
        assert_ne!(text, BASE);
        let e = with_text(&text).unwrap_err();
        assert!(format!("{e}").contains("daemon.session_suffix_len"), "{e}");
    }

    #[test]
    fn invalid_values_name_their_key() {
        for (extra, key) in [
            ("[daemon]\nsession_ttl = \"soon\"\n", "daemon.session_ttl"),
            ("[daemon]\nsession_ttl = \"0s\"\n", "daemon.session_ttl"),
            ("[daemon]\nsession_cap = 0\n", "daemon.session_cap"),
            (
                "[daemon]\ndefault_profile = \"nope\"\n",
                "daemon.default_profile",
            ),
            (
                "[daemon]\nsession_suffix_len = 3\n",
                "daemon.session_suffix_len",
            ),
            ("[vault]\nkey_source = \"keychain\"\n", "vault.key_source"),
            ("[vault]\nsuffix_len = 13\n", "vault.suffix_len"),
            (
                "[vault]\nautomaton_max_entries = 0\n",
                "vault.automaton_max_entries",
            ),
            ("[daemon]\ncache_bytes = \"big\"\n", "line"),
        ] {
            let e = with(extra).unwrap_err();
            assert!(format!("{e}").contains(key), "{extra}: {e}");
            assert!(!format!("{e}").contains("big"), "{e}");
        }
    }

    #[test]
    fn durations_parse() {
        assert_eq!(parse_duration("15m"), Some(Duration::from_secs(900)));
        assert_eq!(parse_duration("2h"), Some(Duration::from_secs(7200)));
        assert_eq!(parse_duration("1d"), Some(Duration::from_secs(86_400)));
        assert_eq!(parse_duration("45s"), Some(Duration::from_secs(45)));
        assert_eq!(parse_duration("30"), Some(Duration::from_secs(30)));
        assert_eq!(parse_duration(" 5m "), Some(Duration::from_secs(300)));
        assert_eq!(parse_duration("5 m"), None);
        assert_eq!(parse_duration("m"), None);
        assert_eq!(parse_duration("5x"), None);
        assert_eq!(parse_duration(""), None);
    }

    #[test]
    fn embedded_config_is_valid() {
        let c = DaemonConfig::embedded();
        assert_eq!(c.daemon.default_profile, "support-email");
    }

    #[test]
    fn load_resolves_relative_dictionary_paths_like_core() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("persons.txt"), "Sarah Leitner\n").unwrap();
        let p = dir.path().join("inumaki.toml");
        let text = BASE.replace("persons = []", "persons = [\"persons.txt\"]");
        assert_ne!(
            text, BASE,
            "the [dictionary] table exists in BASE; edit it, never append a second one"
        );
        std::fs::write(&p, text).unwrap();
        let c = DaemonConfig::load(&p).unwrap();
        assert_eq!(c.core.dictionary.persons[0], dir.path().join("persons.txt"));
        let e = DaemonConfig::load(&dir.path().join("missing.toml")).unwrap_err();
        assert!(format!("{e}").contains("missing.toml"));
    }

    /// End to end through `load`: dictionary contents and a value change
    /// the fingerprint, a comment does not.
    #[test]
    fn fingerprint_follows_values_and_dictionary_contents_not_comments() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("persons.txt");
        std::fs::write(&p, "Sarah Leitner\n").unwrap();
        let cfg_path = dir.path().join("inumaki.toml");
        let text = BASE.replace("persons = []", "persons = [\"persons.txt\"]");
        std::fs::write(&cfg_path, &text).unwrap();
        let fp = || DaemonConfig::load(&cfg_path).unwrap().fingerprint;
        let a = fp();
        assert_eq!(a, fp(), "stable");
        std::fs::write(&p, "Sarah Leitner\nMax Gruber\n").unwrap();
        let b = fp();
        assert_ne!(a, b, "dictionary content is part of the fingerprint");
        std::fs::write(&cfg_path, format!("{text}\n# comment\n")).unwrap();
        assert_eq!(b, fp(), "a comment is not");
        std::fs::write(&cfg_path, format!("{text}\n[daemon]\nsession_cap = 9\n")).unwrap();
        assert_ne!(b, fp(), "a value is");
        assert_ne!(DaemonConfig::embedded().fingerprint, [0u8; 32]);
    }

    /// Critical (B2): a file with only a `[mirror]` table loads over the
    /// embedded default. Its fingerprint is the embedded default's with that
    /// table added, no matter how the file spells it, and the shipped text
    /// loaded as a file fingerprints as the embedded default does.
    #[test]
    fn a_partial_file_loads_over_the_default_and_the_fingerprint_covers_the_merge() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(DEFAULT_CONFIG_FILE);
        let load = |text: &str| {
            std::fs::write(&p, text).unwrap();
            DaemonConfig::load(&p)
        };
        let partial = load("# only the mirror\n[mirror]\nworkers = 2\n").unwrap();
        assert_eq!(partial.daemon.default_profile, "support-email");
        assert_eq!(partial.mirror_cfg.workers, 2);
        let whole = load(&format!("{BASE}\n[mirror]\nworkers = 2\n")).unwrap();
        assert_eq!(partial.fingerprint, whole.fingerprint);
        assert_ne!(partial.fingerprint, DaemonConfig::embedded().fingerprint);
        let proxy = load("[proxy]\nlisten = \"127.0.0.1:8787\"\n").unwrap();
        assert_ne!(proxy.fingerprint, partial.fingerprint);
        assert_eq!(
            load(BASE).unwrap().fingerprint,
            DaemonConfig::embedded().fingerprint
        );
        assert_eq!(
            load("").unwrap().fingerprint,
            DaemonConfig::embedded().fingerprint,
            "an empty file is the shipped default"
        );
    }

    /// The daemon tables are read from the user's text only, so the shipped
    /// default must not define any: a partial file would silently lose it.
    #[test]
    fn the_shipped_default_defines_no_daemon_table() {
        let t: toml::Table = toml::from_str(BASE).unwrap();
        for k in [
            "daemon", "vault", "gateway", "journal", "mail", "proxy", "mirror",
        ] {
            assert!(!t.contains_key(k), "{k}");
        }
    }

    /// Critical (B2): an unknown table or key in a partial file is refused at
    /// the file's own line (not a line of the merged text), with no value.
    #[test]
    fn a_partial_file_refuses_unknown_keys_at_its_own_line() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(DEFAULT_CONFIG_FILE);
        for (text, want) in [
            (
                "# note\n\n[mirror]\nworkers = 2\nwrkers = \"qwxzvk\"\n",
                "mirror table: unknown key `wrkers` at line 5",
            ),
            (
                "# note\n[deamon]\nx = 1\n",
                "unknown table `deamon` at line 2",
            ),
            ("\n\n[tokens]\nsuffix_len = \"qwxzvk\"\n", "line 4"),
        ] {
            std::fs::write(&p, text).unwrap();
            let e = DaemonConfig::load(&p).unwrap_err().to_string();
            assert!(e.contains(want), "{text}: {e}");
            assert!(!e.contains("qwxzvk"), "{text}: {e}");
        }
    }

    /// `configs/default.toml` with its commented examples (`[proxy]`,
    /// `[proxy.upstreams.anthropic]`, `[mirror]`, `[dictionary] aliases`)
    /// uncommented, plus every other daemon table with every key set. It
    /// loads; the retired `gateway.sanitize_descriptions` and the
    /// `binary` alias `proxy.allow_binary`, which this file cannot hold
    /// together with what it has, are added to the parsed value by
    /// [`every_key`].
    fn full_fixture() -> String {
        let uncommented: String = BASE
            .lines()
            .map(|l| match l.strip_prefix("# ") {
                Some(r)
                    if r.starts_with('[')
                        || r.split_once(" = ").is_some_and(|(k, _)| {
                            !k.is_empty() && k.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
                        }) =>
                {
                    r
                }
                _ => l,
            })
            .fold(String::new(), |s, l| s + l + "\n");
        format!(
            "{uncommented}\n\
             [proxy.upstreams.openai]\n\
             base_url = \"https://api.openai.com\"\n\
             extra_headers = [\"x-request-tag\"]\n\
             [proxy.upstreams.openai-codex]\n\
             base_url = \"https://chatgpt.com\"\n\
             extra_headers = [\"x-request-tag\"]\n\
             [daemon]\n\
             socket = \"inumakid.sock\"\n\
             cache_bytes = 1024\n\
             session_ttl = \"15m\"\n\
             session_cap = 10\n\
             default_profile = \"support-email\"\n\
             session_suffix_len = 5\n\
             [vault]\n\
             path = \"vault.sqlite\"\n\
             key_source = \"auto\"\n\
             automaton_max_entries = 10\n\
             suffix_len = 6\n\
             [gateway]\n\
             listen = \"127.0.0.1:8789\"\n\
             upstream_restart_max_backoff = \"30s\"\n\
             upstream_call_timeout = \"60s\"\n\
             max_response_bytes = \"4MiB\"\n\
             max_inflight = 8\n\
             queue_timeout = \"30s\"\n\
             activity_retention_days = 30\n\
             tripwire = \"notify\"\n\
             allowed_origins = [\"http://localhost:3000\"]\n\
             [journal]\n\
             enabled = true\n\
             retention = \"24h\"\n\
             max_bytes = \"64MB\"\n\
             [mail]\n\
             keepalive = \"5m\"\n\
             command_timeout = \"30s\"\n\
             max_message_bytes = \"4MiB\"\n\
             snippet_chars = 200\n\
             handle_retention_days = 30\n\
             auth_retry_after = \"60s\"\n"
        )
    }

    /// The full fixture as a value, with the two keys it cannot hold
    /// (see [`full_fixture`]); asserts every field of every daemon table
    /// is present, so a field added later must be added here too.
    fn every_key() -> toml::Value {
        let mut t: toml::Table = toml::from_str(&full_fixture()).unwrap();
        let table = |t: &toml::Table, k: &str| -> toml::Table {
            t.get(k).and_then(|v| v.as_table()).cloned().unwrap()
        };
        let mut gateway = table(&t, "gateway");
        gateway.insert("sanitize_descriptions".into(), false.into());
        t.insert("gateway".into(), gateway.into());
        let mut proxy = table(&t, "proxy");
        proxy.insert("allow_binary".into(), false.into());
        t.insert("proxy".into(), proxy.clone().into());

        let upstreams = proxy["upstreams"].as_table().unwrap();
        let mut checks: Vec<(&toml::Table, &[&str], &str)> = Vec::new();
        let sections: Vec<(&str, &[&str])> = vec![
            ("daemon", struct_fields::<DaemonSection>()),
            ("vault", struct_fields::<VaultSection>()),
            ("gateway", struct_fields::<GatewaySection>()),
            ("journal", struct_fields::<crate::journal::JournalSection>()),
            ("mail", struct_fields::<crate::mail::MailSection>()),
            (
                "proxy",
                struct_fields::<crate::proxy_config::ProxySection>(),
            ),
            (
                "mirror",
                struct_fields::<crate::mirror_config::MirrorSection>(),
            ),
        ];
        for (name, fields) in &sections {
            checks.push((t[*name].as_table().unwrap(), fields, name));
        }
        let up = struct_fields::<crate::proxy_config::UpstreamSection>();
        for name in struct_fields::<crate::proxy_config::UpstreamsSection>() {
            checks.push((upstreams[*name].as_table().unwrap(), up, name));
        }
        for (table, fields, name) in checks {
            assert!(!fields.is_empty(), "{name}: no fields learned");
            for f in fields {
                assert!(table.contains_key(*f), "fixture lacks {name}.{f}");
            }
        }
        let dictionary = t["dictionary"].as_table().unwrap();
        assert!(dictionary.contains_key("aliases"), "aliases uncommented");
        toml::Value::Table(t)
    }

    /// Every single edit of `v`: each leaf changed (strings, integers by
    /// one, floats in their last bit, booleans flipped, an integer turned
    /// into the equal float), each array grown and its first two elements
    /// swapped, each key removed and renamed, and a key added to each table.
    fn edits(v: &toml::Value) -> Vec<(String, toml::Value)> {
        use toml::Value as V;
        let mut out = Vec::new();
        match v {
            V::String(s) => out.push(("string".into(), V::String(format!("{s}x")))),
            V::Integer(i) => {
                out.push(("integer".into(), V::Integer(i.wrapping_add(1))));
                out.push(("integer as float".into(), V::Float(*i as f64)));
            }
            V::Float(f) => out.push(("float".into(), V::Float(f64::from_bits(f.to_bits() ^ 1)))),
            V::Boolean(b) => out.push(("boolean".into(), V::Boolean(!b))),
            V::Datetime(_) => panic!("no datetime in the fixtures"),
            V::Array(a) => {
                for (i, x) in a.iter().enumerate() {
                    for (what, y) in edits(x) {
                        let mut b = a.clone();
                        b[i] = y;
                        out.push((format!("[{i}] {what}"), V::Array(b)));
                    }
                }
                let mut b = a.clone();
                b.push(
                    a.last()
                        .cloned()
                        .unwrap_or_else(|| V::String(String::new())),
                );
                out.push(("grown".into(), V::Array(b)));
                if a.len() >= 2 && a[0] != a[1] {
                    let mut b = a.clone();
                    b.swap(0, 1);
                    out.push(("reordered".into(), V::Array(b)));
                }
            }
            V::Table(t) => {
                for (k, x) in t {
                    for (what, y) in edits(x) {
                        let mut u = t.clone();
                        u.insert(k.clone(), y);
                        out.push((format!("{k}.{what}"), V::Table(u)));
                    }
                    let mut u = t.clone();
                    let x = u.remove(k).unwrap();
                    out.push((format!("{k} removed"), V::Table(u.clone())));
                    u.insert(format!("{k}_"), x);
                    out.push((format!("{k} renamed"), V::Table(u)));
                }
                let mut u = t.clone();
                u.insert("added_".into(), V::Boolean(true));
                out.push(("key added".into(), V::Table(u)));
            }
        }
        out
    }

    /// Critical (D2): every value in `configs/default.toml` (its commented
    /// examples included) and in every daemon table changes the
    /// fingerprint when it changes. A missed value would leave stale
    /// sanitized mirrors.
    #[test]
    fn every_value_edit_changes_the_fingerprint() {
        let shipped = toml::Value::Table(toml::from_str(BASE).unwrap());
        for (name, v) in [("default.toml", shipped), ("full fixture", every_key())] {
            let base = canonical_fingerprint(&v, &[], &BUILD_REVISION);
            let all = edits(&v);
            assert!(all.len() > 500, "{name}: only {} edits", all.len());
            for (what, edited) in all {
                assert_ne!(
                    base,
                    canonical_fingerprint(&edited, &[], &BUILD_REVISION),
                    "{name}: {what}"
                );
            }
        }
    }

    /// The full fixture is a real configuration, not just TOML.
    #[test]
    fn the_full_fixture_loads() {
        let c = with_text(&full_fixture()).unwrap();
        assert_eq!(c.session_suffix_len, 5);
        assert_ne!(c.fingerprint, DaemonConfig::embedded().fingerprint);
    }

    /// Critical (D2, amendment a): dictionary bytes count with their
    /// category, file, and position: a line moved to another file or
    /// category, a file split in two, or two files swapped changes it.
    #[test]
    fn dictionary_bytes_count_with_their_category_and_file() {
        let v = toml::Value::Table(toml::from_str(BASE).unwrap());
        let fp = |d: &[(&str, Vec<Vec<u8>>)]| canonical_fingerprint(&v, d, &BUILD_REVISION);
        let f = |s: &str| s.as_bytes().to_vec();
        let base = fp(&[
            ("persons", vec![f("Sarah Leitner\nMax Gruber\n")]),
            ("organizations", vec![]),
        ]);
        for (what, d) in [
            (
                "content",
                vec![
                    ("persons", vec![f("Sarah Leitner\nMax Huber\n")]),
                    ("organizations", vec![]),
                ],
            ),
            (
                "line moved to another category",
                vec![
                    ("persons", vec![f("Sarah Leitner\n")]),
                    ("organizations", vec![f("Max Gruber\n")]),
                ],
            ),
            (
                "file split",
                vec![
                    ("persons", vec![f("Sarah Leitner\n"), f("Max Gruber\n")]),
                    ("organizations", vec![]),
                ],
            ),
            (
                "empty file added",
                vec![
                    ("persons", vec![f("Sarah Leitner\nMax Gruber\n"), f("")]),
                    ("organizations", vec![]),
                ],
            ),
        ] {
            assert_ne!(base, fp(&d), "{what}");
        }
        let two = |a: &str, b: &str| fp(&[("persons", vec![f(a), f(b)])]);
        assert_ne!(two("A\n", "B\n"), two("B\n", "A\n"), "files swapped");
    }

    /// Critical (fix round 1): each part of the code revision changes the
    /// fingerprint: the version, [`SANITIZER_GENERATION`], and the build
    /// revision, set or not.
    #[test]
    fn every_part_of_the_revision_changes_the_fingerprint() {
        let v = toml::Value::Table(toml::from_str(BASE).unwrap());
        let r = Revision {
            version: "1.0.0",
            generation: 1,
            build: None,
        };
        let fp = |r: Revision<'_>| canonical_fingerprint(&v, &[], &r);
        let base = fp(r);
        for (what, other) in [
            (
                "version",
                Revision {
                    version: "1.0.1",
                    ..r
                },
            ),
            ("generation", Revision { generation: 2, ..r }),
            (
                "build revision set",
                Revision {
                    build: Some("abc1234"),
                    ..r
                },
            ),
            (
                "build revision empty",
                Revision {
                    build: Some(""),
                    ..r
                },
            ),
        ] {
            assert_ne!(base, fp(other), "{what}");
        }
        let built = |b| {
            fp(Revision {
                build: Some(b),
                ..r
            })
        };
        assert_ne!(built("abc1234"), built("abc1235"), "build revision value");
        assert_eq!(BUILD_REVISION.generation, SANITIZER_GENERATION);
        assert_eq!(BUILD_REVISION.version, env!("CARGO_PKG_VERSION"));
    }

    /// D2: what is not a value does not change the fingerprint: a comment,
    /// blank lines, key order inside a table, a table's position, and how a
    /// value or key is spelled.
    #[test]
    fn comments_order_and_formatting_do_not_change_the_fingerprint() {
        let fp = |text: &str| with_text(text).unwrap().fingerprint;
        let base = fp(&format!(
            "{BASE}\n[daemon]\nsession_cap = 5\ncache_bytes = 1024\n"
        ));
        let tokens = "suffix_len = 4\nopen = \"<\"\nclose = \">\"\n";
        assert!(BASE.contains(tokens));
        for (what, text) in [
            (
                "comment",
                format!("{BASE}\n# a note\n[daemon] # here\nsession_cap = 5\ncache_bytes = 1024\n"),
            ),
            (
                "blank lines",
                format!(
                    "{}\n\n\n[daemon]\n\nsession_cap = 5\n\ncache_bytes = 1024\n\n",
                    BASE.replace("\n\n", "\n\n\n\n")
                ),
            ),
            (
                "key order",
                format!(
                    "{}\n[daemon]\ncache_bytes = 1024\nsession_cap = 5\n",
                    BASE.replace(tokens, "close = \">\"\nopen = \"<\"\nsuffix_len = 4\n")
                ),
            ),
            (
                "table moved",
                format!("[daemon]\nsession_cap = 5\ncache_bytes = 1024\n{BASE}"),
            ),
            (
                "dotted keys",
                format!("daemon.session_cap = 5\ndaemon.cache_bytes = 1024\n{BASE}"),
            ),
            (
                "spelling",
                format!(
                    "{}\n[daemon]\n\"session_cap\" = 0x5\ncache_bytes = 1_024\n",
                    BASE.replace(
                        tokens,
                        "suffix_len   =   4\nopen = '<'\nclose = \"\\u003e\"\n"
                    )
                    .replace("threshold = 0.5\n", "threshold = 0.50\n")
                ),
            ),
        ] {
            assert_eq!(base, fp(&text), "{what}");
        }
    }

    /// Review round 1 #7: reject origin forms that a browser's serialized
    /// `Origin` header could never equal, so an operator's allow-list entry
    /// never silently goes dead.
    #[test]
    fn valid_origin_rejects_forms_that_can_never_match_a_browser_origin() {
        for bad in [
            "HTTP://localhost:3000",   // uppercase scheme
            "http://LOCALHOST:3000",   // uppercase host
            "http://:",                // empty host
            "http://a:b:c",            // ambiguous unbracketed multi-colon host
            "http://localhost:80",     // explicit default port for http
            "https://app.example:443", // explicit default port for https
        ] {
            assert!(!valid_origin(bad), "{bad}");
        }
        for ok in [
            "http://localhost:3000",
            "https://app.example:8443",
            "http://127.0.0.1",
            "http://[::1]:3000",
        ] {
            assert!(valid_origin(ok), "{ok}");
        }
    }

    /// Critical (L81): a misspelled key in a daemon table is refused instead
    /// of silently leaving the default in force. The error names the table,
    /// the key, and the line; never the value.
    #[test]
    fn a_misspelled_key_is_refused_in_every_daemon_table() {
        for table in [
            "daemon",
            "vault",
            "gateway",
            "journal",
            "mail",
            "proxy",
            "mirror",
            "proxy.upstreams.anthropic",
        ] {
            let e = with(&format!("[{table}]\nsesion_ttl = \"qwxzvk-value\"\n"))
                .unwrap_err()
                .to_string();
            let top = table.split('.').next().unwrap();
            assert!(e.contains(&format!("{top} table")), "{table}: {e}");
            assert!(e.contains("unknown key `sesion_ttl`"), "{table}: {e}");
            assert!(e.contains("line"), "{table}: {e}");
            assert!(!e.contains("qwxzvk"), "{table}: {e}");
        }
        // A wrong type names its own table too, not the value.
        let e = with("[proxy]\nlisten = 8787\n").unwrap_err().to_string();
        assert!(e.contains("proxy table: invalid value at line"), "{e}");
        assert!(!e.contains("8787"), "{e}");
    }

    /// `inumaki_client::resolve_socket` (app, MCP shim, hook) refuses the
    /// `[daemon]` keys this struct does not declare; the two lists must match.
    #[test]
    fn client_resolver_knows_exactly_the_daemon_keys() {
        let mut daemon: Vec<&str> = struct_fields::<DaemonSection>().to_vec();
        let mut client: Vec<&str> = inumaki_client::DAEMON_KEYS.to_vec();
        daemon.sort_unstable();
        client.sort_unstable();
        assert_eq!(daemon, client);
    }

    /// Critical: an unknown top-level table is refused (a misspelled
    /// `[deamon]` would otherwise drop every setting in it), while the
    /// engine's own tables, learned from `CoreConfig`, never are. A quoted
    /// key can hold any text, so only a plain key name is printed.
    #[test]
    fn unknown_tables_are_refused_and_engine_tables_are_not() {
        let e = with("[deamon]\nsession_ttl = \"1m\"\n")
            .unwrap_err()
            .to_string();
        assert!(e.contains("unknown table `deamon` at line"), "{e}");
        let e = with("[\"qwxzvk secret\"]\nx = 1\n")
            .unwrap_err()
            .to_string();
        assert!(e.contains("unknown table at line"), "{e}");
        assert!(!e.contains("qwxzvk"), "{e}");
        let e = with("[daemon]\n\"qwxzvk secret\" = 1\n")
            .unwrap_err()
            .to_string();
        assert!(e.contains("daemon table: unknown key at line"), "{e}");
        assert!(!e.contains("qwxzvk"), "{e}");
        // A backtick in a quoted key cuts serde's message short: the
        // fragment before it is a plain key name, but it is not what the
        // file spells there, so nothing of it is printed (review fix 1).
        for (extra, want) in [
            (
                "[daemon]\n\"qzv`wx\" = 1\n",
                "daemon table: unknown key at line",
            ),
            (
                "[daemon]\n\"qzv\" = 1\n",
                "daemon table: unknown key at line",
            ),
            ("[\"qzv`wx\"]\nx = 1\n", "unknown table at line"),
        ] {
            let e = with(extra).unwrap_err().to_string();
            assert!(e.contains(want), "{extra}: {e}");
            assert!(!e.contains("qzv"), "{extra}: {e}");
        }
        let engine = struct_fields::<CoreConfig>();
        for t in [
            "tokens",
            "dictionary",
            "domain",
            "profiles",
            "ner",
            "linking",
        ] {
            assert!(engine.contains(&t), "{t} missing from {engine:?}");
        }
        assert!(with("").is_ok(), "the shipped engine tables are accepted");
    }

    fn write(dir: &Path, text: &str) -> PathBuf {
        let p = dir.join(DEFAULT_CONFIG_FILE);
        std::fs::write(&p, text).unwrap();
        p
    }

    /// L82 (1): `--config` wins, then `<data_dir>/inumaki.toml`, then the
    /// embedded default.
    #[test]
    fn the_data_dir_file_is_used_when_present_and_config_wins() {
        let data = tempfile::tempdir().unwrap();
        let (c, src) = DaemonConfig::resolve(None, data.path()).unwrap();
        assert_eq!(src, ConfigSource::Embedded);
        assert_eq!(src.label(), "embedded");
        assert_eq!(c.fingerprint, DaemonConfig::embedded().fingerprint);

        let p = write(
            data.path(),
            &format!("{BASE}\n[daemon]\ndefault_profile = \"offline\"\n"),
        );
        let (c, src) = DaemonConfig::resolve(None, data.path()).unwrap();
        assert_eq!(c.daemon.default_profile, "offline");
        assert_eq!(src, ConfigSource::File(p.clone()));
        assert_eq!(src.label(), p.display().to_string());

        let other = tempfile::tempdir().unwrap();
        let q = write(
            other.path(),
            &format!("{BASE}\n[daemon]\ndefault_profile = \"strict\"\n"),
        );
        let (c, src) = DaemonConfig::resolve(Some(&q), data.path()).unwrap();
        assert_eq!(c.daemon.default_profile, "strict");
        assert_eq!(src, ConfigSource::File(q));
    }

    /// Critical (L82 (1)): a data-dir file that is present but invalid or
    /// unreadable fails the load; it never falls back to the embedded
    /// default. The error names the file, never its content.
    #[test]
    fn an_invalid_or_unreadable_data_dir_file_fails_closed() {
        let data = tempfile::tempdir().unwrap();
        let p = write(
            data.path(),
            &format!("{BASE}\n[proxy]\nlisten = \"qwxzvk.example:1\"\n"),
        );
        let e = DaemonConfig::resolve(None, data.path())
            .unwrap_err()
            .to_string();
        assert!(e.contains(&format!("config file {}", p.display())), "{e}");
        assert!(e.contains("proxy.listen"), "{e}");
        assert!(!e.contains("qwxzvk"), "{e}");

        std::fs::write(&p, "qwxzvk = [unclosed\n").unwrap();
        let e = DaemonConfig::resolve(None, data.path())
            .unwrap_err()
            .to_string();
        assert!(e.contains("config file") && e.contains("line 1"), "{e}");
        assert!(!e.contains("qwxzvk"), "{e}");

        // A directory where the file should be cannot be read.
        std::fs::remove_file(&p).unwrap();
        std::fs::create_dir(&p).unwrap();
        let e = DaemonConfig::resolve(None, data.path())
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("config file") && e.contains("cannot read"),
            "{e}"
        );
        std::fs::remove_dir(&p).unwrap();

        // A dangling symlink exists: it is an error, not "absent".
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(data.path().join("gone.toml"), &p).unwrap();
            let e = DaemonConfig::resolve(None, data.path())
                .unwrap_err()
                .to_string();
            assert!(e.contains("cannot read"), "{e}");
            std::fs::remove_file(&p).unwrap();
        }

        // No read permission (skipped as root, who reads anything).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            write(data.path(), BASE);
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();
            if std::fs::read(&p).is_err() {
                let e = DaemonConfig::resolve(None, data.path())
                    .unwrap_err()
                    .to_string();
                assert!(
                    e.contains("config file") && e.contains("cannot read"),
                    "{e}"
                );
            }
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
}
