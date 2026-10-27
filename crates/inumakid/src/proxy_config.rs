//! `[proxy]` (M8 spec §10): the model-API proxy's settings, validated once at
//! load. Errors name the key (`proxy.listen`), never the value.
//!
//! Worst-case memory. A request body is buffered whole before it is scanned,
//! so `max_inflight` x `max_request_bytes` bounds the buffered bodies
//! (32 x 8 MiB = 256 MiB with the defaults). The scan itself is admitted
//! against a fixed budget of about 1 GiB of node heap
//! (`inumaki_proxy::config::SCAN_BUDGET_PERMITS`) whatever these two keys
//! say, and `cache_bytes` (256 MiB) is held on top. Budget roughly 1.5 GiB of
//! resident memory for a proxy under full hostile load on the defaults, and
//! scale `max_inflight` and `max_request_bytes` down on a small machine.
//!
//! `definitions_account_values` (`"allow"`, the default, or `"refuse"`) is
//! read by the daemon's proxy host, not by the proxy crate: with `"refuse"`
//! the OS login name and home-directory name (the identity's account
//! values, M8 spec §9 amendment (d)) also fail a request when a tool or
//! schema definition contains them, like the full name and the email always
//! do. `"refuse"` is recommended with the `strict` profile.

use std::net::{IpAddr, SocketAddr};

use axum::http::HeaderName;
use inumaki_core::config::CoreConfig;
use inumaki_core::{Error, TokenSettings};
use inumaki_proxy::config::{DEFAULT_MAX_INFLIGHT, ExtraHeaders};
use inumaki_proxy::forward::extra_header_allowed;
use inumaki_proxy::{BaseUrls, BinaryMode, ProxyConfig, TripwireMode, UncertainMode};
use serde::Deserialize;

use crate::config::{DaemonSection, parse_bytes, parse_duration, valid_origin};

/// The default proxy address. 8787 is the proxy's own port; the gateway
/// keeps 8789.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:8787";

const ANTHROPIC_BASE: &str = "https://api.anthropic.com";
const OPENAI_BASE: &str = "https://api.openai.com";
const CODEX_BASE: &str = "https://chatgpt.com/backend-api/codex";

/// One `[proxy.upstreams.<id>]` table.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamSection {
    /// Replacement for the provider's base URL: `https`, or `http` on a
    /// loopback address (tests). No credentials, query, or fragment.
    pub base_url: Option<String>,
    /// Request header names forwarded to this upstream unchanged, with no
    /// value check (M8 spec §20 amendment of 2026-10-12). Lowercase RFC 9110
    /// token characters, at most [`MAX_EXTRA_HEADERS`], and none of the names
    /// that are never forwarded.
    pub extra_headers: Vec<String>,
}

/// Most `extra_headers` names per upstream.
const MAX_EXTRA_HEADERS: usize = 32;

/// `[proxy.upstreams]`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamsSection {
    /// `/anthropic`.
    pub anthropic: UpstreamSection,
    /// `/openai`.
    pub openai: UpstreamSection,
    /// `/codex`.
    #[serde(rename = "openai-codex")]
    pub openai_codex: UpstreamSection,
}

/// `[proxy]` table.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxySection {
    /// Whether the proxy listens at all.
    pub enabled: bool,
    /// TCP listen address; loopback only.
    pub listen: String,
    /// Sanitization profile; empty means `[daemon] default_profile`.
    pub profile: String,
    /// Idle time before a session's mappings are destroyed, e.g. `4h`.
    pub session_ttl: String,
    /// Most concurrent sessions.
    pub session_cap: usize,
    /// Incremental sanitization cache size, e.g. `256MiB`.
    pub cache_bytes: String,
    /// Largest request body after decompression, e.g. `8MiB`. The spec's
    /// `8MB` is read as decimal by the shared byte parser; the default here
    /// is the binary 8 MiB the proxy crate's constant names.
    pub max_request_bytes: String,
    /// Requests in flight at once.
    pub max_inflight: usize,
    /// Time to the upstream's first byte, e.g. `600s`.
    pub upstream_timeout: String,
    /// Binary parts outside tool results: `placeholder` (the default),
    /// `refuse`, or `forward` (send the payload to the provider unchecked).
    pub binary: Option<String>,
    /// Alias kept for old configurations: `true` is `binary = "forward"`,
    /// `false` is the default. Setting it together with `binary` is an error.
    pub allow_binary: Option<bool>,
    /// `block` or `pass`.
    pub uncertain: String,
    /// `notify` or `block`.
    pub tripwire: String,
    /// Browser origins allowed to reach the proxy; empty rejects every
    /// request that carries `Origin` (M4 spec §16.8).
    pub allowed_origins: Vec<String>,
    /// Base URL overrides.
    pub upstreams: UpstreamsSection,
    /// `allow` or `refuse`: whether the identity's account values (login
    /// and home-directory name) in a tool or schema definition fail the
    /// request ([`AccountValues`]).
    pub definitions_account_values: String,
    /// The cross-session static-prompt NER memo (M8 spec §20, amendment
    /// 2026-10-12): a boolean, `true` when absent. Read as any TOML value
    /// and checked in [`ProxySection::parse`], so a wrong type is an error
    /// that names `proxy.static_cache` rather than the table.
    pub static_cache: Option<toml::Value>,
}

/// What a definition hit on the identity's account values does (M8 spec
/// §9 amendment (d)). Full names and the email always refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccountValues {
    /// Not part of the definition scan (they are still tokenized in chat).
    #[default]
    Allow,
    /// Part of the definition scan: a hit is `400 unsupported_content`.
    Refuse,
}

impl Default for ProxySection {
    fn default() -> Self {
        ProxySection {
            enabled: true,
            listen: DEFAULT_LISTEN.into(),
            profile: String::new(),
            session_ttl: "4h".into(),
            session_cap: 1000,
            cache_bytes: "256MiB".into(),
            // 8 MiB, spelled so `parse_bytes` yields DEFAULT_MAX_REQUEST_BYTES.
            max_request_bytes: "8MiB".into(),
            max_inflight: DEFAULT_MAX_INFLIGHT,
            upstream_timeout: "600s".into(),
            binary: None,
            allow_binary: None,
            uncertain: "block".into(),
            tripwire: "notify".into(),
            allowed_origins: Vec::new(),
            upstreams: UpstreamsSection::default(),
            definitions_account_values: "allow".into(),
            static_cache: None,
        }
    }
}

/// `https://host[:port][/path]`, or `http://` with a loopback IP literal.
/// No userinfo, query, fragment, whitespace, or backslash: the proxy appends
/// the request path to this string, so anything else would change where a
/// sanitized request goes. A trailing `/` is dropped for the same reason.
fn valid_base_url(u: &str) -> Option<String> {
    let (https, rest) = match (u.strip_prefix("https://"), u.strip_prefix("http://")) {
        (Some(r), _) => (true, r),
        (None, Some(r)) => (false, r),
        _ => return None,
    };
    if rest.is_empty()
        || rest
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '@' | '?' | '#' | '\\'))
    {
        return None;
    }
    let (authority, _path) = rest.split_once('/').unwrap_or((rest, ""));
    let (host, port) = match authority.strip_prefix('[') {
        Some(after) => {
            let close = after.find(']')?;
            let tail = &after[close + 1..];
            let port = match tail.strip_prefix(':') {
                Some(p) => Some(p),
                None if tail.is_empty() => None,
                None => return None,
            };
            (&authority[..close + 2], port)
        }
        None => match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        },
    };
    if host.is_empty() || host.contains(':') && !host.starts_with('[') {
        return None;
    }
    if let Some(p) = port
        && (p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) || p.parse::<u16>().is_err())
    {
        return None;
    }
    if !https {
        let ip: IpAddr = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse()
            .ok()?;
        if !ip.is_loopback() {
            return None;
        }
    }
    Some(u.trim_end_matches('/').to_string())
}

impl ProxySection {
    /// The validated `definitions_account_values`; the error names the key.
    pub fn account_values(&self) -> Result<AccountValues, Error> {
        match self.definitions_account_values.as_str() {
            "allow" => Ok(AccountValues::Allow),
            "refuse" => Ok(AccountValues::Refuse),
            _ => Err(Error::ConfigInvalid(
                "proxy.definitions_account_values".into(),
            )),
        }
    }

    /// Validate into the proxy crate's settings. `daemon` supplies the
    /// default profile, `core` the profile names, `session_tokens` the
    /// session token format, and `fingerprint` the configuration hash (this
    /// table's values are part of what it covers).
    pub fn parse(
        &self,
        daemon: &DaemonSection,
        core: &CoreConfig,
        session_tokens: TokenSettings,
        fingerprint: [u8; 32],
    ) -> Result<ProxyConfig, Error> {
        let invalid = |key: &str| Error::ConfigInvalid(format!("proxy.{key}"));
        let listen: SocketAddr = self
            .listen
            .parse()
            .ok()
            .filter(|a: &SocketAddr| a.ip().is_loopback())
            .ok_or_else(|| invalid("listen"))?;
        let profile = if self.profile.is_empty() {
            daemon.default_profile.clone()
        } else {
            self.profile.clone()
        };
        core.resolve_dataset_profile(&profile)
            .map_err(|_| invalid("profile"))?;
        let session_ttl = parse_duration(&self.session_ttl)
            .filter(|d| !d.is_zero())
            .ok_or_else(|| invalid("session_ttl"))?;
        if self.session_cap == 0 {
            return Err(invalid("session_cap"));
        }
        let cache_bytes = parse_bytes(&self.cache_bytes)
            .filter(|b| *b > 0)
            .ok_or_else(|| invalid("cache_bytes"))?;
        let max_request_bytes = parse_bytes(&self.max_request_bytes)
            .filter(|b| *b > 0)
            .ok_or_else(|| invalid("max_request_bytes"))?;
        if self.max_inflight == 0 {
            return Err(invalid("max_inflight"));
        }
        let upstream_timeout = parse_duration(&self.upstream_timeout)
            .filter(|d| !d.is_zero())
            .ok_or_else(|| invalid("upstream_timeout"))?;
        let binary = match (self.binary.as_deref(), self.allow_binary) {
            (Some(_), Some(_)) => return Err(invalid("allow_binary")),
            (_, Some(true)) => BinaryMode::Forward,
            (Some("placeholder"), _) | (None, _) => BinaryMode::Placeholder,
            (Some("refuse"), _) => BinaryMode::Refuse,
            (Some("forward"), _) => BinaryMode::Forward,
            (Some(_), _) => return Err(invalid("binary")),
        };
        let uncertain = match self.uncertain.as_str() {
            "block" => UncertainMode::Block,
            "pass" => UncertainMode::Pass,
            _ => return Err(invalid("uncertain")),
        };
        let tripwire = match self.tripwire.as_str() {
            "notify" => TripwireMode::Notify,
            "block" => TripwireMode::Block,
            _ => return Err(invalid("tripwire")),
        };
        if !self.allowed_origins.iter().all(|o| valid_origin(o)) {
            return Err(invalid("allowed_origins"));
        }
        let base = |o: &UpstreamSection, default: &str, id: &str| match &o.base_url {
            None => Ok(default.to_string()),
            Some(u) => {
                valid_base_url(u).ok_or_else(|| invalid(&format!("upstreams.{id}.base_url")))
            }
        };
        let extra = |o: &UpstreamSection, id: &str| -> Result<Vec<HeaderName>, Error> {
            let bad = || invalid(&format!("upstreams.{id}.extra_headers"));
            if o.extra_headers.len() > MAX_EXTRA_HEADERS {
                return Err(bad());
            }
            o.extra_headers
                .iter()
                .map(|n| {
                    if !extra_header_allowed(n) {
                        return Err(bad());
                    }
                    HeaderName::from_bytes(n.as_bytes()).map_err(|_| bad())
                })
                .collect()
        };
        let static_cache = match &self.static_cache {
            None => true,
            Some(toml::Value::Boolean(b)) => *b,
            Some(_) => return Err(invalid("static_cache")),
        };
        Ok(ProxyConfig {
            enabled: self.enabled,
            listen,
            profile,
            session_ttl,
            session_cap: self.session_cap,
            cache_bytes,
            max_request_bytes,
            max_inflight: self.max_inflight,
            upstream_timeout,
            binary,
            uncertain,
            tripwire,
            allowed_origins: self.allowed_origins.clone(),
            base_urls: BaseUrls {
                anthropic: base(&self.upstreams.anthropic, ANTHROPIC_BASE, "anthropic")?,
                openai: base(&self.upstreams.openai, OPENAI_BASE, "openai")?,
                openai_codex: base(&self.upstreams.openai_codex, CODEX_BASE, "openai-codex")?,
            },
            extra_headers: ExtraHeaders {
                anthropic: extra(&self.upstreams.anthropic, "anthropic")?,
                openai: extra(&self.upstreams.openai, "openai")?,
                openai_codex: extra(&self.upstreams.openai_codex, "openai-codex")?,
            },
            session_tokens,
            static_cache,
            fingerprint,
        })
    }
}

#[cfg(test)]
mod tests {
    use inumaki_proxy::config::DEFAULT_MAX_REQUEST_BYTES;

    use crate::config::DaemonConfig;

    use super::*;

    const BASE: &str = include_str!("../../../configs/default.toml");

    fn with(extra: &str) -> Result<DaemonConfig, Error> {
        DaemonConfig::from_toml(&format!("{BASE}\n{extra}\n"))
    }

    /// Critical: the proxy carries every request body, so it never listens
    /// beyond loopback (M8 spec §4).
    #[test]
    fn listen_must_be_a_loopback_socket_address() {
        for bad in [
            "0.0.0.0:8787",
            "192.168.1.5:8787",
            "[::]:8787",
            "[::ffff:192.168.1.5]:8787",
            "[::ffff:127.0.0.1]:8787",
            "localhost:8787",
            "proxy.example:8787",
            "127.0.0.1",
            "",
        ] {
            let e = with(&format!("[proxy]\nlisten = \"{bad}\"\n")).unwrap_err();
            assert!(format!("{e}").contains("proxy.listen"), "{bad}: {e}");
            assert!(
                !format!("{e}").contains(bad) || bad.is_empty(),
                "{bad}: {e}"
            );
        }
        for ok in ["127.0.0.1:0", "[::1]:0", "127.0.0.2:9000"] {
            let c = with(&format!("[proxy]\nlisten = \"{ok}\"\n")).unwrap();
            assert_eq!(c.proxy.listen.to_string(), ok);
        }
    }

    #[test]
    fn defaults_follow_the_spec_and_the_proxy_crate() {
        let c = with("").unwrap();
        let p = &c.proxy;
        assert!(p.enabled);
        assert_eq!(p.listen.to_string(), "127.0.0.1:8787");
        assert_eq!(p.profile, c.daemon.default_profile);
        assert_eq!(p.max_request_bytes, DEFAULT_MAX_REQUEST_BYTES);
        assert_eq!(p.max_inflight, DEFAULT_MAX_INFLIGHT);
        assert_eq!(p.session_cap, 1000);
        assert_eq!(p.session_ttl.as_secs(), 4 * 3600);
        assert_eq!(p.uncertain, UncertainMode::Block);
        assert_eq!(p.tripwire, TripwireMode::Notify);
        assert_eq!(p.binary, BinaryMode::Placeholder);
        assert_eq!(p.base_urls.openai_codex, CODEX_BASE);
        assert_eq!(p.fingerprint, c.fingerprint);
        assert_eq!(c.proxy_account_values, AccountValues::Allow);
        assert!(p.static_cache, "the static-prompt memo is on by default");
        let c = with("[proxy]\ndefinitions_account_values = \"refuse\"\n").unwrap();
        assert_eq!(c.proxy_account_values, AccountValues::Refuse);
        let c = with("[proxy]\nstatic_cache = false\n").unwrap();
        assert!(!c.proxy.static_cache);
    }

    /// Critical (plan Task 3): a non-boolean `static_cache` fails the load
    /// with an error that names the key, exactly, and never the value.
    #[test]
    fn static_cache_must_be_a_boolean_and_the_error_names_the_key_only() {
        for bad in ["\"yes\"", "1", "\"Sarah Leitner\"", "[true]"] {
            let e = with(&format!("[proxy]\nstatic_cache = {bad}\n")).unwrap_err();
            assert!(
                matches!(&e, Error::ConfigInvalid(k) if k == "proxy.static_cache"),
                "{bad}: {e:?}"
            );
            assert!(!format!("{e:?}").contains("Sarah"), "{e:?}");
        }
    }

    /// Critical: a base URL decides where sanitized requests and the
    /// harness's credentials go.
    #[test]
    fn base_url_overrides_are_https_or_loopback_http() {
        for ok in [
            "https://api.example.com",
            "https://gateway.example:8443/anthropic/",
            "http://127.0.0.1:9999",
            "http://[::1]:9999",
        ] {
            let c = with(&format!(
                "[proxy.upstreams.anthropic]\nbase_url = \"{ok}\"\n"
            ))
            .unwrap();
            assert_eq!(c.proxy.base_urls.anthropic, ok.trim_end_matches('/'));
        }
        for bad in [
            "http://api.example.com",
            "http://192.168.1.5:9999",
            "http://localhost:9999",
            "ftp://127.0.0.1",
            "https://",
            "https://user:pw@api.example.com",
            "https://api.example.com?x=1",
            "https://api.example.com#f",
            "https://api.example.com:notaport",
            "api.example.com",
        ] {
            let e = with(&format!(
                "[proxy.upstreams.openai-codex]\nbase_url = \"{bad}\"\n"
            ))
            .unwrap_err();
            let m = format!("{e}");
            assert!(
                m.contains("proxy.upstreams.openai-codex.base_url"),
                "{bad}: {m}"
            );
            assert!(!m.contains(bad), "{bad}: {m}");
        }
    }

    /// Critical: `extra_headers` lifts every value check for the names in it,
    /// so a bad name fails the load, names the key, and never echoes the value.
    #[test]
    fn extra_headers_parse_and_bad_names_are_refused_without_echo() {
        let c = with("[proxy.upstreams.openai]\nextra_headers = [\"x-gateway-key\", \"cf-access-client-id\"]\n")
            .unwrap();
        let names: Vec<&str> = c
            .proxy
            .extra_headers
            .openai
            .iter()
            .map(|n| n.as_str())
            .collect();
        assert_eq!(names, ["x-gateway-key", "cf-access-client-id"]);
        assert!(c.proxy.extra_headers.anthropic.is_empty());
        assert!(c.proxy.extra_headers.openai_codex.is_empty());

        let too_many: Vec<String> = (0..33).map(|i| format!("x-n{i}")).collect();
        let at_limit: Vec<String> = (0..32).map(|i| format!("x-n{i}")).collect();
        let list = |v: &[String]| {
            let q: Vec<String> = v.iter().map(|n| format!("\"{n}\"")).collect();
            format!("[{}]", q.join(", "))
        };
        with(&format!(
            "[proxy.upstreams.anthropic]\nextra_headers = {}\n",
            list(&at_limit)
        ))
        .unwrap();

        let mut bad: Vec<String> = [
            "X-Gateway-Key",
            "connection",
            "x-inumaki-x",
            "x-codex-turn-metadata",
        ]
        .map(String::from)
        .into();
        bad.push(String::new());
        bad.push("a b".into());
        for name in &bad {
            let e = with(&format!(
                "[proxy.upstreams.openai-codex]\nextra_headers = [\"{name}\"]\n"
            ))
            .unwrap_err();
            for text in [format!("{e}"), format!("{e:?}")] {
                assert!(
                    text.contains("proxy.upstreams.openai-codex.extra_headers"),
                    "{name}: {text}"
                );
                assert!(
                    name.is_empty() || !text.contains(name.as_str()),
                    "{name}: {text}"
                );
            }
        }
        let e = with(&format!(
            "[proxy.upstreams.anthropic]\nextra_headers = {}\n",
            list(&too_many)
        ))
        .unwrap_err();
        let m = format!("{e}");
        assert!(m.contains("proxy.upstreams.anthropic.extra_headers"), "{m}");
        assert!(!m.contains("x-n0"), "{m}");

        // An unknown key in the table is still refused.
        assert!(with("[proxy.upstreams.openai]\nextra_header = []\n").is_err());
    }

    #[test]
    fn binary_words_parse_and_allow_binary_is_an_alias() {
        for (extra, want) in [
            ("binary = \"placeholder\"", BinaryMode::Placeholder),
            ("binary = \"refuse\"", BinaryMode::Refuse),
            ("binary = \"forward\"", BinaryMode::Forward),
            ("allow_binary = true", BinaryMode::Forward),
            ("allow_binary = false", BinaryMode::Placeholder),
        ] {
            let c = with(&format!("[proxy]\n{extra}\n")).unwrap();
            assert_eq!(c.proxy.binary, want, "{extra}");
        }
    }

    /// Critical: `forward` sends unchecked payloads out, so a contradictory
    /// pair of keys must not silently pick one.
    #[test]
    fn binary_and_allow_binary_together_are_refused() {
        let e = with("[proxy]\nbinary = \"refuse\"\nallow_binary = true\n").unwrap_err();
        assert!(format!("{e}").contains("proxy.allow_binary"), "{e}");
    }

    /// Critical: an invalid value names the key and never echoes the value.
    #[test]
    fn invalid_binary_value_names_its_key_not_the_value() {
        let e = with("[proxy]\nbinary = \"Sarah Leitner\"\n").unwrap_err();
        for text in [format!("{e}"), format!("{e:?}")] {
            assert!(text.contains("proxy.binary"), "{text}");
            assert!(!text.contains("Sarah"), "{text}");
        }
    }

    #[test]
    fn invalid_values_name_their_key() {
        for (extra, key) in [
            ("uncertain = \"maybe\"", "proxy.uncertain"),
            ("tripwire = \"off\"", "proxy.tripwire"),
            ("max_inflight = 0", "proxy.max_inflight"),
            ("session_cap = 0", "proxy.session_cap"),
            ("session_ttl = \"0s\"", "proxy.session_ttl"),
            ("max_request_bytes = \"0\"", "proxy.max_request_bytes"),
            ("cache_bytes = \"lots\"", "proxy.cache_bytes"),
            ("upstream_timeout = \"soon\"", "proxy.upstream_timeout"),
            ("profile = \"nope\"", "proxy.profile"),
            ("allowed_origins = [\"*\"]", "proxy.allowed_origins"),
            (
                "definitions_account_values = \"maybe\"",
                "proxy.definitions_account_values",
            ),
        ] {
            let e = with(&format!("[proxy]\n{extra}\n")).unwrap_err();
            assert!(format!("{e}").contains(key), "{extra}: {e}");
        }
    }
}
