//! Counters behind `GET /v1/proxy` (M8 spec §11). Enums, integers, times.

use std::sync::Mutex;
use std::sync::PoisonError;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::config::ProxyConfig;
use crate::error::ErrorClass;
use crate::routes::UpstreamId;
use crate::timing::{RequestTiming, StaticCacheBody, TimingBody, TimingRing};

/// Set to `true` by plan M8-3's Codex ChatGPT-login verification.
pub const CODEX_CHATGPT_VERIFIED: bool = false;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Harness, from `User-Agent` (spec §11); the raw value is dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientKind {
    /// Claude Code.
    ClaudeCode,
    /// Codex CLI.
    Codex,
    /// Hermes agent.
    Hermes,
    /// OpenClaw.
    Openclaw,
    /// Anything else, or no `User-Agent`.
    Other,
}

impl ClientKind {
    /// Classify a `User-Agent` value; the value itself is not kept.
    pub fn from_user_agent(ua: Option<&str>) -> ClientKind {
        let Some(ua) = ua else {
            return ClientKind::Other;
        };
        let l = ua.to_ascii_lowercase();
        if l.starts_with("claude-cli/") {
            ClientKind::ClaudeCode
        } else if l.starts_with("codex_cli_rs/") || l.starts_with("codex_exec/") {
            ClientKind::Codex
        } else if l.contains("hermes-agent") {
            ClientKind::Hermes
        } else if l.contains("openclaw") {
            ClientKind::Openclaw
        } else {
            ClientKind::Other
        }
    }
}

/// How the proxy is listening.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenState {
    /// Bound to this address.
    Running(std::net::SocketAddr),
    /// Not enabled.
    Disabled,
    /// Enabled, but the bind failed or the serve loop ended with an error.
    BindFailed,
}

/// Which OAuth counter a request feeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OauthUse {
    /// API-key request.
    None,
    /// Anthropic OAuth; `translated` when the proxy rewrote the credential.
    Anthropic {
        /// Whether the credential was translated.
        translated: bool,
    },
    /// Codex with a ChatGPT login.
    CodexChatgpt,
}

/// How a request ended, for the counters.
///
/// One rule decides a route's `failing` state (spec §7, applied by
/// [`Status::outcome`]): `Ok` clears it; a `Failed` outcome whose class is
/// `upstream_unreachable`, `upstream_auth`, `upstream_5xx`, `stream_aborted`,
/// or `internal` sets it; every other outcome (privacy refusals, withheld
/// results, rate limits, caller mistakes) leaves it as it was. Every
/// `Failed` outcome and every 451 (`Blocked`, `Uncertain`) records
/// `last_error`; `Blocked` and `Uncertain` also bump their counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Completed.
    Ok,
    /// Refused by the privacy check (answered 451).
    Blocked,
    /// Refused because the verifier was unsure (answered 451).
    Uncertain,
    /// A tool result was withheld after sending (counted only).
    Withheld {
        /// Whether the verifier was unsure.
        uncertain: bool,
    },
    /// A route error with its class and upstream status.
    Failed(ErrorClass, Option<u16>),
    /// Ended without being a route error (not served, caller mistakes).
    NotARouteError,
}

#[derive(Default, Clone)]
struct Route {
    requests: u64,
    blocked: u64,
    uncertain: u64,
    last_request_at: Option<i64>,
    last_error: Option<(ErrorClass, Option<u16>, i64)>,
    failing: bool,
}

#[derive(Default)]
struct Inner {
    routes: [Route; 3],
    clients: Vec<(ClientKind, u64, i64)>,
    anthropic: (u64, u64, Option<ErrorClass>),
    codex: (u64, Option<i64>, Option<ErrorClass>),
    hits: u64,
    misses: u64,
    timing: TimingRing,
}

/// Status counters.
#[derive(Default)]
pub struct Status(Mutex<Inner>);

fn idx(up: UpstreamId) -> usize {
    UpstreamId::ALL
        .iter()
        .position(|u| *u == up)
        .expect("every upstream is listed")
}

impl Status {
    /// Empty counters.
    pub fn new() -> Status {
        Status::default()
    }

    /// Count an arriving request.
    pub fn request(&self, up: UpstreamId, client: ClientKind, oauth: OauthUse) {
        let mut s = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let t = now();
        let r = &mut s.routes[idx(up)];
        r.requests += 1;
        r.last_request_at = Some(t);
        match s.clients.iter_mut().find(|c| c.0 == client) {
            Some(c) => {
                c.1 += 1;
                c.2 = t;
            }
            None => s.clients.push((client, 1, t)),
        }
        match oauth {
            OauthUse::Anthropic { translated } => {
                s.anthropic.0 += 1;
                if translated {
                    s.anthropic.1 += 1;
                }
            }
            OauthUse::CodexChatgpt => s.codex.0 += 1,
            OauthUse::None => {}
        }
    }

    /// Count how a request ended.
    pub fn outcome(&self, up: UpstreamId, o: Outcome, oauth: OauthUse) {
        let mut s = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let t = now();
        let r = &mut s.routes[idx(up)];
        match o {
            Outcome::Ok => r.failing = false,
            Outcome::Blocked => {
                r.blocked += 1;
                r.last_error = Some((ErrorClass::PrivacyBlock, None, t));
            }
            Outcome::Uncertain => {
                r.uncertain += 1;
                r.last_error = Some((ErrorClass::PrivacyBlock, None, t));
            }
            Outcome::Withheld { uncertain } => {
                if uncertain {
                    r.uncertain += 1
                } else {
                    r.blocked += 1
                }
            }
            Outcome::Failed(c, st) => {
                r.last_error = Some((c, st, t));
                // Only these classes set `failing`; the others leave it alone.
                if matches!(
                    c,
                    ErrorClass::UpstreamUnreachable
                        | ErrorClass::UpstreamAuth
                        | ErrorClass::Upstream5xx
                        | ErrorClass::StreamAborted
                        | ErrorClass::Internal
                ) {
                    r.failing = true;
                }
            }
            Outcome::NotARouteError => {}
        }
        let err = match o {
            Outcome::Failed(c, _) => Some(c),
            _ => None,
        };
        match oauth {
            OauthUse::Anthropic { .. } => {
                if err.is_some() {
                    s.anthropic.2 = err
                }
            }
            OauthUse::CodexChatgpt => match err {
                Some(c) => s.codex.2 = Some(c),
                None if o == Outcome::Ok => s.codex.1 = Some(t),
                None => {}
            },
            OauthUse::None => {}
        }
    }

    /// Add incremental-cache hits and misses.
    pub fn cache(&self, hits: u64, misses: u64) {
        let mut s = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        s.hits += hits;
        s.misses += misses;
    }

    /// Keep one request's timing sample (spec §20, 2026-10-12, Part 2).
    pub fn timing(&self, t: RequestTiming) {
        let at = now();
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .timing
            .push(&t, at);
    }

    /// The `timing` object of `GET /v1/proxy`.
    pub fn timing_body(&self) -> TimingBody {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .timing
            .body()
    }

    /// The `GET /v1/proxy` body. Every argument is a value the status
    /// counters do not own (listener, session store, check registry, the
    /// host's memo), so they are passed in rather than grouped.
    #[allow(clippy::too_many_arguments)]
    pub fn body(
        &self,
        cfg: &ProxyConfig,
        listen: &ListenState,
        sessions: u64,
        entries: u64,
        check_routes: u64,
        client_value: &str,
        static_cache: StaticCacheBody,
    ) -> ProxyStatusBody {
        let s = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let addr = match listen {
            ListenState::Running(a) => a.to_string(),
            _ => cfg.listen.to_string(),
        };
        ProxyStatusBody {
            enabled: cfg.enabled,
            listen: addr.clone(),
            state: match listen {
                ListenState::Running(_) => "running",
                ListenState::Disabled => "disabled",
                ListenState::BindFailed => "bind_failed",
            },
            routes: UpstreamId::ALL
                .iter()
                .map(|u| {
                    let r = &s.routes[idx(*u)];
                    RouteBody {
                        prefix: u.prefix(),
                        upstream: u.id(),
                        base_url: format!("http://{addr}{}", u.prefix()),
                        paths: u.served_paths().to_vec(),
                        state: if r.requests == 0 {
                            "idle"
                        } else if r.failing {
                            "failing"
                        } else {
                            "ok"
                        },
                        requests: r.requests,
                        blocked: r.blocked,
                        uncertain: r.uncertain,
                        last_request_at: r.last_request_at,
                        last_error: r.last_error.map(|(class, status, at)| RouteError {
                            class,
                            status: status.map(u64::from),
                            at,
                        }),
                    }
                })
                .collect(),
            clients: s
                .clients
                .iter()
                .map(|(c, n, t)| ClientBody {
                    client: *c,
                    requests: *n,
                    last_at: *t,
                })
                .collect(),
            oauth: OauthBody {
                anthropic: AnthropicBody {
                    requests: s.anthropic.0,
                    translated: s.anthropic.1,
                    last_error: s.anthropic.2,
                },
                codex_chatgpt: CodexBody {
                    verified_in_build: CODEX_CHATGPT_VERIFIED,
                    requests: s.codex.0,
                    last_ok_at: s.codex.1,
                    last_error: s.codex.2,
                },
            },
            sessions,
            incremental_cache: CacheBody {
                hits: s.hits,
                misses: s.misses,
                entries,
            },
            check_routes,
            client_header: ClientHeader {
                name: "X-Inumaki-Client",
                value: client_value.to_string(),
            },
            timing: s.timing.body(),
            static_cache,
            closure_shadow: cfg!(feature = "closure-shadow"),
        }
    }
}

/// `GET /v1/proxy`; field order is `inumaki_client::ProxyBody`'s.
#[derive(Serialize)]
pub struct ProxyStatusBody {
    /// Whether the proxy is enabled.
    pub enabled: bool,
    /// Listen address.
    pub listen: String,
    /// `running`, `disabled`, or `bind_failed`.
    pub state: &'static str,
    /// One entry per upstream.
    pub routes: Vec<RouteBody>,
    /// Harnesses seen.
    pub clients: Vec<ClientBody>,
    /// OAuth counters.
    pub oauth: OauthBody,
    /// Live sessions.
    pub sessions: u64,
    /// Incremental cache counters.
    pub incremental_cache: CacheBody,
    /// Registered check routes.
    pub check_routes: u64,
    /// The header harnesses may send to name themselves.
    pub client_header: ClientHeader,
    /// Where each request's time goes (spec §20, 2026-10-12, Part 2).
    pub timing: TimingBody,
    /// The cross-session static-prompt NER cache's counters.
    pub static_cache: StaticCacheBody,
    /// A measurement build with the closure shadow mode compiled in
    /// (spec §20, 2026-10-12). Serialized only when true.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub closure_shadow: bool,
}

/// One upstream route.
#[derive(Serialize)]
pub struct RouteBody {
    /// Path prefix.
    pub prefix: &'static str,
    /// Upstream id.
    pub upstream: &'static str,
    /// Base URL a harness sets.
    pub base_url: String,
    /// Served paths.
    pub paths: Vec<&'static str>,
    /// `idle`, `ok`, or `failing`.
    pub state: &'static str,
    /// Requests seen.
    pub requests: u64,
    /// Requests refused.
    pub blocked: u64,
    /// Requests refused as uncertain.
    pub uncertain: u64,
    /// Unix seconds of the last request.
    pub last_request_at: Option<i64>,
    /// The last route error.
    pub last_error: Option<RouteError>,
}

/// A route error: class, upstream status, time.
#[derive(Serialize)]
pub struct RouteError {
    /// Error class.
    pub class: ErrorClass,
    /// Upstream HTTP status, if any.
    pub status: Option<u64>,
    /// Unix seconds.
    pub at: i64,
}

/// A harness seen.
#[derive(Serialize)]
pub struct ClientBody {
    /// Harness.
    pub client: ClientKind,
    /// Requests seen.
    pub requests: u64,
    /// Unix seconds of the last request.
    pub last_at: i64,
}

/// OAuth counters.
#[derive(Serialize)]
pub struct OauthBody {
    /// Anthropic OAuth.
    pub anthropic: AnthropicBody,
    /// Codex ChatGPT login.
    pub codex_chatgpt: CodexBody,
}

/// Anthropic OAuth counters.
#[derive(Serialize)]
pub struct AnthropicBody {
    /// Requests seen.
    pub requests: u64,
    /// Requests whose credential was translated.
    pub translated: u64,
    /// The last error class.
    pub last_error: Option<ErrorClass>,
}

/// Codex ChatGPT counters.
#[derive(Serialize)]
pub struct CodexBody {
    /// Whether this build verified the ChatGPT-login path.
    pub verified_in_build: bool,
    /// Requests seen.
    pub requests: u64,
    /// Unix seconds of the last success.
    pub last_ok_at: Option<i64>,
    /// The last error class.
    pub last_error: Option<ErrorClass>,
}

/// Incremental cache counters.
#[derive(Serialize)]
pub struct CacheBody {
    /// Hits.
    pub hits: u64,
    /// Misses.
    pub misses: u64,
    /// Entries held.
    pub entries: u64,
}

/// The client-naming header.
#[derive(Serialize)]
pub struct ClientHeader {
    /// Header name.
    pub name: &'static str,
    /// Value a harness sends.
    pub value: String,
}

impl std::fmt::Debug for ProxyStatusBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyStatusBody")
            .field("state", &self.state)
            .field("sessions", &self.sessions)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A configuration for the body-builder tests.
    fn test_cfg() -> crate::config::ProxyConfig {
        crate::config::ProxyConfig {
            enabled: true,
            listen: "127.0.0.1:8787".parse().unwrap(),
            profile: "p".into(),
            session_ttl: std::time::Duration::from_secs(1),
            session_cap: 1,
            cache_bytes: 1,
            max_request_bytes: 1,
            max_inflight: 1,
            upstream_timeout: std::time::Duration::from_secs(1),
            binary: crate::config::BinaryMode::Refuse,
            uncertain: crate::config::UncertainMode::Block,
            tripwire: crate::config::TripwireMode::Notify,
            allowed_origins: vec![],
            base_urls: crate::config::BaseUrls {
                anthropic: String::new(),
                openai: String::new(),
                openai_codex: String::new(),
            },
            extra_headers: Default::default(),
            session_tokens: Default::default(),
            static_cache: true,
            static_ner: crate::config::StaticNer::Scan,
            fingerprint: [0; 32],
        }
    }

    #[test]
    fn client_kind_drops_the_raw_user_agent() {
        assert_eq!(
            ClientKind::from_user_agent(Some("claude-cli/2.1.0 (external)")),
            ClientKind::ClaudeCode
        );
        assert_eq!(
            ClientKind::from_user_agent(Some("Mozilla/5.0 secret-host")),
            ClientKind::Other
        );
        assert_eq!(ClientKind::from_user_agent(None), ClientKind::Other);
    }

    /// One rule for `failing`: only the failing classes set it, only `Ok`
    /// clears it; 451s and rate limits record `last_error` without touching it.
    #[test]
    fn failing_follows_one_rule() {
        let s = Status::new();
        let up = UpstreamId::Openai;
        let o = OauthUse::None;
        s.request(up, ClientKind::Other, o);
        // (outcome, failing after, blocked, uncertain, last_error class)
        let steps = [
            (
                Outcome::Blocked,
                false,
                1,
                0,
                Some(ErrorClass::PrivacyBlock),
            ),
            (
                Outcome::Failed(ErrorClass::Upstream5xx, Some(502)),
                true,
                1,
                0,
                Some(ErrorClass::Upstream5xx),
            ),
            (
                Outcome::Uncertain,
                true,
                1,
                1,
                Some(ErrorClass::PrivacyBlock),
            ),
            (
                Outcome::Failed(ErrorClass::UpstreamRateLimited, Some(429)),
                true,
                1,
                1,
                Some(ErrorClass::UpstreamRateLimited),
            ),
            (
                Outcome::NotARouteError,
                true,
                1,
                1,
                Some(ErrorClass::UpstreamRateLimited),
            ),
            (
                Outcome::Withheld { uncertain: false },
                true,
                2,
                1,
                Some(ErrorClass::UpstreamRateLimited),
            ),
            (
                Outcome::Ok,
                false,
                2,
                1,
                Some(ErrorClass::UpstreamRateLimited),
            ),
            (
                Outcome::NotARouteError,
                false,
                2,
                1,
                Some(ErrorClass::UpstreamRateLimited),
            ),
            (
                Outcome::Failed(ErrorClass::Internal, None),
                true,
                2,
                1,
                Some(ErrorClass::Internal),
            ),
        ];
        for (i, (outcome, failing, blocked, uncertain, class)) in steps.into_iter().enumerate() {
            s.outcome(up, outcome, o);
            let r = s.0.lock().unwrap().routes[idx(up)].clone();
            assert_eq!(r.failing, failing, "step {i}");
            assert_eq!((r.blocked, r.uncertain), (blocked, uncertain), "step {i}");
            assert_eq!(r.last_error.map(|e| e.0), class, "step {i}");
        }
    }

    #[test]
    fn failing_state_and_debug_carry_no_values() {
        let s = Status::new();
        s.request(UpstreamId::Anthropic, ClientKind::Other, OauthUse::None);
        s.outcome(
            UpstreamId::Anthropic,
            Outcome::Failed(ErrorClass::Upstream5xx, Some(502)),
            OauthUse::None,
        );
        let cfg = test_cfg();
        let b = s.body(
            &cfg,
            &ListenState::Disabled,
            0,
            0,
            0,
            "v",
            StaticCacheBody::new(true, None),
        );
        assert_eq!(b.state, "disabled");
        assert_eq!(b.routes[0].state, "failing");
        assert_eq!(b.routes[1].state, "idle");
        let v = serde_json::to_value(&b).unwrap();
        assert_eq!(v["routes"][0]["last_error"]["class"], "upstream_5xx");
        let d = format!("{b:?}");
        assert!(!d.contains("127.0.0.1") && !d.contains("anthropic"));
    }

    /// The flag is in the body only when the shadow mode is compiled in (true
    /// then), so the default build's contract fixture does not move.
    #[test]
    fn the_shadow_flag_follows_the_feature() {
        let cfg = test_cfg();
        let b = Status::new().body(
            &cfg,
            &ListenState::Disabled,
            0,
            0,
            0,
            "v",
            StaticCacheBody::new(true, None),
        );
        let v = serde_json::to_value(&b).unwrap();
        #[cfg(not(feature = "closure-shadow"))]
        assert!(v.get("closure_shadow").is_none());
        #[cfg(feature = "closure-shadow")]
        assert_eq!(v.get("closure_shadow"), Some(&serde_json::json!(true)));
    }
}
