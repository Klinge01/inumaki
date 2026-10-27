//! M4 spec §16.8: browser origins refused before authentication, no CORS
//! headers ever, Upgrade refused, a foreign Host refused. Controller ruling
//! S5: the Host check runs inside `origin_guard`, before bearer auth, and is
//! port-aware (unlike rmcp's own `allowed_hosts`, kept as a second layer).

mod common;

use std::time::Duration;

use common::*;
use hyper::Method;
use serde_json::json;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

async fn daemon(extra: &str) -> TestDaemon {
    let config = format!(
        "{BASE_CONFIG}\n[daemon]\ndefault_profile = \"offline\"\n[vault]\nkey_source = \"file\"\n[gateway]\nlisten = \"127.0.0.1:0\"\n{extra}\n"
    );
    let d = start_with_config(config, None, Duration::from_secs(3600), None).await;
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets",
            Some(json!({ "id": "crm", "name": "T", "profile": "offline" })),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    d
}

async fn token(d: &TestDaemon) -> String {
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/gateway/tokens",
            Some(json!({ "label": "t" })),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    body["token"].as_str().unwrap().to_string()
}

/// Raw HTTP/1.1 over TCP: status code and the whole response text. A `Host`
/// header is added by default (`127.0.0.1`, no port) unless the caller
/// supplies one, so tests that only care about `Origin` or `Upgrade` still
/// pass the Host check.
async fn raw(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nConnection: close\r\nContent-Length: 2\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\n"
    );
    if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
        req.push_str("Host: 127.0.0.1\r\n");
    }
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n{}");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).to_string();
    let code = text
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    (code, text)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn browser_origins_are_refused_before_authentication() {
    let d = daemon("").await;
    let t = token(&d).await;
    let bearer = format!("Bearer {t}");
    let addr = d.gateway_addr();
    let (code, text) = raw(
        addr,
        "POST",
        "/mcp/crm",
        &[
            ("Origin", "https://evil.example"),
            ("Authorization", &bearer),
        ],
    )
    .await;
    assert_eq!(code, 403, "{text}");
    assert!(text.contains("origin_not_allowed"), "{text}");
    let (code, text) = raw(
        addr,
        "POST",
        "/mcp/crm",
        &[("Origin", "https://evil.example")],
    )
    .await;
    assert_eq!(
        code, 403,
        "no token and a browser origin: still 403, not 401 ({text})"
    );
    let (code, text) = raw(
        addr,
        "POST",
        "/mcp/crm",
        &[("Origin", "null"), ("Authorization", &bearer)],
    )
    .await;
    assert_eq!(code, 403, "{text}");
    let (code, _) = raw(addr, "POST", "/mcp/crm", &[("Authorization", &bearer)]).await;
    assert_ne!(
        code, 403,
        "an MCP client without Origin is not refused by the guard"
    );
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_allowed_origin_passes_the_guard() {
    let d = daemon("allowed_origins = [\"http://localhost:3000\"]").await;
    let t = token(&d).await;
    let bearer = format!("Bearer {t}");
    let (code, text) = raw(
        d.gateway_addr(),
        "POST",
        "/mcp/crm",
        &[
            ("Origin", "http://localhost:3000"),
            ("Authorization", &bearer),
        ],
    )
    .await;
    assert_ne!(code, 403, "{text}");
    let (code, _) = raw(
        d.gateway_addr(),
        "POST",
        "/mcp/crm",
        &[
            ("Origin", "http://localhost:3001"),
            ("Authorization", &bearer),
        ],
    )
    .await;
    assert_eq!(code, 403);
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_cors_headers_preflight_refused_and_upgrade_refused() {
    let d = daemon("allowed_origins = [\"http://localhost:3000\"]").await;
    let t = token(&d).await;
    let bearer = format!("Bearer {t}");
    let addr = d.gateway_addr();
    let (code, text) = raw(
        addr,
        "OPTIONS",
        "/mcp/crm",
        &[
            ("Origin", "https://evil.example"),
            ("Access-Control-Request-Method", "POST"),
        ],
    )
    .await;
    assert_eq!(code, 403, "{text}");
    for (_, text) in [
        raw(
            addr,
            "OPTIONS",
            "/mcp/crm",
            &[
                ("Origin", "http://localhost:3000"),
                ("Access-Control-Request-Method", "POST"),
            ],
        )
        .await,
        raw(
            addr,
            "POST",
            "/mcp/crm",
            &[
                ("Origin", "http://localhost:3000"),
                ("Authorization", &bearer),
            ],
        )
        .await,
        raw(addr, "POST", "/mcp/crm", &[("Authorization", &bearer)]).await,
    ] {
        assert!(
            !text.to_ascii_lowercase().contains("access-control-"),
            "{text}"
        );
    }
    let (code, text) = raw(
        addr,
        "GET",
        "/mcp/crm",
        &[
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
            ("Authorization", &bearer),
        ],
    )
    .await;
    assert_eq!(code, 501, "{text}");
    assert!(text.contains("upgrade_not_supported"), "{text}");
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_foreign_host_is_refused() {
    let d = daemon("").await;
    let t = token(&d).await;
    let bearer = format!("Bearer {t}");
    let (code, text) = raw(
        d.gateway_addr(),
        "POST",
        "/mcp/crm",
        &[("Host", "evil.example"), ("Authorization", &bearer)],
    )
    .await;
    assert!(
        code >= 400 && code != 404,
        "DNS rebinding: a foreign Host must be refused ({text})"
    );
    assert_eq!(code, 403, "{text}");
    assert!(text.contains("host_not_allowed"), "{text}");
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_port_is_refused_before_authentication() {
    let d = daemon("").await;
    let t = token(&d).await;
    let bearer = format!("Bearer {t}");
    let addr = d.gateway_addr();
    let wrong_port = addr.port().wrapping_add(1).max(1);
    let host = format!("localhost:{wrong_port}");
    // No token: still 403 (host check runs before auth).
    let (code, text) = raw(addr, "POST", "/mcp/crm", &[("Host", &host)]).await;
    assert_eq!(code, 403, "{text}");
    assert!(text.contains("host_not_allowed"), "{text}");
    // A valid token does not help: the guard runs first.
    let (code, text) = raw(
        addr,
        "POST",
        "/mcp/crm",
        &[("Host", &host), ("Authorization", &bearer)],
    )
    .await;
    assert_eq!(code, 403, "{text}");
    assert!(text.contains("host_not_allowed"), "{text}");
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bound_port_and_bare_localhost_pass_the_host_check() {
    let d = daemon("").await;
    let t = token(&d).await;
    let bearer = format!("Bearer {t}");
    let addr = d.gateway_addr();
    let host_with_port = format!("localhost:{}", addr.port());
    let (code, text) = raw(
        addr,
        "POST",
        "/mcp/crm",
        &[("Host", &host_with_port), ("Authorization", &bearer)],
    )
    .await;
    assert_ne!(code, 403, "{text}");
    let (code, text) = raw(
        addr,
        "POST",
        "/mcp/crm",
        &[("Host", "localhost"), ("Authorization", &bearer)],
    )
    .await;
    assert_ne!(code, 403, "bare localhost, no port: {text}");
    d.stop().await;
}

#[test]
fn allowed_origins_are_validated() {
    use inumakid::config::DaemonConfig;
    let base = format!("{BASE_CONFIG}\n[daemon]\ndefault_profile = \"offline\"\n");
    for bad in [
        "\"*\"",
        "\"localhost:3000\"",
        "\"http://localhost:3000/path\"",
        "\"file://x\"",
    ] {
        let c = format!("{base}[gateway]\nallowed_origins = [{bad}]\n");
        assert!(
            format!("{:?}", DaemonConfig::from_toml(&c).unwrap_err())
                .contains("gateway.allowed_origins"),
            "{bad}"
        );
    }
    let ok = format!("{base}[gateway]\nallowed_origins = [\"https://app.example:8443\"]\n");
    assert!(DaemonConfig::from_toml(&ok).is_ok());
}

/// A canary `Host` value refused by the guard must never reach the logs
/// (only the fixed refusal class does), the same discipline Task 7's canary
/// test pins for the rest of the gateway.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_canary_host_value_never_appears_in_logs() {
    let cap = Capture::new();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(cap.clone())
                .with_filter(inumakid::run::log_filter(EnvFilter::new("trace"))),
        )
        .init();
    let d = daemon("").await;
    let addr = d.gateway_addr();
    let (code, _) = raw(
        addr,
        "POST",
        "/mcp/crm",
        &[("Host", "qwxzvk-canary-slug.evil.example")],
    )
    .await;
    assert_eq!(code, 403);
    d.stop().await;
    let logs = cap.text();
    assert!(
        !logs.contains("qwxzvk-canary-slug"),
        "the raw Host value leaked into the logs:\n{logs}"
    );
}

/// Review round 1 #6: the guard covers unmatched (fallback) paths too — a
/// foreign `Origin` or `Host` on a path the router does not otherwise
/// handle must still be refused before the fallback's `404` is reached.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_foreign_origin_or_host_is_refused_even_on_an_unmatched_path() {
    let d = daemon("").await;
    let addr = d.gateway_addr();
    let (code, text) = raw(addr, "GET", "/nope", &[("Origin", "https://evil.example")]).await;
    assert_eq!(code, 403, "{text}");
    assert!(text.contains("origin_not_allowed"), "{text}");
    let (code, text) = raw(addr, "GET", "/nope", &[("Host", "evil.example")]).await;
    assert_eq!(code, 403, "{text}");
    assert!(text.contains("host_not_allowed"), "{text}");
    d.stop().await;
}
