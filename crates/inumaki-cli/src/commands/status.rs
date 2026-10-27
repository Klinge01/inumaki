//! `inumaki status`.

use std::path::Path;

use anyhow::{Result, bail};
use hyper::Method;

use crate::client::{call, connect, error_line};
use crate::exit;

pub fn run(
    socket: Option<&Path>,
    data_dir: Option<&Path>,
    config: Option<&Path>,
    json: bool,
) -> Result<u8> {
    let c = connect(socket, data_dir, config)?;
    let r = call(&c, Method::GET, "/v1/status", None)?;
    if !r.status.is_success() {
        bail!("{}", error_line(&r));
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&r.body)?);
        return Ok(exit::OK);
    }
    let b = &r.body;
    println!(
        "inumakid {}  uptime {}s",
        b["version"].as_str().unwrap_or("?"),
        b["uptime_s"]
    );
    println!("data dir   {}", b["data_dir"].as_str().unwrap_or("?"));
    println!("socket     {}", b["socket"].as_str().unwrap_or("?"));
    println!("keys       {}", b["key_source"].as_str().unwrap_or("?"));
    if let Some(src) = b["config_source"].as_str() {
        println!("config     {src}");
    }
    println!("models");
    for m in b["models"].as_array().into_iter().flatten() {
        println!(
            "  {:<18} threads {:<3} sessions {:<3} pool waits {}",
            m["name"].as_str().unwrap_or("?"),
            m["threads"],
            m["sessions"],
            m["pool_waits"]
        );
    }
    println!("profiles");
    for p in b["profiles"].as_array().into_iter().flatten() {
        let avail = p["available"].as_bool().unwrap_or(false);
        println!(
            "  {:<18} {}{}",
            p["name"].as_str().unwrap_or("?"),
            if avail { "available" } else { "unavailable" },
            p["reason"]
                .as_str()
                .map(|r| format!("  ({r})"))
                .unwrap_or_default()
        );
    }
    println!("datasets");
    for d in b["datasets"].as_array().into_iter().flatten() {
        println!(
            "  {:<18} {:<14} epoch {} since {}  entries {}",
            d["id"].as_str().unwrap_or("?"),
            d["profile"].as_str().unwrap_or("?"),
            d["epoch_id"],
            d["epoch_started_at"],
            d["entries"]
        );
    }
    println!("sessions   {}", b["sessions"]);
    let cache = &b["cache"];
    println!(
        "cache      hits {} misses {} bytes {} evictions {}",
        cache["hits"], cache["misses"], cache["bytes"], cache["evictions"]
    );
    println!("pool waits {}", b["pool_waits"]);
    let g = &r.body["gateway"];
    println!(
        "gateway {}  tokens {}  qualification {}",
        g["listen"].as_str().unwrap_or("?"),
        g["tokens"],
        g["qualification"].as_str().unwrap_or("?")
    );
    let activity_dropped = g["activity_dropped"].as_u64().unwrap_or(0);
    if activity_dropped > 0 {
        println!("activity records dropped: {activity_dropped}");
    }
    let journal_dropped = g["journal_dropped"].as_u64().unwrap_or(0);
    if journal_dropped > 0 {
        println!("journal entries dropped: {journal_dropped}");
    }
    for d in g["datasets"].as_array().into_iter().flatten() {
        println!(
            "  {}: calls {} blocked {} uncertain {} unresolved {} unsupported {} limited {} clear-value hits {}",
            d["id"].as_str().unwrap_or(""),
            d["calls"],
            d["blocked"],
            d["uncertain"],
            d["unresolved"],
            d["unsupported"],
            d["limited"],
            d["clear_value_hits"]
        );
        for u in d["upstreams"].as_array().into_iter().flatten() {
            println!(
                "    {:<20} {:<6} {:<12} restarts {} stderr {} B contract {}",
                u["name"].as_str().unwrap_or(""),
                u["kind"].as_str().unwrap_or(""),
                u["state"].as_str().unwrap_or(""),
                u["restarts"],
                u["stderr_bytes"],
                u["contract"].as_str().unwrap_or("")
            );
        }
    }
    // M8 spec decision 22: one proxy line. The client header value is never printed.
    let p = call(&c, Method::GET, "/v1/proxy", None)?;
    if p.status.is_success() {
        println!("{}", proxy_line(&p.body));
        println!("{}", proxy_timing_line(&p.body));
    }
    // The MCP server name is model-visible (Claude Code prefixes it to
    // every tool name): it is the opaque dataset label, never the slug.
    for d in r.body["datasets"].as_array().into_iter().flatten() {
        let id = d["id"].as_str().unwrap_or("");
        let label = d["label"].as_str().unwrap_or("");
        println!(
            "connect: server inumaki-{label} at http://{}/mcp/{id} with header \"Authorization: Bearer <token from inumaki gateway token new>\"; or run: inumaki connect apply HARNESS",
            g["listen"].as_str().unwrap_or("127.0.0.1:8789")
        );
    }
    Ok(exit::OK)
}

/// The one `proxy` line of `inumaki status` (M8 spec decision 22), built from the
/// `GET /v1/proxy` body. It prints the state, the listen address the daemon
/// reports, counters, and the Codex login verification; never the client
/// header value, base URLs, or any error detail.
fn proxy_line(b: &serde_json::Value) -> String {
    let routes: Vec<String> = b["routes"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|r| {
            format!(
                "{} {} {}",
                r["upstream"].as_str().unwrap_or("?"),
                r["state"].as_str().unwrap_or("?"),
                r["requests"]
            )
        })
        .collect();
    format!(
        "proxy {} {}  sessions {}  cache hits {} misses {}  {}  codex-chatgpt {}",
        b["state"].as_str().unwrap_or("?"),
        b["listen"].as_str().unwrap_or("?"),
        b["sessions"],
        b["incremental_cache"]["hits"],
        b["incremental_cache"]["misses"],
        routes.join(", "),
        if b["oauth"]["codex_chatgpt"]["verified_in_build"] == true {
            "verified"
        } else {
            "unverified"
        }
    )
}

/// The second `proxy` line (spec §20 amendment 2026-10-12, Part 2): where the
/// last request's time went, the window's medians and 95th percentiles, and
/// the static-prompt cache counters, built from the `timing` and
/// `static_cache` objects of the `GET /v1/proxy` body. Only durations and
/// counts; `-` stands for a `null` (or a daemon that does not report it).
fn proxy_timing_line(b: &serde_json::Value) -> String {
    let t = &b["timing"];
    if t["window"].as_u64().unwrap_or(0) == 0 {
        return "proxy timing  no requests yet".to_string();
    }
    let ms = |s: &serde_json::Value, field: &str| -> String {
        s[field]
            .as_u64()
            .map_or_else(|| "-".to_string(), |v| format!("{v}ms"))
    };
    let (last, p50, p95) = (&t["last"], &t["p50"], &t["p95"]);
    let c = &b["static_cache"];
    let n = |field: &str| c[field].as_u64().unwrap_or(0);
    format!(
        "proxy timing  last {} (local {}: engine {}, closure {}, scan {}, queue {}; provider {}, first byte {})  p50 local {} provider {}  p95 local {}  static cache hits {} misses {} clears {}",
        ms(last, "total_ms"),
        ms(last, "local_ms"),
        ms(last, "engine_ms"),
        ms(last, "closure_ms"),
        ms(last, "scan_ms"),
        ms(last, "queue_ms"),
        ms(last, "provider_ms"),
        ms(last, "first_byte_ms"),
        ms(p50, "local_ms"),
        ms(p50, "provider_ms"),
        ms(p95, "local_ms"),
        n("hits"),
        n("misses"),
        n("clears"),
    )
}

#[cfg(test)]
mod tests {
    use inumaki_client::ProxyBody;
    use inumaki_core::config::TokenSettings;
    use inumaki_proxy::ListenState;
    use inumaki_proxy::UpstreamId;
    use inumaki_proxy::status::{OauthUse, Outcome, Status};
    use inumaki_proxy::timing::{RequestTiming, StaticCacheBody};
    use std::time::Duration;

    use super::{proxy_line, proxy_timing_line};
    use crate::commands::bench_proxy::config;

    /// The line is built from the daemon's real serializer output, not a hand
    /// written fixture: renaming a field of `GET /v1/proxy` fails here. The
    /// body must also still parse as the client's `ProxyBody`.
    #[test]
    fn proxy_line_renders_the_real_body_and_prints_no_client_value() {
        const CLIENT_VALUE: &str = "client-value-sentinel-7c1e";
        let st = Status::new();
        st.request(
            UpstreamId::Anthropic,
            inumaki_proxy::ClientKind::Other,
            OauthUse::None,
        );
        st.outcome(UpstreamId::Anthropic, Outcome::Ok, OauthUse::None);
        st.cache(7, 3);
        let listen = ListenState::Running(([127, 0, 0, 1], 48123).into());
        let body = st.body(
            &config("offline", TokenSettings::default()),
            &listen,
            2,
            5,
            0,
            CLIENT_VALUE,
            StaticCacheBody::new(true, None),
        );
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["client_header"]["value"], CLIENT_VALUE);
        serde_json::from_value::<ProxyBody>(json.clone()).expect("the client parses the real body");

        let line = proxy_line(&json);
        assert!(
            line.starts_with("proxy running 127.0.0.1:48123  sessions 2  cache hits 7 misses 3  "),
            "{line}"
        );
        assert!(line.contains("anthropic ok 1"), "{line}");
        assert!(line.contains("openai idle 0"), "{line}");
        assert!(line.contains("openai-codex idle 0"), "{line}");
        assert_eq!(
            json["oauth"]["codex_chatgpt"]["verified_in_build"],
            inumaki_proxy::CODEX_CHATGPT_VERIFIED
        );
        let expected = if inumaki_proxy::CODEX_CHATGPT_VERIFIED {
            "codex-chatgpt verified"
        } else {
            "codex-chatgpt unverified"
        };
        assert!(line.ends_with(expected), "{line}");
        assert!(
            !line.contains('?'),
            "a field name no longer matches the body: {line}"
        );
        assert!(!line.contains(CLIENT_VALUE), "{line}");
        assert!(!line.contains("http://"), "{line}");
    }
    /// One sample whose stages are 1, 2, 3, 4, 5 and 6 ms (read, queue, scan,
    /// engine, closure, restore), with a provider time only when forwarded.
    fn sample(forwarded: bool) -> RequestTiming {
        let ms = Duration::from_millis;
        RequestTiming {
            total: ms(100),
            read: ms(1),
            queue: ms(2),
            scan: ms(3),
            engine: ms(4),
            closure: ms(5),
            project: ms(2),
            first_byte: forwarded.then(|| ms(30)),
            provider: forwarded.then(|| ms(60)),
            restore: ms(6),
        }
    }

    fn real_body(st: &Status, memo: Option<inumaki_proxy::memo::MemoStats>) -> serde_json::Value {
        let body = st.body(
            &config("offline", TokenSettings::default()),
            &ListenState::Disabled,
            0,
            0,
            0,
            "client-value-sentinel-7c1e",
            StaticCacheBody::new(true, memo),
        );
        let json = serde_json::to_value(&body).unwrap();
        serde_json::from_value::<ProxyBody>(json.clone()).expect("the client parses the real body");
        json
    }

    /// The timing line is built from the daemon's real serializer output: a
    /// renamed field shows up as `-` or `?` here. No request: one fixed
    /// sentence. A refused request has no provider time: `-`.
    #[test]
    fn proxy_timing_line_renders_the_real_body() {
        let st = Status::new();
        assert_eq!(
            proxy_timing_line(&real_body(&st, None)),
            "proxy timing  no requests yet"
        );

        st.timing(sample(true));
        let memo = inumaki_proxy::memo::MemoStats {
            hits: 5,
            misses: 2,
            entries: 2,
            clears: 1,
        };
        let line = proxy_timing_line(&real_body(&st, Some(memo)));
        assert_eq!(
            line,
            "proxy timing  last 100ms (local 21ms: engine 4ms, closure 5ms, scan 3ms, queue 2ms; provider 60ms, first byte 30ms)  p50 local 21ms provider 60ms  p95 local 21ms  static cache hits 5 misses 2 clears 1"
        );

        // Not forwarded: provider and first byte are null; the p50 provider
        // is the one forwarded sample's, since nulls are skipped.
        st.timing(sample(false));
        let line = proxy_timing_line(&real_body(&st, Some(memo)));
        assert!(
            line.contains(
                "; provider -, first byte -)  p50 local 21ms provider 60ms  p95 local 21ms  "
            ),
            "{line}"
        );
        assert!(
            !line.contains('?') && !line.contains("client-value"),
            "{line}"
        );
    }

    /// A daemon from before the amendment sends neither object.
    #[test]
    fn proxy_timing_line_tolerates_a_body_without_the_objects() {
        let json = serde_json::json!({"state": "running"});
        assert_eq!(proxy_timing_line(&json), "proxy timing  no requests yet");
    }
}
