//! Spec §10.4, §13: with a TRACE subscriber capturing every log line, run
//! sanitize, rehydrate, a blocked request, bad requests, and a sweep
//! against the daemon; the canary name and IBAN, and the tokens minted for
//! them, never appear in the captured logs or in any error body.

mod common;

use std::time::Duration;

use common::*;
use hyper::Method;
use serde_json::json;

const CANARY_NAME: &str = "Zyxwuria Quolnath";
const CANARY_IBAN: &str = "AT61 1904 3002 3457 3201";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logs_and_error_bodies_never_contain_request_text() {
    let cap = Capture::new();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(cap.clone())
        .init();

    // A dictionary so the offline profile detects the canary name.
    let dict = tempfile::tempdir().unwrap();
    let persons = dict.path().join("persons.txt");
    std::fs::write(&persons, format!("{CANARY_NAME}\n")).unwrap();
    let base = BASE_CONFIG.replace(
        "persons = []",
        &format!("persons = [\"{}\"]", persons.display()),
    );
    assert_ne!(base, BASE_CONFIG, "the dictionary line was replaced");
    // `blocky` pins its own `retry_profile`: without it, `extends = "offline"`
    // inherits `verifier.retry_profile = "offline-strict"`, whose entities
    // table has no IBAN override, so the engine's automatic retry would pass
    // the retry profile's tokenize action through and the block would never
    // surface (same adaptation as `api.rs`'s `blocked_request_is_451_...`).
    let config = format!(
        "{base}\n[daemon]\ndefault_profile = \"offline\"\n[vault]\nkey_source = \"file\"\n[gateway]\nlisten = \"127.0.0.1:0\"\n\
         [profiles.blocky]\nextends = \"offline\"\n[profiles.blocky.entities]\nIBAN = {{ action = \"block\", min_confidence = 0.0 }}\n\
         [profiles.blocky.verifier]\nretry_profile = \"blocky\"\n"
    );
    let d = start_with_config(config, None, Duration::from_millis(200), None).await;
    d.dataset("mail").await;
    let text = format!("Hallo {CANARY_NAME}, IBAN {CANARY_IBAN}, danke.");

    let mut error_bodies: Vec<String> = Vec::new();
    let (code, a) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "dataset": "mail", "text": text })),
        )
        .await;
    assert_eq!(code, 200, "{a}");
    let sanitized = a["text"].as_str().unwrap().to_string();
    assert!(
        !sanitized.contains("Zyxwuria") && !sanitized.contains("AT61"),
        "{sanitized}"
    );
    let tokens: Vec<String> = sanitized
        .split_whitespace()
        .filter(|w| w.starts_with('<'))
        .map(|w| w.trim_end_matches([',', '.']).to_string())
        .collect();
    assert_eq!(tokens.len(), 2, "{sanitized}");
    let (code, _) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "dataset": "mail", "text": text })),
        )
        .await;
    assert_eq!(code, 200, "cache hit path");
    let (code, s) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "session": "s", "text": text })),
        )
        .await;
    assert_eq!(code, 200, "{s}");
    let (code, b) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "session": "s", "profile": "blocky", "text": text })),
        )
        .await;
    assert_eq!(code, 451);
    error_bodies.push(b.to_string());
    // `/v1/inspect`: the default (metadata-only) call must stay out of the
    // logs like every other request; the `show_values` call is allowed to
    // carry the canary in its *response* (a labelled local diagnostic), but
    // never in the log, so its body is deliberately not added to
    // `error_bodies` (which the canary sweep below checks against).
    let (code, ib) = d
        .call(
            Method::POST,
            "/v1/inspect",
            Some(json!({ "dataset": "mail", "text": text })),
        )
        .await;
    assert_eq!(code, 200, "{ib}");
    assert!(
        !ib.to_string().contains("Zyxwuria") && !ib.to_string().contains("AT61"),
        "{ib}"
    );
    let (code, _) = d
        .call(
            Method::POST,
            "/v1/inspect",
            Some(json!({ "dataset": "mail", "text": text, "show_values": true })),
        )
        .await;
    assert_eq!(code, 200);
    let (code, r) = d
        .call(
            Method::POST,
            "/v1/rehydrate",
            Some(json!({ "dataset": "mail", "text": sanitized })),
        )
        .await;
    assert_eq!(code, 200);
    assert_eq!(
        r["text"], text,
        "rehydration returns the originals to the caller, not to the log"
    );
    for bad in [
        json!({ "text": text }),
        json!({ "dataset": "nope", "text": text }),
        json!({ "session": "s", "profile": "support-email", "text": text }),
        // serde type errors quote the offending value; the API must not (review C1)
        json!({ "session": "s", "text": [CANARY_NAME] }),
    ] {
        let (code, b) = d.call(Method::POST, "/v1/sanitize", Some(bad)).await;
        assert!(code >= 400, "{b}");
        error_bodies.push(b.to_string());
    }
    let (code, b) = d
        .call(
            Method::POST,
            "/v1/datasets",
            Some(json!({ "id": "x", "name": "y", "rotation_days": CANARY_NAME })),
        )
        .await;
    assert_eq!(code, 400, "{b}");
    error_bodies.push(b.to_string());
    // Review Focus 7 / M4 spec §5.4: raw paths, query strings, path
    // parameters, and user-chosen dataset slugs never reach the access log;
    // only route templates and opaque ids do.
    let (code, _) = d
        .call(Method::GET, "/v1/nope?name=Zyxwuria%20Quolnath", None)
        .await;
    assert_eq!(code, 404);
    let (code, _) = d
        .call(Method::POST, "/v1/datasets/Zyxwuria/rotate", None)
        .await;
    assert_eq!(code, 404);
    let (code, b) = d
        .call(
            Method::POST,
            "/v1/datasets",
            Some(json!({ "id": "qwxzvk-canary-slug", "name": "x" })),
        )
        .await;
    assert_eq!(code, 201, "{b}");
    let (code, _) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "dataset": "qwxzvk-canary-slug", "text": text })),
        )
        .await;
    assert_eq!(code, 200);
    // Cache hit for the canary dataset (Review Focus 7): the second call is
    // served from the cache, exercising `CacheKey`'s Debug and the cache's
    // own tracing without ever naming the slug.
    let (code, _) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "dataset": "qwxzvk-canary-slug", "text": text })),
        )
        .await;
    assert_eq!(code, 200, "cache hit path for the canary dataset");
    let (code, _) = d
        .call(Method::POST, "/v1/datasets/qwxzvk-canary-slug/rotate", None)
        .await;
    assert_eq!(code, 200);
    let (code, _) = d
        .call(Method::DELETE, "/v1/datasets/qwxzvk-canary-slug", None)
        .await;
    assert_eq!(code, 204);
    // Dataset-not-found for the canary slug, now that it is deleted: the
    // `VaultError::DatasetNotFound` path must not echo the slug either.
    let (code, b) = d
        .call(Method::POST, "/v1/datasets/qwxzvk-canary-slug/rotate", None)
        .await;
    assert_eq!(code, 404, "{b}");
    error_bodies.push(b.to_string());

    tokio::time::sleep(Duration::from_millis(500)).await; // at least one sweep
    d.stop().await;

    // Review M1: `CreateBody`'s hand-written `Debug` must not print the
    // display name either, in case something ever logs a request body.
    let create_debug = format!(
        "{:?}",
        inumakid::api::datasets::CreateBody {
            id: "mail".into(),
            name: CANARY_NAME.into(),
            profile: None,
            rotation_days: None,
            grace_days: None,
            kind: None,
            allow_binary: None,
        }
    );
    assert!(
        !create_debug.contains("Zyxwuria") && !create_debug.contains("Quolnath"),
        "{create_debug}"
    );

    let logs = cap.text();
    assert!(
        logs.contains("access"),
        "the subscriber captured the daemon's logs:\n{logs}"
    );
    assert!(logs.contains("sweep"), "a sweep ran:\n{logs}");
    for needle in [
        "Zyxwuria",
        "Quolnath",
        "AT61",
        "1904 3002",
        "3457 3201",
        "qwxzvk",
        "/v1/nope",
        "name=",
    ] {
        assert!(
            !logs.contains(needle),
            "{needle} leaked into the logs:\n{logs}"
        );
        for body in &error_bodies {
            assert!(
                !body.contains(needle),
                "{needle} leaked into an error body: {body}"
            );
        }
    }
    for t in &tokens {
        assert!(
            !logs.contains(t.as_str()),
            "token {t} leaked into the logs:\n{logs}"
        );
    }
    assert!(
        logs.contains("route=/v1/datasets/{id}/rotate")
            || logs.contains("route=\"/v1/datasets/{id}/rotate\""),
        "route templates are logged:\n{logs}"
    );
    assert!(
        logs.contains("unmatched"),
        "unknown paths are logged as unmatched:\n{logs}"
    );
}
