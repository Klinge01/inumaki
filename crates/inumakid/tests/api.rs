mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use common::*;
use hyper::Method;
use inumaki_vault::Clock;
use serde_json::json;

const IBAN_TEXT: &str = "IBAN AT61 1904 3002 3457 3201 bitte.";

fn token_in(text: &str, prefix: &str) -> String {
    text.split_whitespace()
        .find(|w| w.starts_with(prefix))
        .map(|w| w.trim_end_matches(['.', ',']).to_string())
        .unwrap_or_else(|| panic!("no {prefix} token in {text}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_reports_profiles_models_and_data_dir() {
    let d = start().await;
    let (code, body) = d.call(Method::GET, "/v1/status", None).await;
    assert_eq!(code, 200);
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    assert!(body["uptime_s"].is_number());
    assert_eq!(
        body["data_dir"],
        d.dir.path().join("data").to_string_lossy().to_string()
    );
    assert_eq!(body["socket"], d.socket.to_string_lossy().to_string());
    assert_eq!(body["key_source"], "file");
    let profiles = body["profiles"].as_array().unwrap();
    assert!(
        profiles
            .iter()
            .any(|p| p["name"] == "offline" && p["available"] == true)
    );
    let se = profiles
        .iter()
        .find(|p| p["name"] == "support-email")
        .unwrap();
    assert_eq!(se["available"], false);
    assert!(
        se["reason"]
            .as_str()
            .unwrap()
            .contains("inumaki models pull"),
        "{se}"
    );
    assert!(body["models"].as_array().unwrap().is_empty());
    assert_eq!(body["sessions"], 0);
    assert_eq!(body["cache"]["hits"], 0);
    assert_eq!(body["pool_waits"], 0);
    assert!(body["datasets"].as_array().unwrap().is_empty());
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dataset_lifecycle_over_the_api() {
    let d = start().await;
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets",
            Some(json!({ "id": "mail", "name": "Musterkunde GmbH" })),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    assert_eq!(body["id"], "mail");
    assert_eq!(body["name"], "Musterkunde GmbH");
    assert_eq!(
        body["profile"], "offline",
        "defaults to daemon.default_profile"
    );
    assert_eq!(body["rotation_days"], 30);
    assert_eq!(body["grace_days"], 7);
    assert_eq!(body["entries"], 0);
    let epoch = body["epoch_id"].as_i64().unwrap();
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets",
            Some(json!({ "id": "mail", "name": "again" })),
        )
        .await;
    assert_eq!(code, 409);
    assert_eq!(body["error"]["type"], "conflict");
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets",
            Some(json!({ "id": "Bad Id", "name": "x" })),
        )
        .await;
    assert_eq!(code, 400);
    assert_eq!(body["error"]["type"], "bad_request");
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets",
            Some(json!({ "id": "x", "name": "x", "profile": "nope" })),
        )
        .await;
    assert_eq!(code, 400, "{body}");
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets",
            Some(json!({ "id": "files", "name": "F", "profile": "offline", "rotation_days": 1, "grace_days": 0 })),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    let (code, body) = d.call(Method::GET, "/v1/datasets", None).await;
    assert_eq!(code, 200);
    let ids: Vec<&str> = body
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["id"].as_str().unwrap())
        .collect();
    // M6 §9 amendment (M8 spec §9): the proxy's reserved dataset is listed.
    assert_eq!(ids, ["files", "inumaki-chat", "mail"]);
    let (code, body) = d.call(Method::POST, "/v1/datasets/mail/rotate", None).await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["old_epoch"], epoch);
    assert!(body["new_epoch"].as_i64().unwrap() > epoch);
    let (code, body) = d.call(Method::DELETE, "/v1/datasets/mail", None).await;
    assert_eq!((code, body), (204, serde_json::Value::Null));
    let (code, body) = d.call(Method::DELETE, "/v1/datasets/mail", None).await;
    assert_eq!(code, 404);
    assert_eq!(body["error"]["type"], "not_found");
    let (code, _) = d.call(Method::POST, "/v1/datasets/mail/rotate", None).await;
    assert_eq!(code, 404);
    let (_, body) = d.call(Method::GET, "/v1/status", None).await;
    assert_eq!(body["datasets"].as_array().unwrap().len(), 1);
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sanitize_and_rehydrate_with_a_dataset_and_the_cache() {
    let d = start().await;
    d.dataset("mail").await;
    let (code, a) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "dataset": "mail", "text": IBAN_TEXT })),
        )
        .await;
    assert_eq!(code, 200, "{a}");
    assert_eq!(a["outcome"], "pass");
    assert_eq!(a["cached"], false);
    assert_eq!(a["replacements"], 1);
    assert_eq!(a["kinds"], json!(["IBAN"]));
    assert!(a["latency_ms"].is_number());
    let out = a["text"].as_str().unwrap().to_string();
    assert!(!out.contains("AT61"), "{out}");
    let tok = token_in(&out, "<IBAN_");
    assert_eq!(
        tok.len(),
        "<IBAN_".len() + 6 + 1,
        "namespace suffix is 6: {tok}"
    );

    let (code, b) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "dataset": "mail", "text": IBAN_TEXT })),
        )
        .await;
    assert_eq!(code, 200);
    assert_eq!(b["cached"], true);
    assert_eq!(b["text"], out);
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    assert_eq!(st["cache"]["hits"], 1);
    assert_eq!(st["cache"]["misses"], 1);
    assert_eq!(st["datasets"][0]["entries"], 1);

    let (code, r) = d
        .call(
            Method::POST,
            "/v1/rehydrate",
            Some(json!({ "dataset": "mail", "text": out })),
        )
        .await;
    assert_eq!(code, 200, "{r}");
    assert_eq!(r["text"], IBAN_TEXT);
    assert_eq!(r["unknown_tokens"], 0);
    d.stop().await;
}

/// Review Focus 5: a rotation invalidates cached results; the old token still
/// rehydrates during grace.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cache_misses_after_rotation() {
    let d = start().await;
    d.dataset("mail").await;
    let (_, a) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "dataset": "mail", "text": IBAN_TEXT })),
        )
        .await;
    let old = a["text"].as_str().unwrap().to_string();
    let (code, _) = d.call(Method::POST, "/v1/datasets/mail/rotate", None).await;
    assert_eq!(code, 200);
    let (code, b) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "dataset": "mail", "text": IBAN_TEXT })),
        )
        .await;
    assert_eq!(code, 200, "{b}");
    assert_eq!(b["cached"], false);
    assert_ne!(b["text"], old, "new epoch, new token");
    let (_, r) = d
        .call(
            Method::POST,
            "/v1/rehydrate",
            Some(json!({ "dataset": "mail", "text": old })),
        )
        .await;
    assert_eq!(r["text"], IBAN_TEXT, "grace period");
    assert_eq!(r["unknown_tokens"], 0);
    d.stop().await;
}

/// Review I2: the engine is deterministic given the text only within an
/// epoch's fixed knowledge; the namespace's knowledge grows with every
/// mint, so a cached `Pass` recorded while a name was unknown must not be
/// served once that name has since been minted from another document (the
/// known-entity detector would now tokenize it). The offline profile has no
/// NER, so a person mention it does not yet know stays in clear on the
/// first pass; minting the same name directly (standing in for a second
/// document that reached the vault first) must invalidate the cached hit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cache_hit_is_dropped_when_the_namespace_learns_the_name() {
    use inumaki_core::span::EntityKind;
    use inumaki_core::token::TokenStore;

    let d = start().await;
    d.dataset("mail").await;
    let text = "Bitte an Sarah Leitner weiterleiten.";

    let (code, a) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "dataset": "mail", "text": text })),
        )
        .await;
    assert_eq!(code, 200, "{a}");
    assert_eq!(a["cached"], false);
    assert!(
        a["text"].as_str().unwrap().contains("Sarah Leitner"),
        "offline has no NER and the name is not yet known: {a}"
    );

    // Mint the same name into the namespace directly, standing in for a
    // second document whose tokenization reached the vault first.
    {
        let ns = d.state.namespace("mail").unwrap();
        let mut n = ns.lock().unwrap();
        n.token_for(&EntityKind::Person, "Sarah Leitner").unwrap();
    }

    let (code, b) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "dataset": "mail", "text": text })),
        )
        .await;
    assert_eq!(code, 200, "{b}");
    assert_eq!(
        b["cached"], false,
        "the cache must not serve the clear-text result now that the name is known: {b}"
    );
    assert!(
        !b["text"].as_str().unwrap().contains("Sarah Leitner"),
        "now tokenized: {b}"
    );
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    assert_eq!(
        (st["cache"]["hits"].clone(), st["cache"]["misses"].clone()),
        (json!(0), json!(2)),
        "first pass misses on an empty cache, the second misses on disagreement: {st}"
    );
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sanitize_and_rehydrate_with_a_session() {
    let d = start().await;
    let (code, a) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "session": "s1", "text": IBAN_TEXT })),
        )
        .await;
    assert_eq!(code, 200, "{a}");
    assert_eq!(a["cached"], false);
    let out = a["text"].as_str().unwrap().to_string();
    let tok = token_in(&out, "<IBAN_");
    assert_eq!(
        tok.len(),
        "<IBAN_".len() + 4 + 1,
        "session suffix is 4: {tok}"
    );
    let (_, b) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "session": "s1", "text": IBAN_TEXT })),
        )
        .await;
    assert_eq!(b["cached"], false, "sessions are never cached");
    assert_eq!(b["text"], out, "same session, same token");
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    assert_eq!(st["sessions"], 1);
    assert_eq!(st["cache"]["misses"], 0);
    let (_, r) = d
        .call(
            Method::POST,
            "/v1/rehydrate",
            Some(json!({ "session": "s1", "text": out })),
        )
        .await;
    assert_eq!(r["text"], IBAN_TEXT);
    let (code, r) = d
        .call(
            Method::POST,
            "/v1/rehydrate",
            Some(json!({ "session": "s2", "text": out })),
        )
        .await;
    assert_eq!(code, 404, "another session that was never created: {r}");
    assert_eq!(r["error"]["type"], "context_unavailable");
    assert!(r.get("text").is_none());
    d.stop().await;
}

/// M4 spec §8: strict restoration is all-or-nothing on both stores and
/// reports counts only; permissive stays as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rehydrate_strict_on_dataset_and_session() {
    let d = start().await;
    d.dataset("mail").await;
    let (_, a) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "dataset": "mail", "text": IBAN_TEXT })),
        )
        .await;
    let out = a["text"].as_str().unwrap().to_string();
    let (code, r) = d
        .call(
            Method::POST,
            "/v1/rehydrate",
            Some(json!({ "dataset": "mail", "text": out, "strict": true })),
        )
        .await;
    assert_eq!(code, 200, "{r}");
    assert_eq!(r["text"], IBAN_TEXT);
    let bad = format!("{out} <PERSON_000000> <SECRET_REMOVED>");
    let (code, r) = d
        .call(
            Method::POST,
            "/v1/rehydrate",
            Some(json!({ "dataset": "mail", "text": bad, "strict": true })),
        )
        .await;
    assert_eq!(code, 422, "{r}");
    assert_eq!(r["error"]["type"], "unresolved_token");
    assert_eq!(r["error"]["unknown_tokens"], 1);
    assert_eq!(r["error"]["removed_markers"], 1);
    assert!(r.get("text").is_none() && !r.to_string().contains("AT61"));
    let (code, r) = d
        .call(
            Method::POST,
            "/v1/rehydrate",
            Some(json!({ "dataset": "mail", "text": bad })),
        )
        .await;
    assert_eq!(code, 200, "permissive: {r}");
    assert_eq!(r["unknown_tokens"], 1);
    assert_eq!(r["removed_markers"], 1);
    let (_, s) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "session": "s1", "text": IBAN_TEXT })),
        )
        .await;
    let sout = s["text"].as_str().unwrap().to_string();
    let (code, r) = d
        .call(
            Method::POST,
            "/v1/rehydrate",
            Some(json!({ "session": "s1", "text": format!("{sout} <IBAN_0000>"), "strict": true })),
        )
        .await;
    assert_eq!(code, 422, "{r}");
    assert_eq!(r["error"]["unknown_tokens"], 1);
    let (code, r) = d
        .call(
            Method::POST,
            "/v1/rehydrate",
            Some(json!({ "session": "s1", "text": sout, "strict": true })),
        )
        .await;
    assert_eq!(code, 200, "{r}");
    assert_eq!(r["text"], IBAN_TEXT);
    d.stop().await;
}

/// Review Focus 3: a session that expired between sanitize and rehydrate is
/// `context_unavailable`, never a fresh empty session that leaves tokens in place.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rehydrate_of_an_expired_session_is_context_unavailable() {
    let d = start_with("session_ttl = \"1s\"", "", Duration::from_secs(3600), None).await;
    let (_, s) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "session": "s1", "text": IBAN_TEXT })),
        )
        .await;
    let out = s["text"].as_str().unwrap().to_string();
    tokio::time::sleep(Duration::from_millis(1300)).await;
    for strict in [false, true] {
        let (code, r) = d
            .call(
                Method::POST,
                "/v1/rehydrate",
                Some(json!({ "session": "s1", "text": out, "strict": strict })),
            )
            .await;
        assert_eq!(code, 404, "strict={strict}: {r}");
        assert_eq!(r["error"]["type"], "context_unavailable");
    }
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    assert_eq!(
        st["sessions"], 0,
        "the expired session was dropped, not recreated"
    );
    d.stop().await;
}

/// Review Focus 1: a token from another dataset is neither rehydrated nor
/// treated as a leak.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rehydrate_leaves_foreign_tokens_alone() {
    let d = start().await;
    d.dataset("a").await;
    d.dataset("b").await;
    let (_, a) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "dataset": "a", "text": IBAN_TEXT })),
        )
        .await;
    let tok = token_in(a["text"].as_str().unwrap(), "<IBAN_");
    let pasted = format!("Bitte {tok} prüfen.");
    let (code, b) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "dataset": "b", "text": pasted })),
        )
        .await;
    assert_eq!(code, 200, "{b}");
    assert_eq!(
        b["text"], pasted,
        "a foreign token passes through untouched"
    );
    let (_, r) = d
        .call(
            Method::POST,
            "/v1/rehydrate",
            Some(json!({ "dataset": "b", "text": pasted })),
        )
        .await;
    assert_eq!(r["text"], pasted);
    assert_eq!(r["unknown_tokens"], 1);
    let (_, r) = d
        .call(
            Method::POST,
            "/v1/rehydrate",
            Some(json!({ "dataset": "a", "text": pasted })),
        )
        .await;
    assert_eq!(r["text"], "Bitte AT61 1904 3002 3457 3201 prüfen.");
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocked_request_is_451_with_kinds_and_checks_only() {
    // `blocky` also pins its own `retry_profile`: without it, `extends =
    // "offline"` inherits `verifier.retry_profile = "offline-strict"`, whose
    // own entities table has no IBAN override, so the engine's automatic
    // retry (spec §9.1) would pass the retry profile's tokenize action
    // through and the first pass's block would never surface (adaptation:
    // the brief's config for this test omits this and does not 451).
    let d = start_with(
        "",
        "[profiles.blocky]\nextends = \"offline\"\n[profiles.blocky.entities]\nIBAN = { action = \"block\", min_confidence = 0.0 }\n[profiles.blocky.verifier]\nretry_profile = \"blocky\"\n",
        Duration::from_secs(3600),
        None,
    )
    .await;
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "session": "s", "profile": "blocky", "text": IBAN_TEXT })),
        )
        .await;
    assert_eq!(code, 451, "{body}");
    assert_eq!(body["error"]["type"], "privacy_block");
    assert_eq!(body["error"]["kinds"], json!(["IBAN"]));
    assert_eq!(body["error"]["checks"], json!(["Policy"]));
    assert!(!body.to_string().contains("AT61"), "{body}");
    // the same through a dataset is cached as blocked and still 451
    d.dataset("mail").await;
    for _ in 0..2 {
        let (code, body) = d
            .call(
                Method::POST,
                "/v1/sanitize",
                Some(json!({ "dataset": "mail", "profile": "blocky", "text": IBAN_TEXT })),
            )
            .await;
        assert_eq!(code, 451, "{body}");
        assert!(!body.to_string().contains("AT61"));
    }
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unavailable_profile_is_503_naming_the_pull_command() {
    let d = start().await;
    for body in [
        json!({ "session": "s", "profile": "support-email", "text": "x" }),
        json!({ "dataset": "mail", "text": "x" }),
    ] {
        if body.get("dataset").is_some() {
            let (code, b) = d
                .call(
                    Method::POST,
                    "/v1/datasets",
                    Some(json!({ "id": "mail", "name": "M", "profile": "support-email" })),
                )
                .await;
            assert_eq!(code, 201, "{b}");
        }
        let (code, b) = d.call(Method::POST, "/v1/sanitize", Some(body)).await;
        assert_eq!(code, 503, "{b}");
        assert_eq!(b["error"]["type"], "model_unavailable");
        assert!(
            b["error"]["message"]
                .as_str()
                .unwrap()
                .contains("inumaki models pull"),
            "{b}"
        );
    }
    d.stop().await;
}

/// Plan 2c final review, item B: a session's primary profile is never a
/// metadata profile either, the same rule `sanitize_blocks` enforces for a
/// dataset's (service.rs "Fix round 1, finding 1"); `sanitize_session`
/// bypasses `sanitize_blocks` entirely, so it needs its own guard.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_sanitize_refuses_a_metadata_profile() {
    let d = start_with(
        "",
        "[profiles.p]\nextends = \"offline\"\n\
         [profiles.p-md]\nextends = \"p\"\nmetadata_of = \"p\"\nescalate_below = 1.0\n\
         [profiles.p-md.entities]\nPERSON = { action = \"tokenize\", min_confidence = 0.65 }\n\
         [profiles.p-md.verifier]\nretry_profile = \"p-md\"\n",
        Duration::from_secs(3600),
        None,
    )
    .await;
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "session": "s", "profile": "p-md", "text": "Max Mustermann" })),
        )
        .await;
    assert_eq!(code, 422, "{body}");
    assert_eq!(body["error"]["type"], "unsupported_content");
    assert_eq!(body["error"]["message"], "unsupported: metadata_profile");
    assert!(!body.to_string().contains("Max Mustermann"), "{body}");
    // the dataset path (`sanitize_blocks`) already refuses the same profile
    d.dataset("mail").await;
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "dataset": "mail", "profile": "p-md", "text": "x" })),
        )
        .await;
    assert_eq!(code, 422, "{body}");
    assert_eq!(body["error"]["message"], "unsupported: metadata_profile");
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bad_requests_are_400_or_404_with_the_error_shape() {
    let d = start().await;
    for body in [
        json!({ "text": "x" }),
        json!({ "dataset": "mail", "session": "s", "text": "x" }),
        json!({ "session": "s" }),
    ] {
        let (code, b) = d.call(Method::POST, "/v1/sanitize", Some(body)).await;
        assert_eq!(code, 400, "{b}");
        assert_eq!(b["error"]["type"], "bad_request");
        assert!(b["error"]["checks"].is_array());
    }
    let r = d
        .client
        .call_raw(Method::POST, "/v1/sanitize", b"{not json".to_vec())
        .await
        .unwrap();
    assert_eq!(r.status.as_u16(), 400);
    assert_eq!(r.body["error"]["type"], "bad_request");
    let (code, b) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "dataset": "nope", "text": "x" })),
        )
        .await;
    assert_eq!(code, 404, "{b}");
    let (code, _) = d
        .call(
            Method::POST,
            "/v1/rehydrate",
            Some(json!({ "dataset": "nope", "text": "x" })),
        )
        .await;
    assert_eq!(code, 404);
    let (code, b) = d.call(Method::GET, "/v1/nope", None).await;
    assert_eq!(code, 404, "{b}");
    assert_eq!(b["error"]["type"], "not_found");
    let (code, b) = d.call(Method::DELETE, "/v1/status", None).await;
    assert_eq!(code, 405, "{b}");
    assert_eq!(b["error"]["type"], "method_not_allowed");
    d.stop().await;
}

/// Review Focus 6: exactly the limit is accepted, one byte more is 413.
/// Uses `/v1/rehydrate` (one regex pass) so a debug-build test stays fast;
/// the limit layer is the same for every route.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn body_limit_boundary() {
    let d = start().await;
    // Rehydrate never creates a session (M4 spec §5.3): give it one to know first.
    d.call(
        Method::POST,
        "/v1/sanitize",
        Some(json!({ "session": "s", "text": "x" })),
    )
    .await;
    let limit = inumakid::api::BODY_LIMIT;
    let base = serde_json::to_vec(&json!({ "session": "s", "text": "" })).unwrap();
    let make = |total: usize| {
        let text = "x".repeat(total - base.len());
        serde_json::to_vec(&json!({ "session": "s", "text": text })).unwrap()
    };
    let exact = make(limit);
    assert_eq!(exact.len(), limit);
    let r = d
        .client
        .call_raw(Method::POST, "/v1/rehydrate", exact)
        .await
        .unwrap();
    assert_eq!(r.status.as_u16(), 200, "{:?}", r.body["error"]);
    assert_eq!(r.body["text"].as_str().unwrap().len(), limit - base.len());
    let over = make(limit + 1);
    assert_eq!(over.len(), limit + 1);
    let r = d
        .client
        .call_raw(Method::POST, "/v1/rehydrate", over)
        .await
        .unwrap();
    assert_eq!(r.status.as_u16(), 413);
    assert_eq!(r.body["error"]["type"], "payload_too_large");
    assert!(r.body["error"]["kinds"].is_array() && r.body["error"]["checks"].is_array());
    d.stop().await;
}

struct FakeClock(AtomicI64);
impl Clock for FakeClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sweeper_rotates_due_datasets_and_expires_sessions() {
    let clock = Arc::new(FakeClock(AtomicI64::new(1_700_000_000)));
    let c: Arc<dyn Clock> = Arc::clone(&clock) as Arc<dyn Clock>;
    let d = start_with(
        "session_ttl = \"1s\"",
        "",
        Duration::from_millis(200),
        Some(c),
    )
    .await;
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets",
            Some(json!({ "id": "mail", "name": "M", "rotation_days": 1, "grace_days": 0 })),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    let epoch = body["epoch_id"].as_i64().unwrap();
    let (_, a) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "dataset": "mail", "text": IBAN_TEXT })),
        )
        .await;
    d.call(
        Method::POST,
        "/v1/sanitize",
        Some(json!({ "session": "s", "text": IBAN_TEXT })),
    )
    .await;
    clock.0.fetch_add(86_400, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1600)).await;
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    assert!(
        st["datasets"][0]["epoch_id"].as_i64().unwrap() > epoch,
        "rotated by the sweeper: {st}"
    );
    assert_eq!(st["sessions"], 0, "expired by the sweeper");
    let (_, b) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "dataset": "mail", "text": IBAN_TEXT })),
        )
        .await;
    assert_eq!(b["cached"], false);
    assert_ne!(b["text"], a["text"]);
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_endpoint_stops_the_daemon_and_removes_the_socket() {
    let d = start().await;
    let (code, body) = d.call(Method::POST, "/v1/shutdown", None).await;
    assert_eq!(code, 202);
    assert_eq!(body["status"], "shutting_down");
    let socket = d.socket.clone();
    let task_result = tokio::time::timeout(Duration::from_secs(8), d.task).await;
    assert!(
        task_result.is_ok(),
        "server task ended within the grace period"
    );
    assert!(!socket.exists(), "socket file removed");
    assert!(
        d.client
            .call(Method::GET, "/v1/status", None)
            .await
            .is_err()
    );
}

/// Review Focus 4: a dataset deleted underneath an open namespace handle
/// (here through the vault directly, bypassing `AppState::delete_dataset`,
/// which would close the handle first) ends the request with an error body
/// that carries no text, and the daemon keeps serving.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sanitize_after_dataset_vanishes_is_an_error_without_text() {
    let d = start().await;
    d.dataset("mail").await;
    let (code, _) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "dataset": "mail", "text": IBAN_TEXT })),
        )
        .await;
    assert_eq!(code, 200);
    d.state.vault.delete_dataset("mail").unwrap();
    let (code, b) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(
                json!({ "dataset": "mail", "profile": "offline", "text": "Neu: IBAN AT61 1904 3002 3457 3201." }),
            ),
        )
        .await;
    assert_eq!(code, 404, "{b}");
    assert_eq!(b["error"]["type"], "not_found");
    assert!(b.get("text").is_none());
    assert!(!b.to_string().contains("AT61"), "{b}");
    let (code, _) = d.call(Method::GET, "/v1/status", None).await;
    assert_eq!(code, 200, "still serving");
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn second_daemon_on_the_same_socket_is_refused_and_stale_files_are_cleaned() {
    let d = start().await;
    let e = inumakid::server::prepare_socket_path(&d.socket).unwrap_err();
    assert!(matches!(e, inumakid::StartError::AlreadyRunning(_)), "{e}");
    d.stop().await;
    let stale = short_socket_path("stale");
    std::fs::write(&stale, b"").unwrap();
    inumakid::server::prepare_socket_path(&stale).unwrap();
    assert!(!stale.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inspect_is_metadata_only_by_default_and_sanitize_takes_redactions() {
    use inumaki_core::redact::sha256_hex;
    let d = start().await;
    d.dataset("mail").await;
    let text = "Bitte an Sarah Leitner weiterleiten. IBAN AT61 1904 3002 3457 3201.";
    let (code, b) = d
        .call(
            Method::POST,
            "/v1/inspect",
            Some(json!({ "dataset": "mail", "text": text })),
        )
        .await;
    assert_eq!(code, 200, "{b}");
    assert_eq!(
        b["label"],
        "local diagnostic output — not approved for transmission"
    );
    assert_eq!(b["outcome"], "pass");
    assert_eq!(b["spans"].as_array().unwrap().len(), 1);
    assert_eq!(b["spans"][0]["kind"], "IBAN");
    assert!(b["spans"][0].get("original").is_none() && b.get("candidate").is_none());
    assert!(
        !b.to_string().contains("AT61") && !b.to_string().contains("Sarah"),
        "{b}"
    );
    assert_eq!(b["expiry"]["rotation_days"], 30);
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    assert_eq!(st["datasets"][0]["entries"], 0, "inspection never mints");
    let (code, b) = d
        .call(
            Method::POST,
            "/v1/inspect",
            Some(json!({ "dataset": "mail", "text": text, "show_values": true })),
        )
        .await;
    assert_eq!(code, 200);
    assert_eq!(b["spans"][0]["original"], "AT61 1904 3002 3457 3201");
    assert!(b["candidate"].as_str().unwrap().contains("<IBAN_"));
    let red = json!({ "input_sha256": sha256_hex(text), "spans": [{ "start": 9, "end": 22, "kind": "PERSON", "action": "tokenize" }] });
    let (code, b) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "dataset": "mail", "text": text, "redactions": red })),
        )
        .await;
    assert_eq!(code, 200, "{b}");
    assert!(
        b["text"].as_str().unwrap().starts_with("Bitte an <PERSON_"),
        "{b}"
    );
    assert_eq!(b["cached"], false);
    // Fix round 1, finding 2: a stale digest paired with a span over a name
    // the namespace has never seen must be refused before anything is
    // transformed. `spans: []` alone (the original test) would still pass
    // even if a regression transformed first and validated after, since
    // there would be nothing to mint; a real span over an unseen value
    // pins that nothing was minted either.
    let fresh_dataset_text = "Kontakt: Mira Tenzing, bitte zurückrufen.";
    assert_eq!(&fresh_dataset_text[9..21], "Mira Tenzing");
    let stale = json!({
        "input_sha256": sha256_hex("some other text entirely"),
        "spans": [{ "start": 9, "end": 21, "kind": "PERSON", "action": "tokenize" }]
    });
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    let entries_before = st["datasets"][0]["entries"].clone();
    let (code, b) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "dataset": "mail", "text": fresh_dataset_text, "redactions": stale })),
        )
        .await;
    assert_eq!(code, 400, "{b}");
    assert!(b["error"]["message"].as_str().unwrap().contains("digest"));
    assert!(
        !b.to_string().contains("Mira") && !b.to_string().contains("Tenzing"),
        "{b}"
    );
    let (code, b) = d
        .call(
            Method::POST,
            "/v1/inspect",
            Some(json!({ "dataset": "mail", "text": fresh_dataset_text, "redactions": stale })),
        )
        .await;
    assert_eq!(code, 400, "{b}");
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    assert_eq!(
        st["datasets"][0]["entries"], entries_before,
        "a stale-digest redaction must not mint, dataset path"
    );
    // Session path: the same refusal, before any session is even created.
    let fresh_session_text = "Bitte an Elias Vogt schreiben.";
    assert_eq!(&fresh_session_text[9..19], "Elias Vogt");
    let session_stale = json!({
        "input_sha256": sha256_hex("yet another text"),
        "spans": [{ "start": 9, "end": 19, "kind": "PERSON", "action": "tokenize" }]
    });
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    let sessions_before = st["sessions"].clone();
    let (code, b) = d
        .call(
            Method::POST,
            "/v1/sanitize",
            Some(json!({ "session": "stale-check", "text": fresh_session_text, "redactions": session_stale })),
        )
        .await;
    assert_eq!(code, 400, "{b}");
    assert!(b["error"]["message"].as_str().unwrap().contains("digest"));
    assert!(
        !b.to_string().contains("Elias") && !b.to_string().contains("Vogt"),
        "{b}"
    );
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    assert_eq!(
        st["sessions"], sessions_before,
        "a stale-digest redaction must not even create the session"
    );
    d.stop().await;
}
