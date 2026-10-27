//! Spec §13: 16 parallel `sanitize` calls complete with correct results.

mod common;

use common::*;
use hyper::Method;
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sixteen_parallel_sanitize_calls_share_tokens_correctly() {
    let d = start().await;
    d.dataset("mail").await;
    let client = d.client.clone();
    let handles: Vec<_> = (0..16)
        .map(|i| {
            let c = client.clone();
            tokio::spawn(async move {
                // no trailing number: "Nr" sits near the CUSTOMER_ID label list (review M6)
                let text =
                    format!("Mail kunde{i}@example.at, IBAN AT61 1904 3002 3457 3201, Fall {i}.");
                let r = c
                    .call(
                        Method::POST,
                        "/v1/sanitize",
                        Some(&json!({ "dataset": "mail", "text": text })),
                    )
                    .await
                    .unwrap();
                assert_eq!(r.status.as_u16(), 200, "{:?}", r.body);
                let out = r.body["text"].as_str().unwrap().to_string();
                assert!(
                    !out.contains("AT61") && !out.contains("example.at"),
                    "{out}"
                );
                out
            })
        })
        .collect();
    let mut outputs = Vec::new();
    for h in handles {
        outputs.push(h.await.unwrap());
    }
    let iban_tokens: std::collections::HashSet<String> = outputs
        .iter()
        .map(|o| {
            o.split_whitespace()
                .find(|w| w.starts_with("<IBAN_"))
                .unwrap()
                .trim_end_matches(',')
                .to_string()
        })
        .collect();
    assert_eq!(
        iban_tokens.len(),
        1,
        "one entity, one token: {iban_tokens:?}"
    );
    let email_tokens: std::collections::HashSet<String> = outputs
        .iter()
        .map(|o| {
            o.split_whitespace()
                .find(|w| w.starts_with("<EMAIL_"))
                .unwrap()
                .trim_end_matches(',')
                .to_string()
        })
        .collect();
    assert_eq!(email_tokens.len(), 16, "sixteen distinct emails");
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    assert_eq!(st["datasets"][0]["entries"], 17);
    d.stop().await;
}
