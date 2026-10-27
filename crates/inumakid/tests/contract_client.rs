//! M6-0 (spec §9.8): the live router's bodies for the endpoints on `main`
//! decode into the `inumaki-client` types and re-encode to the same bytes
//! (struct-serialized bodies) or the same JSON value (bodies built with
//! `json!`). A failure means the client and the daemon disagree on the
//! contract: fix whichever side departs from spec §9.

mod common;

use common::*;
use inumaki_client::contract::{assert_bytes_round_trip, assert_value_round_trip};
use inumaki_client::{
    ActivityList, ActivityVerify, Client, DatasetBody, DoctorBody, EntityList, ErrorBody,
    ForgetBody, InspectBody, JournalList, JournalRecord, Method, RehydrateResponse, RotateBody,
    SanitizeResponse, ShutdownBody, StatusBody, TokenBody, TokenCreated, UpstreamBody,
};
use inumaki_core::span::EntityKind;
use inumaki_core::verify::CheckId;
use inumaki_vault::{CheckLabel, Direction, FrontDoor, KindCount, KindLabel, NewActivity, Verdict};
use serde_json::{Value, json};

const DS: &str = "qwxzvk-kunde";
const IBAN_TEXT: &str = "IBAN AT61 1904 3002 3457 3201 bitte.";

async fn raw(c: &Client, method: Method, path: &str, body: Value) -> (u16, Vec<u8>) {
    let bytes = if body.is_null() {
        Vec::new()
    } else {
        serde_json::to_vec(&body).unwrap()
    };
    let r = c.raw(method, path, bytes).await.unwrap();
    (r.status, r.body)
}

fn value(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn landed_bodies_match_the_client_types_byte_for_byte() {
    let d = start().await;
    let c = Client::new(&d.socket);

    let (code, b) = raw(
        &c,
        Method::POST,
        "/v1/datasets",
        json!({ "id": DS, "name": "Qwxzvk Kunde" }),
    )
    .await;
    assert_eq!(code, 201);
    assert_bytes_round_trip::<DatasetBody>(&b);
    let (code, b) = raw(&c, Method::GET, "/v1/datasets", Value::Null).await;
    assert_eq!(code, 200);
    assert_bytes_round_trip::<Vec<DatasetBody>>(&b);

    let (code, b) = raw(
        &c,
        Method::POST,
        "/v1/datasets/qwxzvk-kunde/upstreams",
        json!({ "name": "qwxzvk-crm", "kind": "stdio", "command": "x", "args": ["--a"],
                "env": { "CRM_URL": "https://crm.qwxzvk.example" }, "secret_env": { "CRM_TOKEN": "s3cret" } }),
    )
    .await;
    assert_eq!(code, 201, "{}", String::from_utf8_lossy(&b));
    assert_bytes_round_trip::<UpstreamBody>(&b);
    let (code, b) = raw(
        &c,
        Method::GET,
        "/v1/datasets/qwxzvk-kunde/upstreams",
        Value::Null,
    )
    .await;
    assert_eq!(code, 200);
    assert_bytes_round_trip::<Vec<UpstreamBody>>(&b);

    let (code, b) = raw(
        &c,
        Method::POST,
        "/v1/gateway/tokens",
        json!({ "label": "app:claude-code" }),
    )
    .await;
    assert_eq!(code, 201);
    assert_bytes_round_trip::<TokenCreated>(&b);
    let token_id = value(&b)["id"].as_i64().unwrap();
    let (code, b) = raw(&c, Method::GET, "/v1/gateway/tokens", Value::Null).await;
    assert_eq!(code, 200);
    assert_bytes_round_trip::<Vec<TokenBody>>(&b);

    let (code, b) = raw(
        &c,
        Method::POST,
        "/v1/sanitize",
        json!({ "dataset": DS, "text": IBAN_TEXT }),
    )
    .await;
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&b));
    assert_bytes_round_trip::<SanitizeResponse>(&b);
    let sanitized = value(&b)["text"].as_str().unwrap().to_string();
    let (code, b) = raw(
        &c,
        Method::POST,
        "/v1/rehydrate",
        json!({ "dataset": DS, "text": sanitized }),
    )
    .await;
    assert_eq!(code, 200);
    assert_bytes_round_trip::<RehydrateResponse>(&b);
    let (code, b) = raw(
        &c,
        Method::POST,
        "/v1/rehydrate",
        json!({ "dataset": DS, "text": "<PERSON_000000> <SECRET_REMOVED>", "strict": true }),
    )
    .await;
    assert_eq!(code, 422);
    assert_value_round_trip::<ErrorBody>(&value(&b));

    let (code, b) = raw(
        &c,
        Method::POST,
        "/v1/inspect",
        json!({ "dataset": DS, "text": IBAN_TEXT, "show_values": true }),
    )
    .await;
    assert_eq!(code, 200);
    assert_bytes_round_trip::<InspectBody>(&b);

    let v = &d.state.vault;
    let record = v
        .append_activity(NewActivity {
            dataset: v.opaque_ref(DS),
            front_door: FrontDoor::Gateway,
            upstream: Some(v.opaque_upstream(DS, "qwxzvk-crm")),
            direction: Direction::Result,
            verdict: Verdict::Released,
            checks: vec![CheckLabel::of(&CheckId::Leak)],
            kinds: vec![KindCount {
                kind: KindLabel::of(&EntityKind::Iban),
                count: 1,
            }],
            tripwire: false,
            bytes: 12,
            released: Some(v.released_digest(b"released")),
        })
        .unwrap();
    let (code, b) = raw(
        &c,
        Method::GET,
        "/v1/activity?dataset=qwxzvk-kunde&limit=5",
        Value::Null,
    )
    .await;
    assert_eq!(code, 200);
    assert!(!value(&b)["records"].as_array().unwrap().is_empty());
    assert_value_round_trip::<ActivityList>(&value(&b));
    let (code, b) = raw(&c, Method::GET, "/v1/activity/verify", Value::Null).await;
    assert_eq!(code, 200);
    assert_value_round_trip::<ActivityVerify>(&value(&b));

    // Spec §9.3 (plan 2b), M6-3 Task 9a: journal and entities.
    v.append_journal(
        DS,
        &record.id,
        record.at,
        &v.released_digest(b"released"),
        b"released",
    )
    .unwrap();
    let path = format!("/v1/datasets/{DS}/journal");
    let (code, b) = raw(&c, Method::GET, &path, Value::Null).await;
    assert_eq!(code, 200);
    assert_eq!(value(&b)["entries"].as_array().unwrap().len(), 1);
    assert_value_round_trip::<JournalList>(&value(&b));
    for show in ["false", "true"] {
        let path = format!(
            "/v1/datasets/{DS}/journal/{}?show_values={show}",
            record.id.as_str()
        );
        let (code, b) = raw(&c, Method::GET, &path, Value::Null).await;
        assert_eq!(code, 200, "{}", String::from_utf8_lossy(&b));
        assert_bytes_round_trip::<JournalRecord>(&b);
    }
    let (code, b) = raw(
        &c,
        Method::POST,
        "/v1/sanitize",
        json!({ "dataset": DS, "text": "Mail an qwxzvk.kunde@example.com bitte." }),
    )
    .await;
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&b));
    for show in ["false", "true"] {
        let path = format!("/v1/datasets/{DS}/entities?show_values={show}");
        let (code, b) = raw(&c, Method::GET, &path, Value::Null).await;
        assert_eq!(code, 200);
        assert!(value(&b)["entities"].as_array().unwrap().len() >= 2);
        assert_value_round_trip::<EntityList>(&value(&b));
    }
    let iban_token = sanitized
        .split_whitespace()
        .find(|w| w.starts_with("<IBAN_"))
        .unwrap()
        .trim_end_matches('.')
        .to_string();
    let path = format!("/v1/datasets/{DS}/entities/{}", encode_segment(&iban_token));
    let (code, b) = raw(&c, Method::DELETE, &path, Value::Null).await;
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&b));
    assert_bytes_round_trip::<ForgetBody>(&b);
    let (code, b) = raw(
        &c,
        Method::POST,
        &format!("/v1/datasets/{DS}/entities/forget"),
        json!({ "value": "qwxzvk.kunde@example.com" }),
    )
    .await;
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&b));
    assert_bytes_round_trip::<ForgetBody>(&b);

    let (code, b) = raw(&c, Method::GET, "/v1/doctor", Value::Null).await;
    assert_eq!(code, 200);
    assert_bytes_round_trip::<DoctorBody>(&b);

    // Review Focus 1: the status body round-trips byte for byte (plan 3
    // appends `mailboxes`, here empty, after `gateway`;
    // `contract_mailbox.rs` covers a configured one).
    let (code, b) = raw(&c, Method::GET, "/v1/status", Value::Null).await;
    assert_eq!(code, 200);
    assert_bytes_round_trip::<StatusBody>(&b);
    // Additive `config_source`: the path of the file in use, never its text.
    let status: StatusBody = serde_json::from_slice(&b).unwrap();
    let src = status.config_source.expect("config_source");
    assert!(src.ends_with("inumaki.toml"), "{src}");

    let (code, b) = raw(
        &c,
        Method::POST,
        "/v1/datasets/qwxzvk-kunde/rotate",
        Value::Null,
    )
    .await;
    assert_eq!(code, 200);
    assert_value_round_trip::<RotateBody>(&value(&b));

    let (code, b) = raw(&c, Method::GET, "/v1/no-such-route", Value::Null).await;
    assert_eq!(code, 404);
    assert_value_round_trip::<ErrorBody>(&value(&b));

    let (code, _) = raw(
        &c,
        Method::DELETE,
        "/v1/datasets/qwxzvk-kunde/upstreams/qwxzvk-crm",
        Value::Null,
    )
    .await;
    assert_eq!(code, 204);
    let (code, _) = raw(
        &c,
        Method::DELETE,
        &format!("/v1/gateway/tokens/{token_id}"),
        Value::Null,
    )
    .await;
    assert_eq!(code, 204);
    let (code, _) = raw(&c, Method::DELETE, "/v1/datasets/qwxzvk-kunde", Value::Null).await;
    assert_eq!(code, 204);

    let (code, b) = raw(&c, Method::POST, "/v1/shutdown", Value::Null).await;
    assert_eq!(code, 202);
    assert_value_round_trip::<ShutdownBody>(&value(&b));
    d.stop().await;
}
