//! M6 spec §9.4 and §9.8 for plan 3: the live mailbox endpoints and the
//! status `mailboxes` block decode into the `inumaki-client` types and
//! re-encode to the same bytes (struct-serialized bodies), the client's own
//! request type is accepted, and the error answers are the documented
//! shape with the contract's fixed messages; a missing dataset and a
//! missing mailbox are both 404 but say which.

mod common;

use common::*;
use hyper::Method;
use inumaki_client::contract::{assert_bytes_round_trip, assert_value_round_trip};
use inumaki_client::{
    Client, ClientError, ErrorBody, MailboxBody, MailboxCheck, MailboxCreate, MailboxPreset,
    MailboxStatus, Secret, StatusBody,
};
use inumaki_mail::fake::{FakeImap, FakeState};
use serde_json::{Value, json};

const DS: &str = "qwxzvk-mail";

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

fn status_of(e: ClientError) -> (u16, String, String) {
    match e {
        ClientError::Status {
            status,
            error: Some(d),
        } => (status, d.kind, d.message),
        other => panic!("{other}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mailbox_bodies_match_the_client_types_byte_for_byte() {
    let d = start().await;
    let c = Client::new(&d.socket);
    let fake = FakeImap::start(FakeState::new("agent@qwxzvk.example", "secret")).await;
    let (code, _) = raw(
        &c,
        Method::POST,
        "/v1/datasets",
        json!({ "id": DS, "name": "Qwxzvk Mail", "kind": "mailbox" }),
    )
    .await;
    assert_eq!(code, 201);

    // the client's own request type (a generic mailbox on loopback)
    let mut create = MailboxCreate::preset(
        MailboxPreset::Generic,
        "agent@qwxzvk.example",
        Secret::new("secret"),
    );
    create.imap_host = Some("127.0.0.1".into());
    create.imap_port = Some(fake.port());
    create.imap_tls = Some(false);
    create.from_address = Some("Qwxzvk Office <agent@qwxzvk.example>".into());
    let (code, b) = raw(
        &c,
        Method::POST,
        &format!("/v1/datasets/{DS}/mailbox"),
        serde_json::to_value(&create).unwrap(),
    )
    .await;
    assert_eq!(code, 201, "{}", String::from_utf8_lossy(&b));
    assert_bytes_round_trip::<MailboxBody>(&b);
    // a null drafts folder is emitted, never skipped
    assert!(value(&b)["drafts_folder"].is_null());
    assert!(value(&b).as_object().unwrap().contains_key("drafts_folder"));
    let typed = c.set_mailbox(DS, &create).await.unwrap();
    assert_eq!(typed.preset, MailboxPreset::Generic);
    assert_eq!(typed.password_secret, format!("{DS}/mail/password"));

    let (code, b) = raw(
        &c,
        Method::GET,
        &format!("/v1/datasets/{DS}/mailbox"),
        Value::Null,
    )
    .await;
    assert_eq!(code, 200);
    assert_bytes_round_trip::<MailboxBody>(&b);

    let (code, b) = raw(
        &c,
        Method::POST,
        &format!("/v1/datasets/{DS}/mailbox/check"),
        Value::Null,
    )
    .await;
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&b));
    assert_bytes_round_trip::<MailboxCheck>(&b);
    let check = c.check_mailbox(DS).await.unwrap();
    assert_eq!(check.folders, 1);
    assert!(!check.drafts_folder_configured);

    // status: `mailboxes` last, after `gateway`, and byte-identical
    let (code, b) = raw(&c, Method::GET, "/v1/status", Value::Null).await;
    assert_eq!(code, 200);
    assert_bytes_round_trip::<StatusBody>(&b);
    let st = c.status().await.unwrap();
    let mbs: Vec<MailboxStatus> = st.mailboxes.expect("always emitted");
    assert_eq!(mbs.len(), 1);
    assert_eq!(mbs[0].dataset, DS);
    assert_eq!(mbs[0].preset, MailboxPreset::Generic);
    let text = String::from_utf8_lossy(&b).to_string();
    assert!(
        text.find("\"gateway\"").unwrap() < text.find("\"mailboxes\"").unwrap(),
        "{text}"
    );
    assert!(
        !text.contains("agent@qwxzvk.example"),
        "no user name in status"
    );

    // 400 SENDING_REFUSED and a fixed field message, as the client's ErrorBody
    let mut sending = serde_json::to_value(&create).unwrap();
    sending["smtp_host"] = json!("smtp.qwxzvk.example");
    let (code, b) = raw(
        &c,
        Method::POST,
        &format!("/v1/datasets/{DS}/mailbox"),
        sending,
    )
    .await;
    assert_eq!(code, 400);
    assert_value_round_trip::<ErrorBody>(&value(&b));
    let e: ErrorBody = serde_json::from_slice(&b).unwrap();
    assert_eq!(e.error.kind, "bad_request");
    assert_eq!(
        e.error.message,
        "mail sending is not supported; mailboxes are draft-only"
    );
    let mut bad = create.clone();
    bad.imap_host = Some("host with space".into());
    let (code, kind, message) = status_of(c.set_mailbox(DS, &bad).await.unwrap_err());
    assert_eq!(
        (code, kind.as_str(), message.as_str()),
        (400, "bad_request", "unknown or invalid mailbox field")
    );

    // 401 on a wrong password
    let mut wrong = create.clone();
    wrong.password = Secret::new("wrong");
    c.set_mailbox(DS, &wrong).await.unwrap();
    let (code, b) = raw(
        &c,
        Method::POST,
        &format!("/v1/datasets/{DS}/mailbox/check"),
        Value::Null,
    )
    .await;
    assert_eq!(code, 401);
    assert_value_round_trip::<ErrorBody>(&value(&b));
    let (code, kind, _) = status_of(c.check_mailbox(DS).await.unwrap_err());
    assert_eq!((code, kind.as_str()), (401, "mail_auth_failed"));

    // 404: unknown dataset and missing mailbox are distinct messages
    let (code, kind, unknown_dataset) = status_of(c.mailbox("qwxzvk-none").await.unwrap_err());
    assert_eq!((code, kind.as_str()), (404, "not_found"));
    c.delete_mailbox(DS).await.unwrap();
    let (code, b) = raw(
        &c,
        Method::GET,
        &format!("/v1/datasets/{DS}/mailbox"),
        Value::Null,
    )
    .await;
    assert_eq!(code, 404);
    assert_value_round_trip::<ErrorBody>(&value(&b));
    let (code, kind, no_mailbox) = status_of(c.mailbox(DS).await.unwrap_err());
    assert_eq!((code, kind.as_str()), (404, "not_found"));
    assert_eq!(no_mailbox, "mailbox not configured");
    assert_ne!(unknown_dataset, no_mailbox);
    let (code, _, m) = status_of(c.check_mailbox(DS).await.unwrap_err());
    assert_eq!((code, m.as_str()), (404, "mailbox not configured"));
    let (code, _, m) = status_of(c.delete_mailbox(DS).await.unwrap_err());
    assert_eq!((code, m.as_str()), (404, "mailbox not configured"));

    // with no mailbox left, status still emits an empty list last
    let (_, b) = raw(&c, Method::GET, "/v1/status", Value::Null).await;
    assert_bytes_round_trip::<StatusBody>(&b);
    assert_eq!(value(&b)["mailboxes"], json!([]));
    d.stop().await;
}
