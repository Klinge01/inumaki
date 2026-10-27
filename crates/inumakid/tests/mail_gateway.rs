//! M4 spec §6, §8, §13 mail rows, end to end: a mailbox dataset over the
//! scripted IMAP server through the real daemon and gateway (offline
//! profile with a dictionary canary). The endpoints store the password as
//! a secret and install the mail upstream with the shipped contract; folder
//! names and headers reach the agent as tokens; handles survive only by
//! provenance; draft bodies are strictly rehydrated; unresolved tokens
//! append nothing; the tripwire sees clear values in bodies; stale handles
//! are context_unavailable; sending configuration is refused; the password
//! goes with the mailbox and with the dataset.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use common::TestDaemon;
use common::gateway::*;
use hyper::Method;
use inumaki_gateway::{Blocks, BlocksError, FieldHint, TextBlock};
use inumaki_mail::fake::{FakeImap, FakeState};
use inumaki_mail::{CONTRACT_JSON, TOOL_NAMES};
use inumaki_vault::{MailHandleRef, UpstreamKind};
use inumakid::glue::BlocksHandle;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use serde_json::{Value, json};

const CANARY_FOLDER: &str = "Kunde Zyxwuria Quolnath";

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/../inumaki-mail/tests/fixtures/{name}.eml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn seeded() -> FakeState {
    let mut s = FakeState::new("agent", "secret");
    s.add("INBOX", &fixture("plain"));
    s.add("INBOX", &fixture("html"));
    s.add("INBOX", &fixture("quoted"));
    s.add_folder(CANARY_FOLDER, 2000);
    s.add(CANARY_FOLDER, &fixture("attachments"));
    s.add_folder("Drafts", 7000);
    s
}

fn mailbox_body(port: u16, password: &str) -> Value {
    json!({ "preset": "generic", "imap_host": "127.0.0.1", "imap_port": port, "imap_tls": false,
            "username": "agent", "password": password, "from_address": "agent@example.test" })
}

async fn add_mailbox_dataset(d: &TestDaemon, id: &str, port: u16) {
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets",
            Some(json!({ "id": id, "name": "Mail", "kind": "mailbox", "profile": "offline" })),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    let (code, body) = d
        .call(
            Method::POST,
            &format!("/v1/datasets/{id}/mailbox"),
            Some(mailbox_body(port, "secret")),
        )
        .await;
    assert_eq!(code, 201, "{body}");
}

/// The text from `prefix` to the next `>` (a token inside `<…>` too).
fn token_at(text: &str, prefix: &str) -> String {
    let start = text
        .find(prefix)
        .unwrap_or_else(|| panic!("no {prefix} token in {text}"));
    let end = text[start..].find('>').unwrap() + start + 1;
    text[start..end].to_string()
}

async fn call(c: &Client, tool: &str, a: Value) -> CallToolResult {
    c.peer()
        .call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(args(a)))
        .await
        .unwrap()
}

async fn inbox_handle(c: &Client) -> String {
    let r = call(c, "mail_list_folders", json!({})).await;
    assert_ne!(r.is_error, Some(true), "{}", texts(&r));
    let folders = r.structured_content.unwrap()["folders"].clone();
    folders
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == "INBOX")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn search_one(c: &Client, folder: &str, since: &str, before: &str) -> Value {
    let r = call(
        c,
        "mail_search",
        json!({ "folder": folder, "since": since, "before": before }),
    )
    .await;
    assert_ne!(r.is_error, Some(true), "{}", texts(&r));
    r.structured_content.unwrap()["messages"][0].clone()
}

async fn dataset_status(d: &TestDaemon, id: &str) -> Value {
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    st["gateway"]["datasets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["id"] == id)
        .unwrap()
        .clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mailbox_endpoints_store_the_secret_install_the_upstream_and_check() {
    let (d, _dict) = daemon("").await;
    let fake = FakeImap::start(seeded()).await;
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets",
            Some(json!({ "id": "mail", "name": "Mail", "kind": "mailbox", "profile": "offline" })),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets/mail/mailbox",
            Some(mailbox_body(fake.port(), "hunter2-canary")),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    assert_eq!(body["preset"], "generic");
    assert_eq!(body["imap_port"], fake.port());
    assert_eq!(body["imap_tls"], false);
    assert_eq!(body["username"], "agent");
    assert_eq!(body["password_secret"], "mail/mail/password");
    assert!(body["drafts_folder"].is_null());
    assert_eq!(body["handles"], 0);
    assert!(!body.to_string().contains("hunter2"), "{body}");
    assert_eq!(
        &**d.state
            .vault
            .get_secret("mail/mail/password")
            .unwrap()
            .unwrap(),
        b"hunter2-canary"
    );
    let (_, ups) = d
        .call(Method::GET, "/v1/datasets/mail/upstreams", None)
        .await;
    assert!(!ups.to_string().contains("hunter2"), "{ups}");
    let mail = ups
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["name"] == "mail")
        .expect("mail upstream installed");
    assert_eq!(mail["kind"], "mail");
    assert_eq!(
        mail["content_policy"],
        serde_json::from_str::<Value>(CONTRACT_JSON).unwrap()
    );
    let (code, got) = d.call(Method::GET, "/v1/datasets/mail/mailbox", None).await;
    assert_eq!(code, 200);
    assert_eq!(got["username"], "agent");
    assert!(!got.to_string().contains("hunter2"));
    // check: wrong password first (the fake's password is "secret")
    let (code, body) = d
        .call(Method::POST, "/v1/datasets/mail/mailbox/check", None)
        .await;
    assert_eq!(code, 401, "{body}");
    assert_eq!(body["error"]["type"], "mail_auth_failed");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("check the IMAP host"),
        "{body}"
    );
    assert!(!body.to_string().contains("hunter2"));
    // replacing the mailbox keeps one upstream and one secret
    let (code, _) = d
        .call(
            Method::POST,
            "/v1/datasets/mail/mailbox",
            Some(mailbox_body(fake.port(), "secret")),
        )
        .await;
    assert_eq!(code, 201);
    assert_eq!(
        d.state
            .vault
            .upstreams("mail")
            .unwrap()
            .iter()
            .filter(|u| u.spec.kind == UpstreamKind::Mail)
            .count(),
        1
    );
    assert_eq!(
        &**d.state
            .vault
            .get_secret("mail/mail/password")
            .unwrap()
            .unwrap(),
        b"secret"
    );
    let (code, body) = d
        .call(Method::POST, "/v1/datasets/mail/mailbox/check", None)
        .await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["folders"], 3);
    assert_eq!(body["drafts_folder_resolved"], true);
    assert_eq!(
        body["drafts_folder_will_be_created"], false,
        "the fake has a Drafts folder"
    );
    assert_eq!(body["drafts_folder_configured"], false);
    // status lists the mailbox without the username
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    let mb = &st["mailboxes"][0];
    assert_eq!(
        (
            mb["dataset"].as_str().unwrap(),
            mb["preset"].as_str().unwrap(),
            mb["imap_tls"].as_bool().unwrap()
        ),
        ("mail", "generic", false)
    );
    assert!(mb.get("username").is_none());
    // validation: every 400 is one of the contract's fixed messages
    for (body, message) in [
        (
            json!({ "preset": "generic", "username": "a", "password": "b" }),
            "imap_host and imap_port are required for the generic preset",
        ),
        (
            json!({ "preset": "generic", "imap_host": "imap.example.test", "imap_port": 143, "imap_tls": false, "username": "a", "password": "b" }),
            "imap_tls must be true for a non-loopback host",
        ),
        (
            json!({ "preset": "generic", "imap_host": "host with space", "imap_port": 993, "username": "a", "password": "rejected-canary" }),
            "unknown or invalid mailbox field",
        ),
        (
            json!({ "preset": "generic", "imap_host": "imap.example.test", "imap_port": 0, "username": "a", "password": "b" }),
            "unknown or invalid mailbox field",
        ),
        (
            json!({ "preset": "gmail", "username": "a@gmail.com", "password": "b", "from_address": "no-at-sign" }),
            "unknown or invalid mailbox field",
        ),
        (
            json!({ "preset": "gmail", "username": "a\u{7}b", "password": "b" }),
            "unknown or invalid mailbox field",
        ),
        (
            json!({ "preset": "exchange", "username": "a", "password": "b" }),
            "preset must be gmail, outlook, or generic",
        ),
        (
            json!({ "preset": "gmail", "username": "a@gmail.com", "password": "" }),
            "password must be 1 to 512 printable characters",
        ),
        (
            json!({ "preset": "gmail", "username": "a@gmail.com", "password": "ä".repeat(513) }),
            "password must be 1 to 512 printable characters",
        ),
        (
            json!({ "preset": "gmail", "username": "a@gmail.com", "password": "x", "bogus": 1 }),
            "unknown or invalid mailbox field",
        ),
    ] {
        let (code, resp) = d
            .call(
                Method::POST,
                "/v1/datasets/mail/mailbox",
                Some(body.clone()),
            )
            .await;
        assert_eq!(code, 400, "{body}: {resp}");
        assert_eq!(resp["error"]["message"], message, "{body}");
    }
    assert_eq!(
        &**d.state
            .vault
            .get_secret("mail/mail/password")
            .unwrap()
            .unwrap(),
        b"secret",
        "a rejected body does not overwrite the working password"
    );
    // 512 characters of two bytes each are allowed (characters, not bytes)
    let (code, resp) = d
        .call(
            Method::POST,
            "/v1/datasets/mail/mailbox",
            Some(json!({ "preset": "generic", "imap_host": "127.0.0.1", "imap_port": fake.port(), "imap_tls": false, "username": "agent", "password": "ä".repeat(512) })),
        )
        .await;
    assert_eq!(code, 201, "{resp}");
    let (code, _) = d
        .call(
            Method::POST,
            "/v1/datasets/mail/mailbox",
            Some(mailbox_body(fake.port(), "secret")),
        )
        .await;
    assert_eq!(code, 201);
    assert_eq!(
        &**d.state
            .vault
            .get_secret("mail/mail/password")
            .unwrap()
            .unwrap(),
        b"secret",
        "a successful POST stores the new password"
    );
    d.dataset("crm").await;
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets/crm/mailbox",
            Some(mailbox_body(fake.port(), "secret")),
        )
        .await;
    assert_eq!(code, 400, "{body}");
    assert_eq!(body["error"]["message"], "dataset kind must be mailbox");
    let (code, _) = d
        .call(
            Method::POST,
            "/v1/datasets/nope/mailbox",
            Some(mailbox_body(fake.port(), "secret")),
        )
        .await;
    assert_eq!(code, 404);
    let (code, _) = d.call(Method::GET, "/v1/datasets/crm/mailbox", None).await;
    assert_eq!(code, 404);
    let (code, _) = d
        .call(Method::POST, "/v1/datasets/crm/mailbox/check", None)
        .await;
    assert_eq!(code, 404);
    // gmail preset fills host and port
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets",
            Some(json!({ "id": "gm", "name": "G", "kind": "mailbox", "profile": "offline" })),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets/gm/mailbox",
            Some(json!({ "preset": "gmail", "username": "someone@gmail.com", "password": "abcd efgh ijkl mnop" })),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    assert_eq!(
        (
            body["imap_host"].as_str().unwrap(),
            body["imap_port"].as_u64().unwrap(),
            body["imap_tls"].as_bool().unwrap()
        ),
        ("imap.gmail.com", 993, true)
    );
    // removal: the password, the handles, and the mail upstream go with it
    let (code, _) = d
        .call(Method::DELETE, "/v1/datasets/mail/mailbox", None)
        .await;
    assert_eq!(code, 204);
    let (code, _) = d.call(Method::GET, "/v1/datasets/mail/mailbox", None).await;
    assert_eq!(code, 404);
    assert!(
        d.state
            .vault
            .get_secret("mail/mail/password")
            .unwrap()
            .is_none()
    );
    assert!(d.state.vault.upstreams("mail").unwrap().is_empty());
    let (code, _) = d
        .call(Method::DELETE, "/v1/datasets/mail/mailbox", None)
        .await;
    assert_eq!(code, 404);
    // deleting the dataset deletes its password too (no foreign key on secrets)
    assert!(
        d.state
            .vault
            .get_secret("gm/mail/password")
            .unwrap()
            .is_some()
    );
    let (code, _) = d.call(Method::DELETE, "/v1/datasets/gm", None).await;
    assert_eq!(code, 204);
    assert!(
        d.state
            .vault
            .get_secret("gm/mail/password")
            .unwrap()
            .is_none()
    );
    assert!(d.state.vault.mailbox("gm").unwrap().is_none());
    d.stop().await;
}

/// Review Focus 7 (the daemon half).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sending_options_are_refused_and_mail_send_is_absent() {
    let (d, _dict) = daemon("").await;
    let fake = FakeImap::start(seeded()).await;
    let (code, _) = d
        .call(
            Method::POST,
            "/v1/datasets",
            Some(json!({ "id": "mail", "name": "Mail", "kind": "mailbox", "profile": "offline" })),
        )
        .await;
    assert_eq!(code, 201);
    for extra in [
        json!({ "send_mode": "draft_only" }),
        json!({ "smtp_host": "smtp.example.test" }),
        json!({ "smtp_port": 465 }),
        json!({ "send": true }),
        json!({ "mail_send": true }),
    ] {
        let mut body = mailbox_body(fake.port(), "secret");
        for (k, v) in extra.as_object().unwrap() {
            body[k] = v.clone();
        }
        let (code, resp) = d
            .call(Method::POST, "/v1/datasets/mail/mailbox", Some(body))
            .await;
        assert_eq!(code, 400, "{resp}");
        assert_eq!(
            resp["error"]["message"], "mail sending is not supported; mailboxes are draft-only",
            "{extra}"
        );
    }
    assert!(
        d.state.vault.mailbox("mail").unwrap().is_none(),
        "nothing stored"
    );
    assert!(
        d.state
            .vault
            .get_secret("mail/mail/password")
            .unwrap()
            .is_none()
    );
    let (code, _) = d
        .call(
            Method::POST,
            "/v1/datasets/mail/mailbox",
            Some(mailbox_body(fake.port(), "secret")),
        )
        .await;
    assert_eq!(code, 201);
    wait_running(&d, "mail", "mail").await;
    let c = socket_client(&d, "mail").await.unwrap();
    let mut names: Vec<String> = c
        .peer()
        .list_all_tools()
        .await
        .unwrap()
        .iter()
        .map(|t| t.name.to_string())
        .collect();
    names.sort();
    let mut want: Vec<String> = TOOL_NAMES.iter().map(|s| s.to_string()).collect();
    want.sort();
    assert_eq!(names, want);
    let e = mcp_err(
        c.peer()
            .call_tool(CallToolRequestParams::new("mail_send").with_arguments(args(json!({}))))
            .await
            .unwrap_err(),
    );
    assert_eq!(e.message, "unknown_tool");
    c.cancel().await.ok();
    d.stop().await;
}

/// Review Focus 1.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn folder_names_are_data_and_handles_still_select() {
    let (d, _dict) = daemon("").await;
    let fake = FakeImap::start(seeded()).await;
    add_mailbox_dataset(&d, "mail", fake.port()).await;
    wait_running(&d, "mail", "mail").await;
    let c = socket_client(&d, "mail").await.unwrap();
    let r = call(&c, "mail_list_folders", json!({})).await;
    assert_ne!(r.is_error, Some(true), "{}", texts(&r));
    let whole = serde_json::to_string(&r).unwrap();
    assert!(
        !whole.contains("Zyxwuria") && !whole.contains("Quolnath"),
        "{whole}"
    );
    let folders = r.structured_content.clone().unwrap()["folders"].clone();
    let kunde = folders
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"].as_str().unwrap().starts_with("Kunde "))
        .expect("the customer folder, tokenized");
    let person = token_at(kunde["name"].as_str().unwrap(), "<PERSON_");
    assert_eq!(kunde["name"], format!("Kunde {person}"));
    let handle = kunde["id"].as_str().unwrap().to_string();
    assert!(handle.starts_with("mf_") && handle.len() == 19, "{handle}");
    assert!(
        texts(&r).contains(&handle) && texts(&r).contains(&person),
        "{}",
        texts(&r)
    );
    // the handle still selects the real folder
    let m = search_one(&c, &handle, "2026-09-30", "2026-10-01").await;
    assert_eq!(m["folder"], handle);
    assert_eq!(m["subject"], "Unterlagen");
    let id = m["id"].as_str().unwrap().to_string();
    let r = call(&c, "mail_read", json!({ "id": id, "folder": handle })).await;
    let md = texts(&r);
    assert!(
        md.contains(&format!("- Rechnung {person}.pdf (application/pdf)")),
        "attachment names are data: {md}"
    );
    assert!(!md.contains("Zyxwuria"));
    c.cancel().await.ok();
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn search_read_and_draft_reply_rehydrate_through_the_gateway() {
    let (d, _dict) = daemon("").await;
    let fake = FakeImap::start(seeded()).await;
    add_mailbox_dataset(&d, "mail", fake.port()).await;
    wait_running(&d, "mail", "mail").await;
    let c = socket_client(&d, "mail").await.unwrap();
    let inbox = inbox_handle(&c).await;
    let m = search_one(&c, &inbox, "2026-09-28", "2026-09-29").await;
    let from = m["from"].as_str().unwrap();
    let person = token_at(from, "<PERSON_");
    let email = token_at(from, "<EMAIL_");
    assert_eq!(m["from"], format!("{person} <{email}>"));
    assert_eq!(m["subject"], "Termin nächste Woche");
    assert_eq!(
        m["date"], "2026-09-28T09:00:00+02:00",
        "dates are preserved by rule"
    );
    let id = m["id"].as_str().unwrap().to_string();
    assert!(id.starts_with("mm_"));
    // read: same tokens for the same entity, nothing in clear
    let r = call(&c, "mail_read", json!({ "id": id, "folder": inbox })).await;
    let md = texts(&r);
    assert!(
        md.starts_with(&format!("**From:** {person} <{email}>\n")),
        "{md}"
    );
    assert!(
        md.contains("passt Dienstag 14:00") && !md.contains("Zyxwuria"),
        "{md}"
    );
    // draft: the agent writes tokens, the server receives the real values
    let r = call(
        &c,
        "mail_draft_reply",
        json!({ "id": id, "folder": inbox, "body": format!("Sehr geehrte Frau {person},\n\nDienstag 14:00 passt.\n"), "cc": email }),
    )
    .await;
    assert_ne!(r.is_error, Some(true), "{}", texts(&r));
    let sc = r.structured_content.clone().unwrap();
    assert_eq!(sc["status"], "created");
    let draft_id = sc["draft"]["id"].as_str().unwrap().to_string();
    let drafts_folder = sc["draft"]["folder"].as_str().unwrap().to_string();
    assert!(
        draft_id.starts_with("mm_") && drafts_folder.starts_with("mf_"),
        "handles kept after the provenance check"
    );
    assert!(texts(&r).contains("does not send mail") && texts(&r).contains(&draft_id));
    {
        let st = fake.state();
        let st = st.lock().unwrap();
        assert_eq!(st.appends.len(), 1);
        let raw = String::from_utf8_lossy(&st.appends[0].raw).to_string();
        assert!(raw.contains("zyxwuria.quolnath@example.test"), "{raw}");
        assert!(raw.contains("In-Reply-To: <html-1@example.test>"), "{raw}");
        assert!(
            raw.contains("Sehr geehrte Frau Zyxwuria Quolnath,"),
            "rehydrated body: {raw}"
        );
        assert!(
            !raw.contains("<PERSON_") && !raw.contains("<EMAIL_"),
            "{raw}"
        );
        let cc = raw
            .lines()
            .find(|l| l.starts_with("Cc:"))
            .unwrap_or_else(|| panic!("no Cc: {raw}"));
        assert!(cc.contains("zyxwuria.quolnath@example.test"), "{cc}");
    }
    // the draft reads back through its handles, sanitized again
    let r = call(
        &c,
        "mail_read",
        json!({ "id": draft_id, "folder": drafts_folder }),
    )
    .await;
    let md = texts(&r);
    assert!(md.contains(&person) && !md.contains("Zyxwuria"), "{md}");
    let ds = dataset_status(&d, "mail").await;
    assert_eq!(ds["blocked"], 0);
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    assert!(st["mailboxes"][0]["handles"].as_u64().unwrap() >= 4, "{st}");
    c.cancel().await.ok();
    d.stop().await;
}

/// Review Focus 3.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unresolved_token_in_draft_body_appends_nothing() {
    let (d, _dict) = daemon("").await;
    let fake = FakeImap::start(seeded()).await;
    add_mailbox_dataset(&d, "mail", fake.port()).await;
    wait_running(&d, "mail", "mail").await;
    let c = socket_client(&d, "mail").await.unwrap();
    let inbox = inbox_handle(&c).await;
    let id = search_one(&c, &inbox, "2026-09-28", "2026-09-29").await["id"]
        .as_str()
        .unwrap()
        .to_string();
    for (body, cc) in [
        ("Hallo <PERSON_a1b2c3>, danke.", ""),
        ("Hallo <PERSON_REMOVED>, danke.", ""),
        ("Hallo, danke.", "<EMAIL_abcdef>"),
    ] {
        let e = mcp_err(
            c.peer()
                .call_tool(
                    CallToolRequestParams::new("mail_draft_reply").with_arguments(args(
                        json!({ "id": id, "folder": inbox, "body": body, "cc": cc }),
                    )),
                )
                .await
                .unwrap_err(),
        );
        assert_eq!(e.message, "unresolved_token", "{body} / {cc}");
    }
    let st = fake.state();
    assert_eq!(
        st.lock().unwrap().count("APPEND"),
        0,
        "the server saw no write"
    );
    assert!(st.lock().unwrap().appends.is_empty());
    assert_eq!(dataset_status(&d, "mail").await["unresolved"], 3);
    c.cancel().await.ok();
    d.stop().await;
}

/// M4 spec §16.1: the tripwire covers `mail_draft_reply` body and cc.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tripwire_sees_clear_values_in_draft_bodies() {
    let (d, _dict) = daemon("").await;
    let fake = FakeImap::start(seeded()).await;
    add_mailbox_dataset(&d, "mail", fake.port()).await;
    wait_running(&d, "mail", "mail").await;
    let c = socket_client(&d, "mail").await.unwrap();
    let inbox = inbox_handle(&c).await;
    let id = search_one(&c, &inbox, "2026-09-28", "2026-09-29").await["id"]
        .as_str()
        .unwrap()
        .to_string();
    // the namespace knows the canary from the search; the agent writes it in clear
    let r = call(
        &c,
        "mail_draft_reply",
        json!({ "id": id, "folder": inbox, "body": format!("Hallo {CANARY}, passt.") }),
    )
    .await;
    assert_ne!(
        r.is_error,
        Some(true),
        "notify mode proceeds: {}",
        texts(&r)
    );
    assert_eq!(dataset_status(&d, "mail").await["clear_value_hits"], 1);
    let (_, act) = d.call(Method::GET, "/v1/activity?dataset=mail", None).await;
    assert!(
        act["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["tripwire"] == true && r["direction"] == "arguments"),
        "{act}"
    );
    assert!(!act.to_string().contains("Zyxwuria"));
    c.cancel().await.ok();
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_and_foreign_handles_are_context_unavailable_through_the_gateway() {
    let (d, _dict) = daemon("").await;
    let fake = FakeImap::start(seeded()).await;
    add_mailbox_dataset(&d, "mail", fake.port()).await;
    wait_running(&d, "mail", "mail").await;
    let c = socket_client(&d, "mail").await.unwrap();
    let inbox = inbox_handle(&c).await;
    let id = search_one(&c, &inbox, "2026-09-27", "2026-09-28").await["id"]
        .as_str()
        .unwrap()
        .to_string();
    {
        let st = fake.state();
        let mut st = st.lock().unwrap();
        st.folders.get_mut("INBOX").unwrap().messages.remove(0);
        st.bump_uidvalidity("INBOX");
    }
    let r = call(&c, "mail_read", json!({ "id": id, "folder": inbox })).await;
    assert_eq!(r.is_error, Some(true));
    assert!(
        texts(&r).starts_with("context_unavailable: "),
        "{}",
        texts(&r)
    );
    assert!(!texts(&r).contains("Termin"), "never another message");
    let fp = d.state.vault.mailbox("mail").unwrap().unwrap().fingerprint;
    assert!(
        d.state
            .vault
            .resolve_mail_handle("mail", &fp, &id)
            .unwrap()
            .is_none(),
        "invalidated in the vault"
    );
    for (i, f) in [
        ("mm_aaaaaaaaaaaaaaaa", inbox.as_str()),
        (inbox.as_str(), inbox.as_str()),
        ("INBOX", "INBOX"),
    ] {
        let r = call(&c, "mail_read", json!({ "id": i, "folder": f })).await;
        assert!(
            texts(&r).starts_with("context_unavailable: "),
            "{i}/{f}: {}",
            texts(&r)
        );
    }
    c.cancel().await.ok();
    d.stop().await;
}

/// Provenance, not shape: a handle-shaped value the daemon never minted
/// (for this dataset's current mailbox) fails the whole batch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn handle_provenance_is_checked_by_the_daemon() {
    let (d, _dict) = daemon("").await;
    let fake = FakeImap::start(seeded()).await;
    add_mailbox_dataset(&d, "mail", fake.port()).await;
    let blocks = BlocksHandle(Arc::downgrade(&d.state));
    let fp = d.state.vault.mailbox("mail").unwrap().unwrap().fingerprint;
    let real = d
        .state
        .vault
        .mail_handle("mail", &fp, &MailHandleRef::folder("INBOX"))
        .unwrap();
    let out = blocks
        .sanitize_blocks(
            "mail",
            vec![
                TextBlock {
                    text: real.clone(),
                    hint: FieldHint::Handle,
                },
                TextBlock::text(CANARY),
            ],
        )
        .unwrap();
    assert_eq!(out[0].text, real);
    assert_eq!(out[0].replacements, 0);
    assert!(
        out[1].text.starts_with("<PERSON_"),
        "free text still goes through the engine: {}",
        out[1].text
    );
    let lookalike = format!("mm_{}", "a".repeat(16));
    assert!(matches!(
        blocks.sanitize_blocks(
            "mail",
            vec![TextBlock {
                text: lookalike,
                hint: FieldHint::Handle
            }]
        ),
        Err(BlocksError::Unsupported("handle_provenance"))
    ));
    d.dataset("crm").await;
    assert!(
        matches!(
            blocks.sanitize_blocks(
                "crm",
                vec![TextBlock {
                    text: real.clone(),
                    hint: FieldHint::Handle
                }]
            ),
            Err(BlocksError::Unsupported("handle_provenance"))
        ),
        "another dataset's handle"
    );
    // through the gateway: an upstream whose result field is a handle rule
    // passes a minted handle and fails the whole result on any other value
    let mut policy = BTreeMap::new();
    policy.insert("echo", json!({ "result": { "/received": "handle" } }));
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets/mail/upstreams",
            Some(json!({ "name": "s", "kind": "stdio", "command": env!("CARGO_BIN_EXE_inumaki-test-upstream"), "content_policy": { "tools": policy } })),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    wait_running(&d, "mail", "s").await;
    wait_running(&d, "mail", "mail").await;
    let c = socket_client(&d, "mail").await.unwrap();
    let r = call(&c, "echo", json!({ "query": real })).await;
    assert_eq!(r.structured_content.unwrap()["received"], real);
    for q in ["mm_aaaaaaaaaaaaaaaa", "INBOX", "not a handle"] {
        let e = mcp_err(
            c.peer()
                .call_tool(
                    CallToolRequestParams::new("echo").with_arguments(args(json!({ "query": q }))),
                )
                .await
                .unwrap_err(),
        );
        assert_eq!(e.message, "unsupported_content", "{q}");
        assert_eq!(e.data.unwrap()["class"], "handle_provenance", "{q}");
    }
    c.cancel().await.ok();
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mail_upstream_without_a_mailbox_row_fails_closed() {
    let (d, _dict) = daemon("upstream_restart_max_backoff = \"1s\"").await;
    let (code, _) = d
        .call(
            Method::POST,
            "/v1/datasets",
            Some(json!({ "id": "mail", "name": "Mail", "kind": "mailbox", "profile": "offline" })),
        )
        .await;
    assert_eq!(code, 201);
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets/mail/upstreams",
            Some(json!({ "name": "mail", "kind": "mail" })),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    let mut seen = false;
    for _ in 0..100 {
        if upstream_status(&d, "mail", "mail")
            .await
            .is_some_and(|u| u["state"] == "failed(no_mailbox)")
        {
            seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(seen, "{:?}", upstream_status(&d, "mail", "mail").await);
    let c = socket_client(&d, "mail").await.unwrap();
    assert!(
        c.peer().list_all_tools().await.unwrap().is_empty(),
        "no tools from a built-in that never connected"
    );
    c.cancel().await.ok();
    d.stop().await;
}

#[test]
fn mail_config_defaults_and_rejections() {
    use inumakid::config::DaemonConfig;
    let base = format!(
        "{}\n[daemon]\ndefault_profile = \"offline\"\n",
        common::BASE_CONFIG
    );
    let c = DaemonConfig::from_toml(&base).unwrap();
    let m = c.mail_config();
    assert_eq!(m.keepalive, Duration::from_secs(300));
    assert_eq!(m.command_timeout, Duration::from_secs(30));
    assert_eq!(m.max_message_bytes, 4 * 1024 * 1024);
    assert_eq!(m.snippet_chars, 200);
    assert_eq!(m.auth_retry_after, Duration::from_secs(60));
    assert_eq!(c.mail.handle_retention_days, 30);
    for (extra, key) in [
        ("[mail]\nkeepalive = \"5s\"\n", "mail.keepalive"),
        ("[mail]\ncommand_timeout = \"0s\"\n", "mail.command_timeout"),
        (
            "[mail]\nmax_message_bytes = \"1KiB\"\n",
            "mail.max_message_bytes",
        ),
        ("[mail]\nsnippet_chars = 5\n", "mail.snippet_chars"),
        (
            "[mail]\nhandle_retention_days = 0\n",
            "mail.handle_retention_days",
        ),
        (
            "[mail]\nauth_retry_after = \"never\"\n",
            "mail.auth_retry_after",
        ),
    ] {
        let e = DaemonConfig::from_toml(&format!("{base}{extra}")).unwrap_err();
        assert!(format!("{e}").contains(key), "{extra}: {e}");
    }
}
