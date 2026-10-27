//! M4 spec §13 canary for mail: with a TRACE subscriber behind the daemon's
//! own privacy filter capturing every log line, configure a mailbox whose
//! user name, folder, sender, password, and dataset slug are canaries;
//! list, search, read, draft, fail calls with bad handles, an injected
//! query, an unresolved token, and an unknown tool, and run the check
//! endpoint with the right and a wrong password. None of the canaries, no
//! handle, and no header text appears in the logs, and none in any
//! model-visible error.

mod common;

use std::time::Duration;

use common::*;
use hyper::Method;
use inumaki_mail::fake::{FakeImap, FakeState};
use rmcp::ServiceExt;
use rmcp::model::{
    CallToolRequestParams, ClientCapabilities, Implementation, InitializeRequestParams,
};
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use serde_json::json;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const CANARY: &str = "Zyxwuria Quolnath";
const CANARY_FOLDER: &str = "Kunde Zyxwuria Quolnath";
const USER: &str = "zyxwuria.quolnath@example.test";
const SLUG: &str = "qwxzvk-canary-slug";

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/../inumaki-mail/tests/fixtures/{name}.eml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn obj(v: serde_json::Value) -> rmcp::model::JsonObject {
    v.as_object().cloned().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mail_logs_and_errors_never_contain_canaries() {
    let cap = Capture::new();
    // The production filter: everything at TRACE except what the privacy
    // filter drops for every configuration (rmcp, async_imap, imap_proto).
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(cap.clone())
                .with_filter(inumakid::run::log_filter(EnvFilter::new("trace"))),
        )
        .init();
    let mut s = FakeState::new(USER, "hunter2-canary");
    s.add("INBOX", &fixture("html"));
    s.add("INBOX", &fixture("plain"));
    s.add_folder(CANARY_FOLDER, 2000);
    s.add(CANARY_FOLDER, &fixture("attachments"));
    s.add_folder("Drafts", 7000);
    let fake = FakeImap::start(s).await;
    let dict = tempfile::tempdir().unwrap();
    let persons = dict.path().join("persons.txt");
    std::fs::write(&persons, format!("{CANARY}\n")).unwrap();
    let base = BASE_CONFIG.replace(
        "persons = []",
        &format!("persons = [\"{}\"]", persons.display()),
    );
    let config = format!(
        "{base}\n[daemon]\ndefault_profile = \"offline\"\n[vault]\nkey_source = \"file\"\n[gateway]\nlisten = \"127.0.0.1:0\"\n[mail]\ncommand_timeout = \"5s\"\n"
    );
    let d = start_with_config(config, None, Duration::from_millis(200), None).await;
    let (code, _) = d
        .call(
            Method::POST,
            "/v1/datasets",
            Some(json!({ "id": SLUG, "name": CANARY, "kind": "mailbox", "profile": "offline" })),
        )
        .await;
    assert_eq!(code, 201);
    let mailbox = |password: &str| {
        json!({ "preset": "generic", "imap_host": "127.0.0.1", "imap_port": fake.port(), "imap_tls": false,
                "username": USER, "password": password, "drafts_folder": "Drafts" })
    };
    let mut errors: Vec<String> = Vec::new();
    let (code, body) = d
        .call(
            Method::POST,
            &format!("/v1/datasets/{SLUG}/mailbox"),
            Some(mailbox("hunter2-canary")),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    let (code, body) = d
        .call(
            Method::POST,
            &format!("/v1/datasets/{SLUG}/mailbox/check"),
            None,
        )
        .await;
    assert_eq!(code, 200, "{body}");
    for _ in 0..200 {
        let (_, st) = d.call(Method::GET, "/v1/status", None).await;
        let u = &st["gateway"]["datasets"][0]["upstreams"][0];
        if u["state"] == "running" && u["schema_fingerprint"].is_string() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let cfg = StreamableHttpClientTransportConfig::with_uri(format!("http://inumakid/mcp/{SLUG}"));
    let t = StreamableHttpClientTransport::from_unix_socket_with_config(
        &d.socket.to_string_lossy(),
        cfg,
    );
    let c =
        InitializeRequestParams::new(ClientCapabilities::default(), Implementation::new("t", "0"))
            .serve(t)
            .await
            .unwrap();
    let mut handles: Vec<String> = Vec::new();
    let r = c
        .peer()
        .call_tool(CallToolRequestParams::new("mail_list_folders"))
        .await
        .unwrap();
    assert_ne!(r.is_error, Some(true), "{r:?}");
    let folders = r.structured_content.unwrap()["folders"].clone();
    for f in folders.as_array().unwrap() {
        handles.push(f["id"].as_str().unwrap().to_string());
    }
    let inbox = folders
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == "INBOX")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let r = c
        .peer()
        .call_tool(
            CallToolRequestParams::new("mail_search")
                .with_arguments(obj(json!({ "folder": inbox, "query": "example.test" }))),
        )
        .await
        .unwrap();
    assert_ne!(r.is_error, Some(true), "{r:?}");
    let sc = r.structured_content.unwrap();
    let html = sc["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["from"].as_str().unwrap().starts_with("<PERSON_"))
        .expect("the canary sender, tokenized")
        .clone();
    let id = html["id"].as_str().unwrap().to_string();
    handles.push(id.clone());
    let person = html["from"]
        .as_str()
        .unwrap()
        .split(' ')
        .next()
        .unwrap()
        .to_string();
    let r = c
        .peer()
        .call_tool(
            CallToolRequestParams::new("mail_read")
                .with_arguments(obj(json!({ "id": id, "folder": inbox }))),
        )
        .await
        .unwrap();
    assert!(!serde_json::to_string(&r).unwrap().contains("Zyxwuria"));
    let r = c
        .peer()
        .call_tool(
            CallToolRequestParams::new("mail_draft_reply").with_arguments(obj(
                json!({ "id": id, "folder": inbox, "body": format!("Hallo {person}, danke.") }),
            )),
        )
        .await
        .unwrap();
    assert_ne!(r.is_error, Some(true), "{r:?}");
    if let Some(h) = r
        .structured_content
        .as_ref()
        .and_then(|s| s["draft"]["id"].as_str())
    {
        handles.push(h.to_string());
    }
    assert_eq!(
        fake.state().lock().unwrap().appends.len(),
        1,
        "one draft stored"
    );
    for (tool, a) in [
        (
            "mail_read",
            json!({ "id": CANARY, "folder": CANARY_FOLDER }),
        ),
        (
            "mail_read",
            json!({ "id": "mm_aaaaaaaaaaaaaaaa", "folder": inbox }),
        ),
        (
            "mail_search",
            json!({ "query": format!("{CANARY}\r\nX LOGOUT") }),
        ),
        (
            "mail_draft_reply",
            json!({ "id": id, "folder": inbox, "body": "<PERSON_a1b2c3>" }),
        ),
        (CANARY, json!({})),
    ] {
        match c
            .peer()
            .call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(obj(a)))
            .await
        {
            Ok(r) => errors.push(serde_json::to_string(&r).unwrap()),
            Err(e) => errors.push(format!("{e:?}")),
        }
    }
    // a wrong password on the check endpoint
    let (code, body) = d
        .call(
            Method::POST,
            &format!("/v1/datasets/{SLUG}/mailbox"),
            Some(mailbox("wrong-canary")),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    let (code, body) = d
        .call(
            Method::POST,
            &format!("/v1/datasets/{SLUG}/mailbox/check"),
            None,
        )
        .await;
    assert_eq!(code, 401);
    errors.push(body.to_string());
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    assert_eq!(st["mailboxes"][0]["dataset"], SLUG);
    tokio::time::sleep(Duration::from_millis(500)).await;
    c.cancel().await.ok();
    d.stop().await;
    let logs = cap.text();
    assert!(
        logs.contains("mail session connected"),
        "the connector logged:\n{logs}"
    );
    assert!(logs.contains("draft stored"), "{logs}");
    assert!(logs.contains("mailbox check"), "{logs}");
    let mut needles: Vec<&str> = vec![
        "Zyxwuria",
        "zyxwuria",
        "Quolnath",
        "hunter2",
        "wrong-canary",
        "qwxzvk",
        "example.test",
        "Neubaugasse",
        "AT61",
        "Rechnung",
        "Termin",
        "Unterlagen",
        "Kunde ",
        "INBOX",
        "Drafts",
        "LOGOUT",
        "LOGIN",
        &person,
    ];
    needles.extend(handles.iter().map(String::as_str));
    for needle in needles {
        assert!(
            !logs.contains(needle),
            "{needle} leaked into the logs:\n{logs}"
        );
        for e in &errors {
            assert!(!e.contains(needle), "{needle} leaked into an error: {e}");
        }
    }
}
