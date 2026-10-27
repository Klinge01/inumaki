#![cfg(feature = "mail-tests")]
//! M4 spec §13 mail tests against a real IMAP server (GreenMail in Docker,
//! `scripts/greenmail.sh`). Seeds the fixture mailbox plus the canary mail,
//! runs search, read, and draft through the daemon's gateway, and verifies
//! the draft over IMAP: correct recipient and thread, rehydrated body, and
//! a Drafts folder created on first use.
//!
//! Run: `scripts/greenmail.sh start`, then
//! `cargo test -p inumakid --features mail-tests --test mail_greenmail`.
//! The test process reads `GREENMAIL_HOST`, `GREENMAIL_IMAP_PORT`,
//! `GREENMAIL_USER`, and `GREENMAIL_PASSWORD` (defaults match the script)
//! and passes them to the daemon in the mailbox request body; the daemon
//! and the connector read no environment. The feature was asked for, so an
//! unreachable GreenMail fails the test; it does not skip it.
//!
//! GreenMail 2.1.14 omits the space RFC 3501 requires before the literal of a
//! partial fetch (`BODY[TEXT]<0>{200}`); the connector's tolerant reader
//! (`inumaki_mail::tolerant`) inserts it, so this test can pass.

mod common;

use std::time::Duration;

use common::gateway::{args, socket_client, texts, token_in, wait_running};
use common::{BASE_CONFIG, start_with_config};
use hyper::Method;
use inumaki_eval::mail_fixture::{FixtureOptions, dictionary_lists, generate_mailbox};
use inumaki_mail::harness::{SeedMail, clear_folder, list_folder_messages, seed_mailbox};
use inumaki_mail::render::parse_message;
use inumaki_mail::{MailAccount, Preset};
use rmcp::model::{CallToolRequestParams, CallToolResult};
use serde_json::{Value, json};
use zeroize::Zeroizing;

const CANARY: &str = "Zyxwuria Quolnath";
const T: Duration = Duration::from_secs(20);

fn env(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn account() -> MailAccount {
    MailAccount {
        preset: Preset::Generic,
        host: env("GREENMAIL_HOST", "127.0.0.1"),
        port: env("GREENMAIL_IMAP_PORT", "3143")
            .parse()
            .expect("GREENMAIL_IMAP_PORT must be a port number"),
        tls: false,
        username: Zeroizing::new(env("GREENMAIL_USER", "agent")),
        password: Zeroizing::new(env("GREENMAIL_PASSWORD", "secret")),
        drafts_folder: None,
        from_address: Some("agent@example.test".into()),
    }
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/../inumaki-mail/tests/fixtures/{name}.eml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

async fn call(c: &common::gateway::Client, tool: &str, a: Value) -> CallToolResult {
    let r = c
        .peer()
        .call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(args(a)))
        .await
        .unwrap_or_else(|e| panic!("{tool} failed: {e}"));
    assert_ne!(r.is_error, Some(true), "{tool}: {}", texts(&r));
    r
}

/// The messages `mail_search` finds in the `[since, before)` window.
async fn search(c: &common::gateway::Client, folder: &str, since: &str, before: &str) -> Value {
    let r = call(
        c,
        "mail_search",
        json!({ "folder": folder, "since": since, "before": before }),
    )
    .await;
    r.structured_content.unwrap()["messages"].clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn greenmail_search_read_draft_round_trip() {
    let acct = account();
    // seed: five fixtures plus the canary mail (INTERNALDATE 28 Sep 2026)
    let mails = generate_mailbox(&FixtureOptions {
        count: 5,
        ..FixtureOptions::default()
    });
    clear_folder(&acct, T, "INBOX").await.unwrap_or_else(|e| {
        panic!(
            "GreenMail is not usable at {}:{} ({e}); start it with `scripts/greenmail.sh start` \
             or point GREENMAIL_HOST / GREENMAIL_IMAP_PORT / GREENMAIL_USER / GREENMAIL_PASSWORD at it",
            acct.host, acct.port
        )
    });
    clear_folder(&acct, T, "Drafts").await.unwrap();
    let mut seed: Vec<SeedMail> = mails
        .iter()
        .map(|m| SeedMail {
            folder: m.folder.clone(),
            internal_date: Some(m.internal_date.clone()),
            eml: m.eml.clone(),
        })
        .collect();
    seed.push(SeedMail {
        folder: "INBOX".into(),
        internal_date: Some("\"28-Sep-2026 09:00:00 +0200\"".into()),
        eml: fixture("html"),
    });
    assert_eq!(seed_mailbox(&acct, T, &seed).await.unwrap(), 6);

    // daemon: offline profile with the fixtures' names and the canary in the dictionaries
    let lists = dictionary_lists(&mails);
    let dict = tempfile::tempdir().unwrap();
    let write_list = |file: &str, extra: &[&str], values: &[String]| {
        let path = dict.path().join(file);
        let mut text = values.join("\n");
        for e in extra {
            text.push('\n');
            text.push_str(e);
        }
        std::fs::write(&path, text + "\n").unwrap();
        path
    };
    let persons = write_list("persons.txt", &[CANARY], &lists.persons);
    let addresses = write_list("addresses.txt", &[], &lists.addresses);
    let orgs = write_list("organizations.txt", &[], &lists.organizations);
    let base = BASE_CONFIG
        .replace(
            "persons = []",
            &format!("persons = [\"{}\"]", persons.display()),
        )
        .replace(
            "addresses = []",
            &format!("addresses = [\"{}\"]", addresses.display()),
        )
        .replace(
            "organizations = []",
            &format!("organizations = [\"{}\"]", orgs.display()),
        );
    assert_ne!(base, BASE_CONFIG);
    let config = format!(
        "{base}\n[daemon]\ndefault_profile = \"offline\"\n[vault]\nkey_source = \"file\"\n[gateway]\nlisten = \"127.0.0.1:0\"\n[mail]\ncommand_timeout = \"20s\"\n"
    );
    let d = start_with_config(config, None, Duration::from_secs(3600), None).await;
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets",
            Some(
                json!({ "id": "gm", "name": "GreenMail", "kind": "mailbox", "profile": "offline" }),
            ),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets/gm/mailbox",
            Some(json!({
                "preset": "generic", "imap_host": acct.host, "imap_port": acct.port,
                "imap_tls": false, "username": &*acct.username, "password": &*acct.password,
                "from_address": "agent@example.test"
            })),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    let (code, body) = d
        .call(Method::POST, "/v1/datasets/gm/mailbox/check", None)
        .await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(
        body["drafts_folder_will_be_created"], true,
        "GreenMail starts without a Drafts folder; a container that already ran this test \
         keeps the folder it created, so recreate it with `scripts/greenmail.sh start`: {body}"
    );
    wait_running(&d, "gm", "mail").await;
    let c = socket_client(&d, "gm").await.unwrap();

    let r = call(&c, "mail_list_folders", json!({})).await;
    let inbox = r.structured_content.unwrap()["folders"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == "INBOX")
        .expect("INBOX is listed")["id"]
        .as_str()
        .unwrap()
        .to_string();

    // the canary mail (28 Sep 2026) through search and read
    let found = search(&c, &inbox, "2026-09-28", "2026-09-29").await;
    assert_eq!(found.as_array().unwrap().len(), 1, "{found}");
    let from = found[0]["from"].as_str().unwrap();
    assert!(
        from.starts_with("<PERSON_") && !from.contains("Zyxwuria"),
        "{from}"
    );
    let person = token_in(from, "<PERSON_");
    let id = found[0]["id"].as_str().unwrap().to_string();
    let r = call(&c, "mail_read", json!({ "id": id, "folder": inbox })).await;
    let md = texts(&r);
    assert!(
        md.contains("passt Dienstag 14:00") && !md.contains("Zyxwuria"),
        "{md}"
    );

    // draft: created on GreenMail in a Drafts folder the connector made
    let r = call(
        &c,
        "mail_draft_reply",
        json!({ "id": id, "folder": inbox, "body": format!("Sehr geehrte Frau {person},\n\nDienstag passt.\n") }),
    )
    .await;
    let sc = r.structured_content.unwrap();
    assert!(
        sc["draft"]["id"]
            .as_str()
            .is_some_and(|h| h.starts_with("mm_")),
        "the draft was not located by Message-ID on GreenMail: {sc}"
    );
    let drafts = list_folder_messages(&acct, T, "Drafts").await.unwrap();
    assert_eq!(drafts.len(), 1);
    let p = parse_message(&drafts[0]).unwrap();
    assert_eq!(
        p.to[0].address.as_deref(),
        Some("zyxwuria.quolnath@example.test")
    );
    assert_eq!(p.in_reply_to.as_deref(), Some("html-1@example.test"));
    assert!(p.references.iter().any(|r| r == "html-1@example.test"));
    assert!(
        p.body.contains("Sehr geehrte Frau Zyxwuria Quolnath,"),
        "{}",
        p.body
    );
    assert!(!p.body.contains("<PERSON_"));

    // date windows on a real server compare INTERNALDATE: every seeded fixture is found on
    // its own day (the APPEND date-time set it), and a day nothing was appended on finds nothing
    for m in &mails {
        let found = search(&c, &inbox, &m.day, &m.next_day).await;
        assert_eq!(found.as_array().unwrap().len(), 1, "day {}: {found}", m.day);
        assert_eq!(found[0]["subject"], m.subject);
    }
    let none = search(&c, &inbox, "2026-03-01", "2026-03-02").await;
    assert!(none.as_array().unwrap().is_empty(), "{none}");

    // a Reply-To fixture (index 2) is answered at its Reply-To address
    let found = search(&c, &inbox, &mails[2].day, &mails[2].next_day).await;
    let id2 = found[0]["id"].as_str().unwrap().to_string();
    call(
        &c,
        "mail_draft_reply",
        json!({ "id": id2, "folder": inbox, "body": "Danke." }),
    )
    .await;
    let drafts = list_folder_messages(&acct, T, "Drafts").await.unwrap();
    assert_eq!(drafts.len(), 2);
    let last = parse_message(drafts.last().unwrap()).unwrap();
    assert_eq!(
        last.to[0].address.as_deref(),
        Some(mails[2].expected_recipient())
    );
    assert_eq!(
        last.in_reply_to.as_deref(),
        Some(mails[2].message_id.as_str())
    );
    c.cancel().await.ok();
    d.stop().await;
}
