//! M4 spec §6.2 tools over the scripted server with an in-memory handle
//! store: exactly four tools, handles instead of names, search → read →
//! draft, UIDVALIDITY staleness, size limits, draft header correctness,
//! draft-only command set, flag fallback, ambiguous APPEND reported once,
//! validation before any write, memoized authentication failures, and
//! class-only errors and logs.

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use inumaki_mail::fake::{FakeImap, FakeMode, FakeState};
use inumaki_mail::handles::{MailHandles, MemoryHandles, Resolved};
use inumaki_mail::render::parse_message;
use inumaki_mail::{
    CONTRACT_JSON, MailAccount, MailConfig, MailServer, Preset, StaticCredentials, TOOL_NAMES,
};
use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, CallToolResult, JsonObject};
use rmcp::service::{RoleClient, RoleServer, RunningService};
use serde_json::{Value, json};
use zeroize::Zeroizing;

const CANARY_FOLDER: &str = "Kunde Zyxwuria Quolnath";

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}.eml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn account(port: u16, password: &str) -> MailAccount {
    MailAccount {
        preset: Preset::Generic,
        host: "127.0.0.1".into(),
        port,
        tls: false,
        username: Zeroizing::new("agent".into()),
        password: Zeroizing::new(password.into()),
        drafts_folder: None,
        from_address: Some("agent@example.test".into()),
    }
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

type Client = RunningService<RoleClient, ()>;
type Server = RunningService<RoleServer, MailServer>;

struct Rig {
    fake: FakeImap,
    handles: Arc<MemoryHandles>,
    server: MailServer,
    client: Client,
    _serving: Server,
}

async fn rig_with(state: FakeState, password: &str, config: MailConfig) -> Rig {
    let handles = Arc::new(MemoryHandles::new());
    let store = Arc::clone(&handles) as Arc<dyn MailHandles>;
    rig_store(state, password, config, handles, store).await
}

async fn rig_store(
    state: FakeState,
    password: &str,
    config: MailConfig,
    handles: Arc<MemoryHandles>,
    store: Arc<dyn MailHandles>,
) -> Rig {
    let fake = FakeImap::start(state).await;
    let server = MailServer::start(
        Arc::new(StaticCredentials(account(fake.port(), password))),
        store,
        config,
        "ds-label",
    );
    let (a, b) = tokio::io::duplex(64 * 1024);
    let (ar, aw) = tokio::io::split(a);
    let (br, bw) = tokio::io::split(b);
    let (s, c) = tokio::join!(
        rmcp::serve_server(server.clone(), (ar, aw)),
        ().serve((br, bw))
    );
    Rig {
        fake,
        handles,
        server,
        client: c.unwrap(),
        _serving: s.unwrap(),
    }
}

async fn rig() -> Rig {
    rig_with(seeded(), "secret", MailConfig::default()).await
}

fn args(v: Value) -> JsonObject {
    v.as_object().cloned().unwrap()
}

fn text(r: &CallToolResult) -> String {
    r.content
        .iter()
        .filter_map(|c| c.as_text().map(|t| t.text.clone()))
        .collect::<Vec<_>>()
        .join("\n")
}

async fn call(rig: &Rig, tool: &str, a: Value) -> CallToolResult {
    rig.client
        .peer()
        .call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(args(a)))
        .await
        .unwrap()
}

fn class_of(r: &CallToolResult) -> String {
    assert_eq!(r.is_error, Some(true), "expected a tool error, got {r:?}");
    text(r).split(':').next().unwrap().to_string()
}

async fn inbox(rig: &Rig) -> String {
    let r = call(rig, "mail_list_folders", json!({})).await;
    r.structured_content.unwrap()["folders"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == "INBOX")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn search_day(rig: &Rig, folder: &str, day: &str, next: &str) -> Value {
    let r = call(
        rig,
        "mail_search",
        json!({ "folder": folder, "since": day, "before": next }),
    )
    .await;
    assert_ne!(r.is_error, Some(true), "{}", text(&r));
    r.structured_content.unwrap()
}

/// The plain mail (27 Sep) in INBOX: its message handle and INBOX's handle.
async fn plain_in_inbox(rig: &Rig) -> (String, String) {
    let inbox = inbox(rig).await;
    let sc = search_day(rig, &inbox, "2026-09-27", "2026-09-28").await;
    (sc["messages"][0]["id"].as_str().unwrap().to_string(), inbox)
}

/// Review Focus 7 (tool list half).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tool_list_has_exactly_the_four_tools() {
    let rig = rig().await;
    let tools = rig.client.peer().list_all_tools().await.unwrap();
    let mut names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
    names.sort();
    let mut want: Vec<String> = TOOL_NAMES.iter().map(|s| s.to_string()).collect();
    want.sort();
    assert_eq!(names, want);
    assert!(!names.iter().any(|n| n.contains("send")), "{names:?}");
    for t in &tools {
        let s = serde_json::to_string(&t.input_schema).unwrap();
        assert!(
            !s.contains("\"type\":["),
            "no array types (plan 2 discovery rejects them): {s}"
        );
        assert!(t.description.is_some());
    }
    let contract: Value = serde_json::from_str(CONTRACT_JSON).unwrap();
    for n in TOOL_NAMES {
        assert!(
            contract["tools"][n].is_object(),
            "{n} missing from the contract"
        );
    }
    assert_eq!(contract["tools"].as_object().unwrap().len(), 4);
    assert!(
        contract["tools"]["mail_read"].get("result").is_none(),
        "mail_read is text only"
    );
    assert_eq!(
        contract["tools"]["mail_search"]["result"]["/messages/*/id"],
        "handle"
    );
    assert_eq!(
        contract["tools"]["mail_draft_reply"]["arguments"]["/body"],
        "free_text"
    );
    assert!(
        rig.client
            .peer()
            .peer_info()
            .unwrap()
            .server_info
            .as_ref()
            .is_some_and(|i| i.name.contains("inumaki-mail")),
        "the server names itself"
    );
    assert!(!format!("{:?}", rig.server).contains("agent"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_search_read_round_trip_through_handles() {
    let rig = rig().await;
    let r = call(&rig, "mail_list_folders", json!({})).await;
    assert_ne!(r.is_error, Some(true), "{}", text(&r));
    let folders = r.structured_content.clone().unwrap()["folders"].clone();
    let names: Vec<&str> = folders
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["Drafts", "INBOX", CANARY_FOLDER]);
    for f in folders.as_array().unwrap() {
        let id = f["id"].as_str().unwrap();
        assert!(
            id.starts_with("mf_")
                && id.len() == 19
                && id[3..].bytes().all(|b| b.is_ascii_lowercase()),
            "{id}"
        );
        assert!(text(&r).contains(id), "handles appear in the text too");
    }
    let inbox = inbox(&rig).await;
    // search by date window: exactly the html mail (28 Sep)
    let sc = search_day(&rig, &inbox, "2026-09-28", "2026-09-29").await;
    let msgs = sc["messages"].as_array().unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(sc["truncated"], false);
    let m = &msgs[0];
    assert!(m["id"].as_str().unwrap().starts_with("mm_"));
    assert_eq!(m["folder"], inbox);
    assert_eq!(
        m["from"],
        "Zyxwuria Quolnath <zyxwuria.quolnath@example.test>"
    );
    assert_eq!(m["subject"], "Termin nächste Woche");
    assert_eq!(m["date"], "2026-09-28T09:00:00+02:00");
    assert!(
        m["snippet"]
            .as_str()
            .unwrap()
            .starts_with("Hallo, passt Dienstag")
    );
    // a free-text search, newest first, limit and truncation
    let r = call(
        &rig,
        "mail_search",
        json!({ "query": "example.test", "limit": 2 }),
    )
    .await;
    let sc = r.structured_content.clone().unwrap();
    let ids: Vec<&str> = sc["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["subject"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        ["Re: Vertrag V-99871", "Termin nächste Woche"],
        "newest first, INBOX by default"
    );
    assert_eq!(sc["truncated"], true);
    assert!(
        text(&r).starts_with("| id | from | date | subject | snippet |"),
        "{}",
        text(&r)
    );
    // read
    let id = m["id"].as_str().unwrap();
    let r = call(&rig, "mail_read", json!({ "id": id, "folder": inbox })).await;
    assert_ne!(r.is_error, Some(true), "{}", text(&r));
    let md = text(&r);
    assert!(
        md.starts_with("**From:** Zyxwuria Quolnath <zyxwuria.quolnath@example.test>\n"),
        "{md}"
    );
    assert!(md.contains("passt Dienstag 14:00"));
    assert!(r.structured_content.is_none(), "mail_read is text only");
    // the folder handle must belong to the message
    let other = folders
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == CANARY_FOLDER)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let r = call(&rig, "mail_read", json!({ "id": id, "folder": other })).await;
    assert_eq!(class_of(&r), "context_unavailable");
    // unknown, swapped, and malformed handles; raw names are never accepted
    for (i, f) in [
        ("mm_aaaaaaaaaaaaaaaa", inbox.as_str()),
        (inbox.as_str(), inbox.as_str()),
        (id, id),
        ("INBOX", "INBOX"),
        (CANARY_FOLDER, CANARY_FOLDER),
    ] {
        let r = call(&rig, "mail_read", json!({ "id": i, "folder": f })).await;
        assert_eq!(class_of(&r), "context_unavailable", "{i} / {f}");
    }
    let r = call(&rig, "mail_search", json!({ "folder": id, "query": "x" })).await;
    assert_eq!(
        class_of(&r),
        "context_unavailable",
        "a message handle is not a folder"
    );
    let r = call(
        &rig,
        "mail_search",
        json!({ "folder": CANARY_FOLDER, "query": "x" }),
    )
    .await;
    assert_eq!(
        class_of(&r),
        "context_unavailable",
        "a raw folder name is not a handle"
    );
    // argument validation
    for a in [
        json!({}),
        json!({ "id": id }),
        json!({ "folder": inbox }),
        json!({ "id": 5, "folder": inbox }),
    ] {
        assert_eq!(
            class_of(&call(&rig, "mail_read", a).await),
            "invalid_argument"
        );
    }
    for a in [
        json!({}),
        json!({ "query": "x", "limit": 0 }),
        json!({ "query": "x", "limit": 101 }),
        json!({ "query": "x", "limit": "5" }),
        json!({ "since": "27.09.2026" }),
        json!({ "query": "a\r\nB LOGOUT" }),
    ] {
        assert_eq!(
            class_of(&call(&rig, "mail_search", a.clone()).await),
            "invalid_argument",
            "{a}"
        );
    }
    let st = rig.fake.state();
    let st = st.lock().unwrap();
    assert!(
        st.commands.iter().all(|c| c != "UID STORE"),
        "reads mark nothing"
    );
    assert!(
        st.commands.iter().any(|c| c == "EXAMINE") && !st.commands.iter().any(|c| c == "SELECT"),
        "reads use EXAMINE"
    );
    assert_eq!(st.logins, 1, "one connection for everything");
}

/// Review Focus 2: a handle minted before a UIDVALIDITY change never reads
/// the message that now carries its UID, even though the store still
/// resolves it (the live UIDVALIDITY is checked on every use).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn uidvalidity_change_invalidates_message_handles_and_never_reads_another_message() {
    let rig = rig().await;
    let inbox = inbox(&rig).await;
    let sc = search_day(&rig, &inbox, "2026-09-27", "2026-09-28").await;
    let plain = sc["messages"][0]["id"].as_str().unwrap().to_string();
    assert_eq!(sc["messages"][0]["subject"], "Rechnung RE-2026-0042");
    // the folder is rebuilt: the first message is gone and the rest are renumbered, so UID 1 is now the html mail
    {
        let st = rig.fake.state();
        let mut st = st.lock().unwrap();
        let f = st.folders.get_mut("INBOX").unwrap();
        f.messages.remove(0);
        st.bump_uidvalidity("INBOX");
        assert_eq!(st.folders["INBOX"].messages[0].uid, 1);
    }
    assert!(
        rig.handles.resolve(&plain).unwrap().is_some(),
        "the store still resolves the handle minted before the change"
    );
    let fetches_before = rig.fake.state().lock().unwrap().fetches.len();
    let r = call(&rig, "mail_read", json!({ "id": plain, "folder": inbox })).await;
    assert_eq!(class_of(&r), "context_unavailable");
    assert!(
        !text(&r).contains("Termin") && !text(&r).contains("Dienstag"),
        "must not read the message that now has UID 1"
    );
    assert_eq!(
        rig.fake.state().lock().unwrap().fetches.len(),
        fetches_before,
        "nothing was fetched with the stale UID"
    );
    assert!(
        rig.handles.resolve(&plain).unwrap().is_none(),
        "the stale handle is gone from the store"
    );
    assert!(
        rig.handles.resolve(&inbox).unwrap().is_some(),
        "the folder handle survives"
    );
    // the handle stays stale forever; a new search mints fresh ones and reading works again
    let sc = search_day(&rig, &inbox, "2026-09-28", "2026-09-29").await;
    let fresh = sc["messages"][0]["id"].as_str().unwrap().to_string();
    assert_ne!(fresh, plain);
    let r = call(&rig, "mail_read", json!({ "id": fresh, "folder": inbox })).await;
    assert!(text(&r).contains("passt Dienstag 14:00"), "{}", text(&r));
    let r = call(&rig, "mail_read", json!({ "id": plain, "folder": inbox })).await;
    assert_eq!(class_of(&r), "context_unavailable");
}

/// A store whose invalidation lags (the vault's resolve read and touch is
/// not atomic with invalidation): stale handles keep resolving.
struct LaggingHandles(Arc<MemoryHandles>);

impl MailHandles for LaggingHandles {
    fn folder_handle(&self, folder: &str) -> Result<String, inumaki_mail::MailError> {
        self.0.folder_handle(folder)
    }
    fn message_handle(
        &self,
        r: &inumaki_mail::MessageRef,
    ) -> Result<String, inumaki_mail::MailError> {
        self.0.message_handle(r)
    }
    fn resolve(&self, handle: &str) -> Result<Option<Resolved>, inumaki_mail::MailError> {
        self.0.resolve(handle)
    }
    fn invalidate_folder(&self, _folder: &str) -> Result<usize, inumaki_mail::MailError> {
        Ok(0)
    }
}

/// Carry-over (b): every use of a message handle re-checks the live
/// UIDVALIDITY, so a handle minted before the change that the store still
/// resolves can neither read nor be replied to, however often it is used.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stale_handle_the_store_still_resolves_never_reads_or_replies() {
    let handles = Arc::new(MemoryHandles::new());
    let store = Arc::new(LaggingHandles(Arc::clone(&handles))) as Arc<dyn MailHandles>;
    let rig = rig_store(seeded(), "secret", MailConfig::default(), handles, store).await;
    let (plain, inbox) = plain_in_inbox(&rig).await;
    {
        let st = rig.fake.state();
        let mut st = st.lock().unwrap();
        st.folders.get_mut("INBOX").unwrap().messages.remove(0);
        st.bump_uidvalidity("INBOX");
    }
    let fetches_before = rig.fake.state().lock().unwrap().fetches.len();
    for _ in 0..2 {
        for tool in ["mail_read", "mail_draft_reply"] {
            let r = call(
                &rig,
                tool,
                json!({ "id": plain, "folder": inbox, "body": "Danke." }),
            )
            .await;
            assert_eq!(class_of(&r), "context_unavailable", "{tool}");
        }
    }
    assert!(
        rig.handles.resolve(&plain).unwrap().is_some(),
        "still resolves"
    );
    let st = rig.fake.state();
    let st = st.lock().unwrap();
    assert_eq!(
        st.fetches.len(),
        fetches_before,
        "no FETCH with the stale UID"
    );
    assert_eq!(
        st.count("APPEND"),
        0,
        "no draft replies to the wrong message"
    );
}

/// Review Focus 6.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_message_is_refused_before_the_body_is_fetched() {
    let rig = rig_with(
        seeded(),
        "secret",
        MailConfig {
            max_message_bytes: 300,
            ..MailConfig::default()
        },
    )
    .await;
    let (plain, inbox) = plain_in_inbox(&rig).await;
    assert!(fixture("plain").len() > 300);
    let before = rig.fake.state().lock().unwrap().fetches.clone();
    let r = call(&rig, "mail_read", json!({ "id": plain, "folder": inbox })).await;
    assert_eq!(class_of(&r), "resource_limit");
    let after = rig.fake.state().lock().unwrap().fetches.clone();
    let new: Vec<&String> = after.iter().skip(before.len()).collect();
    assert_eq!(
        new.len(),
        1,
        "one FETCH for the size, none for the body: {new:?}"
    );
    assert!(
        new[0].contains("RFC822.SIZE") && !new[0].contains("BODY"),
        "{new:?}"
    );
}

/// The draft-only guarantee plus draft header correctness.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn draft_reply_appends_a_valid_reply_and_returns_its_handle() {
    let rig = rig().await;
    let (plain, inbox) = plain_in_inbox(&rig).await;
    let r = call(&rig, "mail_draft_reply", json!({ "id": plain, "folder": inbox, "body": "Sehr geehrte Frau Leitner,\n\nvielen Dank für Ihre Nachricht.\n", "cc": "Max Huber <max.huber@example.test>" })).await;
    assert_ne!(r.is_error, Some(true), "{}", text(&r));
    assert!(text(&r).contains("does not send mail"), "{}", text(&r));
    let sc = r.structured_content.unwrap();
    assert_eq!(sc["status"], "created");
    let draft_id = sc["draft"]["id"].as_str().unwrap().to_string();
    let drafts_folder = sc["draft"]["folder"].as_str().unwrap().to_string();
    assert!(draft_id.starts_with("mm_") && drafts_folder.starts_with("mf_"));
    match rig.handles.resolve(&draft_id).unwrap().unwrap() {
        Resolved::Message(m) => {
            assert_eq!(
                (m.folder.as_str(), m.uid_validity, m.uid),
                ("Drafts", 7000, 1)
            );
        }
        other => panic!("{other:?}"),
    }
    {
        let st = rig.fake.state();
        let st = st.lock().unwrap();
        assert_eq!(st.appends.len(), 1);
        assert_eq!(st.appends[0].folder, "Drafts");
        assert_eq!(st.appends[0].flags.as_deref(), Some("(\\Draft)"));
        let d = parse_message(&st.appends[0].raw).unwrap();
        assert_eq!(
            d.to[0].display(),
            "Sarah Leitner <sarah.leitner@example.test>"
        );
        assert_eq!(d.cc[0].display(), "Max Huber <max.huber@example.test>");
        assert_eq!(d.from[0].display(), "agent@example.test");
        assert_eq!(d.subject.as_deref(), Some("Re: Rechnung RE-2026-0042"));
        assert_eq!(d.in_reply_to.as_deref(), Some("plain-1@example.test"));
        assert_eq!(d.references, ["plain-1@example.test"]);
        assert!(d.body.contains("vielen Dank für Ihre Nachricht"));
        assert!(d.message_id.as_deref().unwrap().ends_with("@example.test"));
        assert!(d.date.is_some());
    }
    // the draft can be read back through its own handle
    let r = call(
        &rig,
        "mail_read",
        json!({ "id": draft_id, "folder": drafts_folder }),
    )
    .await;
    assert!(
        text(&r).contains("**Subject:** Re: Rechnung RE-2026-0042"),
        "{}",
        text(&r)
    );
    // a reply to the quoted mail extends its References chain
    let sc = search_day(&rig, &inbox, "2026-09-29", "2026-09-30").await;
    let quoted = sc["messages"][0]["id"].as_str().unwrap().to_string();
    let r = call(
        &rig,
        "mail_draft_reply",
        json!({ "id": quoted, "folder": inbox, "body": "Passt." }),
    )
    .await;
    assert_ne!(r.is_error, Some(true), "{}", text(&r));
    {
        let st = rig.fake.state();
        let st = st.lock().unwrap();
        let d = parse_message(&st.appends[1].raw).unwrap();
        assert_eq!(
            d.subject.as_deref(),
            Some("Re: Vertrag V-99871"),
            "an existing Re: is not doubled"
        );
        assert_eq!(
            d.references,
            [
                "quoted-0@musterfirma.example",
                "quoted-1@musterfirma.example",
                "quoted-2@example.test"
            ]
        );
        assert_eq!(d.in_reply_to.as_deref(), Some("quoted-2@example.test"));
        assert!(d.cc.is_empty());
    }
    // Reply-To wins when it is exactly one valid address (the attachments mail in the customer folder)
    let r = call(&rig, "mail_list_folders", json!({})).await;
    let kunde = r.structured_content.unwrap()["folders"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == CANARY_FOLDER)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let sc = search_day(&rig, &kunde, "2026-09-30", "2026-10-01").await;
    let att = sc["messages"][0]["id"].as_str().unwrap().to_string();
    let r = call(
        &rig,
        "mail_draft_reply",
        json!({ "id": att, "folder": kunde, "body": "Danke für die Unterlagen." }),
    )
    .await;
    assert_ne!(r.is_error, Some(true), "{}", text(&r));
    let st = rig.fake.state();
    let st = st.lock().unwrap();
    let d = parse_message(&st.appends[2].raw).unwrap();
    assert_eq!(d.to.len(), 1);
    assert_eq!(
        d.to[0].address.as_deref(),
        Some("anna.reply@example.test"),
        "Reply-To, not From"
    );
    assert_eq!(d.in_reply_to.as_deref(), Some("att-1@example.test"));
    // draft-only: the whole session used read commands plus APPEND to the
    // drafts folder; nothing was selected read-write, flagged, moved,
    // copied, expunged, or sent
    let allowed = [
        "CAPABILITY",
        "LOGIN",
        "LIST",
        "EXAMINE",
        "UID SEARCH",
        "UID FETCH",
        "APPEND",
        "NOOP",
    ];
    for c in &st.commands {
        assert!(allowed.contains(&c.as_str()), "unexpected command {c}");
    }
    assert!(st.appends.iter().all(|a| a.folder == "Drafts"));
    assert_eq!(st.appends.len(), 3, "one stored draft per call");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_ascii_queries_use_literal_plus_or_are_refused() {
    let mut s = FakeState::new("agent", "secret");
    s.add("INBOX", &fixture("latin1"));
    s.add("INBOX", &fixture("plain"));
    let rig = rig_with(s, "secret", MailConfig::default()).await;
    let r = call(&rig, "mail_search", json!({ "query": "Müller" })).await;
    assert_ne!(r.is_error, Some(true), "{}", text(&r));
    let sc = r.structured_content.unwrap();
    assert_eq!(sc["messages"].as_array().unwrap().len(), 1);
    assert_eq!(sc["messages"][0]["subject"], "Rückfrage");
    // the same server without LITERAL+: refused with a fixed class, never sent 8-bit
    drop(rig);
    let mut s = FakeState::new("agent", "secret");
    s.literal_plus = false;
    s.add("INBOX", &fixture("latin1"));
    let rig = rig_with(s, "secret", MailConfig::default()).await;
    let r = call(&rig, "mail_search", json!({ "query": "Müller" })).await;
    assert_eq!(class_of(&r), "invalid_argument");
    let r = call(&rig, "mail_search", json!({ "query": "example.test" })).await;
    assert_ne!(r.is_error, Some(true), "ASCII still works: {}", text(&r));
    assert!(
        rig.fake
            .state()
            .lock()
            .unwrap()
            .commands
            .iter()
            .filter(|c| *c == "UID SEARCH")
            .count()
            == 1,
        "the refused query never reached the server"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drafts_folder_is_created_when_the_server_has_none() {
    let mut s = seeded();
    s.folders.remove("Drafts");
    let rig = rig_with(s, "secret", MailConfig::default()).await;
    let (plain, inbox) = plain_in_inbox(&rig).await;
    let r = call(
        &rig,
        "mail_draft_reply",
        json!({ "id": plain, "folder": inbox, "body": "Danke." }),
    )
    .await;
    assert_ne!(r.is_error, Some(true), "{}", text(&r));
    let st = rig.fake.state();
    let st = st.lock().unwrap();
    assert_eq!(st.count("CREATE"), 1);
    assert!(st.folders.contains_key("Drafts"));
    assert_eq!(st.appends[0].folder, "Drafts");
}

/// Review Focus 4.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ambiguous_append_is_reported_once_and_never_retried() {
    let rig = rig().await;
    let (plain, inbox) = plain_in_inbox(&rig).await;
    rig.fake.state().lock().unwrap().mode = FakeMode::DropAfterLiteralStored;
    let r = call(
        &rig,
        "mail_draft_reply",
        json!({ "id": plain, "folder": inbox, "body": "Danke." }),
    )
    .await;
    assert_eq!(class_of(&r), "draft_status_unknown");
    assert!(text(&r).contains("check the Drafts folder"), "{}", text(&r));
    assert!(r.structured_content.is_none());
    {
        let st = rig.fake.state();
        let st = st.lock().unwrap();
        assert_eq!(st.count("APPEND"), 1, "exactly one attempt");
        assert_eq!(
            st.appends.len(),
            1,
            "the server did store it; the user must look"
        );
        assert_eq!(st.logins, 1);
    }
    // dropped after the literal with nothing stored: just as ambiguous to the client
    rig.fake.state().lock().unwrap().mode = FakeMode::DropAfterLiteral;
    let r = call(
        &rig,
        "mail_draft_reply",
        json!({ "id": plain, "folder": inbox, "body": "Danke." }),
    )
    .await;
    assert_eq!(class_of(&r), "draft_status_unknown");
    {
        let st = rig.fake.state();
        let st = st.lock().unwrap();
        assert_eq!(st.count("APPEND"), 2, "one attempt, no retry");
        assert_eq!(st.logins, 2);
    }
    // the next call reconnects and works
    rig.fake.state().lock().unwrap().mode = FakeMode::Normal;
    let r = call(
        &rig,
        "mail_draft_reply",
        json!({ "id": plain, "folder": inbox, "body": "Nochmal." }),
    )
    .await;
    assert_ne!(r.is_error, Some(true), "{}", text(&r));
    {
        let st = rig.fake.state();
        let st = st.lock().unwrap();
        assert_eq!(st.logins, 3);
        assert_eq!(st.count("APPEND"), 3);
        assert_eq!(st.appends.len(), 2);
    }
    // desynchronised before the literal: nothing was stored, so the unflagged
    // retry is allowed, but only on a fresh session (the old one is out of step)
    rig.fake.state().lock().unwrap().mode = FakeMode::UnsolicitedBeforeContinue;
    let r = call(
        &rig,
        "mail_draft_reply",
        json!({ "id": plain, "folder": inbox, "body": "Und nochmal." }),
    )
    .await;
    assert_ne!(r.is_error, Some(true), "{}", text(&r));
    let st = rig.fake.state();
    let st = st.lock().unwrap();
    assert_eq!(st.logins, 4, "a fresh session for the retry");
    assert_eq!(
        st.count("APPEND"),
        5,
        "the desynchronised attempt plus one retry"
    );
    assert_eq!(st.appends.len(), 3);
    assert!(
        st.appends[2].flags.is_none(),
        "the retry is the unflagged fallback"
    );
    assert_eq!(
        st.appends
            .iter()
            .filter(|a| a.raw.windows(12).any(|w| w == b"Und nochmal."))
            .count(),
        1,
        "stored exactly once"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flag_refusal_retries_once_without_the_flag() {
    let mut s = seeded();
    s.mode = FakeMode::RejectDraftFlag;
    let rig = rig_with(s, "secret", MailConfig::default()).await;
    let (plain, inbox) = plain_in_inbox(&rig).await;
    let r = call(
        &rig,
        "mail_draft_reply",
        json!({ "id": plain, "folder": inbox, "body": "Danke." }),
    )
    .await;
    assert_ne!(r.is_error, Some(true), "{}", text(&r));
    let st = rig.fake.state();
    let st = st.lock().unwrap();
    assert_eq!(
        st.count("APPEND"),
        2,
        "flagged attempt, then one without the flag"
    );
    assert_eq!(st.appends.len(), 1);
    assert!(st.appends[0].flags.is_none());
    assert_eq!(
        st.logins, 1,
        "a refusal after the literal keeps the session"
    );
}

/// Fix round 1 (Important 1): an APPEND answer the client cannot parse
/// comes after the literal, so the draft may be stored: reported once as
/// `draft_status_unknown`, never retried.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unparseable_append_reply_is_ambiguous_and_never_retried() {
    let rig = rig().await;
    let (plain, inbox) = plain_in_inbox(&rig).await;
    rig.fake.state().lock().unwrap().mode = FakeMode::GarbledAfterLiteralStored;
    let r = call(
        &rig,
        "mail_draft_reply",
        json!({ "id": plain, "folder": inbox, "body": "Danke." }),
    )
    .await;
    assert_eq!(class_of(&r), "draft_status_unknown");
    assert!(r.structured_content.is_none());
    let st = rig.fake.state();
    let st = st.lock().unwrap();
    assert_eq!(st.count("APPEND"), 1, "exactly one attempt, no retry");
    assert_eq!(st.appends.len(), 1, "the server did store it");
    assert_eq!(st.logins, 1, "no reconnect for a retry");
}

/// Fix round 1 (Important 2): a stored draft that cannot be located has no
/// `id` at all (never JSON null, which the output schema would reject), and
/// is still `created`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unlocated_draft_omits_its_id_and_still_reports_created() {
    let rig = rig().await;
    let tools = rig.client.peer().list_all_tools().await.unwrap();
    let draft_tool = tools.iter().find(|t| t.name == "mail_draft_reply").unwrap();
    let schema = serde_json::to_value(draft_tool.output_schema.as_deref().unwrap()).unwrap();
    let draft_schema = &schema["properties"]["draft"];
    assert_eq!(draft_schema["properties"]["id"]["type"], "string");
    assert!(
        !draft_schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "id"),
        "id is optional: {draft_schema}"
    );
    let (plain, inbox) = plain_in_inbox(&rig).await;
    rig.fake.state().lock().unwrap().mode = FakeMode::AppendNotListed;
    let r = call(
        &rig,
        "mail_draft_reply",
        json!({ "id": plain, "folder": inbox, "body": "Danke." }),
    )
    .await;
    assert_ne!(r.is_error, Some(true), "{}", text(&r));
    assert!(text(&r).contains("does not send mail") && !text(&r).contains("Draft id"));
    let sc = r.structured_content.unwrap();
    assert_eq!(sc["status"], "created");
    let draft = sc["draft"].as_object().unwrap();
    assert!(!draft.contains_key("id"), "no id key, not even null: {sc}");
    assert!(draft["folder"].as_str().unwrap().starts_with("mf_"));
    let st = rig.fake.state();
    let st = st.lock().unwrap();
    assert_eq!(st.count("APPEND"), 1);
    assert_eq!(st.appends.len(), 1);
}

/// Carry-over (a): a `NO` instead of the `+` continuation (async-imap
/// `Error::Append`, class `append_desync`) stored nothing, so the unflagged
/// retry runs once, on a fresh session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refusal_before_the_literal_retries_once_on_a_fresh_session() {
    let mut s = seeded();
    s.mode = FakeMode::RefuseDraftBeforeLiteral;
    let rig = rig_with(s, "secret", MailConfig::default()).await;
    let (plain, inbox) = plain_in_inbox(&rig).await;
    let r = call(
        &rig,
        "mail_draft_reply",
        json!({ "id": plain, "folder": inbox, "body": "Danke." }),
    )
    .await;
    assert_ne!(r.is_error, Some(true), "{}", text(&r));
    let st = rig.fake.state();
    let st = st.lock().unwrap();
    assert_eq!(st.count("APPEND"), 2, "the refused attempt plus one retry");
    assert_eq!(st.appends.len(), 1, "stored exactly once");
    assert!(st.appends[0].flags.is_none());
    assert_eq!(st.logins, 2, "the retry runs on a fresh session");
}

/// Review Focus 5.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_cc_is_rejected_before_any_append() {
    let rig = rig().await;
    let (plain, inbox) = plain_in_inbox(&rig).await;
    for (a, class) in [
        (
            json!({ "id": plain, "folder": inbox, "body": "x", "cc": "a@b.test\r\nBcc: evil@example.test" }),
            "invalid_argument",
        ),
        (
            json!({ "id": plain, "folder": inbox, "body": "x", "cc": "Just A Name" }),
            "invalid_argument",
        ),
        (
            json!({ "id": plain, "folder": inbox, "body": "x", "cc": "a@b.test, <c@d.test> e@f.test" }),
            "invalid_argument",
        ),
        (
            json!({ "id": plain, "folder": inbox, "body": "with\u{0}nul" }),
            "invalid_argument",
        ),
        (
            json!({ "id": plain, "folder": inbox, "body": "   " }),
            "invalid_argument",
        ),
        (json!({ "id": plain, "folder": inbox }), "invalid_argument"),
        (
            json!({ "id": plain, "folder": inbox, "body": 7 }),
            "invalid_argument",
        ),
        (
            json!({ "id": "mm_zzzzzzzzzzzzzzzz", "folder": inbox, "body": "x" }),
            "context_unavailable",
        ),
        (
            json!({ "id": inbox, "folder": plain, "body": "x" }),
            "context_unavailable",
        ),
    ] {
        let r = call(&rig, "mail_draft_reply", a.clone()).await;
        assert_eq!(class_of(&r), class, "{a}");
    }
    let huge = "x".repeat(256 * 1024 + 1);
    let r = call(
        &rig,
        "mail_draft_reply",
        json!({ "id": plain, "folder": inbox, "body": huge }),
    )
    .await;
    assert_eq!(class_of(&r), "invalid_argument");
    let st = rig.fake.state();
    let st = st.lock().unwrap();
    assert_eq!(st.count("APPEND"), 0, "nothing was written");
    assert!(st.appends.is_empty());
}

/// Review Focus 10.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_failure_is_memoized() {
    let mut s = seeded();
    s.mode = FakeMode::RefuseLogin;
    let rig = rig_with(
        s,
        "wrong",
        MailConfig {
            auth_retry_after: Duration::from_millis(300),
            ..MailConfig::default()
        },
    )
    .await;
    let r = call(&rig, "mail_list_folders", json!({})).await;
    assert_eq!(class_of(&r), "mail_auth_failed");
    assert!(text(&r).contains("check-mailbox"), "{}", text(&r));
    assert!(!text(&r).contains("wrong") && !text(&r).contains("agent"));
    assert_eq!(rig.fake.state().lock().unwrap().login_attempts, 1);
    for tool in ["mail_list_folders", "mail_search"] {
        let r = call(&rig, tool, json!({ "query": "x" })).await;
        assert_eq!(class_of(&r), "mail_auth_failed");
    }
    assert_eq!(
        rig.fake.state().lock().unwrap().login_attempts,
        1,
        "no second login inside the retry window"
    );
    tokio::time::sleep(Duration::from_millis(350)).await;
    {
        let st = rig.fake.state();
        let mut st = st.lock().unwrap();
        st.mode = FakeMode::Normal;
        st.password = "wrong".into();
    }
    let r = call(&rig, "mail_list_folders", json!({})).await;
    assert_ne!(r.is_error, Some(true), "{}", text(&r));
    assert_eq!(rig.fake.state().lock().unwrap().login_attempts, 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn errors_are_classes_and_unknown_tools_are_protocol_errors() {
    let rig = rig().await;
    let e = rig
        .client
        .peer()
        .call_tool(CallToolRequestParams::new("mail_send_qwxzvk").with_arguments(args(json!({}))))
        .await
        .unwrap_err();
    let s = format!("{e:?}");
    assert!(s.contains("unknown tool"), "{s}");
    assert!(
        !s.contains("qwxzvk"),
        "the agent's tool name is not echoed: {s}"
    );
    let r = call(
        &rig,
        "mail_read",
        json!({ "id": CANARY_FOLDER, "folder": CANARY_FOLDER }),
    )
    .await;
    assert_eq!(
        text(&r),
        "context_unavailable: the folder or message handle is unknown or stale; run mail_search again"
    );
    // open a session so shutdown has one to log out of
    inbox(&rig).await;
    rig.server.shutdown().await;
    let st = rig.fake.state();
    let st = st.lock().unwrap();
    assert!(
        st.commands.iter().any(|c| c == "LOGOUT"),
        "shutdown logs out"
    );
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Capture {
        self.clone()
    }
}

/// Privacy: the connector's own log lines (every level) carry no folder
/// name, address, subject, body text, password, user name, or server text,
/// across a full list → search → read → draft → stale-handle session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connector_logs_carry_no_mail_content() {
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::SubscriberExt;
    let cap = Capture::default();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(cap.clone())
            .with_filter(tracing_subscriber::EnvFilter::new("inumaki_mail=trace")),
    );
    // global, not scoped: the server runs on the runtime's worker threads.
    // Other tests in this binary may log here too; they must be clean as well.
    let _ = tracing::subscriber::set_global_default(subscriber);
    let mut s = seeded();
    s.password = "hunter2-canary".into();
    let rig = rig_with(s, "hunter2-canary", MailConfig::default()).await;
    let r = call(&rig, "mail_list_folders", json!({})).await;
    let kunde = r.structured_content.unwrap()["folders"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == CANARY_FOLDER)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let sc = search_day(&rig, &kunde, "2026-09-30", "2026-10-01").await;
    let att = sc["messages"][0]["id"].as_str().unwrap().to_string();
    let r = call(&rig, "mail_read", json!({ "id": att, "folder": kunde })).await;
    assert!(
        text(&r).contains("Zyxwuria"),
        "the agent does see the content"
    );
    let r = call(
        &rig,
        "mail_draft_reply",
        json!({ "id": att, "folder": kunde, "body": "Sehr geehrte Frau Zyxwuria Quolnath, AT61 1904 3002 3457 3201" }),
    )
    .await;
    assert_ne!(r.is_error, Some(true), "{}", text(&r));
    rig.fake
        .state()
        .lock()
        .unwrap()
        .bump_uidvalidity(CANARY_FOLDER);
    let r = call(&rig, "mail_read", json!({ "id": att, "folder": kunde })).await;
    assert_eq!(class_of(&r), "context_unavailable");
    let _ = rig
        .client
        .peer()
        .call_tool(
            CallToolRequestParams::new("mail_send")
                .with_arguments(args(json!({ "to": "qwxzvk-canary-slug" }))),
        )
        .await;
    rig.server.shutdown().await;
    let logs = String::from_utf8(cap.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("served"), "the capture works: {logs}");
    for needle in [
        "Zyxwuria",
        "Quolnath",
        "Kunde",
        "example.test",
        "Unterlagen",
        "Anna",
        "AT61",
        "hunter2",
        "agent",
        "Drafts",
        "INBOX",
        "qwxzvk",
        "mm_",
        "mf_",
    ] {
        assert!(!logs.contains(needle), "{needle} leaked into the logs");
    }
}
