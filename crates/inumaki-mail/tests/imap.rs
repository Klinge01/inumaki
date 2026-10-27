//! The IMAP wrapper against the scripted server (M4 spec §6.1, §11): login
//! and connection classes, folder listing with special-use detection,
//! EXAMINE/UIDVALIDITY, search, summaries, full fetch, APPEND outcomes
//! (stored, refused flag, missing folder, ambiguous), command timeouts,
//! drafts-folder resolution, and check_mailbox.

use std::time::Duration;

use inumaki_mail::check::{CheckReport, check_mailbox};
use inumaki_mail::fake::{FakeImap, FakeMode, FakeState};
use inumaki_mail::imap::{DraftsFolder, Imap};
use inumaki_mail::query::build_search;
use inumaki_mail::render::{parse_message, parse_summary};
use inumaki_mail::stream::connect_stream;
use inumaki_mail::{MailAccount, MailError, Preset};
use zeroize::Zeroizing;

const CANARY_FOLDER: &str = "Kunde Zyxwuria Quolnath";
const T: Duration = Duration::from_secs(5);

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
    s
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connects_lists_examines_searches_and_fetches() {
    let fake = FakeImap::start(seeded()).await;
    let mut imap = Imap::connect(&account(fake.port(), "secret"), T)
        .await
        .unwrap();
    let folders = imap.folders().await.unwrap();
    let raws: Vec<&str> = folders.iter().map(|f| f.raw.as_str()).collect();
    assert_eq!(raws, ["INBOX", CANARY_FOLDER]);
    assert!(
        folders
            .iter()
            .all(|f| f.selectable && !f.drafts_special_use)
    );
    assert_eq!(imap.examine("INBOX").await.unwrap(), 1000);
    assert_eq!(imap.examine(CANARY_FOLDER).await.unwrap(), 2000);
    assert_eq!(
        imap.examine("Nope").await,
        Err(MailError::ContextUnavailable),
        "a missing folder is stale context, not a connection failure"
    );
    imap.examine("INBOX").await.unwrap();
    let all = imap.uid_search("SINCE 1-Jan-2026").await.unwrap();
    assert_eq!(all, [3, 2, 1], "newest first");
    assert_eq!(
        imap.uid_search("SINCE 28-Sep-2026 BEFORE 29-Sep-2026")
            .await
            .unwrap(),
        [2]
    );
    assert_eq!(
        imap.uid_search("OR OR FROM \"huber\" SUBJECT \"huber\" TEXT \"huber\"")
            .await
            .unwrap(),
        [3]
    );
    assert_eq!(
        imap.uid_search("HEADER Message-ID \"<plain-1@example.test>\"")
            .await
            .unwrap(),
        [1]
    );
    assert!(
        imap.uid_search("SINCE 1-Jan-2030")
            .await
            .unwrap()
            .is_empty()
    );
    let sums = imap.fetch_summaries(&[3, 1], 4096).await.unwrap();
    assert_eq!(
        sums.iter().map(|s| s.uid).collect::<Vec<_>>(),
        [1, 3],
        "server order"
    );
    let s = parse_summary(&sums[0].header, &sums[0].text_head, 60);
    assert_eq!(s.subject, "Rechnung RE-2026-0042");
    assert!(
        s.snippet.starts_with("Sehr geehrtes Support-Team"),
        "{}",
        s.snippet
    );
    assert_eq!(sums[0].size as usize, fixture("plain").len());
    let sums = imap.fetch_summaries(&[1], 16).await.unwrap();
    assert_eq!(sums[0].text_head.len(), 16, "partial fetch honoured");
    assert_eq!(
        imap.fetch_size(1).await.unwrap(),
        Some(fixture("plain").len() as u32)
    );
    assert_eq!(imap.fetch_size(99).await.unwrap(), None);
    let raw = imap.fetch_message(1).await.unwrap().unwrap();
    assert_eq!(raw, fixture("plain"));
    assert!(imap.fetch_message(99).await.unwrap().is_none());
    let p = parse_message(&raw).unwrap();
    assert_eq!(p.message_id.as_deref(), Some("plain-1@example.test"));
    imap.noop().await.unwrap();
    imap.logout().await;
    let st = fake.state();
    let st = st.lock().unwrap();
    assert_eq!(st.logins, 1);
    assert!(st.commands.iter().any(|c| c == "LOGOUT"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_failure_unreachable_host_and_plaintext_off_loopback_are_classes() {
    let mut s = seeded();
    s.mode = FakeMode::RefuseLogin;
    let fake = FakeImap::start(s).await;
    let e = Imap::connect(&account(fake.port(), "wrong"), T)
        .await
        .err()
        .unwrap();
    assert_eq!(e, MailError::AuthFailed);
    assert_eq!(fake.state().lock().unwrap().login_attempts, 1);
    let closed = {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    };
    let e = Imap::connect(&account(closed, "secret"), T)
        .await
        .err()
        .unwrap();
    assert!(matches!(e, MailError::Unreachable(_)), "{e:?}");
    let mut a = account(1, "secret");
    a.host = "imap.example.invalid".into();
    a.tls = false;
    let e = connect_stream(&a.host, a.port, a.tls, T)
        .await
        .err()
        .unwrap();
    assert_eq!(
        e,
        MailError::Tls("plaintext_not_loopback"),
        "no socket is opened for plaintext off loopback"
    );
    let d = format!("{e:?} {:?}", account(fake.port(), "hunter2-canary"));
    assert!(!d.contains("hunter2") && !d.contains("agent"), "{d}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commands_time_out_after_login() {
    let mut s = seeded();
    s.mode = FakeMode::StallAfterLogin;
    let fake = FakeImap::start(s).await;
    let mut imap = Imap::connect(&account(fake.port(), "secret"), Duration::from_millis(300))
        .await
        .unwrap();
    let t0 = std::time::Instant::now();
    let e = imap.folders().await.err().unwrap();
    assert_eq!(e, MailError::Timeout);
    assert!(t0.elapsed() < Duration::from_secs(2));
    assert!(e.is_connection());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drafts_folder_resolution_prefers_special_use_then_name_then_create() {
    // Gmail-like: a localized special-use folder
    let mut s = FakeState::new("agent", "secret");
    s.add_folder("[Gmail]/Entw&APw-rfe", 5);
    s.folders
        .get_mut("[Gmail]/Entw&APw-rfe")
        .unwrap()
        .special_use = Some("\\Drafts".into());
    let fake = FakeImap::start(s).await;
    let mut imap = Imap::connect(&account(fake.port(), "secret"), T)
        .await
        .unwrap();
    let f = imap.folders().await.unwrap();
    let gm = f.iter().find(|f| f.raw == "[Gmail]/Entw&APw-rfe").unwrap();
    assert_eq!(gm.display, "[Gmail]/Entwürfe");
    assert!(gm.drafts_special_use);
    assert_eq!(
        imap.resolve_drafts_folder(None).await.unwrap(),
        DraftsFolder::Existing("[Gmail]/Entw&APw-rfe".into())
    );
    let d = format!("{f:?} {:?}", DraftsFolder::Existing(CANARY_FOLDER.into()));
    assert!(
        !d.contains("Zyxwuria") && !d.contains("Entw") && !d.contains("Gmail"),
        "Debug of folder types prints lengths only: {d}"
    );
    assert_eq!(
        imap.resolve_drafts_folder(Some("INBOX")).await.unwrap(),
        DraftsFolder::Existing("INBOX".into()),
        "an explicit folder wins"
    );
    assert_eq!(
        imap.resolve_drafts_folder(Some("[Gmail]/Entwürfe"))
            .await
            .unwrap(),
        DraftsFolder::Existing("[Gmail]/Entw&APw-rfe".into()),
        "the decoded name the user sees matches too, and the raw name is what gets used"
    );
    assert_eq!(
        imap.resolve_drafts_folder(Some("[Gmail]/Entw&APw-rfe"))
            .await
            .unwrap(),
        DraftsFolder::Existing("[Gmail]/Entw&APw-rfe".into())
    );
    assert_eq!(
        imap.resolve_drafts_folder(Some("Nope")).await,
        Err(MailError::DraftsFolderMissing)
    );
    drop(fake);
    // a plain server with a folder literally named Drafts (any case)
    let mut s = FakeState::new("agent", "secret");
    s.add_folder("drafts", 6);
    let fake = FakeImap::start(s).await;
    let mut imap = Imap::connect(&account(fake.port(), "secret"), T)
        .await
        .unwrap();
    assert_eq!(
        imap.resolve_drafts_folder(None).await.unwrap(),
        DraftsFolder::Existing("drafts".into())
    );
    drop(fake);
    // GreenMail-like: nothing → create Drafts on first use
    let fake = FakeImap::start(FakeState::new("agent", "secret")).await;
    let mut imap = Imap::connect(&account(fake.port(), "secret"), T)
        .await
        .unwrap();
    assert_eq!(
        imap.resolve_drafts_folder(None).await.unwrap(),
        DraftsFolder::Create("Drafts".into())
    );
    imap.create("Drafts").await.unwrap();
    assert_eq!(
        imap.resolve_drafts_folder(None).await.unwrap(),
        DraftsFolder::Existing("Drafts".into())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn append_stores_with_flags_and_maps_every_refusal() {
    let mut s = seeded();
    s.add_folder("Drafts", 7000);
    let fake = FakeImap::start(s).await;
    let mut imap = Imap::connect(&account(fake.port(), "secret"), T)
        .await
        .unwrap();
    let draft = b"From: agent@example.test\r\nTo: x@example.test\r\nSubject: Re: hi\r\nMessage-ID: <d1@example.test>\r\n\r\nDanke.\r\n";
    imap.append(
        "Drafts",
        Some("(\\Draft)"),
        Some("\"27-Sep-2026 10:00:00 +0000\""),
        draft,
    )
    .await
    .unwrap();
    assert_eq!(
        fake.state().lock().unwrap().folders["Drafts"].messages[0].internal_date,
        (2026, 9, 27),
        "the APPEND date-time becomes INTERNALDATE"
    );
    {
        let st = fake.state();
        let st = st.lock().unwrap();
        assert_eq!(st.appends.len(), 1);
        assert_eq!(st.appends[0].folder, "Drafts");
        assert_eq!(st.appends[0].flags.as_deref(), Some("(\\Draft)"));
        assert_eq!(st.appends[0].raw, draft);
        assert_eq!(st.folders["Drafts"].messages[0].flags, ["\\Draft"]);
    }
    assert_eq!(imap.select("Drafts").await.unwrap(), 7000);
    assert_eq!(
        imap.uid_search("HEADER Message-ID \"d1@example.test\"")
            .await
            .unwrap(),
        [1]
    );
    // missing folder: refused after the literal, nothing stored, session usable
    let e = imap
        .append("Nope", Some("(\\Draft)"), None, draft)
        .await
        .err()
        .unwrap();
    assert_eq!(e, MailError::DraftRejected("refused"));
    assert!(!e.is_connection());
    imap.noop().await.unwrap();
    // flag rejected
    fake.state().lock().unwrap().mode = FakeMode::RejectDraftFlag;
    let e = imap
        .append("Drafts", Some("(\\Draft)"), None, draft)
        .await
        .err()
        .unwrap();
    assert_eq!(e, MailError::DraftRejected("refused"));
    imap.append("Drafts", None, None, draft).await.unwrap();
    assert_eq!(fake.state().lock().unwrap().appends.len(), 2);
    assert!(
        fake.state().lock().unwrap().folders["Drafts"].messages[1].internal_date >= (2026, 1, 1),
        "no date given: the server stamps now"
    );
    // ambiguous: the connection drops after the literal
    fake.state().lock().unwrap().mode = FakeMode::DropAfterLiteral;
    let e = imap
        .append("Drafts", Some("(\\Draft)"), None, draft)
        .await
        .err()
        .unwrap();
    assert_eq!(e, MailError::DraftStatusUnknown);
    assert!(e.is_connection());
    assert_eq!(
        fake.state().lock().unwrap().count("APPEND"),
        5,
        "five calls, five attempts: the wrapper never retries on its own"
    );
    // desynchronised: an unsolicited line arrives where the continuation was expected;
    // the literal was never sent, so nothing is stored, but the session is unusable
    fake.state().lock().unwrap().mode = FakeMode::UnsolicitedBeforeContinue;
    let mut imap = Imap::connect(&account(fake.port(), "secret"), T)
        .await
        .unwrap();
    let e = imap
        .append("Drafts", Some("(\\Draft)"), None, draft)
        .await
        .err()
        .unwrap();
    assert_eq!(e, MailError::Protocol("append_desync"));
    assert!(
        e.is_connection(),
        "the caller must drop this session before sending anything else"
    );
    assert_eq!(
        fake.state().lock().unwrap().appends.len(),
        2,
        "nothing stored"
    );
    assert_eq!(fake.state().lock().unwrap().count("APPEND"), 6);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_ascii_search_terms_use_literal_plus_or_are_refused() {
    let mut s = FakeState::new("agent", "secret");
    s.add("INBOX", &fixture("latin1"));
    s.add("INBOX", &fixture("plain"));
    let fake = FakeImap::start(s).await;
    let mut imap = Imap::connect(&account(fake.port(), "secret"), T)
        .await
        .unwrap();
    assert!(imap.literal_plus());
    imap.examine("INBOX").await.unwrap();
    let crit = build_search(Some("Müller"), None, None, imap.literal_plus()).unwrap();
    assert!(crit.contains("{7+}\r\nMüller"), "{crit:?}");
    assert_eq!(
        imap.uid_search(&crit).await.unwrap(),
        [1],
        "the literal reached the server intact"
    );
    assert_eq!(
        imap.uid_search("OR OR FROM \"leitner\" SUBJECT \"leitner\" TEXT \"leitner\"")
            .await
            .unwrap(),
        [2]
    );
    // malformed criteria: BAD is the client's fault and keeps the session
    let e = imap.uid_search("SINCE not-a-date").await.err().unwrap();
    assert_eq!(e, MailError::InvalidArgument("imap_command"));
    assert!(!e.is_connection());
    imap.noop().await.unwrap();
    // a server without LITERAL+: the connector refuses instead of sending 8-bit quoted strings
    fake.state().lock().unwrap().literal_plus = false;
    let imap2 = Imap::connect(&account(fake.port(), "secret"), T)
        .await
        .unwrap();
    assert!(!imap2.literal_plus());
    assert!(matches!(
        build_search(Some("Müller"), None, None, imap2.literal_plus()),
        Err(MailError::InvalidArgument("query_charset"))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn check_mailbox_reports_counts_only() {
    let fake = FakeImap::start(seeded()).await;
    let r = check_mailbox(&account(fake.port(), "secret"), T)
        .await
        .unwrap();
    assert_eq!(
        r,
        CheckReport {
            folders: 2,
            drafts_folder_resolved: true,
            drafts_folder_will_be_created: true
        }
    );
    let mut a = account(fake.port(), "secret");
    a.drafts_folder = Some(CANARY_FOLDER.into());
    let r = check_mailbox(&a, T).await.unwrap();
    assert_eq!(
        r,
        CheckReport {
            folders: 2,
            drafts_folder_resolved: true,
            drafts_folder_will_be_created: false
        }
    );
    a.drafts_folder = Some("Missing".into());
    let r = check_mailbox(&a, T).await.unwrap();
    assert!(!r.drafts_folder_resolved);
    assert_eq!(
        check_mailbox(&account(fake.port(), "wrong"), T).await,
        Err(MailError::AuthFailed)
    );
    assert!(!format!("{r:?}").contains("Zyxwuria"));
    let st = fake.state();
    assert!(
        st.lock()
            .unwrap()
            .commands
            .iter()
            .filter(|c| *c == "LOGOUT")
            .count()
            >= 3,
        "check logs out"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_list_is_an_error_not_an_empty_folder_list() {
    let mut s = seeded();
    s.add_folder("Drafts", 7000);
    let fake = FakeImap::start(s).await;
    let mut imap = Imap::connect(&account(fake.port(), "secret"), T)
        .await
        .unwrap();
    fake.state().lock().unwrap().mode = FakeMode::RefuseListAndFetch;
    let e = imap.folders().await.err().unwrap();
    assert_eq!(e, MailError::Protocol("no"));
    // drafts resolution and the check must fail, not fall through to "create Drafts"
    assert_eq!(
        imap.resolve_drafts_folder(None).await.err().unwrap(),
        MailError::Protocol("no")
    );
    // the session is still in step: other commands work, and LIST recovers
    imap.noop().await.unwrap();
    fake.state().lock().unwrap().mode = FakeMode::Normal;
    assert_eq!(imap.folders().await.unwrap().len(), 3);
    fake.state().lock().unwrap().mode = FakeMode::RefuseListAndFetch;
    assert_eq!(
        check_mailbox(&account(fake.port(), "secret"), T).await,
        Err(MailError::Protocol("no")),
        "check_mailbox must not report a created Drafts folder for a refused LIST"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_fetch_is_an_error_not_a_missing_message() {
    let fake = FakeImap::start(seeded()).await;
    let mut imap = Imap::connect(&account(fake.port(), "secret"), T)
        .await
        .unwrap();
    imap.examine("INBOX").await.unwrap();
    fake.state().lock().unwrap().mode = FakeMode::RefuseListAndFetch;
    assert_eq!(
        imap.fetch_message(1).await.err().unwrap(),
        MailError::Protocol("no")
    );
    assert_eq!(
        imap.fetch_size(1).await.err().unwrap(),
        MailError::Protocol("no")
    );
    assert_eq!(
        imap.fetch_summaries(&[1, 2], 64).await.err().unwrap(),
        MailError::Protocol("no")
    );
    // the session is still in step; once the server recovers the message is there
    imap.noop().await.unwrap();
    assert_eq!(imap.uid_search("ALL").await.unwrap(), [3, 2, 1]);
    fake.state().lock().unwrap().mode = FakeMode::Normal;
    assert!(imap.fetch_message(1).await.unwrap().is_some());
    assert_eq!(imap.fetch_message(99).await.unwrap(), None);
}

// The harness helpers wipe and reseed a test mailbox: a refused wipe must be
// an error, a reseed must not pile up, and the fixture's day must become the
// INTERNALDATE (what SINCE/BEFORE search on).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn harness_seeds_with_internal_dates_wipes_and_reseeds() {
    use inumaki_mail::harness::{SeedMail, clear_folder, list_folder_messages, seed_mailbox};
    let fake = FakeImap::start(FakeState::new("agent", "secret")).await;
    let acct = account(fake.port(), "secret");
    let mails: Vec<SeedMail> = [("1", " 5-Jan-2026"), ("2", " 6-Jan-2026")]
        .iter()
        .map(|(n, d)| SeedMail {
            folder: "INBOX".into(),
            internal_date: Some(format!("\"{d} 09:00:00 +0000\"")),
            eml: format!(
                "From: a@x.example\r\nTo: b@x.example\r\nSubject: s{n}\r\nMessage-ID: <m{n}@x.example>\r\nDate: Mon, 1 Jan 2001 00:00:00 +0000\r\n\r\nbody {n}\r\n"
            )
            .into_bytes(),
        })
        .collect();
    assert_eq!(clear_folder(&acct, T, "INBOX").await.unwrap(), 0);
    assert_eq!(
        clear_folder(&acct, T, "Nope").await.unwrap(),
        0,
        "a missing folder has nothing to clear"
    );
    assert!(
        list_folder_messages(&acct, T, "Nope")
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(seed_mailbox(&acct, T, &mails).await.unwrap(), 2);
    let listed = list_folder_messages(&acct, T, "INBOX").await.unwrap();
    assert_eq!(listed.len(), 2);
    assert!(String::from_utf8_lossy(&listed[0]).contains("Subject: s1"));
    // INTERNALDATE, not the Date header (2001) and not today
    let mut imap = Imap::connect(&acct, T).await.unwrap();
    imap.examine("INBOX").await.unwrap();
    assert_eq!(
        imap.uid_search("SINCE 5-Jan-2026 BEFORE 6-Jan-2026")
            .await
            .unwrap(),
        [1]
    );
    imap.logout().await;
    // the second run wipes first: no pile-up, and a folder that did not exist is created
    assert_eq!(clear_folder(&acct, T, "INBOX").await.unwrap(), 2);
    assert!(
        list_folder_messages(&acct, T, "INBOX")
            .await
            .unwrap()
            .is_empty()
    );
    let mut more = mails.clone();
    more.push(SeedMail {
        folder: "Archiv".into(),
        internal_date: None,
        eml: mails[0].eml.clone(),
    });
    assert_eq!(seed_mailbox(&acct, T, &more).await.unwrap(), 3);
    assert_eq!(
        fake.state().lock().unwrap().folders["INBOX"].messages.len(),
        2
    );
    assert_eq!(
        fake.state().lock().unwrap().folders["Archiv"]
            .messages
            .len(),
        1
    );
    // Debug prints lengths, never the message
    assert!(!format!("{:?}", mails[0]).contains("body 1"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn harness_store_and_expunge_are_status_aware() {
    let fake = FakeImap::start(seeded()).await;
    let mut imap = Imap::connect(&account(fake.port(), "secret"), T)
        .await
        .unwrap();
    // no folder selected: the server answers BAD, which must not look like success
    assert_eq!(
        imap.uid_store("1:*", "+FLAGS (\\Deleted)").await,
        Err(MailError::InvalidArgument("imap_command"))
    );
    assert_eq!(
        imap.expunge().await,
        Err(MailError::InvalidArgument("imap_command"))
    );
    assert_eq!(
        fake.state().lock().unwrap().folders["INBOX"].messages.len(),
        3,
        "nothing was deleted"
    );
    // the session is still in step and the commands work once a folder is selected
    imap.select("INBOX").await.unwrap();
    imap.uid_store("1:*", "+FLAGS (\\Deleted)").await.unwrap();
    imap.expunge().await.unwrap();
    assert!(
        fake.state().lock().unwrap().folders["INBOX"]
            .messages
            .is_empty()
    );
}

// GreenMail answers a partial fetch as `BODY[TEXT]<0>{16}` with no space
// before the literal (RFC 3501 wants one); the tolerant reader must give
// the same header and text head as from a conforming server, keep the
// partial fetch bounded, and leave the session in step.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn partial_fetch_without_space_before_literal_is_tolerated() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // the mode really sends the quirk on the wire
    let mut s = seeded();
    s.mode = FakeMode::NoSpaceBeforePartialLiteral;
    let fake = FakeImap::start(s).await;
    let mut raw = tokio::net::TcpStream::connect(fake.addr()).await.unwrap();
    raw.write_all(
        b"a LOGIN \"agent\" \"secret\"\r\nb EXAMINE INBOX\r\n\
c UID FETCH 1 (BODY.PEEK[TEXT]<0.16>)\r\nd LOGOUT\r\n",
    )
    .await
    .unwrap();
    let mut wire = Vec::new();
    tokio::time::timeout(T, raw.read_to_end(&mut wire))
        .await
        .unwrap()
        .unwrap();
    assert!(
        wire.windows(18).any(|w| w == b"BODY[TEXT]<0>{16}\r"),
        "the fake must omit the space"
    );
    drop(fake);

    let plain = fixture("plain");
    let split = plain.windows(4).position(|w| w == b"\r\n\r\n").map_or_else(
        || plain.windows(2).position(|w| w == b"\n\n").unwrap() + 2,
        |i| i + 4,
    );
    let mut results = Vec::new();
    for mode in [FakeMode::Normal, FakeMode::NoSpaceBeforePartialLiteral] {
        let mut s = seeded();
        s.mode = mode;
        let fake = FakeImap::start(s).await;
        let mut imap = Imap::connect(&account(fake.port(), "secret"), T)
            .await
            .unwrap();
        imap.examine("INBOX").await.unwrap();
        let wide = imap.fetch_summaries(&[3, 1], 4096).await.unwrap();
        assert_eq!(wide.iter().map(|s| s.uid).collect::<Vec<_>>(), [1, 3]);
        let s = parse_summary(&wide[0].header, &wide[0].text_head, 60);
        assert_eq!(s.subject, "Rechnung RE-2026-0042", "{mode:?}");
        let narrow = imap.fetch_summaries(&[1], 16).await.unwrap();
        assert_eq!(narrow[0].header, &plain[..split], "{mode:?}");
        assert_eq!(
            narrow[0].text_head,
            &plain[split..split + 16],
            "{mode:?}: partial fetch bounded and intact"
        );
        // still in step: a full fetch after the partial ones is byte-exact
        assert_eq!(imap.fetch_message(1).await.unwrap().unwrap(), plain);
        imap.noop().await.unwrap();
        imap.logout().await;
        let fetches = fake.state().lock().unwrap().fetches.clone();
        assert!(fetches.iter().any(|f| f.contains("BODY.PEEK[TEXT]<0.16>")));
        results.push((wide, narrow));
    }
    assert_eq!(
        results[0], results[1],
        "same rows with and without the space"
    );
}
