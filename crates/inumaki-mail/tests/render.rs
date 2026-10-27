//! M4 spec §6.3 parsing: text preferred, HTML through html2text at 100
//! columns with script/style dropped, quoted history and signatures kept,
//! nested message/rfc822 rendered once, attachments listed by name and
//! type only, charsets decoded, NFC output. Plus the search-query builder,
//! modified UTF-7, and reply-draft serialization with header validation.

use inumaki_mail::draft::{
    MAX_BODY_BYTES, ReplyDraft, build_reply, new_message_id, parse_cc, reply_subject,
    validate_header_text,
};
use inumaki_mail::query::{build_search, decode_utf7, fetch_set, imap_date, quote_search};
use inumaki_mail::render::{
    Attachment, MailAddress, html_to_text, nfc, parse_message, parse_summary, render_markdown,
};
use inumaki_mail::{MailAccount, MailError, Preset};
use mail_parser::MessageParser;

const CANARY: &str = "Zyxwuria Quolnath";

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}.eml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

#[test]
fn plain_text_mail_renders_headers_body_and_keeps_the_signature() {
    let p = parse_message(&fixture("plain")).unwrap();
    assert_eq!(
        p.from[0].display(),
        "Sarah Leitner <sarah.leitner@example.test>"
    );
    assert_eq!(p.to[0].display(), "Support <support@musterfirma.example>");
    assert_eq!(p.cc.len(), 1);
    assert_eq!(p.subject.as_deref(), Some("Rechnung RE-2026-0042"));
    assert_eq!(p.message_id.as_deref(), Some("plain-1@example.test"));
    assert_eq!(p.date.as_deref(), Some("2026-09-27T10:15:00+02:00"));
    assert!(p.body.contains("Neubaugasse 22, 1070 Wien"));
    assert!(
        p.body.contains("Mit freundlichen Grüßen") && p.body.contains("\nSarah Leitner"),
        "signature kept: {}",
        p.body
    );
    assert!(p.attachments.is_empty() && p.nested.is_empty());
    let md = render_markdown(&p);
    assert!(md.starts_with("**From:** Sarah Leitner <sarah.leitner@example.test>\n**To:** Support <support@musterfirma.example>\n**Cc:** Buchhaltung <buchhaltung@musterfirma.example>\n**Date:** 2026-09-27T10:15:00+02:00\n**Subject:** Rechnung RE-2026-0042\n\n"), "{md}");
    assert!(md.contains("AT61 1904 3002 3457 3201"));
    assert!(!md.contains("**Attachments:**"));
}

/// Review Focus 8.
#[test]
fn html_script_and_style_are_dropped() {
    let p = parse_message(&fixture("html")).unwrap();
    // text part preferred over HTML
    assert_eq!(p.body.trim(), "Hallo, passt Dienstag 14:00?");
    assert_eq!(p.subject.as_deref(), Some("Termin nächste Woche"));
    let only = parse_message(&fixture("html_only")).unwrap();
    assert!(
        only.body.contains("bitte um ein Angebot für 3 Geräte"),
        "{}",
        only.body
    );
    assert!(only.body.contains("Danke, Zyxwuria Quolnath"));
    assert!(
        !only.body.contains("MsoNormal") && !only.body.contains("margin:0"),
        "{}",
        only.body
    );
    let html = std::str::from_utf8(&fixture("html")).unwrap().to_string();
    let start = html.find("<html>").unwrap();
    let end = html.rfind("</html>").unwrap() + "</html>".len();
    let text = html_to_text(&html[start..end]);
    assert!(
        text.contains("Dienstag 14:00") && text.contains("Neubaugasse 22"),
        "{text}"
    );
    assert!(
        !text.contains("SCRIPT-CANARY")
            && !text.contains("alert(")
            && !text.contains("color: red")
            && !text.contains("display:none"),
        "{text}"
    );
    assert!(!text.contains("[1]"), "no link footnotes: {text}");
    assert!(
        text.lines()
            .filter(|l| !l.contains("://"))
            .all(|l| l.chars().count() <= 100),
        "prose wraps at 100 columns (unbreakable URLs may overflow): {text}"
    );
}

#[test]
fn quoted_history_is_kept_and_thread_headers_are_parsed() {
    let p = parse_message(&fixture("quoted")).unwrap();
    assert!(
        p.body
            .contains("> Sehr geehrter Herr Huber, Ihr Vertrag V-99871")
    );
    assert!(p.body.contains("Musterweg 7, 8010 Graz"));
    assert_eq!(
        p.in_reply_to.as_deref(),
        Some("quoted-1@musterfirma.example")
    );
    assert_eq!(
        p.references,
        [
            "quoted-0@musterfirma.example",
            "quoted-1@musterfirma.example"
        ]
    );
    assert_eq!(p.subject.as_deref(), Some("Re: Vertrag V-99871"));
}

#[test]
fn attachments_are_listed_and_nested_messages_render_once() {
    let p = parse_message(&fixture("attachments")).unwrap();
    assert_eq!(p.body.trim(), "Anbei die Unterlagen.");
    assert_eq!(p.reply_to.len(), 1);
    assert_eq!(
        p.reply_to[0].display(),
        "Anna Berger <anna.reply@example.test>"
    );
    assert!(
        !render_markdown(&p).contains("**Cc:**")
            && render_markdown(&p)
                .contains("\n**Reply-To:** Anna Berger <anna.reply@example.test>\n**Date:**"),
        "{}",
        render_markdown(&p)
    );
    let names: Vec<(Option<&str>, &str)> = p
        .attachments
        .iter()
        .map(|a| (a.name.as_deref(), a.mime.as_str()))
        .collect();
    assert_eq!(
        names,
        [
            (Some("Rechnung Zyxwuria Quolnath.pdf"), "application/pdf"),
            (Some("logo.png"), "image/png")
        ]
    );
    assert_eq!(
        p.nested.len(),
        1,
        "the forwarded message is rendered inline"
    );
    let n = &p.nested[0];
    assert_eq!(
        n.from[0].display(),
        "Peter Fuchs <peter.fuchs@example.test>"
    );
    assert!(n.body.contains("hier das Original von Peter Fuchs"));
    assert_eq!(
        n.attachments
            .iter()
            .map(|a| a.mime.as_str())
            .collect::<Vec<_>>(),
        ["message/rfc822"],
        "depth two stays a listed attachment"
    );
    assert!(n.nested.is_empty());
    let md = render_markdown(&p);
    assert!(
        md.contains(
            "\n--- Forwarded message ---\n**From:** Peter Fuchs <peter.fuchs@example.test>\n"
        ),
        "{md}"
    );
    assert!(md.contains("**Attachments:**\n- Rechnung Zyxwuria Quolnath.pdf (application/pdf)\n- logo.png (image/png)\n"), "{md}");
    assert!(!md.contains("Should stay a listed attachment"));
    assert!(!md.contains("JVBERi0"), "attachment bytes never rendered");
    // the decoded PDF header text must not be rendered either
    assert!(
        !md.contains("%PDF") && !md.contains("Catalog"),
        "decoded attachment bytes never rendered: {md}"
    );
}

/// Review Focus 8 (second half).
#[test]
fn latin1_and_windows1252_decode() {
    let p = parse_message(&fixture("latin1")).unwrap();
    assert_eq!(
        p.from[0].display(),
        "Jörg Müller <joerg.mueller@example.test>"
    );
    assert_eq!(p.subject.as_deref(), Some("Rückfrage"));
    assert!(p.body.contains("Herr Müller aus Österreich"), "{}", p.body);
    let p = parse_message(&fixture("cp1252")).unwrap();
    assert!(
        p.body.contains("120 € ist offen – bitte überweisen"),
        "{}",
        p.body
    );
    // NFC: a decomposed u-umlaut becomes the composed form
    assert_eq!(nfc("Mu\u{0308}ller"), "Müller");
    assert_eq!(p.body, nfc(&p.body));
}

#[test]
fn summaries_come_from_the_header_and_a_body_prefix() {
    let raw = fixture("plain");
    let split = raw.windows(2).position(|w| w == b"\n\n").unwrap() + 1;
    let (header, text) = raw.split_at(split);
    let s = parse_summary(header, &text[..64.min(text.len())], 40);
    assert_eq!(s.from, "Sarah Leitner <sarah.leitner@example.test>");
    assert_eq!(s.subject, "Rechnung RE-2026-0042");
    assert_eq!(s.date, "2026-09-27T10:15:00+02:00");
    assert_eq!(s.message_id.as_deref(), Some("plain-1@example.test"));
    assert!(
        s.snippet
            .starts_with("Sehr geehrtes Support-Team, ich habe"),
        "{}",
        s.snippet
    );
    assert!(
        s.snippet.ends_with('…') && s.snippet.chars().count() <= 41,
        "{}",
        s.snippet
    );
    // header-only input still yields a summary with an empty snippet
    let s = parse_summary(header, b"", 40);
    assert_eq!(s.snippet, "");
    // garbage input does not panic
    let s = parse_summary(b"\xff\xfe not a header", b"\x00", 40);
    assert_eq!(s.subject, "");
}

/// Review Focus 9.
#[test]
fn queries_are_quoted_or_refused() {
    assert_eq!(quote_search("leitner").unwrap(), "\"leitner\"");
    assert_eq!(
        quote_search("say \"hi\" \\ there").unwrap(),
        "\"say \\\"hi\\\" \\\\ there\""
    );
    for bad in ["a\r\nB1 LOGOUT", "x\n", "nul\u{0}", ""] {
        assert!(
            matches!(quote_search(bad), Err(MailError::InvalidArgument("query"))),
            "{bad:?}"
        );
    }
    assert!(matches!(
        quote_search(&"a".repeat(257)),
        Err(MailError::InvalidArgument("query"))
    ));
    assert_eq!(imap_date("2026-09-27").unwrap(), "27-Sep-2026");
    assert_eq!(imap_date("2026-01-05").unwrap(), "5-Jan-2026");
    for bad in [
        "2026-13-01",
        "2026-02-30",
        "27.09.2026",
        "2026-9-7",
        "20260927",
        "2026-09-27T10:00",
    ] {
        assert!(
            matches!(imap_date(bad), Err(MailError::InvalidArgument("date"))),
            "{bad}"
        );
    }
    assert_eq!(
        build_search(Some("leitner"), None, None, false).unwrap(),
        "OR OR FROM \"leitner\" SUBJECT \"leitner\" TEXT \"leitner\""
    );
    assert_eq!(
        build_search(Some("Müller"), Some("2026-09-01"), Some("2026-10-01"), true).unwrap(),
        "CHARSET UTF-8 OR OR FROM {7+}\r\nMüller SUBJECT {7+}\r\nMüller TEXT {7+}\r\nMüller SINCE 1-Sep-2026 BEFORE 1-Oct-2026",
        "non-ASCII terms travel as LITERAL+ literals (7 bytes for Müller)"
    );
    assert!(
        matches!(
            build_search(Some("Müller"), None, None, false),
            Err(MailError::InvalidArgument("query_charset"))
        ),
        "no LITERAL+: refused, never sent 8-bit in a quoted string"
    );
    assert!(matches!(
        build_search(Some("Mü\r\nller"), None, None, true),
        Err(MailError::InvalidArgument("query"))
    ));
    assert_eq!(
        build_search(None, Some("2026-09-27"), Some("2026-09-28"), false).unwrap(),
        "SINCE 27-Sep-2026 BEFORE 28-Sep-2026"
    );
    assert!(matches!(
        build_search(None, None, None, false),
        Err(MailError::InvalidArgument("search_criteria"))
    ));
    assert!(matches!(
        build_search(Some("  "), None, None, false),
        Err(MailError::InvalidArgument("query"))
    ));
    assert_eq!(fetch_set(&[3, 1, 2]), "3,1,2");
}

#[test]
fn modified_utf7_folder_names_decode() {
    assert_eq!(decode_utf7("INBOX"), "INBOX");
    assert_eq!(decode_utf7("[Gmail]/Entw&APw-rfe"), "[Gmail]/Entwürfe");
    assert_eq!(decode_utf7("Kunde &AMQ-rger"), "Kunde Ärger");
    assert_eq!(decode_utf7("Tom &- Jerry"), "Tom & Jerry");
    assert_eq!(decode_utf7("&ZeVnLIqe-"), "日本語");
    assert_eq!(
        decode_utf7("broken &AP"),
        "broken &AP",
        "an unterminated shift is left as is"
    );
}

/// Review Focus 5.
#[test]
fn cc_and_header_values_are_validated() {
    let cc =
        parse_cc("Anna Berger <anna.berger@example.test>, <max@example.test> ,peter@example.test")
            .unwrap();
    assert_eq!(cc.len(), 3);
    assert_eq!(cc[0].display(), "Anna Berger <anna.berger@example.test>");
    assert_eq!(cc[1].display(), "max@example.test");
    assert_eq!(cc[2].address.as_deref(), Some("peter@example.test"));
    assert!(parse_cc("").unwrap().is_empty());
    for bad in [
        "Anna Berger",
        "anna@example.test\r\nBcc: evil@example.test",
        "<a@b> <c@d>",
        "a@b@c",
        "name <not an address>",
        "\"x\" <a b@c.d>",
    ] {
        assert!(
            matches!(parse_cc(bad), Err(MailError::InvalidArgument("cc"))),
            "{bad:?}"
        );
    }
    let many = (0..21)
        .map(|i| format!("u{i}@example.test"))
        .collect::<Vec<_>>()
        .join(",");
    assert!(matches!(
        parse_cc(&many),
        Err(MailError::InvalidArgument("cc_count"))
    ));
    assert!(validate_header_text("Re: Rechnung", "subject").is_ok());
    assert!(matches!(
        validate_header_text("Re:\r\nX-Injected: 1", "subject"),
        Err(MailError::InvalidArgument("subject"))
    ));
    assert!(matches!(
        validate_header_text(&"a".repeat(999), "subject"),
        Err(MailError::InvalidArgument("subject"))
    ));
    assert_eq!(reply_subject(Some("Rechnung")), "Re: Rechnung");
    assert_eq!(reply_subject(Some("Re: Rechnung")), "Re: Rechnung");
    assert_eq!(reply_subject(Some("AW: Rechnung")), "AW: Rechnung");
    assert_eq!(reply_subject(Some("  re: x ")), "re: x");
    assert_eq!(reply_subject(None), "Re:");
    let id = new_message_id("example.test").unwrap();
    assert!(
        id.ends_with("@example.test") && id.len() == 40 + "@example.test".len(),
        "{id}"
    );
    assert_ne!(id, new_message_id("example.test").unwrap());
}

#[test]
fn reply_drafts_carry_thread_headers_and_refuse_bad_input() {
    let to = MailAddress {
        name: Some("Sarah Leitner".into()),
        address: Some("sarah.leitner@example.test".into()),
    };
    let cc = parse_cc("Max Huber <max.huber@example.test>").unwrap();
    let refs = vec!["quoted-0@musterfirma.example".to_string()];
    let d = ReplyDraft {
        from: "agent@example.test",
        to: &to,
        cc: &cc,
        subject: "Re: Rechnung RE-2026-0042",
        in_reply_to: Some("plain-1@example.test"),
        references: &refs,
        body: "Sehr geehrte Frau Leitner,\n\nvielen Dank für Ihre Nachricht.\n",
        message_id: "abc123@example.test",
        date_unix: 1_790_000_000,
    };
    let bytes = build_reply(&d).unwrap();
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        text.contains("In-Reply-To: <plain-1@example.test>"),
        "{text}"
    );
    assert!(
        text.contains("References: <quoted-0@musterfirma.example> <plain-1@example.test>"),
        "{text}"
    );
    assert!(text.contains("Message-ID: <abc123@example.test>"), "{text}");
    assert!(!text.contains("X-Mailer"), "{text}");
    let m = MessageParser::default().parse(&bytes).unwrap();
    assert_eq!(
        m.to().unwrap().first().unwrap().address(),
        Some("sarah.leitner@example.test")
    );
    assert_eq!(
        m.to().unwrap().first().unwrap().name(),
        Some("Sarah Leitner")
    );
    assert_eq!(
        m.cc().unwrap().first().unwrap().address(),
        Some("max.huber@example.test")
    );
    assert_eq!(
        m.from().unwrap().first().unwrap().address(),
        Some("agent@example.test")
    );
    assert_eq!(m.subject(), Some("Re: Rechnung RE-2026-0042"));
    assert_eq!(m.message_id(), Some("abc123@example.test"));
    assert_eq!(m.date().map(|d| d.to_timestamp()), Some(1_790_000_000));
    assert!(
        m.body_text(0)
            .unwrap()
            .contains("vielen Dank für Ihre Nachricht")
    );
    // refusals, all before any bytes are produced
    let no_addr = MailAddress {
        name: Some("Nobody".into()),
        address: None,
    };
    assert!(matches!(
        build_reply(&ReplyDraft { to: &no_addr, ..d }),
        Err(MailError::DraftRejected("recipient"))
    ));
    assert!(matches!(
        build_reply(&ReplyDraft {
            subject: "Re:\r\nBcc: x@y",
            ..d
        }),
        Err(MailError::InvalidArgument("subject"))
    ));
    assert!(matches!(
        build_reply(&ReplyDraft {
            body: "with \u{0} nul",
            ..d
        }),
        Err(MailError::InvalidArgument("body"))
    ));
    assert!(matches!(
        build_reply(&ReplyDraft { body: "   \n", ..d }),
        Err(MailError::InvalidArgument("body"))
    ));
    let huge = "x".repeat(MAX_BODY_BYTES + 1);
    assert!(matches!(
        build_reply(&ReplyDraft { body: &huge, ..d }),
        Err(MailError::InvalidArgument("body"))
    ));
    assert!(matches!(
        build_reply(&ReplyDraft {
            from: "not-an-address",
            ..d
        }),
        Err(MailError::DraftRejected("from_address"))
    ));
    let bad_cc = vec![MailAddress {
        name: Some("X\r\nY".into()),
        address: Some("a@b.test".into()),
    }];
    assert!(matches!(
        build_reply(&ReplyDraft { cc: &bad_cc, ..d }),
        Err(MailError::InvalidArgument("cc"))
    ));
    // non-ASCII subject and name are encoded, and round-trip
    let to2 = MailAddress {
        name: Some("Jörg Müller".into()),
        address: Some("joerg@example.test".into()),
    };
    let bytes = build_reply(&ReplyDraft {
        to: &to2,
        subject: "Re: Rückfrage",
        cc: &[],
        ..d
    })
    .unwrap();
    assert!(
        bytes.iter().all(|b| b.is_ascii()),
        "headers and body are 7-bit safe"
    );
    let m = MessageParser::default().parse(&bytes).unwrap();
    assert_eq!(m.subject(), Some("Re: Rückfrage"));
    assert_eq!(m.to().unwrap().first().unwrap().name(), Some("Jörg Müller"));
    // display-name injection: a name that tries to smuggle a second address or close the phrase
    let evil = MailAddress {
        name: Some("Evil, \"Person\" <attacker@evil.test> \\".into()),
        address: Some("sarah.leitner@example.test".into()),
    };
    let bytes = build_reply(&ReplyDraft {
        to: &evil,
        cc: &[],
        ..d
    })
    .unwrap();
    let m = MessageParser::default().parse(&bytes).unwrap();
    let to = m.to().unwrap();
    assert_eq!(
        to.iter().count(),
        1,
        "exactly one recipient: {}",
        String::from_utf8_lossy(&bytes)
    );
    assert_eq!(
        to.first().unwrap().address(),
        Some("sarah.leitner@example.test")
    );
    assert_eq!(
        to.first().unwrap().name(),
        Some("Evil, Person attacker@evil.test"),
        "angle brackets, quotes, and backslashes are stripped from the display name"
    );
    assert!(!String::from_utf8_lossy(&bytes).contains("<attacker@evil.test>"));
}

#[test]
fn presets_supply_connection_defaults_and_hints_without_promises() {
    assert_eq!(Preset::Gmail.imap_defaults(), Some(("imap.gmail.com", 993)));
    assert_eq!(
        Preset::Outlook.imap_defaults(),
        Some(("outlook.office365.com", 993))
    );
    assert_eq!(Preset::Generic.imap_defaults(), None);
    assert_eq!(Preset::parse("gmail"), Some(Preset::Gmail));
    assert_eq!(Preset::parse("Gmail"), None);
    assert!(Preset::Gmail.auth_hint().contains("app password"));
    assert!(
        Preset::Outlook.auth_hint().contains("OAuth")
            && Preset::Outlook.auth_hint().contains("unsupported")
    );
    for p in [Preset::Gmail, Preset::Outlook, Preset::Generic] {
        assert!(
            !p.auth_hint().contains("works"),
            "hints do not promise: {}",
            p.auth_hint()
        );
    }
    let a = MailAccount {
        preset: Preset::Generic,
        host: "127.0.0.1".into(),
        port: 3143,
        tls: false,
        username: zeroize::Zeroizing::new("agent".into()),
        password: zeroize::Zeroizing::new("hunter2-canary".into()),
        drafts_folder: Some(CANARY.into()),
        from_address: None,
    };
    assert!(
        matches!(
            a.draft_from(),
            Err(MailError::DraftRejected("from_address"))
        ),
        "a bare login name is not a From"
    );
    let mut b = a.clone();
    b.from_address = Some("agent@example.test".into());
    assert_eq!(b.draft_from().unwrap(), "agent@example.test");
    let mut c = a.clone();
    c.username = zeroize::Zeroizing::new("agent@example.test".into());
    assert_eq!(c.draft_from().unwrap(), "agent@example.test");
    let d = format!("{a:?}");
    assert!(
        !d.contains("hunter2") && !d.contains("agent") && !d.contains("Zyxwuria"),
        "{d}"
    );
    assert!(d.contains("127.0.0.1") && d.contains("3143"));
    let e = MailError::AuthFailed;
    assert_eq!(e.class(), "mail_auth_failed");
    assert!(!e.hint().is_empty());
    assert!(
        MailError::DraftStatusUnknown.is_connection()
            && !MailError::ContextUnavailable.is_connection()
    );
}

/// Global Constraints: `Debug` prints counts and lengths, never content.
#[test]
fn debug_output_carries_no_message_content() {
    let addr = MailAddress {
        name: Some(CANARY.into()),
        address: Some("zyxwuria.quolnath@example.test".into()),
    };
    let att = Attachment {
        name: Some(format!("Rechnung {CANARY}.pdf")),
        mime: "application/pdf".into(),
    };
    let raw = fixture("html");
    let split = raw.windows(2).position(|w| w == b"\n\n").unwrap() + 1;
    let (header, text) = raw.split_at(split);
    let summary = parse_summary(header, text, 40);
    assert!(
        summary.from.contains("Zyxwuria"),
        "fixture carries the canary"
    );
    let refs = vec!["ref-canary@example.test".to_string()];
    let cc = [addr.clone()];
    let draft = ReplyDraft {
        from: "agent@example.test",
        to: &addr,
        cc: &cc,
        subject: "Re: Zyxwuria Quolnath",
        in_reply_to: Some("plain-1@example.test"),
        references: &refs,
        body: "Zyxwuria Quolnath wohnt in Neubaugasse 22",
        message_id: "abc@example.test",
        date_unix: 1_790_000_000,
    };
    let parsed = parse_message(&fixture("attachments")).unwrap();
    for dbg in [
        format!("{addr:?}"),
        format!("{att:?}"),
        format!("{summary:?}"),
        format!("{draft:?}"),
        format!("{parsed:?}"),
    ] {
        for needle in [
            "Zyxwuria",
            "Quolnath",
            "example.test",
            "Neubaugasse",
            "Rechnung",
            "Anbei",
        ] {
            assert!(!dbg.contains(needle), "{needle} leaked in Debug: {dbg}");
        }
    }
}

/// Carry-over (c): thread ids from a hostile original are dropped, never
/// written as two ids (or a second header) in one header line.
#[test]
fn invalid_thread_ids_are_dropped_and_an_invalid_own_id_is_refused() {
    use inumaki_mail::draft::valid_msgid;
    assert!(valid_msgid("plain-1@example.test"));
    for bad in ["", "a> <b@evil.test", "a b@x", "a\tb", "a\u{1b}b", "<a@b>"] {
        assert!(!valid_msgid(bad), "{bad:?}");
    }
    let to = MailAddress {
        name: None,
        address: Some("sarah.leitner@example.test".into()),
    };
    let refs = vec![
        "ok-1@example.test".to_string(),
        "x> <injected@evil.test".to_string(),
        "two words@evil.test".to_string(),
        String::new(),
    ];
    let d = ReplyDraft {
        from: "agent@example.test",
        to: &to,
        cc: &[],
        subject: "Re: x",
        in_reply_to: Some("orig> <second@evil.test"),
        references: &refs,
        body: "Danke.",
        message_id: "abc123@example.test",
        date_unix: 1_790_000_000,
    };
    let text = String::from_utf8(build_reply(&d).unwrap()).unwrap();
    assert!(!text.contains("evil.test"), "{text}");
    assert!(
        !text.contains("In-Reply-To"),
        "an invalid original id omits In-Reply-To: {text}"
    );
    assert!(
        text.contains("References: <ok-1@example.test>\r\n"),
        "{text}"
    );
    assert!(matches!(
        build_reply(&ReplyDraft {
            message_id: "a> <b",
            ..d
        }),
        Err(MailError::InvalidArgument("message_id"))
    ));
}

/// Carry-over (d): sender-controlled control characters (ESC, NUL, …)
/// never reach the agent-visible Markdown, and `Attachment`'s `Debug`
/// prints no MIME type.
#[test]
fn control_characters_in_headers_and_attachment_names_become_spaces() {
    let raw = b"From: Evil\x1b[31m <evil@example.test>\r\n\
Subject: Hallo\x1b]0;pwned\x07 Welt\x00!\r\n\
Message-ID: <ctl-1@example.test>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"b\"\r\n\
\r\n\
--b\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
Text.\r\n\
--b\r\n\
Content-Type: application/pdf; name=\"a\x1b[2Jb.pdf\"\r\n\
Content-Disposition: attachment; filename=\"a\x1b[2Jb.pdf\"\r\n\
\r\n\
JVBERi0=\r\n\
--b--\r\n";
    let m = MessageParser::default().parse(&raw[..]).unwrap();
    assert!(
        m.subject().unwrap().contains('\u{1b}'),
        "the parser keeps the escape, so the test is not vacuous"
    );
    let p = parse_message(raw).unwrap();
    let md = render_markdown(&p);
    assert!(!md.chars().any(|c| c.is_control() && c != '\n'), "{md:?}");
    assert!(md.contains("Hallo"), "{md}");
    assert!(md.contains("b.pdf"), "{md}");
    let att = Attachment {
        name: Some("x.pdf".into()),
        mime: "application/zyxwuria-canary".into(),
    };
    let dbg = format!("{att:?}");
    assert!(
        !dbg.contains("zyxwuria") && !dbg.contains("application"),
        "{dbg}"
    );
}
