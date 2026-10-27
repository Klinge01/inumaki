# Mail providers: what was verified

inumaki's mail connector speaks IMAP4rev1 over implicit TLS (port 993) and
logs in with a user name and an app password. It reads folders and messages
and stores reply drafts with IMAP `APPEND`. It never sends mail and has no
SMTP configuration. Presets supply connection settings only; this page says
what was actually tried. Anything not listed as verified is unverified, and
nothing here is a promise that a provider works.

| Preset | IMAP | Authentication | Status |
|---|---|---|---|
| `gmail` | `imap.gmail.com:993` | Google app password (needs 2-step verification on the account and IMAP enabled in Gmail settings) | **Unverified.** Not yet tried against a real account. When it is, record the date, the account type (personal or Workspace), and the result of `inumaki dataset check-mailbox` here. |
| `outlook` | `outlook.office365.com:993` | None available: Microsoft retired basic authentication for IMAP, so a password or app password is refused and IMAP needs OAuth 2.0 | **Unsupported in milestone 4.** `mail_auth_failed` says so. OAuth for IMAP is deferred (M4 spec §2). |
| `generic` | user-supplied host and port; TLS required unless the host is loopback | user name and password (`LOGIN`) | **Exercised against the scripted fake and GreenMail 2.1.14 (passes); unverified against other servers.** Dovecot and others: record when tried. |

## The GreenMail suite

`crates/inumakid/tests/mail_greenmail.rs` is gated behind the `mail-tests`
feature and needs Docker. It starts nothing itself; run it like this:

```sh
scripts/greenmail.sh start        # pinned greenmail/standalone:2.1.14 on 127.0.0.1:3143
cargo test -p inumakid --features mail-tests --test mail_greenmail
scripts/greenmail.sh stop
```

Restart the container before every run (the test asserts that `Drafts` does
not exist yet). If another service already owns port 3143, move the container
with `GREENMAIL_IMAP_PORT=<port> scripts/greenmail.sh start` and give the
test the same variable; never point the suite at a port you do not own,
because it wipes the INBOX and Drafts folder of the account it logs into.
Use it only with the throwaway account `agent`. The `inumaki mail-tasks`
runner wipes the same way.

**Result (2026-10-05, run once): the suite passes against GreenMail 2.1.14.**
The first run failed at the first `mail_search` with `mail_unreachable`:
GreenMail answers a partial fetch as `BODY[TEXT]<0>{200}` with no space before
the literal, where RFC 3501 requires one after the `>`, and `async-imap`
cannot decode that line. The connection now wraps the socket in a tolerant
reader (`inumaki_mail::tolerant::TolerantStream`) that inserts the missing
space; literal data and everything the connector writes pass through
untouched. With it, the run confirmed against GreenMail: INTERNALDATE set from
the `APPEND` date-time and honoured by `SINCE`/`BEFORE`, `HEADER Message-ID`
search (the draft id is returned), automatic creation of `Drafts`, `APPEND`
with `\Draft`, the `UID STORE`/`EXPUNGE` wipe, and the reply recipient and
`In-Reply-To`. There is no full-text fallback and none is planned (it would
defeat the byte cap on what `mail_search` fetches). One run against one server
is all that was done; the connector's behaviour on any other server is
unproven.

## Drafts folder

The connector uses, in order: the folder configured with `--drafts-folder`
(it must exist, otherwise `drafts_folder_missing`), the folder the server marks
with the RFC 6154 `\Drafts` attribute (Gmail: `[Gmail]/Drafts`; a localized
name such as `[Gmail]/Entwürfe` can also be typed as `--drafts-folder`), a
folder named `Drafts` in any case, or it creates `Drafts` on the first draft.
Drafts are stored with the `\Draft` flag; if the server refuses the flag the
draft is stored once more without it (an `APPEND` that never reached the literal is likewise retried once, without the flag, on a fresh session). How the draft looks in a mail client
(appears under Drafts, editable, sendable) must be checked per provider and
recorded here.

## Certificates

The connector trusts the Mozilla root store (`webpki-roots`) and nothing
else. A server with a private or self-signed certificate (GreenMail's IMAPS,
some NAS boxes) cannot be reached over TLS in milestone 4; the check reports
`mail_tls_failed`. Plaintext IMAP is accepted for `127.0.0.1`, `::1`, and
`localhost` only (`--imap-plaintext-loopback`).

## Search

Search terms are sent as IMAP `OR OR FROM x SUBJECT x TEXT x`. A non-ASCII
term needs `CHARSET UTF-8` and a LITERAL+ literal (RFC 7888); on a server that
does not advertise `LITERAL+` the connector answers `invalid_argument` rather
than sending 8-bit text in a quoted string. Whether a given server's `TEXT`
search matches a non-ASCII term inside a UTF-8 body is not something the fake
server can show; record it here per real provider.

`since` and `before` compare the **received date** (IMAP INTERNALDATE), not the
`Date` header, on every server: a mail forwarded or imported today is found
under today's date. The fixture harness appends fixtures with their own
date-time so that the date-window tasks are reproducible.
