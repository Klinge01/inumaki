//! Tray color (spec §6.2) and notification text (spec §6.5).

use std::time::{SystemTime, UNIX_EPOCH};

use inumaki_app_lib::appstate::{AppStateFile, CheckMemo, LastCheck, last_check_summary};
use inumaki_app_lib::ctx::Ctx;
use inumaki_app_lib::notify;
use inumaki_app_lib::paths::AppPaths;
use inumaki_app_lib::poll;
use inumaki_app_lib::tray::{self, PathTone, Tone, TrayColor, TrayInput};
use inumaki_client::mock::{Canned, MockDaemon};
use inumaki_client::{ActivityRecord, CheckResults, PathStatus};
use serde_json::json;

fn results(status: PathStatus) -> CheckResults {
    let mut r = serde_json::from_str(inumaki_client::contract::fixture("check_report"))
        .map(|r: inumaki_client::CheckReport| r.results)
        .unwrap();
    r.gateway.status = status;
    r.mirror.status = status;
    r.proxy.status = status;
    r
}

/// The Overview summary and the tray share one predicate: no memo is no
/// summary; a failed memo counts even when a newer one passed; `at` is the
/// newest memo's time.
#[test]
fn last_check_summary_is_the_newest_time_and_any_failure() {
    let mut s = AppStateFile::default();
    assert_eq!(last_check_summary(&s), None);
    s.last_check.insert(
        "codex".into(),
        CheckMemo {
            at: 100,
            results: results(PathStatus::Failed),
        },
    );
    s.last_check.insert(
        "claude-code".into(),
        CheckMemo {
            at: 200,
            results: results(PathStatus::Passed),
        },
    );
    assert_eq!(
        last_check_summary(&s),
        Some(LastCheck {
            at: 200,
            failed: true
        })
    );
    s.last_check.remove("codex");
    assert_eq!(
        last_check_summary(&s),
        Some(LastCheck {
            at: 200,
            failed: false
        })
    );
}

fn pt(harness: &'static str, path: &'static str, tone: Tone) -> PathTone {
    PathTone {
        harness,
        path,
        tone,
    }
}

/// The bundled glyph decodes (the tray is built at startup): black on a
/// light menu bar, white on a dark one, and the dot in the status color.
#[test]
fn tray_icon_is_the_glyph_with_a_status_dot() {
    for c in [
        TrayColor::Grey,
        TrayColor::Red,
        TrayColor::Yellow,
        TrayColor::Green,
    ] {
        for (dark, ink) in [(false, 0u8), (true, 255u8)] {
            let img = tray::icon(c, dark);
            let (w, h) = (img.width(), img.height());
            assert_eq!((w, h), (45, 30));
            let px: Vec<&[u8]> = img.rgba().chunks_exact(4).collect();
            let at = |x: u32, y: u32| px[(y * w + x) as usize];
            assert_eq!(&at(39, 5)[..3], &tray::rgb(c)[..], "the dot's center");
            assert_eq!(at(39, 5)[3], 255);
            assert!(
                px.iter().any(|p| p[..3] == [ink, ink, ink] && p[3] == 255),
                "the glyph"
            );
            assert!(px.iter().any(|p| p[3] == 0), "a transparent background");
            assert!(
                px.iter()
                    .all(|p| p[3] == 0 || p[..3] == [ink, ink, ink] || p[..3] == tray::rgb(c)),
                "only ink and the dot color"
            );
        }
    }
}

/// The menu's summary line: fixed words per color, the config error apart.
#[test]
fn summary_line_is_a_fixed_word_per_color() {
    assert_eq!(
        tray::summary_line(TrayColor::Yellow, false),
        "Connected, Easy mode"
    );
    assert_eq!(
        tray::summary_line(TrayColor::Grey, false),
        "Service not running"
    );
    assert_eq!(
        tray::summary_line(TrayColor::Red, true),
        "Configuration error"
    );
    assert_eq!(tray::summary_line(TrayColor::Red, false), "Needs attention");
    assert_eq!(tray::summary_line(TrayColor::Green, false), "Protected");
}

/// The second line names a time and fixed words only (R21).
#[test]
fn check_line_says_today_a_date_failed_or_none() {
    use chrono::{FixedOffset, TimeZone};
    let tz = FixedOffset::east_opt(2 * 3600).unwrap();
    let t = |y, mo, d, h, mi| tz.with_ymd_and_hms(y, mo, d, h, mi, 0).unwrap().timestamp();
    let passed = |at| Some(LastCheck { at, failed: false });
    let now = t(2026, 10, 19, 15, 30);
    assert_eq!(
        tray::check_line(passed(t(2026, 10, 19, 9, 5)), now, &tz, false),
        "Last check passed today at 09:05"
    );
    // 01:30 here is still the day before in UTC; the zone decides "today".
    assert_eq!(
        tray::check_line(passed(t(2026, 10, 19, 1, 30)), now, &tz, false),
        "Last check passed today at 01:30"
    );
    assert_eq!(
        tray::check_line(passed(t(2026, 10, 18, 23, 59)), now, &tz, false),
        "Last check passed on 2026-10-18"
    );
    let failed = Some(LastCheck {
        at: t(2026, 10, 19, 9, 5),
        failed: true,
    });
    assert_eq!(
        tray::check_line(failed, now, &tz, false),
        "Last check failed"
    );
    assert_eq!(tray::check_line(None, now, &tz, false), "No check yet");
    // A time in the future (clock skew) never prints a future date or time.
    let future = t(2026, 10, 20, 9, 5);
    assert_eq!(
        tray::check_line(passed(future), now, &tz, false),
        "Last check passed"
    );
    assert_eq!(
        tray::check_line(
            Some(LastCheck {
                at: future,
                failed: true
            }),
            now,
            &tz,
            false
        ),
        "Last check failed"
    );
    for last in [None, passed(now), failed] {
        assert_eq!(
            tray::check_line(last, now, &tz, true),
            "The config file can't be read. Open inumaki for details."
        );
    }
}

/// Yellow means the service answers and nothing is broken; the summary says
/// "Connected" only when a harness is (L5-32), never more than is true.
#[test]
fn summary_says_not_connected_without_a_connected_harness() {
    use inumaki_app_lib::harness::cards::HarnessCard;
    use inumaki_app_lib::harness::ops::{HookState, Login};
    use inumaki_client::HarnessId;
    let card = |connected| HarnessCard {
        id: HarnessId::ClaudeCode,
        name: "Claude Code",
        binary_found: true,
        version: None,
        tested: true,
        login: Login::Unknown,
        connected,
        disconnected: false,
        paths: Vec::new(),
        hook: HookState::NotApplicable,
        drift: 0,
        grant: None,
        last_check_at: None,
    };
    let input = TrayInput {
        reachable: true,
        paths: Vec::new(),
        failing: false,
        disconnected: false,
        config_error: false,
    };
    let tz = chrono::FixedOffset::east_opt(0).unwrap();
    let summary = |cards: &[HarnessCard]| {
        tray::MenuModel::new(TrayColor::Yellow, &input, cards, None, 0, &tz).summary
    };
    assert_eq!(summary(&[]), "Not connected");
    assert_eq!(summary(&[card(false)]), "Not connected");
    assert_eq!(summary(&[card(false), card(true)]), "Connected, Easy mode");
    // Other colors keep their words.
    let red = tray::MenuModel::new(TrayColor::Red, &input, &[], None, 0, &tz);
    assert_eq!(red.summary, "Needs attention");
}

fn harness_card(
    connected: bool,
    last_check_at: Option<i64>,
    paths: &[inumaki_app_lib::harness::ops::PathState],
) -> inumaki_app_lib::harness::cards::HarnessCard {
    use inumaki_app_lib::harness::cards::{HarnessCard, PathView};
    use inumaki_app_lib::harness::ops::{HookState, Login, PathKind};
    HarnessCard {
        id: inumaki_client::HarnessId::ClaudeCode,
        name: "Claude Code",
        binary_found: true,
        version: None,
        tested: true,
        login: Login::Unknown,
        connected,
        disconnected: false,
        paths: paths
            .iter()
            .map(|&state| PathView {
                path: PathKind::Mcp,
                state,
                reason: None,
                detail: None,
                acknowledged: false,
                last_check: None,
            })
            .collect(),
        hook: HookState::NotApplicable,
        drift: 0,
        grant: None,
        last_check_at,
    }
}

fn yellow_input() -> TrayInput {
    TrayInput {
        reachable: true,
        paths: Vec::new(),
        failing: false,
        disconnected: false,
        config_error: false,
    }
}

/// A passed check counts only for a connected harness (a memo outlives a
/// Revert); a failure counts wherever it is.
#[test]
fn check_line_counts_only_connected_harnesses_for_a_pass() {
    let tz = chrono::FixedOffset::east_opt(0).unwrap();
    let (at, now) = (1_790_000_000, 1_790_000_100);
    let line = |cards: &[_], last| {
        tray::MenuModel::new(TrayColor::Yellow, &yellow_input(), cards, last, now, &tz).check
    };
    let passed = Some(LastCheck { at, failed: false });
    // A passed memo on a disconnected card, a connected card without one.
    assert_eq!(
        line(
            &[
                harness_card(false, Some(at), &[]),
                harness_card(true, None, &[])
            ],
            passed
        ),
        "No check yet"
    );
    // A card a failed Reconnect left disconnected carries no pass either.
    let mut down = harness_card(true, Some(at), &[]);
    down.disconnected = true;
    assert_eq!(line(&[down], passed), "No check yet");
    // The connected card's own memo is shown.
    let shown = line(&[harness_card(true, Some(at), &[])], passed);
    assert!(shown.starts_with("Last check passed today at "), "{shown}");
    // A failed memo on any card still says failed.
    assert_eq!(
        line(
            &[harness_card(true, None, &[])],
            Some(LastCheck { at, failed: true })
        ),
        "Last check failed"
    );
}

/// A connected harness with an unverified path shows the amber ring with a
/// dot and says so; the other words stay.
#[test]
fn a_connected_harness_with_an_unverified_path_is_unv() {
    use inumaki_app_lib::harness::ops::PathState;
    let lines = |c| tray::glyph_lines(&[c]);
    assert_eq!(
        lines(harness_card(
            true,
            None,
            &[PathState::Connected, PathState::Unverified]
        )),
        [(
            "Claude Code: connected, not verified".to_string(),
            tray::MenuGlyph::Unv
        )]
    );
    assert_eq!(
        lines(harness_card(true, None, &[PathState::Connected])),
        [("Claude Code: connected".to_string(), tray::MenuGlyph::On)]
    );
    assert_eq!(
        lines(harness_card(
            true,
            None,
            &[PathState::Broken, PathState::Unverified]
        ))[0]
            .1,
        tray::MenuGlyph::Bad
    );
}

/// The menu icons: 32 x 32, the disc colors at the center, a ring (and a
/// dashed ring) hollow in the middle.
#[test]
fn glyph_icons_are_discs_and_rings() {
    use tray::MenuGlyph::{Bad, Na, Off, On, Unv};
    let center = |g| {
        let img = tray::glyph_icon(g, false);
        assert_eq!((img.width(), img.height()), (32, 32));
        let i = (16 * 32 + 16) * 4;
        img.rgba()[i..i + 4].to_vec()
    };
    for (g, c) in [(On, TrayColor::Yellow), (Bad, TrayColor::Red)] {
        let p = center(g);
        assert_eq!((&p[..3], p[3]), (&tray::rgb(c)[..], 255));
    }
    for g in [Off, Na] {
        assert_eq!(center(g)[3], 0, "{g:?} is hollow");
    }
    let unv = center(Unv);
    assert_eq!(
        (&unv[..3], unv[3]),
        (&tray::rgb(TrayColor::Yellow)[..], 255),
        "the ring's dot"
    );
    let summary = tray::summary_icon(TrayColor::Green);
    let i = (16 * 32 + 16) * 4;
    assert_eq!(&summary.rgba()[i..i + 4], &[46, 160, 67, 255]);
}

#[test]
fn tray_color_rules() {
    let s = AppStateFile::default();
    let yellow = vec![
        pt("claude-code", "mcp", Tone::Ok),
        pt("claude-code", "files", Tone::Off),
    ];
    assert_eq!(
        tray::color(
            &TrayInput {
                reachable: false,
                paths: yellow.clone(),
                failing: false,
                disconnected: false,
                config_error: false
            },
            &s
        ),
        TrayColor::Grey
    );
    assert_eq!(
        tray::color(
            &TrayInput {
                reachable: true,
                paths: yellow.clone(),
                failing: false,
                disconnected: false,
                config_error: false
            },
            &s
        ),
        TrayColor::Yellow
    );
    assert_eq!(
        tray::color(
            &TrayInput {
                reachable: true,
                paths: yellow.clone(),
                failing: true,
                disconnected: false,
                config_error: false
            },
            &s
        ),
        TrayColor::Red,
        "failing upstream or route"
    );
    let broken = vec![pt("codex", "mcp", Tone::Broken)];
    assert_eq!(
        tray::color(
            &TrayInput {
                reachable: true,
                paths: broken,
                failing: false,
                disconnected: false,
                config_error: false
            },
            &s
        ),
        TrayColor::Red
    );
    // A path that is unsupported by design (the card shows it red with its
    // reason) is not a fault: the tray stays yellow, acknowledged
    // or not. The menu line carries the "not protected" word.
    let mut ack = AppStateFile::default();
    ack.acknowledged.insert("openclaw/chat".into());
    for state in [&s, &ack] {
        assert_eq!(
            tray::color(
                &TrayInput {
                    reachable: true,
                    paths: vec![pt("openclaw", "chat", Tone::Unsupported)],
                    failing: false,
                    disconnected: false,
                    config_error: false
                },
                state
            ),
            TrayColor::Yellow
        );
    }
    // It does not hide a real fault next to it.
    let mixed = vec![
        pt("hermes", "files", Tone::Unsupported),
        pt("hermes", "mcp", Tone::Broken),
    ];
    assert_eq!(
        tray::color(
            &TrayInput {
                reachable: true,
                paths: mixed,
                failing: false,
                disconnected: false,
                config_error: false
            },
            &s
        ),
        TrayColor::Red
    );
    // A failed end-to-end check colors it red (spec §6.2, §6.6).
    let mut failed = AppStateFile::default();
    let results = serde_json::from_str(inumaki_client::contract::fixture("check_report"))
        .map(|r: inumaki_client::CheckReport| r.results)
        .unwrap();
    failed
        .last_check
        .insert("claude-code".into(), CheckMemo { at: 1, results });
    assert_eq!(
        tray::color(
            &TrayInput {
                reachable: true,
                paths: yellow.clone(),
                failing: false,
                disconnected: false,
                config_error: false
            },
            &failed
        ),
        TrayColor::Red
    );
    // A Reconnect that failed after its revert left a detected harness
    // disconnected (Task 5): its card says so, and the tray follows the cards.
    assert_eq!(
        tray::color(
            &TrayInput {
                reachable: true,
                paths: yellow,
                failing: false,
                disconnected: true,
                config_error: false
            },
            &s
        ),
        TrayColor::Red
    );
}

fn rec(
    at: i64,
    dataset: &str,
    front_door: &str,
    direction: &str,
    verdict: &str,
    kinds: &[&str],
    tripwire: bool,
) -> ActivityRecord {
    serde_json::from_value(json!({
        "id": format!("{at:032x}"), "at": at, "dataset": dataset, "front_door": front_door,
        "upstream": "qwxzvk-crm", "direction": direction, "verdict": verdict, "checks": [],
        "kinds": kinds.iter().map(|k| json!({ "kind": k, "count": 1 })).collect::<Vec<_>>(),
        "tripwire": tripwire, "bytes": 10, "released": null
    }))
    .unwrap()
}

#[test]
fn notifications_name_kinds_front_door_and_counts_only() {
    let records = vec![
        rec(
            3,
            "qwxzvk-kunde",
            "gateway",
            "result",
            "blocked",
            &["PERSON"],
            false,
        ),
        rec(
            2,
            "qwxzvk-kunde",
            "gateway",
            "result",
            "blocked",
            &["IBAN", "PERSON"],
            false,
        ),
        rec(
            1,
            "qwxzvk-akten",
            "mirror",
            "result",
            "released",
            &["PERSON"],
            true,
        ),
        rec(
            1,
            "check-0123456789ab",
            "gateway",
            "result",
            "blocked",
            &["PERSON"],
            false,
        ),
        rec(
            1,
            "qwxzvk-kunde",
            "gateway",
            "result",
            "released",
            &["PERSON"],
            false,
        ),
        rec(
            1,
            "qwxzvk-kunde",
            "hook",
            "result",
            "blocked",
            &["qwxzvk custom kind"],
            false,
        ),
    ];
    let out = notify::render(&records);
    assert_eq!(
        out,
        [
            "Blocked 2 tool results (IBAN, PERSON)",
            "Blocked a tool output",
            "Stopped a known value in a file (PERSON)",
        ]
    );
    assert!(
        out.iter()
            .all(|s| !s.contains("qwxzvk") && !s.contains("check-"))
    );
}

#[tokio::test]
async fn tick_notifies_each_new_record_once() {
    let m = MockDaemon::start().await;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let body = json!({ "records": [serde_json::to_value(rec(now + 100, "qwxzvk-kunde", "proxy", "request", "blocked", &["EMAIL"], false)).unwrap()] });
    m.set("GET", "/v1/activity", Canned::json(200, body));
    let dir = tempfile::tempdir().unwrap();
    let (ctx, notes) = Ctx::for_tests(
        AppPaths::under(&dir.path().join("data"), dir.path()),
        m.client(),
    );
    let snap = poll::tick(&ctx).await;
    assert!(snap.reachable);
    poll::tick(&ctx).await;
    assert_eq!(notes.sent(), ["Blocked a chat message (EMAIL)"]);
    // The cursor stays on the record's second (another record of that second
    // may still arrive) and the id already seen is not notified again.
    let q = m
        .requests()
        .into_iter()
        .rfind(|r| r.route == "/v1/activity")
        .unwrap();
    assert!(q.query.unwrap().contains(&format!("since={}", now + 100)));
    // A second record in the same second arrives later: it notifies once.
    let mut second = rec(
        now + 100,
        "qwxzvk-kunde",
        "gateway",
        "result",
        "blocked",
        &["IBAN"],
        false,
    );
    second.id = format!("{:032x}", 7);
    let body = json!({ "records": [serde_json::to_value(&second).unwrap(), serde_json::to_value(rec(now + 100, "qwxzvk-kunde", "proxy", "request", "blocked", &["EMAIL"], false)).unwrap()] });
    m.set("GET", "/v1/activity", Canned::json(200, body));
    poll::tick(&ctx).await;
    poll::tick(&ctx).await;
    assert_eq!(
        notes.sent(),
        [
            "Blocked a chat message (EMAIL)",
            "Blocked a tool result (IBAN)"
        ]
    );
}

#[tokio::test]
async fn a_burst_over_the_page_says_there_is_more() {
    let m = MockDaemon::start().await;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let records: Vec<_> = (0..200)
        .map(|i| {
            let mut r = rec(
                now + 10 + i,
                "kunde",
                "gateway",
                "result",
                "blocked",
                &["PERSON"],
                false,
            );
            r.id = format!("{i:032x}");
            serde_json::to_value(r).unwrap()
        })
        .collect();
    m.set(
        "GET",
        "/v1/activity",
        Canned::json(200, json!({ "records": records })),
    );
    let dir = tempfile::tempdir().unwrap();
    let (ctx, notes) = Ctx::for_tests(
        AppPaths::under(&dir.path().join("data"), dir.path()),
        m.client(),
    );
    poll::tick(&ctx).await;
    let sent = notes.sent();
    assert!(
        sent.contains(&"Blocked 200 tool results (PERSON)".to_string()),
        "{sent:?}"
    );
    assert!(
        sent.contains(&poll::MORE.to_string()),
        "a full page means more records than shown: {sent:?}"
    );
}

#[tokio::test]
async fn an_unchanged_full_page_does_not_repeat_the_more_notice() {
    let m = MockDaemon::start().await;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let records: Vec<_> = (0..200)
        .map(|i| {
            let mut r = rec(
                now + 10,
                "kunde",
                "gateway",
                "result",
                "blocked",
                &["PERSON"],
                false,
            );
            r.id = format!("{i:032x}");
            serde_json::to_value(r).unwrap()
        })
        .collect();
    m.set(
        "GET",
        "/v1/activity",
        Canned::json(200, json!({ "records": records })),
    );
    let dir = tempfile::tempdir().unwrap();
    let (ctx, notes) = Ctx::for_tests(
        AppPaths::under(&dir.path().join("data"), dir.path()),
        m.client(),
    );
    poll::tick(&ctx).await;
    poll::tick(&ctx).await;
    poll::tick(&ctx).await;
    let sent = notes.sent();
    assert_eq!(
        sent.iter().filter(|s| *s == poll::MORE).count(),
        1,
        "{sent:?}"
    );
    assert_eq!(sent.len(), 2, "{sent:?}");
}

#[tokio::test]
async fn a_quiet_window_skips_notifications_but_advances_the_cursor() {
    let m = MockDaemon::start().await;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let body = json!({ "records": [serde_json::to_value(rec(now + 100, "opaque-label", "gateway", "result", "blocked", &["PERSON"], false)).unwrap()] });
    m.set("GET", "/v1/activity", Canned::json(200, body.clone()));
    let dir = tempfile::tempdir().unwrap();
    let (ctx, notes) = Ctx::for_tests(
        AppPaths::under(&dir.path().join("data"), dir.path()),
        m.client(),
    );
    ctx.quiet_for(60);
    poll::tick(&ctx).await;
    assert!(notes.sent().is_empty(), "{:?}", notes.sent());
    assert_eq!(
        ctx.activity.lock().unwrap().at,
        now + 100,
        "the cursor advanced"
    );
    // Quiet ends: the same record does not notify late.
    ctx.quiet_until
        .store(0, std::sync::atomic::Ordering::Relaxed);
    poll::tick(&ctx).await;
    assert!(notes.sent().is_empty(), "{:?}", notes.sent());
}

#[test]
fn a_config_error_turns_the_tray_red_even_when_the_service_is_unreachable() {
    let input = TrayInput {
        reachable: false,
        paths: vec![],
        failing: false,
        disconnected: false,
        config_error: true,
    };
    assert_eq!(
        tray::color(&input, &AppStateFile::default()),
        TrayColor::Red
    );
    assert_eq!(
        tray::tooltip(TrayColor::Red, true, true, true),
        "inumaki: configuration error"
    );
}

/// Ruling L97: grey while a connected harness runs the hook names the
/// consequence (fixed words); grey without one, and every other color,
/// reads as before.
#[test]
fn grey_with_an_installed_hook_says_tool_output_is_blocked() {
    assert_eq!(
        tray::tooltip(TrayColor::Grey, false, true, true),
        "inumaki: service not running; tool output is blocked in connected sessions"
    );
    assert_eq!(
        tray::tooltip(TrayColor::Grey, false, false, false),
        "inumaki: service not running"
    );
    assert_eq!(
        tray::tooltip(TrayColor::Yellow, false, true, true),
        "inumaki: connected"
    );
    // Yellow without a connected harness does not say "connected".
    assert_eq!(
        tray::tooltip(TrayColor::Yellow, false, false, false),
        "inumaki: not connected"
    );
    assert_eq!(
        tray::tooltip(TrayColor::Red, false, true, true),
        "inumaki: something needs attention"
    );
}
