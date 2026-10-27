//! The tray icon (M6 spec §6.2): grey when the service is not reachable;
//! red with "configuration error" when the config file that names the
//! socket cannot be read;
//! red when something connected is broken, a route or upstream fails, the
//! last end-to-end check failed, or a Reconnect left a harness disconnected;
//! yellow otherwise. A path that is unsupported by design (a card shows it
//! red with its reason) does not make the tray red: the tray stays yellow
//! and the harness's menu line says "a path is not protected". Green is
//! reserved for Protected mode (M7). The icon is the
//! inumaki glyph in black or white, following the appearance, with a status
//! dot in that color.

use inumaki_client::PathStatus;
use tauri::AppHandle;
use tauri::image::Image;
use tauri::menu::{IconMenuItem, IsMenuItem, Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;

use crate::appstate::{AppStateFile, LastCheck, last_check_summary};

/// Menu id: open the settings window.
pub const MENU_OPEN: &str = "open";
/// Menu id: run the end-to-end check.
pub const MENU_CHECK: &str = "check";
/// Menu id: quit the app (the service keeps running).
pub const MENU_QUIT: &str = "quit";
const TRAY_ID: &str = "main";

/// The four colors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TrayColor {
    /// Not installed, not running, not reachable.
    Grey,
    /// Something connected is broken.
    Red,
    /// Nothing is broken at the Easy level. A path that is unsupported by
    /// design can still be unprotected; the menu line says so.
    Yellow,
    /// Protected mode (M7).
    Green,
}

/// A path's contribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    /// Not connected.
    Off,
    /// Connected or unverified.
    Ok,
    /// Unsupported by design: red on the card, but not a fault, so it does
    /// not color the tray.
    Unsupported,
    /// Drift, service down, failing route.
    Broken,
}

/// One harness path.
#[derive(Debug, Clone)]
pub struct PathTone {
    /// Harness id.
    pub harness: &'static str,
    /// `mcp`, `files`, `chat`.
    pub path: &'static str,
    /// Tone.
    pub tone: Tone,
}

/// What the color depends on.
#[derive(Debug, Clone)]
pub struct TrayInput {
    /// The service answers.
    pub reachable: bool,
    /// Harness paths.
    pub paths: Vec<PathTone>,
    /// A gateway upstream or proxy route is failing.
    pub failing: bool,
    /// A detected harness is disconnected after a failed Reconnect (its card
    /// says so; `state.reconnect_failed` of other harnesses does not count).
    pub disconnected: bool,
    /// The config file that names the socket cannot be read: the user has to
    /// act, so this is red, not the grey of "not installed or not running".
    pub config_error: bool,
}

/// The color for `i` under `state`.
pub fn color(i: &TrayInput, state: &AppStateFile) -> TrayColor {
    if i.config_error {
        return TrayColor::Red;
    }
    if !i.reachable {
        return TrayColor::Grey;
    }
    let red_path = i.paths.iter().any(|p| match p.tone {
        Tone::Broken => true,
        Tone::Unsupported | Tone::Off | Tone::Ok => false,
    });
    let failed_check = last_check_summary(state).is_some_and(|l| l.failed);
    if red_path || i.failing || failed_check || i.disconnected {
        TrayColor::Red
    } else {
        TrayColor::Yellow
    }
}

/// The tray glyph (`icons/tray.png`, rendered from `icons/source/tray.svg`
/// at 30 px high, 15 pt at 2×): only its alpha is used.
const TRAY_GLYPH: &[u8] = include_bytes!("../icons/tray.png");

/// The status dot: center and radius in glyph pixels, in the glyph's empty
/// top-right corner.
const DOT: (f32, f32, f32) = (39.0, 5.7, 5.7);

/// The status color's RGB.
pub fn rgb(c: TrayColor) -> [u8; 3] {
    match c {
        TrayColor::Grey => [138, 144, 153],
        TrayColor::Red => [212, 57, 47],
        TrayColor::Yellow => [226, 185, 59],
        TrayColor::Green => [46, 160, 67],
    }
}

/// The glyph in black (light menu bar) or white (`dark`), with a status dot
/// in the color of `c`. Not a template image: a template cannot carry the
/// dot's color, so the caller passes the appearance.
pub fn icon(c: TrayColor, dark: bool) -> Image<'static> {
    let ink = if dark { 255 } else { 0 };
    let glyph = Image::from_bytes(TRAY_GLYPH).expect("the bundled tray glyph is a valid PNG");
    let (w, h) = (glyph.width(), glyph.height());
    let dot = rgb(c);
    let (cx, cy, r) = DOT;
    let px = glyph
        .rgba()
        .chunks_exact(4)
        .enumerate()
        .flat_map(|(i, p)| {
            let (x, y) = ((i as u32 % w) as f32 + 0.5, (i as u32 / w) as f32 + 0.5);
            let d = ((x - cx).powi(2) + (y - cy).powi(2)).sqrt();
            // Antialiased edge: full inside, fading over one pixel.
            let cover = (r + 0.5 - d).clamp(0.0, 1.0);
            if cover > 0.0 {
                [dot[0], dot[1], dot[2], (cover * 255.0).round() as u8]
            } else {
                [ink, ink, ink, p[3]]
            }
        })
        .collect();
    Image::new_owned(px, w, h)
}

/// Whether the menu bar is dark: the app's appearance, read from the
/// settings window (on macOS the theme is app-wide).
pub fn dark(app: &AppHandle) -> bool {
    use tauri::Manager;
    app.get_webview_window("main")
        .and_then(|w| w.theme().ok())
        .is_some_and(|t| t == tauri::Theme::Dark)
}

/// Create the tray icon with its menu (the menu of a service that is not
/// running; the poller replaces it with the real one on its first tick).
pub fn build(app: &AppHandle) -> tauri::Result<()> {
    let menu = menu(app, &MenuModel::initial(), dark(app))?;
    TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon(TrayColor::Grey, dark(app)))
        .tooltip("inumaki")
        .menu(&menu)
        .on_menu_event(|app, e| match e.id().as_ref() {
            MENU_OPEN => crate::show_window(app),
            MENU_CHECK => run_check_from_tray(app),
            MENU_QUIT => app.exit(0),
            _ => {}
        })
        .build(app)?;
    Ok(())
}

/// The notification after a check from the tray: fixed text only (spec §6.5).
pub fn check_notice(
    r: &Result<crate::check::run::CheckRun, crate::error::CmdError>,
) -> &'static str {
    match r {
        Ok(run)
            if run.reports.iter().all(|r| {
                [&r.results.gateway, &r.results.mirror, &r.results.proxy]
                    .iter()
                    .all(|p| p.status != PathStatus::Failed)
            }) =>
        {
            if run.warning.is_some() {
                "End-to-end check passed, but the harness chat check was skipped; open inumaki for details"
            } else {
                "End-to-end check passed"
            }
        }
        Ok(_) => "End-to-end check failed; open inumaki for details",
        Err(e) if e.kind == "check_in_progress" => "An end-to-end check is already running",
        Err(_) => "End-to-end check could not run; open inumaki for details",
    }
}

fn run_check_from_tray(app: &AppHandle) {
    use tauri::Manager;
    let Some(ctx) = app.try_state::<std::sync::Arc<crate::ctx::Ctx>>() else {
        return;
    };
    let ctx = std::sync::Arc::clone(ctx.inner());
    tauri::async_runtime::spawn(async move {
        let r = crate::applog::logged("tray_run_check", crate::check::run::run_check(&ctx)).await;
        ctx.notifier.notify(check_notice(&r));
    });
}

/// A connected harness's card shows the hook installed: while the service
/// is unreachable, that hook blocks every hooked tool result (ruling L97,
/// fail closed). A hook the harness does not run yet (Codex, not trusted)
/// does not count.
pub fn hook_blocks(cards: &[crate::harness::cards::HarnessCard]) -> bool {
    cards
        .iter()
        .any(|c| c.connected && c.hook == crate::harness::ops::HookState::Installed)
}

/// The tooltip for `c`; `config_error` names the one red state that is not
/// about a harness; `hook_blocks` ([`hook_blocks`]) names the consequence of
/// grey while a connected harness runs the hook; `any_connected` keeps yellow
/// from saying "connected" when no harness is.
pub fn tooltip(
    c: TrayColor,
    config_error: bool,
    hook_blocks: bool,
    any_connected: bool,
) -> &'static str {
    match c {
        TrayColor::Grey if hook_blocks => {
            "inumaki: service not running; tool output is blocked in connected sessions"
        }
        TrayColor::Grey => "inumaki: service not running",
        TrayColor::Red if config_error => "inumaki: configuration error",
        TrayColor::Red => "inumaki: something needs attention",
        TrayColor::Yellow if !any_connected => "inumaki: not connected",
        TrayColor::Yellow => "inumaki: connected",
        TrayColor::Green => "inumaki: protected",
    }
}

/// Recolor the tray (`dark`: the menu bar's appearance, see [`dark`]).
pub fn set(
    app: &AppHandle,
    c: TrayColor,
    dark: bool,
    config_error: bool,
    hook_blocks: bool,
    any_connected: bool,
) {
    if let Some(t) = app.tray_by_id(TRAY_ID) {
        let _ = t.set_icon(Some(icon(c, dark)));
        let _ = t.set_tooltip(Some(tooltip(c, config_error, hook_blocks, any_connected)));
    }
}

/// Some harness is connected (a card's `connected`).
pub fn any_connected(cards: &[crate::harness::cards::HarnessCard]) -> bool {
    cards.iter().any(|c| c.connected)
}

/// The status glyph of a harness line in the menu (spec §9.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuGlyph {
    /// Connected: amber disc.
    On,
    /// Connected, not verified: amber ring with a dot.
    Unv,
    /// Not connected: grey ring.
    Off,
    /// A path that is unsupported by design: grey dashed ring.
    Na,
    /// Needs attention: red disc.
    Bad,
}

/// Menu icon edge in pixels (16 pt at 2×).
const GLYPH_PX: u32 = 32;
/// Outer radius of every menu glyph, in pixels (a 4 px margin).
const GLYPH_R: f32 = 12.0;

/// An RGBA image whose alpha is `cover(x, y)` (pixel centers) in `rgb`.
fn paint(rgb: [u8; 3], cover: impl Fn(f32, f32) -> f32) -> Image<'static> {
    let px = (0..GLYPH_PX * GLYPH_PX)
        .flat_map(|i| {
            let (x, y) = ((i % GLYPH_PX) as f32 + 0.5, (i / GLYPH_PX) as f32 + 0.5);
            let a = (cover(x, y).clamp(0.0, 1.0) * 255.0).round() as u8;
            [rgb[0], rgb[1], rgb[2], a]
        })
        .collect();
    Image::new_owned(px, GLYPH_PX, GLYPH_PX)
}

/// Antialiased coverage of a disc of radius `r` around the glyph center:
/// full inside, fading over one pixel (the same edge as the dot in [`icon`]).
fn disc(d: f32, r: f32) -> f32 {
    (r + 0.5 - d).clamp(0.0, 1.0)
}

/// Coverage of a ring of outer radius [`GLYPH_R`] and stroke `w`.
fn ring(d: f32, w: f32) -> f32 {
    disc(d, GLYPH_R).min((d - (GLYPH_R - w) + 0.5).clamp(0.0, 1.0))
}

/// Dashes around the ring: `N` of them, each as long as its gap. The edge
/// along the arc is antialiased like the others.
fn dashes(x: f32, y: f32) -> f32 {
    const N: f32 = 8.0;
    let c = GLYPH_PX as f32 / 2.0;
    let turn = (y - c).atan2(x - c) / std::f32::consts::TAU;
    let seg = std::f32::consts::TAU * (GLYPH_R - 1.25) / N;
    let u = (turn * N).rem_euclid(1.0) * seg;
    let half = seg / 2.0;
    // Signed distance to the nearest dash edge along the arc, positive inside.
    let s = if u <= half {
        u.min(half - u)
    } else {
        -(u - half).min(seg - u)
    };
    (s + 0.5).clamp(0.0, 1.0)
}

/// The 32 × 32 px menu icon for `g`: drawn like the dot in [`icon`]. The
/// colors read on both appearances, so `dark` does not change them (it is
/// part of the signature for a future appearance-specific tone).
pub fn glyph_icon(g: MenuGlyph, _dark: bool) -> Image<'static> {
    let c = GLYPH_PX as f32 / 2.0;
    let dist = move |x: f32, y: f32| ((x - c).powi(2) + (y - c).powi(2)).sqrt();
    match g {
        MenuGlyph::On => paint(rgb(TrayColor::Yellow), move |x, y| {
            disc(dist(x, y), GLYPH_R)
        }),
        MenuGlyph::Unv => paint(rgb(TrayColor::Yellow), move |x, y| {
            let d = dist(x, y);
            ring(d, 3.0).max(disc(d, 4.0))
        }),
        MenuGlyph::Off => paint(rgb(TrayColor::Grey), move |x, y| ring(dist(x, y), 2.5)),
        MenuGlyph::Na => paint(rgb(TrayColor::Grey), move |x, y| {
            ring(dist(x, y), 2.5).min(dashes(x, y))
        }),
        MenuGlyph::Bad => paint(rgb(TrayColor::Red), move |x, y| disc(dist(x, y), GLYPH_R)),
    }
}

/// The summary line's icon: a disc in the tray color.
pub fn summary_icon(c: TrayColor) -> Image<'static> {
    let m = GLYPH_PX as f32 / 2.0;
    paint(rgb(c), move |x, y| {
        disc(((x - m).powi(2) + (y - m).powi(2)).sqrt(), GLYPH_R)
    })
}

fn weakest(c: &crate::harness::cards::HarnessCard) -> (&'static str, MenuGlyph) {
    use crate::harness::ops::PathState::*;
    if c.disconnected || c.paths.iter().any(|p| p.state == Broken) {
        ("needs attention", MenuGlyph::Bad)
    } else if c
        .paths
        .iter()
        .any(|p| p.state == Unsupported && !p.acknowledged)
    {
        ("a path is not protected", MenuGlyph::Na)
    } else if c.connected && c.paths.iter().any(|p| p.state == Unverified) {
        ("connected, not verified", MenuGlyph::Unv)
    } else if c.connected {
        ("connected", MenuGlyph::On)
    } else {
        ("not connected", MenuGlyph::Off)
    }
}

/// The disabled status lines of the menu: product names and fixed words only
/// (never a server name, dataset, or path).
pub fn menu_lines(cards: &[crate::harness::cards::HarnessCard]) -> Vec<String> {
    glyph_lines(cards).into_iter().map(|(l, _)| l).collect()
}

/// [`menu_lines`] with each line's glyph.
pub fn glyph_lines(cards: &[crate::harness::cards::HarnessCard]) -> Vec<(String, MenuGlyph)> {
    cards
        .iter()
        .map(|c| {
            let (word, glyph) = weakest(c);
            (format!("{}: {}", c.name, word), glyph)
        })
        .collect()
}

/// The first menu line: the tray color in fixed words.
pub fn summary_line(c: TrayColor, config_error: bool) -> &'static str {
    match c {
        TrayColor::Yellow => "Connected, Easy mode",
        TrayColor::Grey => "Service not running",
        TrayColor::Red if config_error => "Configuration error",
        TrayColor::Red => "Needs attention",
        TrayColor::Green => "Protected",
    }
}

/// The second menu line (R21): when the newest check ran, in `tz`. Fixed
/// words and a time only; `now` is Unix seconds.
pub fn check_line(
    last: Option<LastCheck>,
    now: i64,
    tz: &impl chrono::TimeZone,
    config_error: bool,
) -> String {
    use chrono::Timelike;
    if config_error {
        return "The config file can't be read. Open inumaki for details.".into();
    }
    let Some(last) = last else {
        return "No check yet".into();
    };
    if last.failed {
        return "Last check failed".into();
    }
    // A timestamp the zone cannot represent, or one in the future (clock
    // skew): say only what is known.
    let Some(at) = tz
        .timestamp_opt(last.at, 0)
        .single()
        .filter(|_| last.at <= now)
    else {
        return "Last check passed".into();
    };
    let today = tz.timestamp_opt(now, 0).single().map(|n| n.date_naive());
    if today == Some(at.date_naive()) {
        format!(
            "Last check passed today at {:02}:{:02}",
            at.hour(),
            at.minute()
        )
    } else {
        format!("Last check passed on {}", at.date_naive())
    }
}

/// Everything the menu shows: fixed words, product names, and glyphs. The
/// poller rebuilds the menu only when this changes.
#[derive(Debug, Clone, PartialEq)]
pub struct MenuModel {
    /// The tray color (the summary's icon).
    pub color: TrayColor,
    /// [`summary_line`].
    pub summary: &'static str,
    /// [`check_line`].
    pub check: String,
    /// One line per harness with its glyph ([`glyph_lines`]).
    pub harness: Vec<(String, MenuGlyph)>,
    /// The service answers ("Run the check" is enabled).
    pub reachable: bool,
}

impl MenuModel {
    /// The menu of a service that is not running, before the first poll.
    pub fn initial() -> Self {
        Self {
            color: TrayColor::Grey,
            summary: summary_line(TrayColor::Grey, false),
            check: "No check yet".into(),
            harness: Vec::new(),
            reachable: false,
        }
    }

    /// The model for one poll tick; `last` is the newest check across all
    /// memos ([`last_check_summary`]).
    pub fn new(
        color: TrayColor,
        input: &TrayInput,
        cards: &[crate::harness::cards::HarnessCard],
        last: Option<LastCheck>,
        now: i64,
        tz: &impl chrono::TimeZone,
    ) -> Self {
        // Yellow only says the service answers and nothing is broken: with
        // no harness connected, "Connected" would overstate (L5-32).
        let summary = if color == TrayColor::Yellow && !any_connected(cards) {
            "Not connected"
        } else {
            summary_line(color, input.config_error)
        };
        // A passed check counts only for a harness that is connected now (a
        // memo outlives a Revert); a failure counts wherever it is, so the
        // line fails closed like the color does.
        let last = match last {
            Some(l) if l.failed => Some(l),
            _ => cards
                .iter()
                .filter(|c| c.connected && !c.disconnected)
                .filter_map(|c| c.last_check_at)
                .max()
                .map(|at| LastCheck { at, failed: false }),
        };
        Self {
            color,
            summary,
            check: check_line(last, now, tz, input.config_error),
            harness: glyph_lines(cards),
            reachable: input.reachable,
        }
    }
}

/// The menu for `m`: summary and check line (disabled), the harness lines,
/// then "Open inumaki", "Run the check", and "Quit".
fn menu(app: &AppHandle, m: &MenuModel, dark: bool) -> tauri::Result<Menu<tauri::Wry>> {
    let summary = IconMenuItem::new(
        app,
        m.summary,
        false,
        Some(summary_icon(m.color)),
        None::<&str>,
    )?;
    let check = MenuItem::new(app, &m.check, false, None::<&str>)?;
    let harness = m
        .harness
        .iter()
        .map(|(line, g)| {
            IconMenuItem::new(app, line, false, Some(glyph_icon(*g, dark)), None::<&str>)
        })
        .collect::<tauri::Result<Vec<_>>>()?;
    let open = MenuItem::with_id(app, MENU_OPEN, "Open inumaki", true, Some("CmdOrCtrl+O"))?;
    let run = MenuItem::with_id(app, MENU_CHECK, "Run the check", m.reachable, None::<&str>)?;
    let quit = MenuItem::with_id(
        app,
        MENU_QUIT,
        "Quit inumaki (service keeps running)",
        true,
        None::<&str>,
    )?;
    let seps = [
        PredefinedMenuItem::separator(app)?,
        PredefinedMenuItem::separator(app)?,
        PredefinedMenuItem::separator(app)?,
    ];
    let mut items: Vec<&dyn IsMenuItem<tauri::Wry>> = vec![&summary, &check, &seps[0]];
    items.extend(harness.iter().map(|i| i as &dyn IsMenuItem<tauri::Wry>));
    items.push(&seps[1]);
    items.push(&open);
    items.push(&run);
    items.push(&seps[2]);
    items.push(&quit);
    Menu::with_items(app, &items)
}

/// Rebuild the menu from `m`. Returns whether the menu was set.
pub fn set_menu(app: &AppHandle, m: &MenuModel) -> bool {
    let Some(t) = app.tray_by_id(TRAY_ID) else {
        return false;
    };
    menu(app, m, dark(app)).is_ok_and(|menu| t.set_menu(Some(menu)).is_ok())
}
