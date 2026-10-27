//! M5 spec §16.1 item 1 under `support-email` (review I11): the no-original
//! fixture through the real engine. M5 spec §16.2: one 20 KB file, from the
//! source file's last write to the mirror file's appearance, 50 runs, idle
//! daemon; `offline` and `support-email`. Prints p50, p95, max, the
//! breakdown, and the blocked-file rate, and asserts nothing about the
//! latency target (the MVP ships measured). Also times a daemon start with
//! a folder of 2000 small files.
//!
//! Needs `INUMAKI_MODELS_DIR`. Run with `--nocapture` to see the numbers.
#![cfg(feature = "models-tests")]
// The measurements are printed for the report.
#![allow(clippy::print_stdout)]

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use common::Capture;
use common::mirror::{serve_on, start_mirror_with_models};
use hyper::Method;
use inumaki_core::span::EntityKind;
use inumaki_core::token::TokenStore;
use inumaki_eval::{GenFamily, GenOptions, generate};
use serde_json::{Value, json};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const NAME: &str = "Zyxwuria Quolnath";
const BLOCKED_SUFFIX: &str = ".inumaki-blocked.txt";

/// One test at a time: the numbers are only meaningful on an idle daemon.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The mirror's `debug` events (numbers only), captured process-wide: the
/// mirror's worker threads must be seen.
fn capture() -> &'static Capture {
    static CAP: OnceLock<Capture> = OnceLock::new();
    CAP.get_or_init(|| {
        let cap = Capture::new();
        let _ = tracing_subscriber::registry()
            .with(EnvFilter::new("inumaki_mirror=debug"))
            .with(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .with_writer(cap.clone()),
            )
            .try_init();
        cap
    })
}

/// A synthetic German/English business letter of at least 20 KB, different
/// for every `i` (a repeated text would measure the sanitization cache).
fn letter(i: usize) -> String {
    let docs = generate(&GenOptions {
        seed: 1000 + i as u64,
        count: 1000,
        transforms: false,
        family: GenFamily::Tuning,
    });
    let mut out = String::new();
    for d in docs {
        out.push_str(&d.text);
        out.push_str("\n\n");
        if out.len() >= 20 * 1024 {
            break;
        }
    }
    assert!(out.len() >= 20 * 1024, "generator too small");
    out
}

fn walk(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            let rel = p.strip_prefix(root).unwrap().to_string_lossy().into_owned();
            if p.is_dir() {
                stack.push(p);
                out.push((rel, Vec::new()));
            } else {
                out.push((rel, std::fs::read(&p).unwrap_or_default()));
            }
        }
    }
    out
}

fn blocked_count(mirror: &Path) -> usize {
    walk(mirror)
        .iter()
        .filter(|(p, _)| p.ends_with(BLOCKED_SUFFIX))
        .count()
}

/// Files and placeholders directly in the mirror: each source file adds
/// exactly one (a withheld file's placeholder has an opaque name).
fn mirrored_entries(mirror: &Path) -> usize {
    std::fs::read_dir(mirror)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.path().is_file() && !e.file_name().to_string_lossy().starts_with('.'))
        .count()
}

async fn add_folder(m: &common::TestDaemon, id: &str, profile: &str, src: &Path) -> PathBuf {
    let (code, body) = m
        .call(
            Method::POST,
            "/v1/datasets",
            Some(json!({"id": id, "name": "L", "profile": profile, "kind": "folder"})),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    let (code, body) = m
        .call(
            Method::POST,
            &format!("/v1/datasets/{id}/folder"),
            Some(json!({"source": src})),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    PathBuf::from(body["mirror"].as_str().unwrap())
}

async fn folder_status(call: &common::TestDaemon, id: &str) -> Value {
    let (_, l) = call.call(Method::GET, "/v1/folders", None).await;
    l["folders"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["dataset"] == id)
        .cloned()
        .unwrap()
}

fn idle(f: &Value) -> bool {
    f["state"] == "watching" && f["files"]["pending"] == 0
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_original_in_the_mirror_under_support_email() {
    use unicode_normalization::UnicodeNormalization;
    let _one = ONE_AT_A_TIME.lock().await;
    let m = start_mirror_with_models().await;
    let (code, _) =
        m.d.call(
            Method::POST,
            "/v1/datasets",
            Some(
                json!({"id": "noorig", "name": "N", "profile": "support-email", "kind": "folder"}),
            ),
        )
        .await;
    assert_eq!(code, 201);
    let s = Arc::clone(&m.d.state);
    tokio::task::spawn_blocking(move || {
        let ns = s.namespace("noorig").unwrap();
        let mut n = ns.lock().unwrap();
        for (k, o) in [
            (EntityKind::Person, NAME),
            (EntityKind::Organization, "Quolnath GmbH"),
            (EntityKind::Person, "Quolnath"),
        ] {
            n.token_for(&k, o).unwrap();
        }
    })
    .await
    .unwrap();
    // The spec §16.1 item 1 fixture, plus the encodings the real decoders
    // handle.
    let src = m.base.join("noorig");
    std::fs::create_dir_all(src.join("Kunden/Quolnath GmbH")).unwrap();
    std::fs::create_dir_all(src.join("Kunde.Quolnath")).unwrap();
    std::fs::create_dir_all(src.join(NAME)).unwrap();
    std::fs::write(
        src.join("Angebot_Zyxwuria_Quolnath.txt"),
        format!("Sehr geehrter Herr {NAME},\n"),
    )
    .unwrap();
    std::fs::write(
        src.join("Kunden/Quolnath GmbH/liste.csv"),
        format!("name,{NAME}\n\"{NAME}\",Wien\n"),
    )
    .unwrap();
    std::fs::write(
        src.join("Kunde.Quolnath/k.json"),
        format!(
            "{{\"{NAME}\": {{\"first\": \"Zyxwuria\", \"last\": \"Quolnath\", \"n\": 4366012345678}}}}"
        ),
    )
    .unwrap();
    std::fs::write(src.join("Brief.Zyxwuria Quolnath"), "x").unwrap();
    std::fs::write(src.join("seite.html"), "<p>Herr Zyxwuria Quoln&#97;th</p>").unwrap();
    std::fs::write(
        src.join("mail.eml"),
        format!("From: {NAME} <z@example.invalid>\r\nSubject: Hallo\r\n\r\nGruss, {NAME}\r\n"),
    )
    .unwrap();
    // Windows-1252.
    std::fs::write(
        src.join("export.csv"),
        b"Kunde;Ort\nZyxwuria Quolnath;M\xFCnchen\n",
    )
    .unwrap();
    std::fs::write(
        src.join("gross Zyxwuria Quolnath.txt"),
        vec![b'a'; 2 * 1024 * 1024],
    )
    .unwrap();
    std::os::unix::fs::symlink("/etc/hosts", src.join(format!("link {NAME}"))).unwrap();
    let (code, body) =
        m.d.call(
            Method::POST,
            "/v1/datasets/noorig/folder",
            Some(json!({"source": src})),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    let mirror = PathBuf::from(body["mirror"].as_str().unwrap());
    let until = Instant::now() + Duration::from_secs(300);
    loop {
        let f = folder_status(&m.d, "noorig").await;
        if idle(&f) {
            break;
        }
        assert!(Instant::now() < until, "the scan did not finish");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let files = walk(&mirror);
    // The claim is about released files: a fixture that withholds everything
    // would pass an absence check for nothing. At least one file that is no
    // placeholder and no bookkeeping must carry a token.
    let released_with_token = files
        .iter()
        .filter(|(p, _)| {
            let name = p.rsplit('/').next().unwrap_or(p);
            let placeholder = name.contains(".inumaki-") && name.ends_with(".txt");
            !name.starts_with('.') && !placeholder
        })
        .filter(|(_, b)| String::from_utf8_lossy(b).contains("<PERSON_"))
        .count();
    assert!(
        released_with_token >= 1,
        "no released file carries a token: {} entries, {} placeholders",
        files.len(),
        blocked_count(&mirror)
    );
    assert!(files.len() >= 12, "too few entries: {}", files.len());
    for (path, bytes) in &files {
        let text = String::from_utf8_lossy(bytes);
        // "Zyxwuria" alone is the JSON first/last split; the number is the
        // object-level case in the same file.
        for o in [NAME, "Quolnath", "Zyxwuria", "4366012345678"] {
            for v in [
                o.to_string(),
                o.nfd().collect::<String>(),
                o.to_lowercase(),
                o.replace(' ', "_"),
            ] {
                assert!(!path.contains(&v), "original in a path");
                assert!(!text.contains(&v), "original in a mirror file");
            }
        }
    }
    println!(
        "no-original fixture under support-email: {} entries, {released_with_token} released with a token, {} placeholders for blocked files",
        files.len(),
        blocked_count(&mirror)
    );
}

fn pct(v: &mut [Duration], p: f64) -> Duration {
    v.sort();
    v[((v.len() as f64 - 1.0) * p).round() as usize]
}

fn nums(text: &str, event: &str, key: &str) -> Vec<u64> {
    let pat = format!("{key}=");
    text.lines()
        .filter(|l| l.contains(event))
        .filter_map(|l| {
            let i = l.find(&pat)? + pat.len();
            let digits: String = l[i..].chars().take_while(char::is_ascii_digit).collect();
            digits.parse().ok()
        })
        .collect()
}

fn p(v: &mut [u64], q: f64) -> u64 {
    if v.is_empty() {
        return 0;
    }
    v.sort();
    v[((v.len() as f64 - 1.0) * q).round() as usize]
}

async fn run(profile: &str) {
    let m = start_mirror_with_models().await;
    let id = format!("lat-{profile}");
    let src = m.base.join(format!("src-{profile}"));
    std::fs::create_dir_all(&src).unwrap();
    let mirror = add_folder(&m.d, &id, profile, &src).await;
    // An idle daemon: the empty scan is done and the model is warm (one
    // untimed file first).
    std::fs::write(src.join("warm.txt"), letter(999)).unwrap();
    let until = Instant::now() + Duration::from_secs(300);
    while mirrored_entries(&mirror) < 1 {
        if Instant::now() >= until {
            panic!(
                "warm-up file did not appear: {}",
                folder_status(&m.d, &id).await
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    capture().0.lock().unwrap().clear();
    let mut totals = Vec::new();
    let mut timeouts = 0;
    for i in 0..50 {
        let body = letter(i);
        let t0 = Instant::now();
        std::fs::write(src.join(format!("brief-{i}.txt")), body).unwrap();
        while mirrored_entries(&mirror) < i + 2 {
            if t0.elapsed() > Duration::from_secs(60) {
                timeouts += 1;
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        totals.push(t0.elapsed());
        // Idle between runs: the next write starts on a quiet daemon.
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let log = capture().text();
    let blocked = blocked_count(&mirror);
    let (p50, p95, max) = (
        pct(&mut totals, 0.5),
        pct(&mut totals, 0.95),
        *totals.iter().max().unwrap(),
    );
    let mut san = nums(&log, "mirror file", "sanitize_ms");
    let mut wr = nums(&log, "mirror file", "write_ms");
    let mut batch = nums(&log, "mirror sub-batch", "batch_ms");
    println!(
        "LATENCY {profile}: p50 {} ms, p95 {} ms, max {} ms; blocked {blocked}/51 (warm-up file included); timeouts {timeouts}; \
         sanitize p50 {} p95 {} ms; write p50 {} p95 {} ms; sub-batch p50 {} p95 {} max {} ms ({} calls, {} released files)",
        p50.as_millis(),
        p95.as_millis(),
        max.as_millis(),
        p(&mut san, 0.5),
        p(&mut san, 0.95),
        p(&mut wr, 0.5),
        p(&mut wr, 0.95),
        p(&mut batch, 0.5),
        p(&mut batch, 0.95),
        p(&mut batch, 1.0),
        batch.len(),
        san.len(),
    );
    assert_eq!(timeouts, 0, "{profile}: a run timed out");
    std::fs::write(
        std::env::temp_dir().join(format!("inumaki-m5-latency-{profile}.json")),
        format!(
            "{{\"profile\":\"{profile}\",\"p50_ms\":{},\"p95_ms\":{},\"max_ms\":{},\"blocked\":{blocked},\"timeouts\":{timeouts}}}\n",
            p50.as_millis(),
            p95.as_millis(),
            max.as_millis()
        ),
    )
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mirror_latency_20kb() {
    let _one = ONE_AT_A_TIME.lock().await;
    capture();
    // `MIRROR_LATENCY_PROFILES=support-email` limits a rerun to one profile.
    let only = std::env::var("MIRROR_LATENCY_PROFILES").ok();
    for profile in ["offline", "support-email"] {
        if only.as_deref().is_none_or(|o| o.contains(profile)) {
            run(profile).await;
        }
    }
}

/// `AppState::start` plus the time to a first answer on the control
/// socket, with a folder of 2000 small files already mirrored (offline
/// profile: the point is the manifest and watches, not the models).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn startup_with_2000_files() {
    let _one = ONE_AT_A_TIME.lock().await;
    let t = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(t.path()).unwrap();
    let root = base.join("Inumaki");
    let src = base.join("src-many");
    for d in 0..20 {
        let dir = src.join(format!("d{d}"));
        std::fs::create_dir_all(&dir).unwrap();
        for f in 0..100 {
            std::fs::write(
                dir.join(format!("f{f}.txt")),
                format!("Notiz {d}-{f}: Termin am Donnerstag, bitte zurueckrufen.\n"),
            )
            .unwrap();
        }
    }
    let first = serve_on(&base, &root).await;
    let c = &first.client;
    let r = c
        .call(
            Method::POST,
            "/v1/datasets",
            Some(&json!({"id": "many", "name": "M", "profile": "offline", "kind": "folder"})),
        )
        .await
        .unwrap();
    assert_eq!(r.status.as_u16(), 201);
    let r = c
        .call(
            Method::POST,
            "/v1/datasets/many/folder",
            Some(&json!({"source": src})),
        )
        .await
        .unwrap();
    assert_eq!(r.status.as_u16(), 201);
    let scan_started = Instant::now();
    let until = Instant::now() + Duration::from_secs(600);
    loop {
        let r = c.call(Method::GET, "/v1/folders", None).await.unwrap();
        let f = &r.body["folders"][0];
        if idle(f) && f["files"]["mirrored"] == 2000 {
            break;
        }
        assert!(Instant::now() < until, "the scan did not finish");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let scan = scan_started.elapsed();
    first.stop().await;
    let second = serve_on(&base, &root).await;
    println!(
        "STARTUP 2000 files: AppState::start {} ms, until the socket answered {} ms (first scan took {} s)",
        second.start.as_millis(),
        second.ready.as_millis(),
        scan.as_secs()
    );
    second.stop().await;
}
