//! `inumaki mail-tasks` end to end: a real daemon, the scripted fake IMAP
//! server as the test mailbox, the runner playing the agent through the
//! dataset's gateway. Nothing here touches a real mailbox.
//!
//! The daemon harness is a small copy of the one in `daemon_cli.rs` (a test
//! target cannot import another's helpers), with the same
//! `start_with_base(tag, base, extra)` shape: the base config is edited by the
//! caller (dictionaries) and the one `[gateway]` table is written once.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use assert_cmd::Command;
use inumaki_eval::mail_fixture::{
    DEFAULT_FIXTURE_SEED, DictionaryLists, FixtureMail, FixtureOptions, dictionary_lists,
    fixture_digest, generate_mailbox,
};
use inumaki_mail::fake::{FakeImap, FakeState};
use predicates::prelude::*;

const BASE_CONFIG: &str = include_str!("../../../configs/default.toml");
const CANARY_PASSWORD: &str = "hunter2-canary";

struct Daemon {
    dir: tempfile::TempDir,
    socket: PathBuf,
    child: Child,
}

/// An empty data directory shared by every CLI process in this file, so a real
/// `<data dir>/inumaki.toml` or socket on the machine never changes what a
/// command loads. A test that needs a particular directory passes `--data-dir`,
/// which wins over the environment.
fn isolated_data_dir() -> &'static Path {
    static DATA_DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    DATA_DIR.get_or_init(|| tempfile::tempdir().unwrap()).path()
}

fn std_bin() -> std::process::Command {
    let mut c = std::process::Command::new(assert_cmd::cargo::cargo_bin("inumaki"));
    c.env("INUMAKI_DATA_DIR", isolated_data_dir());
    c
}

/// A socket path short enough for macOS (104 bytes): keep the tag short.
fn short_socket(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "inumaki-mt-{}-{nanos}-{tag}.sock",
        std::process::id()
    ))
}

fn start_with_base(tag: &str, base: &str, extra_toml: &str) -> Daemon {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("inumaki.toml");
    std::fs::write(
        &cfg,
        format!(
            "{base}\n[daemon]\ndefault_profile = \"offline\"\n[vault]\nkey_source = \"file\"\n[gateway]\nlisten = \"127.0.0.1:0\"\n[proxy]\nlisten = \"127.0.0.1:0\"\n{extra_toml}\n[mirror]\nroot = \"{d}/mirror-root\"\noutbox_root = \"{d}/mirror-outbox\"\n",
            d = dir.path().display()
        ),
    )
    .unwrap();
    let models = dir.path().join("no-models");
    std::fs::create_dir_all(&models).unwrap();
    let socket = short_socket(tag);
    let log = std::fs::File::create(dir.path().join("daemon.log")).unwrap();
    let child = std_bin()
        .args(["daemon", "--config"])
        .arg(&cfg)
        .arg("--data-dir")
        .arg(dir.path().join("data"))
        .arg("--socket")
        .arg(&socket)
        .arg("--models-dir")
        .arg(&models)
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if std::os::unix::net::UnixStream::connect(&socket).is_ok() {
            return Daemon { dir, socket, child };
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut child = child;
    let _ = child.kill();
    let _ = child.wait();
    panic!(
        "daemon did not start; log: {}",
        std::fs::read_to_string(dir.path().join("daemon.log")).unwrap_or_default()
    );
}

impl Daemon {
    fn cli(&self) -> Command {
        let mut c = Command::cargo_bin("inumaki").unwrap();
        c.env("INUMAKI_DATA_DIR", isolated_data_dir());
        c.arg("--socket").arg(&self.socket);
        c
    }

    fn term(&self) {
        std::process::Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .unwrap();
    }

    fn wait(mut self, within: Duration) -> std::process::ExitStatus {
        let deadline = Instant::now() + within;
        loop {
            if let Some(st) = self.child.try_wait().unwrap() {
                return st;
            }
            assert!(
                Instant::now() < deadline,
                "daemon did not exit; log: {}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("daemon.log")).unwrap_or_default()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket);
    }
}

fn secret_file(dir: &Path, name: &str, contents: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, contents).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    p
}

/// The runner's arguments for the fake mailbox at `port`.
fn runner_args(port: &str, pw: &Path, more: &[&str]) -> Vec<std::ffi::OsString> {
    let mut a: Vec<std::ffi::OsString> = [
        "mail-tasks",
        "--dataset",
        "mt",
        "--imap-host",
        "127.0.0.1",
        "--imap-port",
        port,
        "--imap-plaintext-loopback",
        "--user",
        "agent",
        "--password-file",
    ]
    .iter()
    .map(Into::into)
    .collect();
    a.push(pw.into());
    a.extend(more.iter().map(Into::into));
    a
}

fn outcome_counters(r: &serde_json::Value) -> u64 {
    [
        "completed",
        "search_blocked",
        "search_miss",
        "read_blocked",
        "read_residue",
        "draft_failed",
        "draft_missing",
        "wrong_recipient",
        "wrong_thread",
        "wrong_restoration",
        "unresolved_tokens",
        "unresolved_token",
        "privacy_block",
        "mail_error",
    ]
    .iter()
    .map(|k| {
        r[*k]
            .as_u64()
            .unwrap_or_else(|| panic!("counter {k} in {r}"))
    })
    .sum()
}

/// A daemon with a mailbox dataset `mt` over a scripted fake IMAP server,
/// the offline profile reading dictionaries built from the fixtures.
struct Rig {
    rt: tokio::runtime::Runtime,
    fake: FakeImap,
    port: String,
    d: Daemon,
    mails: Vec<FixtureMail>,
    lists: DictionaryLists,
    dict: tempfile::TempDir,
    pw: PathBuf,
}

fn rig(tag: &str, count: usize) -> Rig {
    rig_seed(tag, count, DEFAULT_FIXTURE_SEED)
}

fn rig_seed(tag: &str, count: usize, seed: u64) -> Rig {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let fake = rt.block_on(FakeImap::start(FakeState::new("agent", CANARY_PASSWORD)));
    let port = fake.port().to_string();
    // dictionaries from the fixtures so the offline profile detects them
    let mails = generate_mailbox(&FixtureOptions {
        count,
        seed,
        ..FixtureOptions::default()
    });
    let lists = dictionary_lists(&mails);
    let dict = tempfile::tempdir().unwrap();
    let write_list = |name: &str, items: &[String]| {
        let p = dict.path().join(name);
        std::fs::write(&p, items.join("\n") + "\n").unwrap();
        p
    };
    let persons = write_list("persons.txt", &lists.persons);
    let addresses = write_list("addresses.txt", &lists.addresses);
    let orgs = write_list("organizations.txt", &lists.organizations);
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
    let d = start_with_base(tag, &base, "[mail]\ncommand_timeout = \"5s\"\n");
    let pw = secret_file(dict.path(), "pw", &format!("{CANARY_PASSWORD}\n"));
    d.cli()
        .args([
            "dataset",
            "add-mailbox",
            "mt",
            "--profile",
            "offline",
            "--preset",
            "generic",
            "--user",
            "agent",
            "--imap-host",
            "127.0.0.1",
            "--imap-port",
            &port,
            "--imap-plaintext-loopback",
            "--from-address",
            "agent@example.test",
            "--password-file",
        ])
        .arg(&pw)
        .assert()
        .success();
    Rig {
        rt,
        fake,
        port,
        d,
        mails,
        lists,
        dict,
        pw,
    }
}

#[test]
fn mail_tasks_runner_seeds_drives_reports_and_wipes() {
    let Rig {
        rt,
        fake,
        port,
        d,
        mails,
        lists,
        dict,
        pw,
    } = rig("mt", 5);

    // first run
    let report_path = dict.path().join("report.json");
    let out = d
        .cli()
        .args(runner_args(
            &port,
            &pw,
            &["--count", "5", "--seed", "4711", "--report-json"],
        ))
        .arg(&report_path)
        .output()
        .unwrap();
    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(out.status.success(), "{stdout}{stderr}");
    assert!(
        stdout.contains("tasks 5") && stdout.contains("wrong_recipient 0"),
        "{stdout}"
    );
    let report_text = std::fs::read_to_string(&report_path).unwrap();
    let r: serde_json::Value = serde_json::from_str(&report_text).unwrap();

    // the password and the fixture's identifiers reach no stream, no report, no daemon log
    let log = d.log();
    for (what, text) in [
        ("stdout", stdout.as_ref()),
        ("stderr", stderr.as_ref()),
        ("report", report_text.as_str()),
        ("daemon log", log.as_str()),
    ] {
        assert!(!text.contains(CANARY_PASSWORD), "password canary in {what}");
        let emails = mails
            .iter()
            .flat_map(|m| [Some(&m.from_address), m.reply_to.as_ref()])
            .flatten();
        for secret in lists
            .persons
            .iter()
            .chain(&lists.addresses)
            .chain(&lists.organizations)
            .chain(emails)
        {
            assert!(!text.contains(secret.as_str()), "a fixture value in {what}");
        }
    }

    // the frozen report shape, on the real output
    assert_eq!(r["tasks"], 5);
    assert_eq!(r["seed"], 4711);
    assert_eq!(r["count"], 5);
    assert_eq!(r["family"], "tuning");
    assert_eq!(r["dataset"], "mt");
    assert_eq!(
        r["fixture_digest"],
        fixture_digest(&mails),
        "the digest pins the seeded bytes"
    );
    assert!(
        r["interventions"].is_null(),
        "a scripted run does not measure interventions: {r}"
    );
    assert!(
        r["provenance"]["daemon_version"]
            .as_str()
            .is_some_and(|v| !v.is_empty()),
        "{r}"
    );
    assert_eq!(r["provenance"]["profile"], "offline");
    assert!(r["provenance"]["models"].is_array());
    assert!(r["provenance"]["config_fingerprint"].is_null());
    assert_eq!(r["gate"]["target"], 0.9);
    assert_eq!(
        outcome_counters(&r),
        5,
        "every task has exactly one outcome: {r}"
    );
    assert_eq!(r["per_task"].as_array().unwrap().len(), 5);
    // the mailbox answered, the gateway let the dictionaries' mails through, and nothing was misaddressed
    for k in [
        "search_blocked",
        "search_miss",
        "wrong_recipient",
        "wrong_thread",
        "unresolved_tokens",
        "unresolved_token",
        "mail_error",
    ] {
        assert_eq!(r[k], 0, "{k}: {r}");
    }
    // The exact outcome of the pinned run (seed 4711, 5 mails, offline profile with the
    // fixtures' dictionaries): all five complete. The mail at index 2 carries a card number
    // wrapped across a line; the engine used to miss it (the leak check blocked the read with
    // `privacy_block`), and since plan 4a's line-wrap detection it is tokenized.
    assert_eq!(r["per_task"][2]["outcome"], "completed", "{r}");
    assert_eq!(r["privacy_block"], 0, "{r}");
    let completed = r["completed"].as_u64().unwrap();
    assert_eq!(completed, 5, "{r}");
    assert_eq!(r["gate"]["pass"], true, "5 of 5 meets the 90 % gate: {r}");
    {
        let st = fake.state();
        let st = st.lock().unwrap();
        assert_eq!(st.folders["INBOX"].messages.len(), 5, "seeded");
        let drafts = st
            .folders
            .get("Drafts")
            .map(|f| f.messages.len())
            .unwrap_or(0) as u64;
        assert_eq!(
            drafts,
            completed + r["wrong_restoration"].as_u64().unwrap(),
            "one draft per task that reached the draft step; residue and blocked tasks never do"
        );
    }

    // a second run wipes and reseeds instead of piling up, with a stray draft in the way
    {
        let st = fake.state();
        let mut st = st.lock().unwrap();
        let raw = st.folders["INBOX"].messages[0].raw.clone();
        st.add("Drafts", &raw);
    }
    let report2 = dict.path().join("report2.json");
    let code = d
        .cli()
        .args(runner_args(
            &port,
            &pw,
            &[
                "--count",
                "5",
                "--seed",
                "4711",
                "--require-gate",
                "--report-json",
            ],
        ))
        .arg(&report2)
        .output()
        .unwrap()
        .status
        .code();
    let r2: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report2).unwrap()).unwrap();
    assert_eq!(
        code,
        Some(if r2["gate"]["pass"] == true { 0 } else { 5 }),
        "--require-gate exits 5 exactly when the gate is missed: {r2}"
    );
    assert_eq!(
        r2["fixture_digest"], r["fixture_digest"],
        "same seed, same mailbox"
    );
    assert_eq!(
        r2["completed"], r["completed"],
        "the stray draft changed nothing"
    );
    {
        let st = fake.state();
        let st = st.lock().unwrap();
        assert_eq!(
            st.folders["INBOX"].messages.len(),
            5,
            "wiped and reseeded, not doubled"
        );
        let drafts = st
            .folders
            .get("Drafts")
            .map(|f| f.messages.len())
            .unwrap_or(0) as u64;
        assert_eq!(
            drafts,
            r2["completed"].as_u64().unwrap() + r2["wrong_restoration"].as_u64().unwrap(),
            "the stray draft was wiped"
        );
    }

    // a remote host is refused without --allow-remote, before anything is touched
    d.cli()
        .args([
            "mail-tasks",
            "--dataset",
            "mt",
            "--imap-host",
            "imap.example.test",
            "--imap-port",
            "993",
            "--user",
            "agent",
            "--password-file",
        ])
        .arg(&pw)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--allow-remote"))
        .stderr(predicate::str::contains("imap.example.test").not());
    // the drafts folder is wiped too: never the INBOX, and never another account's mailbox
    d.cli()
        .args(runner_args(&port, &pw, &["--drafts-folder", "inbox"]))
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--drafts-folder"));
    let mut other_user = runner_args(&port, &pw, &[]);
    let at = other_user.iter().position(|x| x == "agent").unwrap();
    other_user[at] = "someone-else".into();
    d.cli()
        .args(other_user)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("different login than --user"))
        .stderr(predicate::str::contains("someone-else").not());
    // a mailbox the dataset does not read is refused rather than wiped
    let other = (fake.port() as u32 + 1).to_string();
    d.cli()
        .args(runner_args(&other, &pw, &["--count", "5"]))
        .assert()
        .code(2)
        .stderr(predicate::str::contains("different IMAP host or port"));
    // a password file others can read is refused
    let loose = dict.path().join("loose");
    std::fs::write(&loose, CANARY_PASSWORD).unwrap();
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).unwrap();
    d.cli()
        .args(runner_args(&port, &loose, &[]))
        .assert()
        .code(2)
        .stderr(predicate::str::contains("chmod 600"))
        .stderr(predicate::str::contains(CANARY_PASSWORD).not());
    assert_eq!(
        fake.state().lock().unwrap().folders["INBOX"].messages.len(),
        5
    );
    d.term();
    assert!(d.wait(Duration::from_secs(10)).success());
    drop(fake);
    drop(rt);
}

#[test]
fn an_unknown_family_and_a_missing_mailbox_are_usage_errors() {
    let d = start_with_base("mf", BASE_CONFIG, "");
    let dir = tempfile::tempdir().unwrap();
    let pw = secret_file(dir.path(), "pw", CANARY_PASSWORD);
    // --family is an enum: clap rejects anything else
    d.cli()
        .args(runner_args("1143", &pw, &["--family", "other"]))
        .assert()
        .code(2);
    // a dataset without a mailbox is refused with the next step named
    d.cli()
        .args(["dataset", "add", "plain", "--name", "Plain"])
        .assert()
        .success();
    d.cli()
        .args([
            "mail-tasks",
            "--dataset",
            "plain",
            "--imap-host",
            "127.0.0.1",
            "--imap-port",
            "1143",
            "--imap-plaintext-loopback",
            "--user",
            "agent",
            "--password-file",
        ])
        .arg(&pw)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("add-mailbox"))
        .stderr(predicate::str::contains(CANARY_PASSWORD).not());
}

/// The Reply-To path end to end: with seed 1 the three mails (index 2 carries
/// a Reply-To) all complete through the gateway, and the stored draft for
/// index 2 goes to the Reply-To address, not to the sender.
#[test]
fn the_reply_to_fixture_completes_and_the_draft_goes_to_its_address() {
    let r = rig_seed("rt", 3, 1);
    let report = r.dict.path().join("report.json");
    let out =
        r.d.cli()
            .args(runner_args(
                &r.port,
                &r.pw,
                &[
                    "--count",
                    "3",
                    "--seed",
                    "1",
                    "--require-gate",
                    "--report-json",
                ],
            ))
            .arg(&report)
            .output()
            .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report).unwrap()).unwrap();
    assert_eq!(v["completed"], 3, "{v}");
    assert_eq!(v["gate"]["pass"], true, "{v}");
    assert_eq!(v["per_task"][2]["outcome"], "completed", "{v}");
    let m = &r.mails[2];
    let reply_to = m
        .reply_to
        .as_deref()
        .expect("every third mail has a Reply-To");
    let st = r.fake.state();
    let st = st.lock().unwrap();
    let drafts: Vec<_> = st.folders["Drafts"]
        .messages
        .iter()
        .filter_map(|d| inumaki_mail::render::parse_message(&d.raw))
        .filter(|p| p.in_reply_to.as_deref() == Some(m.message_id.as_str()))
        .collect();
    assert_eq!(drafts.len(), 1, "one draft replies to the Reply-To mail");
    let to: Vec<_> = drafts[0]
        .to
        .iter()
        .filter_map(|a| a.address.as_deref())
        .collect();
    assert_eq!(to, [reply_to], "the draft goes to the Reply-To address");
    assert_ne!(to[0], m.from_address);
}
