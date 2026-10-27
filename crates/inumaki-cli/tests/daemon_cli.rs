//! `inumaki daemon` end to end: start as a child process, drive it over the
//! socket with the CLI, stop it with SIGTERM.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use assert_cmd::Command;
use predicates::prelude::*;

const BASE_CONFIG: &str = include_str!("../../../configs/default.toml");

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

/// The CLI binary as an `assert_cmd` command (for `.write_stdin()` and `.assert()`).
fn bin() -> Command {
    let mut c = Command::cargo_bin("inumaki").unwrap();
    c.env("INUMAKI_DATA_DIR", isolated_data_dir());
    c
}

/// The CLI binary as a plain `std::process::Command` (for a long-running child).
fn std_bin() -> std::process::Command {
    let mut c = std::process::Command::new(assert_cmd::cargo::cargo_bin("inumaki"));
    c.env("INUMAKI_DATA_DIR", isolated_data_dir());
    c
}

fn short_socket(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "inumaki-cli-{}-{nanos}-{tag}.sock",
        std::process::id()
    ))
}

fn start_with(tag: &str, extra_toml: &str) -> Daemon {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    start_in(dir, tag, extra_toml, &data)
}

/// Start with the data directory at `data_dir` (which outlives `dir`, so a
/// test can stop the daemon and copy the vault files it wrote).
fn start_in(dir: tempfile::TempDir, tag: &str, extra_toml: &str, data_dir: &Path) -> Daemon {
    match try_start_in(dir, tag, extra_toml, data_dir) {
        Ok(d) => d,
        Err(log) => panic!("daemon did not start; log: {log}"),
    }
}

/// `Err(log)` when the daemon does not answer on its socket in time.
fn try_start_in(
    dir: tempfile::TempDir,
    tag: &str,
    extra_toml: &str,
    data_dir: &Path,
) -> Result<Daemon, String> {
    let cfg = dir.path().join("inumaki.toml");
    std::fs::write(
        &cfg,
        format!(
            "{BASE_CONFIG}\n[daemon]\ndefault_profile = \"offline\"\n[vault]\nkey_source = \"file\"\n[gateway]\nlisten = \"127.0.0.1:0\"\n[proxy]\nlisten = \"127.0.0.1:0\"\n{extra_toml}\n[mirror]\nroot = \"{d}/mirror-root\"\noutbox_root = \"{d}/mirror-outbox\"\n",
            d = dir.path().display()
        ),
    )
    .unwrap();
    let models = dir.path().join("no-models");
    std::fs::create_dir_all(&models).unwrap();
    let socket = short_socket(tag);
    let log = std::fs::File::create(dir.path().join("daemon.log")).unwrap();
    let mut child = std_bin()
        .args(["daemon", "--config"])
        .arg(&cfg)
        .arg("--data-dir")
        .arg(data_dir)
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
            return Ok(Daemon { dir, socket, child });
        }
        if child.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // Reap the child before returning: `Child`'s own `Drop` does not wait
    // (clippy::zombie_processes).
    let _ = child.kill();
    let _ = child.wait();
    Err(std::fs::read_to_string(dir.path().join("daemon.log")).unwrap_or_default())
}

fn start(tag: &str) -> Daemon {
    start_with(tag, "")
}

impl Daemon {
    fn cli(&self) -> Command {
        let mut c = bin();
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

fn data_dir(d: &Daemon) -> &Path {
    d.dir.path()
}

#[test]
fn daemon_starts_and_answers_status() {
    let d = start("status");
    d.cli()
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("offline"))
        .stdout(predicate::str::contains("available"))
        .stdout(predicate::str::contains("support-email"))
        .stdout(predicate::str::contains("inumaki models pull"))
        .stdout(predicate::str::is_match(r"(?m)^config     /.*inumaki\.toml$").unwrap());
    let out = d
        .cli()
        .args(["status", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["key_source"], "file");
    assert!(data_dir(&d).join("data").join("vault.sqlite").exists());
    d.term();
    assert!(d.wait(Duration::from_secs(10)).success());
}

#[test]
fn dataset_sanitize_rehydrate_round_trip_and_exit_codes() {
    let d = start("roundtrip");
    d.cli()
        .args(["dataset", "add", "mail", "--name", "Musterkunde GmbH"])
        .assert()
        .success()
        .stdout(predicate::str::contains("mail"));
    d.cli()
        .args(["dataset", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("mail"))
        .stdout(predicate::str::contains("offline"));
    let text = "IBAN AT61 1904 3002 3457 3201 bitte";
    let out = d
        .cli()
        .args(["sanitize", "--dataset", "mail", "-"])
        .write_stdin(text)
        .assert()
        .success()
        .stdout(predicate::str::contains("<IBAN_"))
        .stdout(predicate::str::contains("AT61").not())
        .get_output()
        .stdout
        .clone();
    let sanitized = String::from_utf8(out).unwrap();
    let again = d
        .cli()
        .args(["sanitize", "--dataset", "mail", "-"])
        .write_stdin(text)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(
        String::from_utf8(again).unwrap(),
        sanitized,
        "same namespace, same token"
    );
    d.cli()
        .args(["rehydrate", "--dataset", "mail", "-"])
        .write_stdin(sanitized.clone())
        .assert()
        .success()
        .stdout(predicate::eq(text))
        .stderr(predicate::str::is_empty());
    d.cli()
        .args(["rehydrate", "--dataset", "mail", "-"])
        .write_stdin("<IBAN_000000> und <PERSON_000000>")
        .assert()
        .success()
        .stderr(predicate::str::contains("unknown tokens: 2"));
    // sessions use 4-hex suffixes and are independent of datasets
    let s = d
        .cli()
        .args(["sanitize", "--session", "s1", "-"])
        .write_stdin(text)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8(s).unwrap();
    let tok = s
        .split_whitespace()
        .find(|w| w.starts_with("<IBAN_"))
        .unwrap();
    assert_eq!(tok.len(), "<IBAN_".len() + 4 + 1, "{tok}");
    d.cli()
        .args(["dataset", "rotate", "mail"])
        .assert()
        .success()
        .stdout(predicate::str::contains("epoch"));
    d.cli()
        .args(["dataset", "remove", "mail"])
        .assert()
        .success();
    d.cli()
        .args(["sanitize", "--dataset", "mail", "-"])
        .write_stdin(text)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not_found"));
    // exactly one of --dataset/--session
    d.cli()
        .args(["sanitize", "-"])
        .write_stdin("x")
        .assert()
        .code(2);
    d.term();
    assert!(d.wait(Duration::from_secs(10)).success());
}

#[test]
fn strict_rehydrate_exits_3_with_empty_stdout_and_missing_session_is_2() {
    let d = start("strict");
    d.cli()
        .args(["dataset", "add", "mail", "--name", "M"])
        .assert()
        .success();
    let out = d
        .cli()
        .args(["sanitize", "--dataset", "mail", "-"])
        .write_stdin("IBAN AT61 1904 3002 3457 3201 bitte")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let sanitized = String::from_utf8(out).unwrap();
    d.cli()
        .args(["rehydrate", "--strict", "--dataset", "mail", "-"])
        .write_stdin(sanitized.clone())
        .assert()
        .success()
        .stdout(predicate::eq("IBAN AT61 1904 3002 3457 3201 bitte"));
    d.cli()
        .args(["rehydrate", "--strict", "--dataset", "mail", "-"])
        .write_stdin(format!("{sanitized} <PERSON_000000> <SECRET_REMOVED>"))
        .assert()
        .code(3)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains(
            "unresolved tokens: unknown=1 removed=1",
        ))
        .stderr(predicate::str::contains("AT61").not());
    d.cli()
        .args(["rehydrate", "--strict", "--session", "never-created", "-"])
        .write_stdin("<IBAN_0000>")
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("context_unavailable"));
    d.term();
    assert!(d.wait(Duration::from_secs(10)).success());
}

#[test]
fn blocked_sanitize_exits_3_without_values() {
    // `verifier.retry_profile = "blocky"` (self-reference) disables the
    // automatic retry pass (`Engine::from_config` treats a retry profile
    // equal to its own name as "no retry"); without it the pipeline would
    // retry into the inherited `offline-strict`, which does not carry this
    // profile's IBAN override, and the block would not stick.
    let d = start_with(
        "blocked",
        "[profiles.blocky]\nextends = \"offline\"\n[profiles.blocky.verifier]\nretry_profile = \"blocky\"\n[profiles.blocky.entities]\nIBAN = { action = \"block\", min_confidence = 0.0 }\n",
    );
    d.cli()
        .args(["sanitize", "--session", "s", "--profile", "blocky", "-"])
        .write_stdin("IBAN AT61 1904 3002 3457 3201")
        .assert()
        .code(3)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains(
            "blocked: kinds=IBAN checks=Policy",
        ))
        .stderr(predicate::str::contains("AT61").not());
    d.term();
    assert!(d.wait(Duration::from_secs(10)).success());
}

#[test]
fn no_daemon_is_exit_2_with_a_hint() {
    let socket = short_socket("none");
    bin()
        .arg("--socket")
        .arg(&socket)
        .arg("status")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("inumaki daemon"));
}

/// L82 (1): without `--config` the CLI reads `<data dir>/inumaki.toml`, the
/// file the daemon reads, so it dials the socket that file names; `--config`
/// still wins; a present but invalid file fails the command (exit 2) and
/// names the file, never its text.
#[test]
fn the_cli_reads_the_data_dir_config_and_refuses_an_invalid_one() {
    let data = tempfile::tempdir().unwrap();
    let cfg = data.path().join("inumaki.toml");
    std::fs::write(
        &cfg,
        format!("{BASE_CONFIG}\n[daemon]\nsocket = \"from-data-dir.sock\"\n"),
    )
    .unwrap();
    bin()
        .arg("--data-dir")
        .arg(data.path())
        .arg("status")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("from-data-dir.sock"));

    let other = tempfile::tempdir().unwrap();
    let explicit = other.path().join("explicit.toml");
    std::fs::write(
        &explicit,
        format!("{BASE_CONFIG}\n[daemon]\nsocket = \"from-flag.sock\"\n"),
    )
    .unwrap();
    bin()
        .arg("--data-dir")
        .arg(data.path())
        .arg("--config")
        .arg(&explicit)
        .arg("status")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("from-flag.sock"))
        .stderr(predicate::str::contains("from-data-dir.sock").not());

    std::fs::write(
        &cfg,
        format!("{BASE_CONFIG}\n[daemon]\nsocket_path = \"qwxzvk.sock\"\n"),
    )
    .unwrap();
    bin()
        .arg("--data-dir")
        .arg(data.path())
        .arg("status")
        .assert()
        .code(2)
        .stderr(predicate::str::contains(format!(
            "config file {}",
            cfg.display()
        )))
        .stderr(predicate::str::contains(
            "daemon table: unknown key `socket_path`",
        ))
        .stderr(predicate::str::contains("qwxzvk").not());
}

#[test]
fn daemon_start_errors_exit_2() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::write(data.join("vault.sqlite"), b"not a database").unwrap();
    bin()
        .args(["daemon", "--data-dir"])
        .arg(&data)
        .arg("--socket")
        .arg(short_socket("bad"))
        .assert()
        .code(2)
        .stderr(predicate::str::contains("vault"));
}

/// The gateway listener is bound after the control socket: when its port
/// is taken the daemon exits 2 and leaves no socket file behind.
#[test]
fn a_taken_gateway_port_exits_2_without_a_socket_file() {
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = taken.local_addr().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("inumaki.toml");
    std::fs::write(
        &cfg,
        format!(
            "{BASE_CONFIG}\n[daemon]\ndefault_profile = \"offline\"\n[vault]\nkey_source = \"file\"\n[gateway]\nlisten = \"{addr}\"\n[proxy]\nlisten = \"127.0.0.1:0\"\n[mirror]\nroot = \"{d}/mirror-root\"\noutbox_root = \"{d}/mirror-outbox\"\n",
            d = dir.path().display()
        ),
    )
    .unwrap();
    let models = dir.path().join("no-models");
    std::fs::create_dir_all(&models).unwrap();
    let socket = short_socket("taken");
    bin()
        .args(["daemon", "--config"])
        .arg(&cfg)
        .arg("--data-dir")
        .arg(dir.path().join("data"))
        .arg("--socket")
        .arg(&socket)
        .arg("--models-dir")
        .arg(&models)
        .timeout(Duration::from_secs(30))
        .assert()
        .code(2);
    assert!(!socket.exists(), "socket file removed");
    drop(taken);
}

/// Review Focus 7: SIGTERM lets an in-flight request finish and the socket
/// file is removed. The test proves "the request never fails and the socket
/// is gone". The text (about 1.3 MB, roughly 1.5 s to sanitize in a debug
/// build) is sized to still be in flight when the signal lands shortly after
/// the client has sent it (not after a fixed delay from the spawn, which a
/// loaded machine outruns), and to finish well inside `SHUTDOWN_GRACE` (5 s) even on a loaded
/// machine; a 5 MB text took about 5.4 s alone and raced the grace period.
#[test]
fn daemon_finishes_inflight_request_on_sigterm() {
    let d = start("sigterm");
    let socket = d.socket.clone();
    let text = format!("Konto AT61 1904 3002 3457 3201 {}", "wort ".repeat(250_000));
    // The CLI reads all of stdin before it connects, and the text is far
    // larger than a pipe buffer: once `write_all` has returned, the client is
    // running and about to send, however slow the process start was on a
    // loaded machine. The signal lands a short time after that, while the
    // daemon is still sanitizing.
    let (written_tx, written_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        use std::io::Write;
        let mut c = std_bin();
        c.arg("--socket").arg(&socket);
        c.args(["sanitize", "--session", "s", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = c.spawn().unwrap();
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(text.as_bytes()).unwrap();
        drop(stdin);
        written_tx.send(()).unwrap();
        child.wait_with_output().unwrap()
    });
    written_rx.recv().unwrap();
    std::thread::sleep(Duration::from_millis(150));
    d.term();
    let out = worker.join().unwrap();
    assert!(
        out.status.success(),
        "in-flight request finished: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("<IBAN_"));
    let socket = d.socket.clone();
    let status = d.wait(Duration::from_secs(10));
    assert!(status.success());
    assert!(!socket.exists(), "socket file removed on shutdown");
}

#[test]
fn bench_via_daemon_reports_cold_and_warm_passes() {
    let d = start("bench");
    let out = d
        .cli()
        .args(["bench", "--via-daemon", "--generate", "15"])
        .assert()
        .success()
        .stdout(predicate::str::contains("cold "))
        .stdout(predicate::str::contains("warm "))
        .get_output()
        .stdout
        .clone();
    let out = String::from_utf8(out).unwrap();
    let line = out
        .lines()
        .find(|l| l.starts_with("warm cache hits "))
        .expect("hits line");
    let nums = line
        .trim_start_matches("warm cache hits ")
        .split_whitespace()
        .next()
        .unwrap();
    let (hits, total) = nums.split_once('/').unwrap();
    let (hits, total): (usize, usize) = (hits.parse().unwrap(), total.parse().unwrap());
    // Task 7c: a mail cached on the cold pass before a later mail minted a
    // value it carries in clear (seed 42: the first mail's company surname)
    // is a miss on the warm pass and sanitized fresh; its store-linked
    // result is never cached (plan 4a decision 7). Every other non-blocked
    // mail is a hit.
    assert!(
        total > 1 && total - hits <= 1,
        "every non-blocked document but the store-linked one is a cache hit on the warm pass: {line}"
    );
    d.cli()
        .args(["dataset", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("bench-").not());
    d.term();
    assert!(d.wait(Duration::from_secs(10)).success());
}

#[test]
fn inspect_prints_metadata_and_refuses_show_values_off_a_tty() {
    let d = start("inspect");
    d.cli()
        .args(["dataset", "add", "mail", "--name", "M"])
        .assert()
        .success();
    d.cli()
        .args(["inspect", "--dataset", "mail", "-"])
        .write_stdin("IBAN AT61 1904 3002 3457 3201 bitte")
        .assert()
        .success()
        .stdout(predicate::str::contains("local diagnostic output"))
        .stdout(predicate::str::contains("IBAN"))
        .stdout(predicate::str::contains("tokenize"))
        .stdout(predicate::str::contains("AT61").not());
    d.cli()
        .args(["inspect", "--dataset", "mail", "--show-values", "-"])
        .write_stdin("IBAN AT61 1904 3002 3457 3201 bitte")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("terminal"));
    let dir = tempfile::tempdir().unwrap();
    let text = "Bitte an Sarah Leitner weiterleiten.";
    let digest = {
        use sha2::{Digest, Sha256};
        Sha256::digest(text.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    let red = dir.path().join("red.json");
    std::fs::write(
        &red,
        format!(
            "{{\"input_sha256\":\"{digest}\",\"spans\":[{{\"start\":9,\"end\":22,\"kind\":\"PERSON\",\"action\":\"tokenize\"}}]}}"
        ),
    )
    .unwrap();
    d.cli()
        .args(["sanitize", "--dataset", "mail", "--redactions"])
        .arg(&red)
        .arg("-")
        .write_stdin(text)
        .assert()
        .success()
        .stdout(predicate::str::contains("Bitte an <PERSON_"))
        .stdout(predicate::str::contains("Sarah").not());
    d.term();
    assert!(d.wait(Duration::from_secs(10)).success());
}

#[test]
fn upstream_token_status_and_doctor_commands() {
    let d = start("m4cli");
    let dir = tempfile::tempdir().unwrap();
    let secret_file = dir.path().join("env.json");
    std::fs::write(&secret_file, "{\"TOKEN\":\"hunter2-canary\"}").unwrap();
    std::fs::set_permissions(&secret_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let policy = dir.path().join("policy.json");
    std::fs::write(
        &policy,
        include_str!("../../../docs/examples/scripted-upstream.policy.json"),
    )
    .unwrap();
    d.cli()
        .args(["dataset", "upstream", "add", "crm", "a", "--content-policy"])
        .arg(&policy)
        .args(["--secret-env-file"])
        .arg(&secret_file)
        .args(["--env", "PLAIN=1", "--stdio", "/bin/true"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "dataset crm created with profile strict",
        ))
        .stdout(predicate::str::contains("upstream a added"))
        .stdout(predicate::str::contains("hunter2").not());
    d.cli()
        .args(["dataset", "upstream", "list", "crm"])
        .assert()
        .success()
        .stdout(predicate::str::contains("a "))
        .stdout(predicate::str::contains("reviewed"))
        .stdout(predicate::str::contains("hunter2").not());
    d.cli()
        .args([
            "dataset",
            "upstream",
            "add",
            "crm",
            "b",
            "--http",
            "http://x",
            "--stdio",
            "/bin/true",
        ])
        .assert()
        .code(2);
    let out = d
        .cli()
        .args(["gateway", "token", "new", "claude-code"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let token = String::from_utf8(out).unwrap();
    assert!(token.trim().starts_with("inumaki-gw-"), "{token}");
    d.cli()
        .args(["gateway", "token", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("claude-code"))
        .stdout(predicate::str::contains(token.trim()).not());
    let out = d
        .cli()
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("gateway 127.0.0.1:"))
        .stdout(predicate::str::contains("Authorization: Bearer <token"))
        .get_output()
        .stdout
        .clone();
    // The suggested MCP server name is model-visible (Claude Code prefixes
    // it to every tool name): the opaque dataset label, never the slug.
    let out = String::from_utf8(out).unwrap();
    let connect = out
        .lines()
        .find(|l| l.starts_with("connect: server inumaki-"))
        .unwrap_or_else(|| panic!("{out}"));
    let server = connect.split_whitespace().nth(2).unwrap();
    let label = server.strip_prefix("inumaki-").unwrap();
    assert!(
        label.len() == 16 && label.bytes().all(|b| b.is_ascii_hexdigit()),
        "{connect}"
    );
    assert!(!server.contains("crm"), "{connect}");
    assert!(connect.contains("/mcp/crm "), "{connect}");
    assert!(
        connect.contains("Authorization: Bearer <token"),
        "{connect}"
    );
    assert!(!connect.contains("claude mcp add"), "{connect}");
    d.cli()
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "vault: keys from file, integrity ok",
        ))
        .stdout(predicate::str::is_match(r"(?m)^config: /.*inumaki\.toml$").unwrap())
        .stdout(predicate::str::contains("model gliner-x-small   missing"))
        .stdout(predicate::str::contains("upstream a"))
        .stdout(predicate::str::contains("contract ready"))
        .stdout(predicate::str::contains("next: model"))
        .stdout(predicate::str::contains("hunter2").not());
    d.cli()
        .args(["gateway", "token", "revoke", "1"])
        .assert()
        .success();
    d.cli()
        .args(["dataset", "upstream", "remove", "crm", "a"])
        .assert()
        .success();
    // I1: `--stdio` is the last flag, so child arguments that look like this
    // command's own flags (a leading-hyphen `-n`) still reach the child.
    d.cli()
        .args([
            "dataset",
            "upstream",
            "add",
            "crm",
            "c",
            "--stdio",
            "/bin/echo",
            "-n",
            "hello",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("upstream c added"));
    // I4: a secret file readable by group or others is refused, without
    // ever reading its content into a request.
    let loose = dir.path().join("loose.json");
    std::fs::write(&loose, "{\"TOKEN\":\"hunter2-canary\"}").unwrap();
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).unwrap();
    d.cli()
        .args([
            "dataset",
            "upstream",
            "add",
            "crm",
            "loose",
            "--secret-env-file",
        ])
        .arg(&loose)
        .args(["--stdio", "/bin/true"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("chmod 600"))
        .stderr(predicate::str::contains("hunter2").not());
    // I5: a malformed secrets file (a number instead of a string) fails with
    // a fixed message; the offending value never reaches stderr.
    let bad = dir.path().join("bad.json");
    std::fs::write(&bad, "{\"PIN\":123456}").unwrap();
    std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o600)).unwrap();
    d.cli()
        .args([
            "dataset",
            "upstream",
            "add",
            "crm",
            "bad",
            "--secret-env-file",
        ])
        .arg(&bad)
        .args(["--stdio", "/bin/true"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("must be a JSON object of strings"))
        .stderr(predicate::str::contains("123456").not());
    // M6: a non-secret `--header` whose name looks like a credential is
    // refused before anything is sent, pointing at `--secret-header`.
    d.cli()
        .args([
            "dataset",
            "upstream",
            "add",
            "crm",
            "creds",
            "--header",
            "Authorization=Bearer x",
            "--stdio",
            "/bin/true",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--secret-header"));
    // The same for `--env`: a credential-like name is refused before
    // anything is sent, pointing at `--secret-env`; the value is not echoed.
    d.cli()
        .args([
            "dataset",
            "upstream",
            "add",
            "envcreds",
            "gh",
            "--env",
            "GITHUB_TOKEN=ghp-canary-value",
            "--stdio",
            "/bin/true",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--secret-env"))
        .stderr(predicate::str::contains("ghp-canary-value").not());
    let listed = d
        .cli()
        .args(["dataset", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert!(
        !String::from_utf8_lossy(&listed).contains("envcreds"),
        "a refused upstream must not create its dataset"
    );
    d.term();
    assert!(d.wait(Duration::from_secs(10)).success());
}

#[test]
fn activity_lists_and_verifies_over_the_socket() {
    let d = start("activity");
    d.cli()
        .args(["activity", "--verify"])
        .assert()
        .success()
        .stdout(predicate::str::contains("activity chain ok: 0 records"));
    let out = d
        .cli()
        .args(["activity", "--json", "--since", "3600", "--limit", "5"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["records"], serde_json::json!([]));
    d.cli()
        .args(["activity", "--dataset", "Not&Valid"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("a-z, 0-9 and '-' only"));
    d.term();
    assert!(d.wait(Duration::from_secs(10)).success());
}

/// Review Focus 6: `journal show --show-values` off a terminal is refused
/// before the daemon is contacted; ids are checked before any request and
/// never echoed.
#[test]
fn journal_commands_list_show_and_refuse_values_off_a_tty() {
    let zeros = "0".repeat(32);
    // No daemon at this socket: the refusal comes first, not a connect error.
    bin()
        .arg("--socket")
        .arg(std::env::temp_dir().join("inumaki-cli-no-daemon.sock"))
        .args([
            "journal",
            "show",
            "--dataset",
            "crm",
            &zeros,
            "--show-values",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("terminal"))
        .stderr(predicate::str::contains("connect").not());
    let d = start("journal");
    d.cli()
        .args(["dataset", "add", "crm", "--name", "C"])
        .assert()
        .success();
    d.cli()
        .args(["journal", "list", "--dataset", "crm"])
        .assert()
        .success()
        .stdout(predicate::str::contains("no journal entries for crm"));
    d.cli()
        .args([
            "journal",
            "show",
            "--dataset",
            "crm",
            &zeros,
            "--show-values",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("terminal"));
    d.cli()
        .args(["journal", "show", "--dataset", "crm", &zeros])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not_found"));
    d.cli()
        .args(["journal", "show", "--dataset", "crm", "not-an-id"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("32 lowercase hex"))
        .stderr(predicate::str::contains("not-an-id").not());
    d.cli()
        .args(["journal", "list", "--dataset", "Not&Valid"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("a-z, 0-9 and '-' only"))
        .stderr(predicate::str::contains("Not&Valid").not());
    d.term();
    assert!(d.wait(Duration::from_secs(10)).success());
}

/// Task 5 (M4 spec §16.3): `dataset entities` lists tokens and metadata,
/// `dataset forget --token` removes one entity; Review Focus 6: the
/// originals need a terminal and a forget value never comes from argv.
#[test]
fn entities_and_forget_commands() {
    // No daemon at this socket: the refusals come first, not a connect error.
    let nowhere = std::env::temp_dir().join("inumaki-cli-no-daemon.sock");
    bin()
        .arg("--socket")
        .arg(&nowhere)
        .args(["dataset", "entities", "mail", "--show-values"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("terminal"))
        .stderr(predicate::str::contains("connect").not());
    bin()
        .arg("--socket")
        .arg(&nowhere)
        .args(["dataset", "entities", "Not&Valid"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("a-z, 0-9 and '-' only"))
        .stderr(predicate::str::contains("Not&Valid").not());
    let d = start("entities");
    d.cli()
        .args(["dataset", "add", "mail", "--name", "M"])
        .assert()
        .success();
    d.cli()
        .args(["dataset", "entities", "mail"])
        .assert()
        .success()
        .stdout(predicate::str::contains("no entities in mail"));
    d.cli()
        .args(["sanitize", "--dataset", "mail", "-"])
        .write_stdin("IBAN AT61 1904 3002 3457 3201 bitte")
        .assert()
        .success();
    d.cli()
        .args(["dataset", "entities", "mail"])
        .assert()
        .success()
        .stdout(predicate::str::contains("<IBAN_"))
        .stdout(predicate::str::contains("USES (store)"))
        .stdout(predicate::str::contains("AT61").not());
    d.cli()
        .args(["dataset", "entities", "mail", "--show-values"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("terminal"))
        .stdout(predicate::str::contains("AT61").not());
    // The value is never taken from the command line: clap refuses it
    // before any prompt or request, and the entity stays.
    for argv in [
        vec![
            "dataset",
            "forget",
            "mail",
            "--value",
            "AT61 1904 3002 3457 3201",
        ],
        vec![
            "dataset",
            "forget",
            "mail",
            "--value=AT61 1904 3002 3457 3201",
        ],
    ] {
        d.cli().args(&argv).assert().code(2);
    }
    let out = d
        .cli()
        .args(["dataset", "entities", "mail", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let body: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(body["entities"].as_array().unwrap().len(), 1, "{body}");
    let token = body["entities"][0]["token"].as_str().unwrap().to_string();
    assert!(token.starts_with("<IBAN_"), "{token}");
    assert!(body["entities"][0].get("original").is_none(), "{body}");
    d.cli()
        .args(["dataset", "forget", "mail", "--token", &token, "--value"])
        .assert()
        .code(2);
    d.cli()
        .args(["dataset", "forget", "mail", "--token", &token])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "forgot 1 entity in mail: kinds IBAN, 1 token(s)",
        ));
    d.cli()
        .args(["dataset", "entities", "mail"])
        .assert()
        .success()
        .stdout(predicate::str::contains("no entities in mail"));
    d.cli()
        .args(["dataset", "forget", "mail", "--token", &token])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not_found"));
    d.cli()
        .args(["dataset", "forget", "mail"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("exactly one"));
    assert!(!d.log().contains("AT61"), "{}", d.log());
    d.term();
    assert!(d.wait(Duration::from_secs(10)).success());
}

const DRILL_TEXT: &str = "Kundin Zyxwuria Quolnath, IBAN AT61 1904 3002 3457 3201, danke.";

fn copy_vault(from: &Path, to: &Path, with_key: bool) {
    std::fs::create_dir_all(to).unwrap();
    std::fs::copy(from.join("vault.sqlite"), to.join("vault.sqlite")).unwrap();
    if with_key {
        std::fs::copy(from.join("vault.key"), to.join("vault.key")).unwrap();
    }
}

/// docs/runbook.md: stop the daemon (it checkpoints the WAL), copy
/// `vault.sqlite` and `vault.key` into an isolated directory, start a daemon
/// there, and restore with `--strict`. Synthetic data only.
#[test]
fn restore_drill_into_an_isolated_directory() {
    let root = tempfile::tempdir().unwrap();
    let live = root.path().join("live");
    let a = start_in(tempfile::tempdir().unwrap(), "drill-a", "", &live);
    a.cli()
        .args(["dataset", "add", "drill", "--name", "Restore drill"])
        .assert()
        .success();
    let sanitized = String::from_utf8(
        a.cli()
            .args(["sanitize", "--dataset", "drill", "-"])
            .write_stdin(DRILL_TEXT)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert!(
        sanitized.contains("<IBAN_") && !sanitized.contains("AT61"),
        "{sanitized}"
    );
    a.term();
    assert!(a.wait(Duration::from_secs(10)).success());
    // A clean stop leaves nothing in the WAL: the copy of vault.sqlite is complete.
    let wal = live.join("vault.sqlite-wal");
    assert!(
        !wal.exists() || std::fs::metadata(&wal).unwrap().len() == 0,
        "WAL not checkpointed at shutdown"
    );
    assert!(
        live.join("vault.key").exists(),
        "file key source writes vault.key"
    );

    let restore = root.path().join("restore");
    copy_vault(&live, &restore, true);
    let b = start_in(tempfile::tempdir().unwrap(), "drill-b", "", &restore);
    b.cli()
        .args(["dataset", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("drill"));
    b.cli()
        .args(["rehydrate", "--strict", "--dataset", "drill", "-"])
        .write_stdin(sanitized.clone())
        .assert()
        .success()
        .stdout(predicate::eq(DRILL_TEXT));
    let out = b
        .cli()
        .args(["status", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["key_source"], "file");
    assert!(v["data_dir"].as_str().unwrap().ends_with("restore"));
    b.term();
    assert!(b.wait(Duration::from_secs(10)).success());
}

/// A copy of `vault.sqlite` without its key must not open: no fresh key is
/// accepted silently, the daemon exits 2, and the log names the error class only.
#[test]
fn restore_without_the_key_fails_closed() {
    let root = tempfile::tempdir().unwrap();
    let live = root.path().join("live");
    let a = start_in(tempfile::tempdir().unwrap(), "nokey-a", "", &live);
    a.cli()
        .args(["dataset", "add", "drill", "--name", "Restore drill"])
        .assert()
        .success();
    a.cli()
        .args(["sanitize", "--dataset", "drill", "-"])
        .write_stdin(DRILL_TEXT)
        .assert()
        .success();
    a.term();
    assert!(a.wait(Duration::from_secs(10)).success());

    let nokey = root.path().join("nokey");
    copy_vault(&live, &nokey, false);
    let log = match try_start_in(tempfile::tempdir().unwrap(), "nokey-b", "", &nokey) {
        Ok(_) => panic!("a vault copied without its key must not open"),
        Err(log) => log,
    };
    assert!(log.contains("failed to start"), "{log}");
    assert!(
        log.contains("do not belong to this vault"),
        "the error class names the keys: {log}"
    );
    assert!(!log.contains("AT61") && !log.contains("Quolnath"), "{log}");
    // Whatever the failed start left behind (it may have generated a key file
    // while looking for one), the real key still opens the copy.
    let _ = std::fs::remove_file(nokey.join("vault.key"));
    std::fs::copy(live.join("vault.key"), nokey.join("vault.key")).unwrap();
    let b = start_in(tempfile::tempdir().unwrap(), "nokey-c", "", &nokey);
    b.cli()
        .args(["dataset", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("drill"));
    b.term();
    assert!(b.wait(Duration::from_secs(10)).success());
}

/// A 0600 file holding `contents`.
fn secret_file(dir: &Path, name: &str, contents: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, contents).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    p
}

/// Run a CLI command; (exit code, stdout, stderr). The password canary must
/// appear in neither stream, whatever the command did.
fn run_no_canary(d: &Daemon, args: &[&str], extra: &[&Path]) -> (i32, String, String) {
    let mut c = d.cli();
    c.args(args);
    for p in extra {
        c.arg(p);
    }
    let out = c.output().unwrap();
    let (so, se) = (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    );
    assert!(
        !so.contains("hunter2"),
        "password on stdout of {args:?}: {so}"
    );
    assert!(
        !se.contains("hunter2"),
        "password on stderr of {args:?}: {se}"
    );
    (out.status.code().unwrap(), so, se)
}

#[test]
fn mailbox_commands_configure_check_and_remove() {
    use inumaki_mail::fake::{FakeImap, FakeState};
    let rt = tokio::runtime::Runtime::new().unwrap();
    let fake = rt.block_on(FakeImap::start(FakeState::new("agent", "hunter2-canary")));
    let port = fake.port().to_string();
    let d = start("mailbox");
    let dir = tempfile::tempdir().unwrap();
    let pw = secret_file(dir.path(), "pw", "hunter2-canary\n");
    let add = |pwfile: &Path| {
        run_no_canary(
            &d,
            &[
                "dataset",
                "add-mailbox",
                "mail",
                "--preset",
                "generic",
                "--user",
                "agent",
                "--imap-host",
                "127.0.0.1",
                "--imap-port",
                &port,
                "--imap-plaintext-loopback",
                "--password-file",
            ],
            &[pwfile],
        )
    };
    // The first add creates the dataset (no --profile sent: the daemon's default applies).
    let (code, out, err) = add(&pw);
    assert_eq!(code, 0, "{out}{err}");
    assert!(
        out.contains("dataset mail created (kind mailbox, profile offline)"),
        "{out}"
    );
    assert!(
        out.contains("mailbox configured for mail (generic, 127.0.0.1:"),
        "{out}"
    );
    assert!(
        out.contains("mailbox ok: 1 folders; drafts folder will be created (Drafts)"),
        "{out}"
    );
    let (code, out, _) = run_no_canary(&d, &["dataset", "check-mailbox", "mail"], &[]);
    assert_eq!(
        (code, out.contains("mailbox ok: 1 folders")),
        (0, true),
        "{out}"
    );
    let (code, out, _) = run_no_canary(&d, &["dataset", "list"], &[]);
    assert_eq!((code, out.contains("mail ")), (0, true), "{out}");
    // A wrong password: stored, but the check fails with the preset's hint and exit 6.
    let wrong = secret_file(dir.path(), "wrong", "nope");
    let (code, out, err) = add(&wrong);
    assert_eq!(code, 6, "{out}{err}");
    assert!(out.contains("mailbox configured for mail"), "{out}");
    assert!(err.contains("mail_auth_failed"), "{err}");
    assert!(err.contains("check the IMAP host"), "{err}");
    assert!(!err.contains("nope") && !out.contains("nope"));
    // Put the working password back, then remove.
    assert_eq!(add(&pw).0, 0);
    let (code, out, _) = run_no_canary(&d, &["dataset", "remove-mailbox", "mail"], &[]);
    assert_eq!(
        (code, out.contains("mailbox removed from mail")),
        (0, true),
        "{out}"
    );
    let (code, _, err) = run_no_canary(&d, &["dataset", "check-mailbox", "mail"], &[]);
    assert_eq!(code, 6);
    assert!(err.contains("mailbox not configured"), "{err}");
    let (code, _, err) = run_no_canary(&d, &["dataset", "remove-mailbox", "mail"], &[]);
    assert_eq!(code, 2);
    assert!(err.contains("mailbox not configured"), "{err}");
    assert!(!d.log().contains("hunter2"), "{}", d.log());
    d.term();
    assert!(d.wait(Duration::from_secs(10)).success());
    drop(fake);
    drop(rt);
}

#[test]
fn mailbox_validation_fails_before_any_dataset_is_created() {
    let d = start("mbv");
    let dir = tempfile::tempdir().unwrap();
    let pw = secret_file(dir.path(), "pw", "hunter2-canary\n");
    let loose = dir.path().join("loose");
    std::fs::write(&loose, "hunter2-canary").unwrap();
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).unwrap();
    // Plaintext off loopback (an explicit host, then a preset's default host).
    let (code, _, err) = run_no_canary(
        &d,
        &[
            "dataset",
            "add-mailbox",
            "m2",
            "--preset",
            "generic",
            "--user",
            "agent",
            "--imap-host",
            "imap.example.test",
            "--imap-port",
            "143",
            "--imap-plaintext-loopback",
            "--password-file",
        ],
        &[&pw],
    );
    assert_eq!(code, 2);
    assert!(err.contains("imap_tls"), "{err}");
    let (code, _, err) = run_no_canary(
        &d,
        &[
            "dataset",
            "add-mailbox",
            "m3",
            "--preset",
            "gmail",
            "--user",
            "a@gmail.com",
            "--imap-plaintext-loopback",
            "--password-file",
        ],
        &[&pw],
    );
    assert_eq!(code, 2);
    assert!(err.contains("imap_tls"), "{err}");
    // Generic needs host and port; an unknown preset is a clap usage error.
    let (code, _, err) = run_no_canary(
        &d,
        &[
            "dataset",
            "add-mailbox",
            "m4",
            "--preset",
            "generic",
            "--user",
            "agent",
            "--imap-host",
            "imap.example.test",
            "--password-file",
        ],
        &[&pw],
    );
    assert_eq!(code, 2);
    assert!(
        err.contains("imap_host and imap_port are required"),
        "{err}"
    );
    let (code, _, _) = run_no_canary(
        &d,
        &[
            "dataset",
            "add-mailbox",
            "m5",
            "--preset",
            "yahoo",
            "--user",
            "agent",
            "--password-file",
        ],
        &[&pw],
    );
    assert_eq!(code, 2);
    // A bad dataset id and a world-readable password file.
    let (code, _, _) = run_no_canary(
        &d,
        &[
            "dataset",
            "add-mailbox",
            "Bad_Id",
            "--preset",
            "gmail",
            "--user",
            "a@gmail.com",
            "--password-file",
        ],
        &[&pw],
    );
    assert_eq!(code, 2);
    let (code, _, err) = run_no_canary(
        &d,
        &[
            "dataset",
            "add-mailbox",
            "m6",
            "--preset",
            "gmail",
            "--user",
            "a@gmail.com",
            "--password-file",
        ],
        &[&loose],
    );
    assert_eq!(code, 2);
    assert!(err.contains("chmod 600"), "{err}");
    // None of them left a dataset behind.
    let (code, out, _) = run_no_canary(&d, &["dataset", "list"], &[]);
    assert_eq!(code, 0);
    for id in ["m2", "m3", "m4", "m5", "m6", "Bad_Id"] {
        assert!(!out.contains(id), "{id} left behind: {out}");
    }
    d.term();
    assert!(d.wait(Duration::from_secs(10)).success());
}

#[test]
fn mailbox_plaintext_off_loopback_is_refused_before_any_request() {
    // No daemon at all: the refusal is client-side, so it never reaches the socket.
    let dir = tempfile::tempdir().unwrap();
    let pw = secret_file(dir.path(), "pw", "hunter2-canary\n");
    let out = bin()
        .args(["--socket"])
        .arg(dir.path().join("none.sock"))
        .args([
            "dataset",
            "add-mailbox",
            "m",
            "--preset",
            "generic",
            "--user",
            "agent",
            "--imap-host",
            "imap.example.test",
            "--imap-port",
            "143",
            "--imap-plaintext-loopback",
            "--password-file",
        ])
        .arg(&pw)
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2));
    assert!(err.contains("imap_tls"), "{err}");
    assert!(!err.contains("cannot connect"), "{err}");
    assert!(!err.contains("hunter2"));
}

#[test]
fn a_non_mailbox_dataset_is_refused_by_all_three_commands() {
    let d = start("mbk");
    let dir = tempfile::tempdir().unwrap();
    let pw = secret_file(dir.path(), "pw", "hunter2-canary\n");
    d.cli()
        .args(["dataset", "add", "crm", "--name", "CRM"])
        .assert()
        .success();
    let (code, out, err) = run_no_canary(
        &d,
        &[
            "dataset",
            "add-mailbox",
            "crm",
            "--preset",
            "gmail",
            "--user",
            "a@gmail.com",
            "--password-file",
        ],
        &[&pw],
    );
    assert_eq!(code, 2, "{out}{err}");
    assert!(err.contains("not a mailbox dataset"), "{err}");
    // The daemon's own message: a dataset with no mailbox row.
    let (code, _, err) = run_no_canary(&d, &["dataset", "check-mailbox", "crm"], &[]);
    assert_eq!(code, 6);
    assert!(err.contains("mailbox not configured"), "{err}");
    let (code, _, err) = run_no_canary(&d, &["dataset", "remove-mailbox", "crm"], &[]);
    assert_eq!(code, 2);
    assert!(err.contains("mailbox not configured"), "{err}");
    // An unknown dataset has its own message.
    let (code, _, err) = run_no_canary(&d, &["dataset", "check-mailbox", "nope"], &[]);
    assert_eq!(code, 6);
    assert!(err.contains("not_found"), "{err}");
    d.term();
    assert!(d.wait(Duration::from_secs(10)).success());
}
