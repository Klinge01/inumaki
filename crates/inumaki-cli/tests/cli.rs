use assert_cmd::Command;
use predicates::prelude::*;

/// The CLI with an empty data directory of its own, so a real
/// `<data dir>/inumaki.toml` on the machine never changes what it loads.
fn bin() -> Command {
    static DATA_DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    let data = DATA_DIR.get_or_init(|| tempfile::tempdir().unwrap());
    let mut c = Command::cargo_bin("inumaki").unwrap();
    c.env("INUMAKI_DATA_DIR", data.path());
    c
}

#[test]
fn scan_lists_spans_from_stdin() {
    bin()
        .args(["scan", "--profile", "offline", "-"])
        .write_stdin("Mail sarah@example.at, IBAN AT61 1904 3002 3457 3201.")
        .assert()
        .success()
        .stdout(predicate::str::contains("EMAIL"))
        .stdout(predicate::str::contains("IBAN"))
        .stdout(predicate::str::contains("sarah@example.at"));
}

#[test]
fn scan_json() {
    let out = bin()
        .args(["scan", "--profile", "offline", "--json", "-"])
        .write_stdin("sarah@example.at")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v[0]["kind"], "EMAIL");
    assert_eq!(v[0]["start"], 0);
    assert_eq!(v[0]["end"], 16);
}

/// I1: offsets refer to the NFC form, and scan slices that form.
#[test]
fn scan_nfd_input_reports_nfc_offsets() {
    let out = bin()
        .args(["scan", "--profile", "offline", "--json", "-"])
        .write_stdin("Mu\u{0308}ller: sarah@example.at")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let email = v
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["kind"] == "EMAIL")
        .unwrap();
    assert_eq!(email["text"], "sarah@example.at");
    assert_eq!(email["start"], "Müller: ".len());
}

#[test]
fn tokenize_replaces_and_prints_map_on_stderr() {
    bin()
        .args(["tokenize", "--profile", "offline", "--map", "-"])
        .write_stdin("IBAN AT61 1904 3002 3457 3201 bitte")
        .assert()
        .success()
        .stdout(predicate::str::contains("<IBAN_"))
        .stdout(predicate::str::contains("AT61").not())
        .stderr(predicate::str::contains("AT61 1904 3002 3457 3201"));
}

#[test]
fn tokenize_without_map_keeps_stderr_clean() {
    bin()
        .args(["tokenize", "--profile", "offline", "-"])
        .write_stdin("IBAN AT61 1904 3002 3457 3201")
        .assert()
        .success()
        .stderr(predicate::str::is_empty());
}

#[test]
fn tokenize_blocked_exits_3_without_values() {
    let dir = tempfile_dir();
    let cfg = dir.join("block.toml");
    std::fs::write(
        &cfg,
        r#"
        [profiles.fast]
        default_action = "tokenize"
        ner_sanitizer = "none"
        [profiles.fast.entities.IBAN]
        action = "block"
        min_confidence = 0.0
        [profiles.fast.verifier]
        allow_no_ner = true
        "#,
    )
    .unwrap();
    bin()
        .args([
            "tokenize",
            "--config",
            cfg.to_str().unwrap(),
            "--profile",
            "fast",
            "-",
        ])
        .write_stdin("AT61 1904 3002 3457 3201")
        .assert()
        .code(3)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("IBAN"))
        .stderr(predicate::str::contains("AT61").not());
}

/// M1: PassUncertain prints kinds and check ids (never values) to stderr
/// and still exits 0.
#[test]
fn tokenize_pass_uncertain_reports_on_stderr_and_exits_0() {
    let dir = tempfile_dir();
    let cfg = dir.join("uncertain.toml");
    std::fs::write(
        &cfg,
        r#"
        [[domain.patterns]]
        regex = "Elektriker"
        kind = "PROFESSION"

        [profiles.fast]
        default_action = "tokenize"
        ner_sanitizer = "none"
        [profiles.fast.entities]
        PROFESSION  = { action = "preserve", min_confidence = 0.0 }
        DATE        = { action = "preserve", min_confidence = 0.0 }
        POSTAL_CODE = { action = "preserve", min_confidence = 0.0 }
        [profiles.fast.verifier]
        on_uncertain = "pass"
        allow_no_ner = true
        "#,
    )
    .unwrap();
    bin()
        .args([
            "tokenize",
            "--config",
            cfg.to_str().unwrap(),
            "--profile",
            "fast",
            "-",
        ])
        .write_stdin("Elektriker seit 01.02.2020 in 1010 Wien.")
        .assert()
        .code(0)
        .stdout(predicate::str::contains("Elektriker seit 01.02.2020"))
        .stderr(predicate::str::starts_with("uncertain: kinds="))
        .stderr(predicate::str::contains("checks=Combination"))
        .stderr(predicate::str::contains("01.02.2020").not())
        .stderr(predicate::str::contains("1010").not())
        .stderr(predicate::str::contains("Elektriker").not());
}

#[test]
fn bad_config_exits_2() {
    bin()
        .args(["scan", "--config", "/nonexistent/x.toml", "-"])
        .write_stdin("x")
        .assert()
        .code(2);
}

#[test]
fn missing_model_is_a_config_error_naming_pull() {
    let dir = tempfile_dir();
    bin()
        .args(["tokenize", "--models-dir", dir.to_str().unwrap(), "-"])
        .write_stdin("Sarah Leitner")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("inumaki models pull"))
        .stderr(predicate::str::contains("Sarah").not());
}

fn tempfile_dir() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("inumaki-cli-test-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn eval_offline_runs_and_writes_a_baseline() {
    let dir = tempfile_dir();
    let base = dir.join("offline.toml");
    bin()
        .args([
            "eval",
            "--profile",
            "offline",
            "--generate",
            "30",
            "--write-baseline",
            base.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("leak rate"));
    assert!(base.exists());
}

#[test]
fn eval_regression_exits_4() {
    let dir = tempfile_dir();
    let base = dir.join("impossible.toml");
    std::fs::write(
        &base,
        "profile = \"offline\"\ndocs = 30\nleak_rate = 0.0\nverifier_fn_rate = 0.0\n[recall]\nIBAN = 1.5\n",
    )
    .unwrap();
    bin()
        .args([
            "eval",
            "--profile",
            "offline",
            "--generate",
            "30",
            "--baseline",
            base.to_str().unwrap(),
        ])
        .assert()
        .code(4)
        .stderr(predicate::str::contains("IBAN recall"));
}

/// I3: a baseline measured on a different platform prints a warning, but
/// still gates normally (here: no regression, so exit 0).
#[test]
fn eval_baseline_platform_mismatch_prints_a_warning() {
    let dir = tempfile_dir();
    let base = dir.join("other-platform.toml");
    // `eval` defaults to the hand-written cases plus `--generate 30`, so the crafted
    // baseline's corpus size must match that total or the corpus-size gate
    // (report.rs `Baseline::check`) fails this run for an unrelated reason.
    let docs = inumaki_eval::cases::embedded_cases().len() + 30;
    std::fs::write(
        &base,
        format!(
            "profile = \"offline\"\ndocs = {docs}\nleak_rate = 1.0\nverifier_fn_rate = 1.0\nplatform = \"bogus-os-bogus-arch\"\n[recall]\n"
        ),
    )
    .unwrap();
    bin()
        .args([
            "eval",
            "--profile",
            "offline",
            "--generate",
            "30",
            "--baseline",
            base.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "warning: baseline was measured on bogus-os-bogus-arch, this run is on",
        ));
}

#[test]
fn eval_json_has_no_text() {
    let out = bin()
        .args(["eval", "--profile", "offline", "--generate", "10", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8(out).unwrap();
    let v: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert!(v["per_kind"].is_object());
    for name in inumaki_eval::data::FIRST_NAMES.iter().take(10) {
        assert!(!s.contains(name), "report must not contain corpus text");
    }
}

#[test]
fn bench_offline_prints_percentiles() {
    bin()
        .args(["bench", "--profile", "offline", "--generate", "20"])
        .assert()
        .success()
        .stdout(predicate::str::contains("p50"));
}

/// Plan 4a Task 5: `--via-service` runs the mail track through
/// `sanitize_blocks` in an in-process daemon state; the report says where it
/// was measured and carries the link metrics.
#[test]
fn eval_via_service_runs_the_mail_track() {
    let out = bin()
        .args([
            "eval",
            "--profile",
            "offline",
            "--cases-only",
            "--via-service",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["provenance"]["family"], "cases+service");
    assert!(v["links"]["tokens_total"].as_u64().unwrap() > 0, "{v}");
    assert!(v["docs"].as_u64().unwrap() > 0);
    assert_eq!(v["store_errors"], 0, "{v}");
}

/// The tool-json track still runs through the service path (plan 4a Task 5
/// extended `ServiceSanitizer`, which that track shares). Ignored by
/// default: the full tool-json corpus takes ~110 s in a debug build; run it
/// once per plan gate with `cargo test -p inumaki-cli --test cli -- --ignored
/// eval_tool_json_via_service_still_runs`.
#[test]
#[ignore = "slow (full tool-json corpus); run in the plan gate"]
fn eval_tool_json_via_service_still_runs() {
    let out = bin()
        .args([
            "eval",
            "--profile",
            "offline",
            "--track",
            "tool-json",
            "--via-service",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(
        v["provenance"]["family"]
            .as_str()
            .unwrap()
            .starts_with("tool-json+"),
        "{v}"
    );
    assert_eq!(v["store_errors"], 0, "{v}");
}

/// Plan 4a Task 6: a persistent-dataset sequence through the real service
/// (vault, restart, rotation, clock advance, sweep). Deliberately tiny (12
/// documents, `offline` profile: no models) so it stays fast in a debug
/// build; the full 300-step runs are measured with the release binary.
/// What it protects: tokens minted before the rotation resolve during grace
/// and not after expiry plus the sweep (on a warm namespace handle: a stale
/// working set once kept them resolving), no event may fail, and no token may
/// restore to wrong text. A fresh `--sequences --track tool-json` is refused.
#[test]
fn eval_sequences_expire_old_epoch_tokens_through_the_service() {
    let out = bin()
        .args([
            "eval",
            "--profile",
            "offline",
            "--sequences",
            "--sequence-steps",
            "12",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["provenance"]["family"], "sequence+service");
    let q = &v["sequence"];
    assert_eq!(q["steps"], 12, "{v}");
    assert_eq!(q["restarts"], 2, "{v}");
    assert_eq!(q["rotations"], 1, "{v}");
    assert_eq!(q["event_failures"], 0, "{v}");
    assert_eq!(v["store_errors"], 0, "{v}");
    assert_eq!(v["links"]["wrong_restorations"], 0, "{v}");
    assert_eq!(q["restore_errors"], 0, "{v}");
    assert_eq!(q["reused_after_rotation"], 0, "{v}");
    // identifier tokens (contract and invoice numbers, no models needed)
    // exist in this run: they must resolve on the warm handle during grace
    // (a store that answers nothing fails here) and not after expiry + sweep
    let pre = q["pre_rotation_tokens"].as_u64().unwrap();
    assert!(pre > 0, "the run minted tokens before the rotation: {v}");
    assert_eq!(
        q["resolved_within_grace"].as_u64().unwrap(),
        pre,
        "a token of the closed epoch stopped resolving during grace: {v}"
    );
    assert_eq!(
        q["unresolved_after_grace"].as_u64().unwrap(),
        pre,
        "a token of the expired epoch still resolves: {v}"
    );
}

#[test]
fn eval_sequences_refuse_another_track() {
    bin()
        .args([
            "eval",
            "--profile",
            "offline",
            "--sequences",
            "--track",
            "tool-json",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--track"));
}
