//! Login service and helper binaries (M6 spec §7.1, §7.2, §11 "golden renders").
//! No real launchctl or systemctl runs: a RecordingRunner answers them.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use inumaki_app_lib::ctx::Ctx;
use inumaki_app_lib::paths::AppPaths;
use inumaki_app_lib::service::runner::{RecordingRunner, RunOutput, Runner};
use inumaki_app_lib::service::{self, launchd, systemd};
use inumaki_client::Client;
use inumaki_client::mock::{Canned, MockDaemon};
use serde_json::json;

fn ctx_at(root: &Path, client: Client) -> (Ctx, Arc<RecordingRunner>) {
    let paths = AppPaths::under(&root.join("data"), &root.join("home"));
    std::fs::create_dir_all(&paths.home).unwrap();
    let runner = Arc::new(RecordingRunner::default());
    let (ctx, _notes) = Ctx::for_tests(paths, client);
    (ctx.with_runner(runner.clone()), runner)
}

fn fake_helpers(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    for h in service::HELPERS {
        std::fs::write(dir.join(h), format!("#!/bin/sh\n# {h}\n")).unwrap();
        std::fs::set_permissions(dir.join(h), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

#[test]
fn plist_and_unit_render_golden() {
    let bin = Path::new("/Users/a&b/Library/Application Support/inumaki/bin");
    let log = Path::new("/Users/a&b/Library/Application Support/inumaki/logs/inumakid.log");
    let plist = launchd::render(bin, log);
    assert!(
        plist.contains(
            "<string>/Users/a&amp;b/Library/Application Support/inumaki/bin/inumakid</string>"
        ),
        "{plist}"
    );
    assert!(plist.contains("<key>StandardErrorPath</key><string>/Users/a&amp;b/Library/Application Support/inumaki/logs/inumakid.log</string>"));
    assert!(plist.contains("<key>INUMAKI_MANAGED_BY</key><string>app</string>"));
    assert!(plist.contains("<key>Label</key><string>inumaki.inumakid</string>"));
    assert!(
        plist.contains("<key>SuccessfulExit</key><false/>"),
        "KeepAlive on unsuccessful exit"
    );
    assert!(!plist.contains('@'), "every placeholder is rendered");
    let unit = systemd::render(Path::new("/home/u 1/.local/share/inumaki/bin"));
    assert!(
        unit.contains("ExecStart=\"/home/u 1/.local/share/inumaki/bin/inumakid\"\n"),
        "{unit}"
    );
    assert!(unit.contains("Environment=INUMAKI_MANAGED_BY=app\n"));
    assert!(!unit.contains("/usr/bin/inumakid") && !unit.contains("MANAGED_BY=deb"));
    assert!(
        unit.contains("WantedBy=default.target") && unit.contains("UMask=0077"),
        "the rest is the .deb unit"
    );
    assert_eq!(
        systemd::render(Path::new("/h/100%/bin"))
            .lines()
            .find(|l| l.starts_with("ExecStart"))
            .unwrap(),
        "ExecStart=/h/100%%/bin/inumakid",
        "systemd specifiers are escaped"
    );
}

/// Review Focus 4.
#[tokio::test]
async fn install_refuses_a_service_managed_elsewhere() {
    let m = MockDaemon::start().await;
    let mut body: serde_json::Value =
        serde_json::from_str(inumaki_client::contract::fixture("service")).unwrap();
    body["managed_by"] = json!("homebrew");
    m.set("GET", "/v1/service", Canned::json(200, body));
    let root = tempfile::tempdir().unwrap();
    let (ctx, runner) = ctx_at(root.path(), m.client());
    fake_helpers(&root.path().join("bundle"));
    for r in [
        service::install_with(
            &ctx,
            &root.path().join("bundle"),
            Duration::from_millis(100),
            &[root.path().join("no-system-unit").as_path()],
        )
        .await,
        service::remove(&ctx).await,
        service::restart(&ctx, Duration::from_millis(100)).await,
    ] {
        assert_eq!(r.unwrap_err().kind, "managed_elsewhere");
    }
    assert!(runner.calls().is_empty(), "{:?}", runner.calls());
    assert!(!launchd::plist_path(&ctx.paths.home).exists());
    assert!(!systemd::unit_path(&ctx.paths.home).exists());
    assert!(!ctx.paths.bin_dir.exists());
}

/// Review Focus 4, stopped services: the files of another installer are
/// enough to refuse, and a service file the app did not write is never touched.
#[tokio::test]
async fn install_refuses_the_files_of_another_installer_even_when_stopped() {
    let root = tempfile::tempdir().unwrap();
    let nobody = root.path().join("none.sock");
    let bundle = root.path().join("bundle");
    fake_helpers(&bundle);
    let no_unit = root.path().join("no-system-unit");
    // Homebrew's LaunchAgent, service stopped.
    let (ctx, runner) = ctx_at(root.path(), Client::new(&nobody));
    let brew = ctx
        .paths
        .home
        .join("Library/LaunchAgents/homebrew.mxcl.inumaki.plist");
    std::fs::create_dir_all(brew.parent().unwrap()).unwrap();
    std::fs::write(&brew, "<plist/>").unwrap();
    assert_eq!(
        service::install_with(
            &ctx,
            &bundle,
            Duration::from_millis(100),
            &[no_unit.as_path()]
        )
        .await
        .unwrap_err()
        .kind,
        "managed_elsewhere"
    );
    std::fs::remove_file(&brew).unwrap();
    // The .deb's user unit.
    let deb = root.path().join("usr-lib-systemd-user-inumakid.service");
    std::fs::write(&deb, "[Service]\nEnvironment=INUMAKI_MANAGED_BY=deb\n").unwrap();
    assert_eq!(
        service::install_with(&ctx, &bundle, Duration::from_millis(100), &[deb.as_path()])
            .await
            .unwrap_err()
            .kind,
        "managed_elsewhere"
    );
    // A plist or unit at the app's own path without the app's marker (written by hand).
    let own = if cfg!(target_os = "macos") {
        launchd::plist_path(&ctx.paths.home)
    } else {
        systemd::unit_path(&ctx.paths.home)
    };
    std::fs::create_dir_all(own.parent().unwrap()).unwrap();
    std::fs::write(&own, "hand-written").unwrap();
    for r in [
        service::install_with(
            &ctx,
            &bundle,
            Duration::from_millis(100),
            &[no_unit.as_path()],
        )
        .await,
        service::remove(&ctx).await,
        service::restart(&ctx, Duration::from_millis(100)).await,
    ] {
        assert_eq!(r.unwrap_err().kind, "managed_elsewhere");
    }
    assert!(runner.calls().is_empty(), "{:?}", runner.calls());
    assert_eq!(
        std::fs::read_to_string(&own).unwrap(),
        "hand-written",
        "never rewritten or removed"
    );
    assert!(!ctx.paths.bin_dir.exists(), "no helper copied either");
}

/// Review item 7: a test context can never run launchctl, systemctl, or codesign.
#[tokio::test]
async fn test_contexts_never_run_real_programs() {
    let root = tempfile::tempdir().unwrap();
    let (ctx, _) = Ctx::for_tests(
        AppPaths::under(&root.path().join("data"), &root.path().join("home")),
        Client::new(root.path().join("none.sock")),
    );
    assert!(
        ctx.runner.run(Path::new("/usr/bin/true"), &[]).is_err(),
        "for_tests uses a runner that refuses every call"
    );
}

#[tokio::test]
async fn install_copies_helpers_and_registers_the_service() {
    let root = tempfile::tempdir().unwrap();
    // Nothing answers: the service is not installed yet.
    let (ctx, runner) = ctx_at(root.path(), Client::new(root.path().join("none.sock")));
    let bundle = root.path().join("bundle");
    fake_helpers(&bundle);
    let err = service::install_with(
        &ctx,
        &bundle,
        Duration::from_millis(300),
        &[root.path().join("no-system-unit").as_path()],
    )
    .await
    .unwrap_err();
    assert_eq!(
        err.kind, "service_did_not_start",
        "nothing starts under a RecordingRunner"
    );
    for h in service::HELPERS {
        let p = ctx.paths.bin_dir.join(h);
        assert_eq!(
            std::fs::read(&p).unwrap(),
            std::fs::read(bundle.join(h)).unwrap()
        );
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }
    let calls = runner.calls();
    if cfg!(target_os = "macos") {
        // Cleared and signed as the temporary, before it replaces the helper.
        for h in service::HELPERS {
            let p = ctx
                .paths
                .bin_dir
                .join(format!(".{h}.tmp"))
                .display()
                .to_string();
            assert!(
                calls.contains(&vec!["/usr/bin/xattr".into(), "-c".into(), p.clone()]),
                "{calls:?}"
            );
            assert!(calls.contains(&vec![
                "/usr/bin/codesign".into(),
                "--force".into(),
                "-s".into(),
                "-".into(),
                "-i".into(),
                h.to_string(),
                p
            ]));
        }
        let plist = launchd::plist_path(&ctx.paths.home);
        assert_eq!(
            std::fs::read_to_string(&plist).unwrap(),
            launchd::render(
                &ctx.paths.bin_dir,
                &ctx.paths.data_dir.join("logs/inumakid.log")
            )
        );
        let log = ctx.paths.data_dir.join("logs/inumakid.log");
        assert_eq!(
            std::fs::metadata(&log).unwrap().permissions().mode() & 0o777,
            0o600,
            "the daemon log exists, private, before launchd opens it"
        );
        let last = calls.last().unwrap();
        assert_eq!(&last[..2], ["/bin/launchctl", "bootstrap"]);
        assert!(last[2].starts_with("gui/"));
        assert_eq!(last[3], plist.display().to_string());
        assert!(
            !calls.iter().any(|c| c.iter().any(|a| a == "bootout")),
            "no plist of the app's existed: nothing is booted out {calls:?}"
        );
    } else {
        assert_eq!(
            std::fs::read_to_string(systemd::unit_path(&ctx.paths.home)).unwrap(),
            systemd::render(&ctx.paths.bin_dir)
        );
        assert!(
            calls.iter().any(|c| c.ends_with(&[
                "--user".into(),
                "enable".into(),
                "--now".into(),
                "inumakid".into()
            ])),
            "{calls:?}"
        );
    }
}

#[tokio::test]
async fn helpers_are_refreshed_only_when_they_differ() {
    let root = tempfile::tempdir().unwrap();
    let (ctx, runner) = ctx_at(root.path(), Client::new(root.path().join("none.sock")));
    let bundle = root.path().join("bundle");
    fake_helpers(&bundle);
    let r = runner.as_ref();
    assert_eq!(
        service::bin::install_helpers(r, &bundle, &ctx.paths.bin_dir).unwrap(),
        4
    );
    assert_eq!(
        service::bin::install_helpers(r, &bundle, &ctx.paths.bin_dir).unwrap(),
        0
    );
    std::fs::write(bundle.join("inumakid"), "#!/bin/sh\n# new\n").unwrap();
    assert!(service::bin::needs_refresh(
        &bundle.join("inumakid"),
        &ctx.paths.bin_dir.join("inumakid")
    ));
    assert_eq!(
        service::bin::install_helpers(r, &bundle, &ctx.paths.bin_dir).unwrap(),
        1
    );
    std::fs::remove_file(bundle.join("inumaki-hook")).unwrap();
    assert_eq!(
        service::bin::install_helpers(r, &bundle, &ctx.paths.bin_dir)
            .unwrap_err()
            .kind,
        "helper_missing"
    );
}

/// A symlink planted at a temporary path is never followed: the helper copy
/// and the service file replace the link, the link's target stays as it was.
#[tokio::test]
async fn temporary_files_never_follow_a_planted_symlink() {
    let root = tempfile::tempdir().unwrap();
    let (ctx, runner) = ctx_at(root.path(), Client::new(root.path().join("none.sock")));
    let bundle = root.path().join("bundle");
    fake_helpers(&bundle);
    let victim = root.path().join("victim");
    std::fs::write(&victim, "keep").unwrap();
    std::fs::create_dir_all(&ctx.paths.bin_dir).unwrap();
    std::os::unix::fs::symlink(&victim, ctx.paths.bin_dir.join(".inumakid.tmp")).unwrap();
    let own = if cfg!(target_os = "macos") {
        launchd::plist_path(&ctx.paths.home)
    } else {
        systemd::unit_path(&ctx.paths.home)
    };
    std::fs::create_dir_all(own.parent().unwrap()).unwrap();
    let tmp_name = format!(".{}.tmp", own.file_name().unwrap().to_string_lossy());
    std::os::unix::fs::symlink(&victim, own.parent().unwrap().join(tmp_name)).unwrap();
    let _ = service::install_with(
        &ctx,
        &bundle,
        Duration::from_millis(100),
        &[root.path().join("no-system-unit").as_path()],
    )
    .await;
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
    assert!(
        std::fs::read_to_string(&own)
            .unwrap()
            .contains("INUMAKI_MANAGED_BY")
    );
    assert!(!runner.calls().is_empty());
}

/// Review Focus 5 (app side).
#[tokio::test]
async fn restart_only_after_a_finished_download() {
    let m = MockDaemon::start().await;
    let root = tempfile::tempdir().unwrap();
    let (ctx, runner) = ctx_at(root.path(), m.client());
    let job = |state: &str, restart: bool, started: i64| -> inumaki_client::ModelsJob {
        serde_json::from_value(json!({ "state": state, "started_at": started, "files": [], "error": null, "restart_required": restart })).unwrap()
    };
    // The daemon says "app" but the app's own service file is missing (a
    // daemon started by hand with the app's marker): nothing is restarted.
    assert!(
        !service::after_models_poll(&ctx, &job("done", true, 1))
            .await
            .unwrap()
    );
    assert!(runner.calls().is_empty(), "{:?}", runner.calls());
    // The app's own service file (restart touches only a service the app wrote).
    let own = if cfg!(target_os = "macos") {
        launchd::plist_path(&ctx.paths.home)
    } else {
        systemd::unit_path(&ctx.paths.home)
    };
    std::fs::create_dir_all(own.parent().unwrap()).unwrap();
    let text = if cfg!(target_os = "macos") {
        launchd::render(
            &ctx.paths.bin_dir,
            &ctx.paths.data_dir.join("logs/inumakid.log"),
        )
    } else {
        systemd::render(&ctx.paths.bin_dir)
    };
    std::fs::write(&own, text).unwrap();
    assert!(
        !service::after_models_poll(&ctx, &job("running", false, 1))
            .await
            .unwrap()
    );
    assert!(
        !service::after_models_poll(&ctx, &job("failed", false, 1))
            .await
            .unwrap()
    );
    assert!(runner.calls().is_empty());
    // The service fixture says managed_by "app": the app restarts it, once per job.
    assert!(
        service::after_models_poll(&ctx, &job("done", true, 2))
            .await
            .unwrap()
    );
    assert!(
        !service::after_models_poll(&ctx, &job("done", true, 2))
            .await
            .unwrap()
    );
    let restarts = runner
        .calls()
        .iter()
        .filter(|c| c.iter().any(|a| a == "kickstart" || a == "restart"))
        .count();
    assert_eq!(restarts, 1, "{:?}", runner.calls());
}

/// Two overlapping polls of one finished job (React StrictMode, or FirstRun
/// and Settings both showing the Models section) restart the service once.
#[tokio::test]
async fn overlapping_polls_restart_once() {
    let m = MockDaemon::start().await;
    let root = tempfile::tempdir().unwrap();
    let (ctx, runner) = ctx_at(root.path(), m.client());
    let own = if cfg!(target_os = "macos") {
        launchd::plist_path(&ctx.paths.home)
    } else {
        systemd::unit_path(&ctx.paths.home)
    };
    std::fs::create_dir_all(own.parent().unwrap()).unwrap();
    let text = if cfg!(target_os = "macos") {
        launchd::render(
            &ctx.paths.bin_dir,
            &ctx.paths.data_dir.join("logs/inumakid.log"),
        )
    } else {
        systemd::render(&ctx.paths.bin_dir)
    };
    std::fs::write(&own, text).unwrap();
    let job: inumaki_client::ModelsJob = serde_json::from_value(json!({ "state": "done", "started_at": 7, "files": [], "error": null, "restart_required": true })).unwrap();
    let (a, b) = tokio::join!(
        service::after_models_poll(&ctx, &job),
        service::after_models_poll(&ctx, &job)
    );
    assert_eq!([a.unwrap(), b.unwrap()].iter().filter(|r| **r).count(), 1);
    let restarts = runner
        .calls()
        .iter()
        .filter(|c| c.iter().any(|a| a == "kickstart" || a == "restart"))
        .count();
    assert_eq!(restarts, 1, "{:?}", runner.calls());
}

/// Answers exit 0 except for codesign, which fails.
#[derive(Default)]
struct CodesignFails;

impl Runner for CodesignFails {
    fn run(&self, program: &Path, _args: &[String]) -> std::io::Result<RunOutput> {
        Ok(RunOutput {
            code: Some(if program.ends_with("codesign") { 1 } else { 0 }),
        })
    }
}

/// A failed signature never removes or replaces the working helper (a
/// missing hook binary would fail open; a missing inumakid cannot respawn).
#[tokio::test]
async fn a_failed_signature_keeps_the_previous_helper() {
    if !cfg!(target_os = "macos") {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (ctx, runner) = ctx_at(root.path(), Client::new(root.path().join("none.sock")));
    let bundle = root.path().join("bundle");
    fake_helpers(&bundle);
    service::bin::install_helpers(runner.as_ref(), &bundle, &ctx.paths.bin_dir).unwrap();
    let before = std::fs::read(ctx.paths.bin_dir.join("inumaki-hook")).unwrap();
    std::fs::write(bundle.join("inumaki-hook"), "#!/bin/sh\n# newer\n").unwrap();
    let err =
        service::bin::install_helpers(&CodesignFails, &bundle, &ctx.paths.bin_dir).unwrap_err();
    assert_eq!(err.kind, "sign_failed");
    assert_eq!(
        std::fs::read(ctx.paths.bin_dir.join("inumaki-hook")).unwrap(),
        before
    );
    assert!(
        !ctx.paths.bin_dir.join(".inumaki-hook.tmp").exists(),
        "only the temporary is removed"
    );
    for h in service::HELPERS {
        assert!(ctx.paths.bin_dir.join(h).is_file(), "{h} still installed");
    }
}

/// A daemon that answers but cannot say who runs it (older than
/// `GET /v1/service`) is never replaced.
#[tokio::test]
async fn install_refuses_a_daemon_that_does_not_name_its_manager() {
    let m = MockDaemon::start().await;
    m.set(
        "GET",
        "/v1/service",
        Canned::json(
            404,
            json!({ "error": { "kind": "not_found", "message": "no such route" } }),
        ),
    );
    let root = tempfile::tempdir().unwrap();
    let (ctx, runner) = ctx_at(root.path(), m.client());
    let bundle = root.path().join("bundle");
    fake_helpers(&bundle);
    let err = service::install_with(
        &ctx,
        &bundle,
        Duration::from_millis(100),
        &[root.path().join("no-system-unit").as_path()],
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind, "managed_elsewhere");
    assert!(runner.calls().is_empty(), "{:?}", runner.calls());
    assert!(!ctx.paths.bin_dir.exists());
}

/// Review Focus 4: `sudo brew services` (a LaunchDaemon outside the home
/// directory), stopped, is enough to refuse; the real install checks it by default.
#[tokio::test]
async fn install_refuses_a_stopped_root_homebrew_service() {
    assert!(service::SYSTEM_FILES.contains(&"/Library/LaunchDaemons/homebrew.mxcl.inumaki.plist"));
    assert!(service::SYSTEM_FILES.contains(&service::DEB_UNIT));
    let root = tempfile::tempdir().unwrap();
    let (ctx, runner) = ctx_at(root.path(), Client::new(root.path().join("none.sock")));
    let bundle = root.path().join("bundle");
    fake_helpers(&bundle);
    let daemon = root
        .path()
        .join("Library-LaunchDaemons-homebrew.mxcl.inumaki.plist");
    std::fs::write(&daemon, "<plist/>").unwrap();
    let missing = root.path().join("no-system-unit");
    let err = service::install_with(
        &ctx,
        &bundle,
        Duration::from_millis(100),
        &[missing.as_path(), daemon.as_path()],
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind, "managed_elsewhere");
    assert!(runner.calls().is_empty(), "{:?}", runner.calls());
    assert!(!ctx.paths.bin_dir.exists());
}

/// Jobs the daemon reports without a start time share no key with a real
/// start time: each such job restarts once, and only once.
#[tokio::test]
async fn a_job_without_a_start_time_restarts_once() {
    let m = MockDaemon::start().await;
    let root = tempfile::tempdir().unwrap();
    let (ctx, runner) = ctx_at(root.path(), m.client());
    let own = if cfg!(target_os = "macos") {
        launchd::plist_path(&ctx.paths.home)
    } else {
        systemd::unit_path(&ctx.paths.home)
    };
    std::fs::create_dir_all(own.parent().unwrap()).unwrap();
    let text = if cfg!(target_os = "macos") {
        launchd::render(
            &ctx.paths.bin_dir,
            &ctx.paths.data_dir.join("logs/inumakid.log"),
        )
    } else {
        systemd::render(&ctx.paths.bin_dir)
    };
    std::fs::write(&own, text).unwrap();
    let job = |state: &str, started: Option<i64>| -> inumaki_client::ModelsJob {
        serde_json::from_value(json!({ "state": state, "started_at": started, "files": [], "error": null, "restart_required": state == "done" })).unwrap()
    };
    let restarts = || {
        runner
            .calls()
            .iter()
            .filter(|c| c.iter().any(|a| a == "kickstart" || a == "restart"))
            .count()
    };
    // A job that started at 0 does not block one without a start time.
    assert!(
        service::after_models_poll(&ctx, &job("done", Some(0)))
            .await
            .unwrap()
    );
    assert!(
        service::after_models_poll(&ctx, &job("done", None))
            .await
            .unwrap()
    );
    assert!(
        !service::after_models_poll(&ctx, &job("done", None))
            .await
            .unwrap(),
        "only once"
    );
    assert_eq!(restarts(), 2);
    // A new job (seen running) without a start time restarts once again.
    assert!(
        !service::after_models_poll(&ctx, &job("running", None))
            .await
            .unwrap()
    );
    assert!(
        service::after_models_poll(&ctx, &job("done", None))
            .await
            .unwrap()
    );
    assert!(
        !service::after_models_poll(&ctx, &job("done", None))
            .await
            .unwrap()
    );
    assert_eq!(restarts(), 3, "{:?}", runner.calls());
}

/// A daemon that names the app as its manager while the app's own service
/// file is gone: Remove says so instead of reporting a removal it did not do.
#[tokio::test]
async fn remove_without_the_apps_service_file_is_an_error() {
    let m = MockDaemon::start().await;
    let root = tempfile::tempdir().unwrap();
    let (ctx, runner) = ctx_at(root.path(), m.client());
    let e = service::remove(&ctx).await.unwrap_err();
    assert_eq!(e.kind, "service_not_installed_by_app");
    assert!(runner.calls().is_empty(), "{:?}", runner.calls());
}

/// A control character in a path would break the unit's lines or land raw
/// in the plist: refused before anything is written or run.
#[test]
fn paths_with_control_characters_are_refused() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let runner = RecordingRunner::default();
    let bad = root.path().join("bin\nExecStartPre=/bin/false");
    let log = root.path().join("app.log");
    let e = systemd::install(&runner, &home, &bad).unwrap_err();
    assert_eq!(e.kind, "service_file_unwritable");
    let e = launchd::install(&runner, &home, &bad, &log, false).unwrap_err();
    assert_eq!(e.kind, "service_file_unwritable");
    let e = launchd::install(
        &runner,
        &home,
        root.path(),
        &root.path().join("a\tb.log"),
        false,
    )
    .unwrap_err();
    assert_eq!(e.kind, "service_file_unwritable");
    assert!(!systemd::unit_path(&home).exists());
    assert!(!launchd::plist_path(&home).exists());
    assert!(runner.calls().is_empty(), "{:?}", runner.calls());
}
