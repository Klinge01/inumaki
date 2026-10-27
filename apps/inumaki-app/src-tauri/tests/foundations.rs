//! Privacy foundations (M6 spec §6.6): errors without messages, a log that
//! takes only fixed strings, a private state file; and the not-available
//! rule for routes of lanes that have not merged (Review Focus 2).

use std::os::unix::fs::PermissionsExt;

use inumaki_app_lib::applog;
use inumaki_app_lib::appstate::{self, AppStateFile};
use inumaki_app_lib::ctx::Ctx;
use inumaki_app_lib::error::CmdError;
use inumaki_app_lib::paths::AppPaths;
use inumaki_client::mock::{Canned, MockDaemon};

#[tokio::test]
async fn not_available_only_for_missing_routes() {
    let m = MockDaemon::start().await;
    let c = m.client();
    m.set(
        "GET",
        "/v1/folders",
        Canned::error(404, "not_found", "no such route", &[]),
    );
    assert_eq!(
        CmdError::from(c.folders().await.unwrap_err()).kind,
        "not_available"
    );
    m.set("GET", "/v1/proxy", Canned::raw(404, "Not Found"));
    assert_eq!(
        CmdError::from(c.proxy().await.unwrap_err()).kind,
        "not_available"
    );
    m.set(
        "GET",
        "/v1/datasets/{id}/mailbox",
        Canned::error(404, "not_found", "dataset qwxzvk-kunde not found", &[]),
    );
    let e = CmdError::from(c.mailbox("qwxzvk-kunde").await.unwrap_err());
    assert_eq!((e.kind, e.status), ("not_found", Some(404)));
    m.set(
        "POST",
        "/v1/inspect",
        Canned::error(
            451,
            "privacy_block",
            "blocked qwxzvk",
            &["PERSON", "qwxzvk kind"],
        ),
    );
    let e = CmdError::from(
        c.inspect(&inumaki_client::InspectRequest::new("x", "y"))
            .await
            .unwrap_err(),
    );
    assert_eq!(e.kind, "privacy_block");
    assert_eq!(e.kinds, ["PERSON"]);
    m.set(
        "GET",
        "/v1/status",
        Canned::error(500, "qwxzvk_kind", "qwxzvk", &[]),
    );
    let e = CmdError::from(c.status().await.unwrap_err());
    assert_eq!(e.kind, "error", "unknown kinds collapse to a fixed string");
    let shown = format!("{e:?} {}", serde_json::to_string(&e).unwrap());
    assert!(!shown.contains("qwxzvk"), "{shown}");
    drop(m);
    let gone = inumaki_client::Client::new(std::env::temp_dir().join("inumaki-app-none.sock"));
    assert_eq!(
        CmdError::from(gone.status().await.unwrap_err()).kind,
        "service_unreachable"
    );
}

#[test]
fn applog_takes_fixed_strings_and_the_panic_hook_logs_the_location_only() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("logs").join("app.log");
    applog::init(&log);
    // Only this test installs the hook, so other tests' failures still print their reason.
    applog::install_panic_hook();
    applog::command("connect", 12, "ok", Some(200));
    applog::count("install_helpers", "copied", 3);
    let _ = std::thread::spawn(|| panic!("value qwxzvk-canary in a panic message")).join();
    let text = std::fs::read_to_string(&log).unwrap();
    assert!(
        text.contains("cmd=connect ms=12 outcome=ok status=200"),
        "{text}"
    );
    assert!(text.contains("cmd=install_helpers copied=3"), "{text}");
    assert!(text.contains("panic at="), "{text}");
    assert!(!text.contains("qwxzvk"), "{text}");
    assert!(
        !text.contains(&dirs::home_dir().unwrap().display().to_string()),
        "no home path: {text}"
    );
    assert_eq!(
        std::fs::metadata(&log).unwrap().permissions().mode() & 0o777,
        0o600
    );
    // A log created earlier with a looser mode is tightened by init.
    let old = dir.path().join("old.log");
    std::fs::write(&old, "").unwrap();
    std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o644)).unwrap();
    applog::init(&old);
    assert_eq!(
        std::fs::metadata(&old).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn state_file_is_private_atomic_and_tolerates_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let paths = AppPaths::under(&dir.path().join("data"), dir.path());
    let mut s = AppStateFile::default();
    s.acknowledged.insert("openclaw/chat".into());
    s.backups
        .insert("codex".into(), vec!["20260929T101500Z".into()]);
    appstate::save(&paths.state_file, &s).unwrap();
    assert_eq!(
        std::fs::metadata(&paths.state_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(&paths.app_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let back = appstate::load(&paths.state_file);
    assert!(back.acknowledged.contains("openclaw/chat"));
    assert_eq!(back.backups["codex"], ["20260929T101500Z"]);
    std::fs::write(&paths.state_file, "{not json").unwrap();
    assert!(
        appstate::load(&paths.state_file).backups.is_empty(),
        "a corrupt file reads as empty, never as a panic"
    );
}

#[test]
fn state_key_is_private_random_and_stable() {
    let dir = tempfile::tempdir().unwrap();
    let paths = AppPaths::under(&dir.path().join("data"), dir.path());
    let a = appstate::load_or_create_key(&paths.state_key).unwrap();
    let b = appstate::load_or_create_key(&paths.state_key).unwrap();
    assert_eq!(a.len(), 32);
    assert_eq!(*a, *b, "the key survives a restart");
    assert_eq!(
        std::fs::metadata(&paths.state_key)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[tokio::test]
async fn update_state_persists() {
    let m = MockDaemon::start().await;
    let dir = tempfile::tempdir().unwrap();
    let (ctx, _) = Ctx::for_tests(
        AppPaths::under(&dir.path().join("data"), dir.path()),
        m.client(),
    );
    ctx.update_state(|s| s.prefs.first_run_done = true).unwrap();
    assert!(appstate::load(&ctx.paths.state_file).prefs.first_run_done);
}

#[test]
fn kind_labels_never_admit_a_value() {
    use inumaki_app_lib::error::kind_ok;
    for ok in [
        "PERSON",
        "IBAN",
        "EMAIL",
        "CUSTOMER_ID",
        "STREET_ADDRESS",
        "SECRET",
        "K2",
    ] {
        assert!(kind_ok(ok), "{ok}");
    }
    for bad in [
        "4366412345",
        "AT611904300234573201",
        "",
        "person",
        "_X",
        "PERSON qwxzvk",
        &"A".repeat(33),
    ] {
        assert!(!kind_ok(bad), "{bad}");
    }
}

#[test]
fn a_corrupt_state_file_is_kept_for_the_backup_ids_it_holds() {
    let dir = tempfile::tempdir().unwrap();
    let paths = AppPaths::under(&dir.path().join("data"), dir.path());
    std::fs::create_dir_all(&paths.app_dir).unwrap();
    std::fs::write(&paths.state_file, "{not json").unwrap();
    assert!(appstate::load(&paths.state_file).backups.is_empty());
    let kept = paths.state_file.with_file_name("state.json.corrupt");
    assert_eq!(std::fs::read_to_string(&kept).unwrap(), "{not json");
    assert_eq!(
        std::fs::metadata(&kept).unwrap().permissions().mode() & 0o777,
        0o600
    );
    appstate::save(&paths.state_file, &AppStateFile::default()).unwrap();
    assert_eq!(
        std::fs::read_to_string(&kept).unwrap(),
        "{not json",
        "a later save does not overwrite it"
    );
}

#[tokio::test]
async fn a_failed_save_leaves_the_in_memory_state_unchanged() {
    let m = MockDaemon::start().await;
    let dir = tempfile::tempdir().unwrap();
    let paths = AppPaths::under(&dir.path().join("data"), dir.path());
    let (ctx, _) = Ctx::for_tests(paths.clone(), m.client());
    // A regular file where the directory should be: the save cannot succeed.
    std::fs::create_dir_all(paths.app_dir.parent().unwrap()).unwrap();
    std::fs::remove_dir_all(&paths.app_dir).ok();
    std::fs::write(&paths.app_dir, "x").unwrap();
    assert!(ctx.update_state(|s| s.prefs.first_run_done = true).is_err());
    assert!(!ctx.state().prefs.first_run_done);
}

#[tokio::test]
async fn no_key_means_no_server_keys() {
    let m = MockDaemon::start().await;
    let dir = tempfile::tempdir().unwrap();
    let paths = AppPaths::under(&dir.path().join("data"), dir.path());
    // The key's directory is a file: no key can be created.
    std::fs::create_dir_all(paths.state_key.parent().unwrap().parent().unwrap()).unwrap();
    std::fs::write(paths.state_key.parent().unwrap(), "x").unwrap();
    let (ctx, _) = Ctx::for_tests(paths, m.client());
    assert_eq!(ctx.state_key().unwrap_err().kind, "state_unwritable");
}

/// The socket follows `[daemon] socket` of the data directory's config, the
/// data directory does not move with it, and an unreadable file is an error
/// the app reports (naming the file, not its content) instead of a quiet
/// fall back to the default socket (D1, amendment b).
#[tokio::test]
async fn socket_follows_the_config_file_and_a_bad_one_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    assert_eq!(
        AppPaths::under(&data, dir.path()).socket,
        data.join("inumakid.sock")
    );

    std::fs::write(
        data.join("inumaki.toml"),
        "[daemon]\nsocket = \"/run/x/custom.sock\"\n",
    )
    .unwrap();
    let paths = AppPaths::under(&data, dir.path());
    assert_eq!(paths.socket, std::path::PathBuf::from("/run/x/custom.sock"));
    assert_eq!(paths.data_dir, data);
    assert_eq!(paths.bin_dir, data.join("bin"));
    assert!(paths.config_error.is_none());

    std::fs::write(data.join("inumaki.toml"), "SECRET-TEXT = = [").unwrap();
    let paths = AppPaths::under(&data, dir.path());
    let why = paths.config_error.clone().expect("a bad file is reported");
    assert!(why.contains("inumaki.toml"), "{why}");
    assert!(!why.contains("SECRET-TEXT"), "{why}");
    assert_ne!(paths.socket, data.join("inumakid.sock"));
    // Even with a daemon answering on the client's socket, the poll reports
    // the service as unreachable.
    let m = MockDaemon::start().await;
    let (ctx, _) = Ctx::for_tests(paths, m.client());
    assert!(!inumaki_app_lib::poll::fetch(&ctx).await.reachable);
}
