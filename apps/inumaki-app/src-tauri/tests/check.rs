//! The app's check runner (M6 spec §8.2, §6.6; Review Focus 1 and 3).
//! Every harness here is `/bin/sh`; no installed harness ever runs.

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use inumaki_adapters::{CheckPlan, Invocation};
use inumaki_app_lib::check::{run, tmp};
use inumaki_app_lib::ctx::Ctx;
use inumaki_app_lib::harness::Detected;
use inumaki_app_lib::harness::ops::*;
use inumaki_app_lib::paths::AppPaths;
use inumaki_client::mock::{Canned, MockDaemon};
use inumaki_client::{CheckReport, HarnessId};

const CANARY: &str = "Record: Qwendolin Zyxwuria, IBAN AT61 1904 3002 3457 3201";
const CHECK: &str = "0123456789abcdef0123456789abcdef";

fn ctx(root: &Path, m: &MockDaemon) -> Ctx {
    let (ctx, _) = Ctx::for_tests(
        AppPaths::under(&root.join("data"), &root.join("home")),
        m.client(),
    );
    ctx
}

fn sh(root: &Path, script: &str, timeout: Duration) -> Invocation {
    Invocation {
        program: "/bin/sh".into(),
        args: vec!["-c".into(), script.into()],
        env: vec![("CANARY".into(), CANARY.into())],
        cwd: root.to_path_buf(),
        files: vec![],
        timeout,
    }
}

fn harness_body(m: &MockDaemon) -> serde_json::Value {
    m.requests()
        .into_iter()
        .find(|q| q.route == "/v1/check/{id}/harness")
        .unwrap()
        .body
        .unwrap()
}

/// Review Focus 1.
#[test]
fn leftover_check_dirs_are_removed_at_start() {
    let root = tempfile::tempdir().unwrap();
    let paths = AppPaths::under(&root.path().join("data"), &root.path().join("home"));
    std::fs::create_dir_all(tmp::root(&paths).join("abc").join("config")).unwrap();
    tmp::sweep(&paths);
    assert!(!tmp::root(&paths).exists());
    let dirs = tmp::create(&paths, CHECK, "claude-code").unwrap();
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&dirs.config)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let r = dirs.root.clone();
    drop(dirs);
    assert!(!r.exists(), "CheckDirs removes itself on drop");
    assert!(
        tmp::create(&paths, "../escape", "codex").is_err(),
        "a check id never steers the directory"
    );
}

/// Review Focus 3.
#[tokio::test]
async fn harness_output_never_reaches_the_app_log_or_state() {
    let m = MockDaemon::start().await;
    let root = tempfile::tempdir().unwrap();
    let c = ctx(root.path(), &m);
    inumaki_app_lib::applog::init(&c.paths.log_file);
    let (r, _) = run::run_invocation(
        &c,
        CHECK,
        HarnessId::ClaudeCode,
        &sh(
            root.path(),
            "printf '%s' \"$CANARY\"",
            Duration::from_secs(5),
        ),
    )
    .await
    .unwrap();
    assert_eq!(r.id, CHECK);
    assert_eq!(
        harness_body(&m)["output"],
        CANARY,
        "the output goes to the daemon, and only there"
    );
    run::remember(&c, Some(HarnessId::ClaudeCode), &r).unwrap();
    for f in [&c.paths.log_file, &c.paths.state_file] {
        let text = std::fs::read_to_string(f).unwrap_or_default();
        assert!(
            !text.contains("Zyxwuria") && !text.contains("AT61"),
            "{}: {text}",
            f.display()
        );
    }
    assert!(
        std::fs::read_to_string(&c.paths.state_file)
            .unwrap()
            .contains("claude-code"),
        "the verdict is remembered under the harness key"
    );
}

/// The invocation's environment is the whole environment.
#[tokio::test]
async fn the_harness_inherits_no_environment() {
    let m = MockDaemon::start().await;
    let root = tempfile::tempdir().unwrap();
    let c = ctx(root.path(), &m);
    run::run_invocation(
        &c,
        CHECK,
        HarnessId::Codex,
        &sh(
            root.path(),
            "printf '%s|%s' \"${HOME-unset}\" \"${USER-unset}\"",
            Duration::from_secs(5),
        ),
    )
    .await
    .unwrap();
    assert_eq!(harness_body(&m)["output"], "unset|unset");
}

#[tokio::test]
async fn a_hung_harness_is_killed_at_its_timeout_with_its_children() {
    let m = MockDaemon::start().await;
    let root = tempfile::tempdir().unwrap();
    let c = ctx(root.path(), &m);
    let pidfile = root.path().join("child.pid");
    let script = format!("sleep 30 & echo $! > '{}'; wait", pidfile.display());
    let t = Instant::now();
    run::run_invocation(
        &c,
        CHECK,
        HarnessId::Codex,
        &sh(root.path(), &script, Duration::from_millis(500)),
    )
    .await
    .unwrap();
    assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
    std::thread::sleep(Duration::from_millis(200));
    let child = std::fs::read_to_string(&pidfile)
        .unwrap()
        .trim()
        .to_string();
    let alive = std::process::Command::new("/bin/kill")
        .args(["-0", &child])
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap()
        .success();
    assert!(!alive, "the harness's own children die with it");
    assert_eq!(
        harness_body(&m)["exit_code"],
        -2,
        "timeout is reported as exit code -2"
    );
}

#[tokio::test]
async fn output_beyond_the_cap_is_drained_not_blocking() {
    let m = MockDaemon::start().await;
    let root = tempfile::tempdir().unwrap();
    let c = ctx(root.path(), &m);
    let t = Instant::now();
    run::run_invocation(
        &c,
        CHECK,
        HarnessId::Codex,
        &sh(
            root.path(),
            "head -c 3000000 /dev/zero | tr '\\0' a",
            Duration::from_secs(10),
        ),
    )
    .await
    .unwrap();
    assert!(t.elapsed() < Duration::from_secs(5));
    let posted = harness_body(&m);
    assert_eq!(
        posted["exit_code"], 0,
        "the harness finished instead of stalling on a full pipe"
    );
    assert_eq!(posted["output"].as_str().unwrap().len(), run::MAX_OUTPUT);
}

#[tokio::test]
async fn the_check_is_deleted_even_when_a_step_fails() {
    let m = MockDaemon::start().await;
    m.set(
        "POST",
        "/v1/check/{id}/direct",
        Canned::error(500, "internal", "boom", &[]),
    );
    let root = tempfile::tempdir().unwrap();
    let c = ctx(root.path(), &m);
    assert!(run::run_with(&c, Vec::new()).await.is_err());
    assert!(
        m.requests()
            .iter()
            .any(|q| q.method == "DELETE" && q.route == "/v1/check/{id}")
    );
}

/// Cross-lane contract (M6-3 part A): a live check blocks new ones (409, up
/// to the 10-minute TTL when the app lost an earlier create), and `GET
/// /v1/check/{id}` tells "nothing ran yet" from "no such check".
#[tokio::test]
async fn check_errors_keep_their_meaning() {
    let m = MockDaemon::start().await;
    let root = tempfile::tempdir().unwrap();
    let c = ctx(root.path(), &m);
    m.set(
        "POST",
        "/v1/check",
        Canned::error(409, "conflict", "a check is running", &[]),
    );
    let e = run::run_with(&c, Vec::new()).await.unwrap_err();
    assert_eq!(e.kind, "check_running");
    assert!(
        !m.requests().iter().any(|q| q.method == "DELETE"),
        "no id, nothing to delete"
    );
    let get = |msg: &'static str| {
        m.set(
            "GET",
            "/v1/check/{id}",
            Canned::error(404, "not_found", msg, &[]),
        );
        c.client.check_report(CHECK)
    };
    let e = run::check_error(get("no check report yet").await.unwrap_err());
    assert_eq!(e.kind, "check_no_report");
    let e = run::check_error(get("no such check").await.unwrap_err());
    assert_eq!(e.kind, "check_expired");
}

/// The token-bearing configuration files are private, and an invocation
/// cannot write outside an absolute, `..`-free path.
#[tokio::test]
async fn invocation_files_are_private_and_confined() {
    use std::os::unix::fs::PermissionsExt;
    let m = MockDaemon::start().await;
    let root = tempfile::tempdir().unwrap();
    let c = ctx(root.path(), &m);
    let cfg = root.path().join("config");
    std::fs::create_dir_all(&cfg).unwrap();
    let mut inv = sh(root.path(), "true", Duration::from_secs(5));
    inv.files = vec![(cfg.join("check-mcp.json"), "Bearer inumaki_gw_x".into())];
    run::run_invocation(&c, CHECK, HarnessId::ClaudeCode, &inv)
        .await
        .unwrap();
    let meta = std::fs::metadata(cfg.join("check-mcp.json")).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    for bad in [
        std::path::PathBuf::from("relative.json"),
        cfg.join("..").join("escape.json"),
    ] {
        inv.files = vec![(bad, "x".into())];
        let e = run::run_invocation(&c, CHECK, HarnessId::ClaudeCode, &inv)
            .await
            .unwrap_err();
        assert_eq!(e.kind, "check_tmp_unwritable");
    }
    assert!(!root.path().join("escape.json").exists());
}

/// Review I1: a check that ends at once keeps notifications quiet for a
/// few seconds only, not for the longest run it might have been.
#[tokio::test]
async fn a_failed_check_does_not_keep_notifications_quiet() {
    let m = MockDaemon::start().await;
    m.set(
        "POST",
        "/v1/check",
        Canned::error(409, "conflict", "a check is running", &[]),
    );
    let root = tempfile::tempdir().unwrap();
    let c = ctx(root.path(), &m);
    run::run_with(&c, Vec::new()).await.unwrap_err();
    let now = inumaki_app_lib::poll::now();
    let until = c.quiet_until.load(std::sync::atomic::Ordering::Relaxed);
    // Quiet past the next hidden-window poll (45 s), far short of the
    // up-front window of a full run (255 s).
    let after = run::quiet_after();
    assert!(after >= 45, "{after}");
    assert!(
        until >= now + after - 1 && until <= now + after + 1,
        "quiet for {} s",
        until - now
    );
}

/// The tray and the window never run two checks at once.
#[tokio::test]
async fn a_second_concurrent_check_is_refused() {
    let m = MockDaemon::start().await;
    m.set(
        "POST",
        "/v1/check/{id}/direct",
        Canned::fixture(200, "check_report").delayed(Duration::from_millis(500)),
    );
    let root = tempfile::tempdir().unwrap();
    let c = ctx(root.path(), &m);
    let (a, b) = tokio::join!(run::run_with(&c, Vec::new()), run::run_with(&c, Vec::new()));
    assert!(a.is_ok());
    assert_eq!(b.unwrap_err().kind, "check_in_progress");
}

// ---- the proxy URLs of a check are used only while the proxy runs ----

/// A harness whose check run is `/bin/sh -c 'touch $MARKER'`: a marker file
/// proves a process ran, and the plan's routes show which URLs reached it.
struct PlanOps {
    inner: Arc<common::FakeOps>,
    marker: PathBuf,
    plans: Mutex<Vec<Vec<(String, String)>>>,
    /// The `path_env` of each plan.
    paths: Mutex<Vec<String>>,
    /// The `source_dir` of each plan.
    source_dirs: Mutex<Vec<Option<PathBuf>>>,
    /// The program and its `sh -c` script (or arguments) and timeout.
    program: String,
    args: Vec<String>,
    timeout: Duration,
    /// Runs when the plan is built, just before the harness starts.
    on_plan: Option<Box<dyn Fn() + Send + Sync>>,
}

impl HarnessOps for PlanOps {
    fn id(&self) -> HarnessId {
        self.inner.id()
    }
    fn name(&self) -> &'static str {
        self.inner.name()
    }
    fn refresh(&self) {}
    fn install(&self) -> Option<InstallInfo> {
        self.inner.install()
    }
    fn active_backup(&self) -> Option<String> {
        self.inner.active_backup()
    }
    fn servers(&self, gateway_base: &str) -> Result<Vec<ServerEntry>, OpError> {
        self.inner.servers(gateway_base)
    }
    fn status(&self, sys: &SystemView) -> CardStatus {
        self.inner.status(sys)
    }
    fn preview(&self, req: &ConnectRequest) -> Result<Vec<FileChange>, OpError> {
        self.inner.preview(req)
    }
    fn apply(&self, req: &ConnectRequest) -> Result<String, OpError> {
        self.inner.apply(req)
    }
    fn revert(&self, backup: &str) -> Result<RevertSummary, OpError> {
        self.inner.revert(backup)
    }
    fn backups(&self) -> Vec<BackupInfo> {
        self.inner.backups()
    }
    fn delete_backup(&self, backup: &str) -> Result<(), OpError> {
        self.inner.delete_backup(backup)
    }
    fn check_invocation(&self, plan: &CheckPlan) -> Option<Invocation> {
        self.plans.lock().unwrap().push(plan.routes.clone());
        self.paths.lock().unwrap().push(plan.path_env.clone());
        self.source_dirs
            .lock()
            .unwrap()
            .push(plan.source_dir.clone());
        if let Some(f) = &self.on_plan {
            f();
        }
        Some(Invocation {
            program: self.program.clone().into(),
            args: self.args.clone(),
            env: vec![("MARKER".into(), self.marker.display().to_string())],
            cwd: plan.workdir.clone(),
            files: vec![],
            timeout: self.timeout,
        })
    }
}

fn plan_ops(root: &Path) -> Arc<PlanOps> {
    Arc::new(PlanOps {
        inner: common::FakeOps::new(HarnessId::ClaudeCode),
        marker: root.join("harness-ran"),
        plans: Mutex::new(Vec::new()),
        paths: Mutex::new(Vec::new()),
        source_dirs: Mutex::new(Vec::new()),
        program: "/bin/sh".into(),
        args: vec!["-c".into(), "touch \"$MARKER\"".into()],
        timeout: Duration::from_secs(5),
        on_plan: None,
    })
}

/// Like [`plan_ops`] with its own marker name and a hook run when its plan is built.
fn plan_ops_with(
    root: &Path,
    marker: &str,
    on_plan: impl Fn() + Send + Sync + 'static,
) -> Arc<PlanOps> {
    Arc::new(PlanOps {
        inner: common::FakeOps::new(HarnessId::ClaudeCode),
        marker: root.join(marker),
        plans: Mutex::new(Vec::new()),
        paths: Mutex::new(Vec::new()),
        source_dirs: Mutex::new(Vec::new()),
        program: "/bin/sh".into(),
        args: vec!["-c".into(), "touch \"$MARKER\"".into()],
        timeout: Duration::from_secs(5),
        on_plan: Some(Box::new(on_plan)),
    })
}

fn connected(ops: &Arc<PlanOps>) -> Detected {
    Detected {
        id: HarnessId::ClaudeCode,
        ops: ops.clone(),
        connected: true,
        binary: None,
        hook_command: None,
    }
}

/// `GET /v1/proxy` as the contract fixture, with `state` and `listen` replaced.
fn proxy_answer(state: &str, listen: &str) -> Canned {
    let mut v: serde_json::Value =
        serde_json::from_slice(&Canned::fixture(200, "proxy").body.unwrap()).unwrap();
    v["state"] = state.into();
    v["listen"] = listen.into();
    Canned::json(200, v)
}

/// `POST /v1/check` as the contract fixture, its one route at `base_url`.
fn created_with(base_url: &str) -> Canned {
    let mut v: serde_json::Value =
        serde_json::from_slice(&Canned::fixture(201, "check_created").body.unwrap()).unwrap();
    v["proxy"]["routes"][0]["base_url"] = base_url.into();
    Canned::json(201, v)
}

/// A refused run: no harness started, no URL reached an adapter, the direct
/// result stayed, the check was deleted, and the fixed warning is shown.
async fn assert_refused(m: &MockDaemon, ops: &PlanOps, reports: &[CheckReport], warning: &str) {
    assert!(!ops.marker.exists(), "no harness process ran");
    assert!(
        ops.plans.lock().unwrap().is_empty(),
        "no plan, so no URL, was built"
    );
    assert_eq!(reports.len(), 1, "the direct result stays");
    assert!(
        !m.requests()
            .iter()
            .any(|q| q.route == "/v1/check/{id}/harness"),
        "nothing was posted for a harness"
    );
    assert!(
        m.requests()
            .iter()
            .any(|q| q.method == "DELETE" && q.route == "/v1/check/{id}"),
        "the check is deleted"
    );
    assert!(!warning.is_empty());
    for leak in [
        "127.0.0.1",
        "8787",
        "9999",
        "evil",
        "check/",
        "0123456789abcdef",
    ] {
        assert!(!warning.contains(leak), "{warning}");
    }
}

/// The daemon hands out proxy routes although the proxy is not listening
/// (bind failed, disabled): whatever holds the port would receive the check
/// conversation and the harness's credentials.
#[tokio::test]
async fn no_harness_runs_against_a_proxy_that_is_not_running() {
    for state in ["bind_failed", "disabled"] {
        let m = MockDaemon::start().await;
        m.set("GET", "/v1/proxy", proxy_answer(state, "127.0.0.1:8787"));
        let root = tempfile::tempdir().unwrap();
        let c = ctx(root.path(), &m);
        let ops = plan_ops(root.path());
        let out = run::run_with(&c, vec![connected(&ops)]).await.unwrap();
        assert_refused(&m, &ops, &out.reports, out.warning.unwrap_or_default()).await;
    }
}

/// Running, but a route points somewhere other than the proxy's own listen
/// address: another loopback port, a non-loopback host, a userinfo trick,
/// another scheme.
#[tokio::test]
async fn no_harness_runs_against_a_route_that_is_not_the_proxy_address() {
    for url in [
        "http://127.0.0.1:9999/check/0123456789abcdef0123456789abcdef/anthropic",
        "http://evil.example:8787/check/0123456789abcdef0123456789abcdef/anthropic",
        "http://10.0.0.5:8787/check/0123456789abcdef0123456789abcdef/anthropic",
        "http://127.0.0.1:8787@evil.example/check/0123456789abcdef0123456789abcdef/anthropic",
        "https://127.0.0.1:8787/check/0123456789abcdef0123456789abcdef/anthropic",
    ] {
        let m = MockDaemon::start().await;
        m.set(
            "GET",
            "/v1/proxy",
            proxy_answer("running", "127.0.0.1:8787"),
        );
        m.set("POST", "/v1/check", created_with(url));
        let root = tempfile::tempdir().unwrap();
        let c = ctx(root.path(), &m);
        let ops = plan_ops(root.path());
        let out = run::run_with(&c, vec![connected(&ops)]).await.unwrap();
        assert_refused(&m, &ops, &out.reports, out.warning.unwrap_or_default()).await;
    }
    // A listen address that is not a loopback socket address is refused even
    // when the routes agree with it (`localhost` is resolved by the harness
    // itself, so it names no address the proxy bound).
    for listen in ["10.0.0.5:8787", "localhost:8787"] {
        let m = MockDaemon::start().await;
        m.set("GET", "/v1/proxy", proxy_answer("running", listen));
        m.set(
            "POST",
            "/v1/check",
            created_with(&format!(
                "http://{listen}/check/0123456789abcdef0123456789abcdef/anthropic"
            )),
        );
        let root = tempfile::tempdir().unwrap();
        let c = ctx(root.path(), &m);
        let ops = plan_ops(root.path());
        let out = run::run_with(&c, vec![connected(&ops)]).await.unwrap();
        assert_refused(&m, &ops, &out.reports, out.warning.unwrap_or_default()).await;
    }
}

/// The status cannot be read: fail closed.
#[tokio::test]
async fn no_harness_runs_when_the_proxy_status_is_unreadable() {
    let m = MockDaemon::start().await;
    m.set(
        "GET",
        "/v1/proxy",
        Canned::error(500, "internal", "boom", &[]),
    );
    let root = tempfile::tempdir().unwrap();
    let c = ctx(root.path(), &m);
    let ops = plan_ops(root.path());
    let out = run::run_with(&c, vec![connected(&ops)]).await.unwrap();
    assert_refused(&m, &ops, &out.reports, out.warning.unwrap_or_default()).await;
}

/// Positive control: running, loopback, the route is the listen address.
#[tokio::test]
async fn a_harness_runs_against_the_running_proxys_own_loopback_address() {
    let m = MockDaemon::start().await;
    let root = tempfile::tempdir().unwrap();
    let c = ctx(root.path(), &m);
    let ops = plan_ops(root.path());
    let out = run::run_with(&c, vec![connected(&ops)]).await.unwrap();
    assert!(ops.marker.exists(), "the harness ran");
    assert_eq!(out.reports.len(), 2);
    assert_eq!(out.warning, None);
    let plans = ops.plans.lock().unwrap();
    assert_eq!(plans.len(), 1);
    assert!(plans[0][0].1.starts_with("http://127.0.0.1:8787/check/"));
}

/// The proxy stops listening while the first harness runs: the second one
/// does not start, its plan (and so its URLs) is never built, the first
/// report stays, and the fixed warning is set.
#[tokio::test]
async fn a_refusal_between_harness_runs_stops_the_remaining_ones() {
    let m = Arc::new(MockDaemon::start().await);
    let root = tempfile::tempdir().unwrap();
    let c = ctx(root.path(), &m);
    let flip = Arc::clone(&m);
    let first = plan_ops_with(root.path(), "first-ran", move || {
        flip.set(
            "GET",
            "/v1/proxy",
            proxy_answer("bind_failed", "127.0.0.1:8787"),
        );
    });
    let second = plan_ops_with(root.path(), "second-ran", || {});
    let out = run::run_with(&c, vec![connected(&first), connected(&second)])
        .await
        .unwrap();
    assert!(first.marker.exists(), "the first harness ran");
    assert!(!second.marker.exists(), "the second harness did not run");
    assert!(
        second.plans.lock().unwrap().is_empty(),
        "no plan, so no URL, was built for the second"
    );
    assert_eq!(out.reports.len(), 2, "the direct result and the first run");
    let warning = out.warning.expect("the fixed warning is set");
    assert!(!warning.is_empty());
    for leak in ["127.0.0.1", "8787", "check/"] {
        assert!(!warning.contains(leak), "{warning}");
    }
}

/// A `PlanOps` whose run is `program args...` with `timeout`.
fn plan_ops_running(root: &Path, program: &str, args: &[&str], timeout: Duration) -> Arc<PlanOps> {
    Arc::new(PlanOps {
        inner: common::FakeOps::new(HarnessId::ClaudeCode),
        marker: root.join("harness-ran"),
        plans: Mutex::new(Vec::new()),
        paths: Mutex::new(Vec::new()),
        source_dirs: Mutex::new(Vec::new()),
        program: program.into(),
        args: args.iter().map(|a| (*a).into()).collect(),
        timeout,
        on_plan: None,
    })
}

/// A failed harness run names its cause with a closed set (127 is a
/// shebang interpreter or binary that was not found), and nothing else.
#[tokio::test]
async fn a_harness_run_reports_how_it_ended() {
    use run::ExitClass::*;
    let cases: [(&str, &[&str], Duration, run::ExitClass); 5] = [
        ("/bin/sh", &["-c", "exit 0"], Duration::from_secs(5), Ok),
        (
            "/bin/sh",
            &["-c", "exit 127"],
            Duration::from_secs(5),
            ExitNonzero { code: 127 },
        ),
        (
            "/nonexistent/inumaki-test-harness",
            &[],
            Duration::from_secs(5),
            CouldNotStart,
        ),
        (
            "/bin/sh",
            &["-c", "kill -9 $$"],
            Duration::from_secs(5),
            Signaled,
        ),
        (
            "/bin/sh",
            &["-c", "sleep 30"],
            Duration::from_millis(300),
            TimedOut,
        ),
    ];
    for (program, args, timeout, want) in cases {
        let m = MockDaemon::start().await;
        let root = tempfile::tempdir().unwrap();
        let c = ctx(root.path(), &m);
        let ops = plan_ops_running(root.path(), program, args, timeout);
        let out = run::run_with(&c, vec![connected(&ops)]).await.unwrap();
        assert_eq!(
            out.runs,
            vec![run::HarnessRunInfo {
                harness: HarnessId::ClaudeCode,
                exit: want
            }]
        );
        let json = serde_json::to_string(&out.runs).unwrap();
        assert!(
            !json.contains("/bin") && !json.contains("sleep"),
            "no path or text in the closed set: {json}"
        );
    }
}

/// A shebang script finds its interpreter next to the harness's binary:
/// that directory is appended to the login PATH, once, and only when safe.
#[tokio::test]
async fn the_harness_binary_directory_is_appended_to_the_path() {
    let root = tempfile::tempdir().unwrap();
    let run_with_binary = |binary: Option<PathBuf>| {
        let root = root.path().to_path_buf();
        async move {
            let m = MockDaemon::start().await;
            let c = ctx(&root, &m);
            let ops = plan_ops(&root);
            let mut d = connected(&ops);
            d.binary = binary;
            run::run_with(&c, vec![d]).await.unwrap();
            ops.paths.lock().unwrap().clone()
        }
    };
    // The login PATH of `Ctx::for_tests` is `/usr/bin:/bin`.
    let paths = run_with_binary(Some("/opt/homebrew/bin/codex".into())).await;
    assert_eq!(paths, vec!["/usr/bin:/bin:/opt/homebrew/bin".to_string()]);
    let paths = run_with_binary(Some("/usr/bin/codex".into())).await;
    assert_eq!(paths, vec!["/usr/bin:/bin".to_string()], "no duplicate");
    for bad in ["relative/codex", "/opt/a:b/codex", "/opt/a\nb/codex"] {
        let paths = run_with_binary(Some(bad.into())).await;
        assert_eq!(paths, vec!["/usr/bin:/bin".to_string()], "{bad:?}");
    }
    let paths = run_with_binary(None).await;
    assert_eq!(paths, vec!["/usr/bin:/bin".to_string()]);
}

/// M6 spec §9.7 amendment 2026-10-10: the plan carries the daemon's check
/// source directory, and drops one without its shape.
#[tokio::test]
async fn the_plan_carries_the_daemons_source_dir() {
    let fixture: serde_json::Value =
        serde_json::from_slice(&Canned::fixture(201, "check_created").body.unwrap()).unwrap();
    let daemon_dir = fixture["mirror"]["source_dir"]
        .as_str()
        .unwrap()
        .to_string();
    let source_dirs = |source_dir: Option<&str>| {
        let mut v = fixture.clone();
        match source_dir {
            Some(d) => v["mirror"]["source_dir"] = d.into(),
            None => {
                v["mirror"].as_object_mut().unwrap().remove("source_dir");
            }
        }
        async move {
            let m = MockDaemon::start().await;
            m.set("POST", "/v1/check", Canned::json(201, v));
            let root = tempfile::tempdir().unwrap();
            let c = ctx(root.path(), &m);
            let ops = plan_ops(root.path());
            run::run_with(&c, vec![connected(&ops)]).await.unwrap();
            assert!(ops.marker.exists(), "the harness ran");
            ops.source_dirs.lock().unwrap().clone()
        }
    };
    assert_eq!(
        source_dirs(Some(&daemon_dir)).await,
        vec![Some(PathBuf::from(&daemon_dir))]
    );
    // An older daemon sends none.
    assert_eq!(source_dirs(None).await, vec![None]);
    for bad in [
        "/Users/qwxzvk",
        "relative/inumaki-check-ab-x/source",
        "/tmp/inumaki-check-ab-x/../source",
        "/tmp/other-ab-x/source",
    ] {
        assert_eq!(source_dirs(Some(bad)).await, vec![None], "{bad:?}");
    }
}
