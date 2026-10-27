#![cfg(feature = "harness-tests")]
//! Real harness runs (M6 spec §11): run locally where Claude Code or Codex
//! is installed, against a throwaway daemon with M5 and M8 whose socket is
//! in INUMAKI_HARNESS_SOCKET (M6-3 Task 9b starts it). Synthetic data
//! only; the harnesses run with temporary configuration directories.

use std::sync::Arc;

use inumaki_app_lib::check::run;
use inumaki_app_lib::ctx::Ctx;
use inumaki_app_lib::paths::AppPaths;
use inumaki_client::{ActivityQuery, Client, FrontDoor, PathStatus, Verdict};

#[tokio::test]
async fn every_installed_harness_passes_the_check() {
    let socket = std::env::var("INUMAKI_HARNESS_SOCKET").expect("INUMAKI_HARNESS_SOCKET");
    let root = tempfile::tempdir().unwrap();
    let home = dirs::home_dir().unwrap();
    let mut paths = AppPaths::under(&root.path().join("data"), &home);
    // The hook gets `--socket` from `ctx.paths.socket`: it must name the
    // throwaway daemon, the same socket the client talks to.
    paths.socket = std::path::PathBuf::from(&socket);
    let (ctx, _) = Ctx::for_tests(paths.clone(), Client::new(&paths.socket));
    // `Ctx::for_tests` fixes the login PATH to `/usr/bin:/bin`, which hides
    // `node` from npm- and brew-installed harnesses (Codex is a
    // `#!/usr/bin/env node` script: `env: node: No such file`, exit 127,
    // before any request reaches the proxy). Use the real process PATH.
    let ctx = ctx.with_login_path(Arc::new(|| std::env::var("PATH").ok()));
    // Detection only: the real adapters look at the real home; nothing is applied.
    let ctx = ctx.with_harnesses(inumaki_app_lib::harness::adapt::all(&paths));
    // Detection is cached (M6-2 Task 4b): detect once before listing.
    ctx.harnesses.iter().for_each(|o| o.refresh());
    let hook = std::env::var_os("INUMAKI_HOOK_BIN").map(std::path::PathBuf::from);
    let found: Vec<_> = inumaki_app_lib::harness::detected(&ctx)
        .into_iter()
        .filter(|d| d.binary.is_some())
        .map(|mut d| {
            d.connected = true;
            d.hook_command = hook.clone();
            d
        })
        .collect();
    assert!(!found.is_empty(), "no harness installed");
    let expected = found.len() + 1;
    let run = run::run_with(&ctx, found).await.unwrap();
    // A skipped harness run (proxy not running) must not pass as success.
    assert_eq!(run.warning, None, "the harness runs were skipped");
    assert_eq!(
        run.reports.len(),
        expected,
        "the direct run plus one per harness"
    );
    for r in run.reports.iter().skip(1) {
        let h = r.harness.unwrap();
        // How the harness process ended (a closed set, no output).
        let exit = run.runs.iter().find(|i| i.harness == h).map(|i| i.exit);
        assert_eq!(
            r.results.gateway.status,
            PathStatus::Passed,
            "{h:?}: {:?} exit {exit:?}",
            r.results.gateway
        );
        assert_eq!(
            r.results.proxy.status,
            PathStatus::Passed,
            "{h:?}: {:?} exit {exit:?}",
            r.results.proxy
        );
        assert!(
            !r.results.proxy.canary_in_upstream,
            "{h:?}: the Bash cat of the source file leaked"
        );
    }
    if hook.is_some() {
        // Review C2: the hook ran and substituted tokens for the Bash output;
        // a block message would also keep the canary out, but proves nothing.
        let acts = ctx
            .client
            .activity(&ActivityQuery {
                dataset: None,
                since: None,
                limit: Some(500),
            })
            .await
            .unwrap();
        let hook_records: Vec<_> = acts
            .records
            .iter()
            .filter(|r| r.front_door == FrontDoor::Hook)
            .collect();
        // Counts by verdict only. A `pass` writes no record: the daemon's
        // `hook action=… tool=… root_match=…` lines and its
        // `check harness requests … bash=…` line say whether the Bash call
        // ran, was denied (`Error`), or reached the hook at all.
        let count = |v: Verdict| hook_records.iter().filter(|r| r.verdict == v).count();
        let (released, blocked) = (count(Verdict::Released), count(Verdict::Blocked));
        assert!(
            released > 0,
            "the hook replaced the output with tokens: hook records released={released} \
             blocked={blocked} total={}; see the daemon log's `bash=` line",
            hook_records.len()
        );
        assert!(
            hook_records.iter().all(|r| r.verdict != Verdict::Blocked),
            "the hook blocked instead of tokenizing"
        );
    }
}
