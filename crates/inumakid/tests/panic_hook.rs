//! The daemon's panic hook (M5, Task 8b): a panic whose message quotes
//! content (an `unwrap` of an error that carries the text prints it) leaves
//! only a fixed line and the source location on stderr. The check runs in a child
//! process (this test binary again), so the hook and stderr are its own.

use std::process::Command;

const CHILD: &str = "INUMAKI_PANIC_HOOK_CHILD";
const CANARY: &str = "Zyxwuria Quolnath AT61 1904 3002 3457 3201";

/// Child side: does nothing unless the parent set [`CHILD`]. Panics on a
/// worker thread the way a mirror worker would (an `unwrap` of an error that
/// carries the text; std's `str` slicing message no longer quotes the string
/// since Rust 1.99), then exits 0 so the harness prints nothing of its own.
#[test]
fn child_panics_with_content() {
    let Ok(mode) = std::env::var(CHILD) else {
        return;
    };
    if mode == "hook" {
        inumakid::run::install_panic_hook();
    }
    let text = format!("Kunde {CANARY}");
    let r = std::thread::spawn(move || {
        let parsed: Result<usize, String> = std::hint::black_box(Err(text));
        parsed.unwrap()
    })
    .join();
    assert!(r.is_err(), "the unwrap panicked");
    std::process::exit(0);
}

fn run_child(mode: &str) -> String {
    let out = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "child_panics_with_content",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, mode)
        .env("RUST_BACKTRACE", "1")
        .output()
        .unwrap();
    assert!(out.status.success(), "child exited normally");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn a_panic_message_never_reaches_stderr() {
    // Control: without the hook the default one prints the content, so the
    // test would see a leak.
    let leaked = run_child("default");
    assert!(leaked.contains("Zyxwuria"), "control: {leaked}");
    let err = run_child("hook");
    assert!(!err.contains("Zyxwuria") && !err.contains("3457"), "{err}");
    assert!(err.contains(inumakid::run::PANIC_LINE), "{err}");
    assert!(err.contains("panic_hook.rs:"), "the location stays: {err}");
}
