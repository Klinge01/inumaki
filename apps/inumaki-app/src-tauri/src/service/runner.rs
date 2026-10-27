//! External programs (launchctl, systemctl, xattr, codesign) behind a
//! trait, so tests record the argv instead of changing the machine. Output
//! is discarded: it can contain paths, and nothing here needs it.

use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Mutex, PoisonError};

/// Exit status of one run.
#[derive(Debug, Clone, Copy)]
pub struct RunOutput {
    /// Exit code; `None` when killed by a signal.
    pub code: Option<i32>,
}

impl RunOutput {
    /// Exit code 0.
    pub fn ok(&self) -> bool {
        self.code == Some(0)
    }
}

/// Runs a program to completion.
pub trait Runner: Send + Sync {
    /// Run `program` with `args`; stdin, stdout, and stderr are null.
    fn run(&self, program: &Path, args: &[String]) -> std::io::Result<RunOutput>;
}

/// The real runner. Only `Ctx::new` (the production constructor) uses it.
pub struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&self, program: &Path, args: &[String]) -> std::io::Result<RunOutput> {
        let st = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        Ok(RunOutput { code: st.code() })
    }
}

/// Refuses every call: the default of `Ctx::for_tests`, so no test can run
/// launchctl, systemctl, xattr, or codesign by accident.
pub struct FailingRunner;

impl Runner for FailingRunner {
    fn run(&self, _program: &Path, _args: &[String]) -> std::io::Result<RunOutput> {
        Err(std::io::Error::other("no external programs in tests"))
    }
}

/// Records every call and answers exit 0.
#[derive(Default)]
pub struct RecordingRunner {
    calls: Mutex<Vec<Vec<String>>>,
}

impl RecordingRunner {
    /// Calls so far, each as `[program, args…]`.
    pub fn calls(&self) -> Vec<Vec<String>> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Runner for RecordingRunner {
    fn run(&self, program: &Path, args: &[String]) -> std::io::Result<RunOutput> {
        let mut v = vec![program.display().to_string()];
        v.extend(args.iter().cloned());
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(v);
        Ok(RunOutput { code: Some(0) })
    }
}
