//! Finding a harness (spec §4.4). A GUI app does not inherit the shell's
//! `PATH`, so known locations come first and the login shell second, each
//! with a 3-second limit. Only names and presence are read, never a secret.

use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Limit for `--version`, the login shell, and the keychain query.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Environment variables detection may look at: config-directory overrides
/// by value (docs/harness-adapters.md §2: OpenClaw has no
/// `OPENCLAW_CONFIG_DIR`; Task 6 resolves its file from these four), and
/// credential variables by presence only.
const OVERRIDES: &[&str] = &[
    "CLAUDE_CONFIG_DIR",
    "CODEX_HOME",
    "HERMES_HOME",
    "OPENCLAW_CONFIG_PATH",
    "OPENCLAW_STATE_DIR",
    "OPENCLAW_HOME",
    "OPENCLAW_PROFILE",
];
const PRESENCE: &[&str] = &["ANTHROPIC_API_KEY", "OPENAI_API_KEY"];

/// What detection may use. Tests build it over a temporary home.
#[derive(Clone)]
pub struct ProbeEnv {
    /// Home directory.
    pub home: PathBuf,
    /// Selected environment (credential variables map to `""`).
    pub env: BTreeMap<String, String>,
    /// `$SHELL`, for `command -v`.
    pub login_shell: Option<PathBuf>,
    /// Run binaries (`--version`, the login shell, `security`); off in tests.
    pub run_binaries: bool,
    /// The login shell's `PATH`, when the caller has it (a GUI app does not
    /// inherit one with `node`). `version` runs the binary with it, else
    /// with the inherited `PATH`.
    pub login_path: Option<String>,
}

impl std::fmt::Debug for ProbeEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeEnv")
            .field("vars", &self.env.len())
            .field("run_binaries", &self.run_binaries)
            .finish_non_exhaustive()
    }
}

impl ProbeEnv {
    /// The current user's environment.
    pub fn from_process() -> Option<ProbeEnv> {
        let home = PathBuf::from(std::env::var_os("HOME")?);
        let mut env = BTreeMap::new();
        for k in OVERRIDES {
            if let Some(v) = std::env::var_os(k)
                .and_then(|v| v.into_string().ok())
                .filter(|v| !v.is_empty())
            {
                env.insert((*k).to_string(), v);
            }
        }
        for k in PRESENCE {
            if std::env::var_os(k).is_some_and(|v| !v.is_empty()) {
                env.insert((*k).to_string(), String::new());
            }
        }
        let login_shell = std::env::var_os("SHELL").map(PathBuf::from);
        Some(ProbeEnv {
            home,
            env,
            login_shell,
            run_binaries: true,
            login_path: None,
        })
    }

    /// A test environment over `home`: no variables, no binaries run.
    pub fn for_tests(home: &Path) -> ProbeEnv {
        ProbeEnv {
            home: home.to_path_buf(),
            env: BTreeMap::new(),
            login_shell: None,
            run_binaries: false,
            login_path: None,
        }
    }

    /// A config-directory override.
    pub fn var(&self, k: &str) -> Option<&str> {
        self.env
            .get(k)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    }

    /// A variable is set (credentials: presence only).
    pub fn has(&self, k: &str) -> bool {
        self.env.contains_key(k)
    }
}

/// A regular file with an execute bit.
pub fn is_executable(p: &Path) -> bool {
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

fn run(mut cmd: Command) -> Option<(bool, String)> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + PROBE_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    let mut out = String::new();
    child
        .stdout
        .take()?
        .take(4096)
        .read_to_string(&mut out)
        .ok()?;
    Some((status.success(), out))
}

/// The binary `name` (a fixed harness binary name): `extra` paths, the
/// known locations, then the login shell's `command -v`. The fixed host
/// locations (`/opt/homebrew/bin`, `/usr/local/bin`) are skipped when
/// `!env.run_binaries` (preflight C2), so a test never depends on what is
/// actually installed on the machine running it; only paths under the
/// test's own temporary home are considered.
pub fn find_binary(env: &ProbeEnv, name: &str, extra: &[PathBuf]) -> Option<PathBuf> {
    let fixed: Vec<PathBuf> = if env.run_binaries {
        ["/opt/homebrew/bin", "/usr/local/bin"]
            .iter()
            .map(PathBuf::from)
            .collect()
    } else {
        Vec::new()
    };
    let known = fixed.into_iter().chain(
        [
            ".local/bin",
            ".npm-global/bin",
            ".claude/local",
            ".cargo/bin",
        ]
        .iter()
        .map(|d| env.home.join(d)),
    );
    if let Some(p) = extra
        .iter()
        .cloned()
        .chain(known.map(|d| d.join(name)))
        .find(|p| is_executable(p))
    {
        return Some(p);
    }
    if !env.run_binaries {
        return None;
    }
    let shell = env.login_shell.as_ref()?;
    let mut cmd = Command::new(shell);
    cmd.arg("-lc").arg(format!("command -v {name}"));
    let (ok, out) = run(cmd)?;
    let p = PathBuf::from(out.trim());
    (ok && p.is_absolute() && is_executable(&p)).then_some(p)
}

/// `path_env` with the directory of `binary` appended: a shebang script
/// (`#!/usr/bin/env node`) finds its interpreter next to the binary for
/// brew, npm and nvm installs, and a GUI app's `PATH` may be just
/// `/usr/bin:/bin`. Only an absolute directory without `:` or control
/// characters, and not already on the `PATH`.
pub fn with_binary_dir(path_env: &str, binary: Option<&Path>) -> String {
    let Some(dir) = binary.and_then(Path::parent).and_then(Path::to_str) else {
        return path_env.to_string();
    };
    let ok = dir.starts_with('/') && !dir.chars().any(|c| c == ':' || c.is_control());
    if !ok || path_env.split(':').any(|p| p == dir) {
        return path_env.to_string();
    }
    if path_env.is_empty() {
        dir.to_string()
    } else {
        format!("{path_env}:{dir}")
    }
}

/// The first `major.minor[.patch]` in `bin --version`. The child's `PATH`
/// is the login-shell one (else the inherited one) plus `bin`'s directory,
/// so a `node` script finds `node`.
pub fn version(env: &ProbeEnv, bin: &Path) -> Option<String> {
    if !env.run_binaries {
        return None;
    }
    let base = env
        .login_path
        .clone()
        .unwrap_or_else(|| std::env::var("PATH").unwrap_or_default());
    let mut cmd = Command::new(bin);
    cmd.arg("--version")
        .env("PATH", with_binary_dir(&base, Some(bin)));
    let (_, out) = run(cmd)?;
    out.split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .find(|w| w.split('.').filter(|p| !p.is_empty()).count() >= 2)
        .map(str::to_string)
}

fn triple(v: &str) -> (u64, u64, u64) {
    let mut it = v.split('.').map(|p| p.parse::<u64>().unwrap_or(0));
    (
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
    )
}

/// `min <= v <= max` by numeric components.
pub fn version_in(v: &str, min: &str, max: &str) -> bool {
    (triple(min)..=triple(max)).contains(&triple(v))
}

/// A macOS keychain item exists (its data is never requested: no `-w`, and
/// both stdout and stderr are discarded; existence is the exit status
/// alone, preflight C6).
pub fn keychain_item_exists(env: &ProbeEnv, service: &str) -> bool {
    if !env.run_binaries || !cfg!(target_os = "macos") {
        return false;
    }
    let mut cmd = Command::new("/usr/bin/security");
    cmd.arg("find-generic-password").arg("-s").arg(service);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let Ok(mut child) = cmd.spawn() else {
        return false;
    };
    let deadline = Instant::now() + PROBE_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(s)) => return s.success(),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn script(path: &Path, body: &str) {
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn version_finds_the_interpreter_next_to_the_binary() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("codex");
        script(&bin, "#!/bin/sh\nexec fakenode\n");
        script(
            &dir.path().join("fakenode"),
            "#!/bin/sh\necho codex-cli 0.1.2\n",
        );
        let mut env = ProbeEnv::for_tests(dir.path());
        env.run_binaries = true;
        // A Finder-like PATH without the binary's directory.
        env.login_path = Some("/usr/bin:/bin".into());
        assert_eq!(version(&env, &bin).as_deref(), Some("0.1.2"));
    }

    #[test]
    fn with_binary_dir_rules() {
        let bin = |d: &str| PathBuf::from(d).join("codex");
        let add = |p: &str, d: &str| with_binary_dir(p, Some(&bin(d)));
        assert_eq!(add("/usr/bin", "/opt/n/bin"), "/usr/bin:/opt/n/bin");
        assert_eq!(add("", "/opt/n/bin"), "/opt/n/bin");
        // Already present: unchanged.
        assert_eq!(
            add("/opt/n/bin:/usr/bin", "/opt/n/bin"),
            "/opt/n/bin:/usr/bin"
        );
        // Rejected: ':' or a control character in the directory, or not absolute.
        assert_eq!(add("/usr/bin", "/opt/a:b"), "/usr/bin");
        assert_eq!(add("/usr/bin", "/opt/a\nb"), "/usr/bin");
        assert_eq!(add("/usr/bin", "rel/bin"), "/usr/bin");
        assert_eq!(with_binary_dir("/usr/bin", None), "/usr/bin");
    }
}
