//! Path states from a harness's files and the caller's `SystemState`
//! (spec §4.6). Green is Protected mode's; the best Easy-mode state is
//! `Connected` (yellow).

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::detect::is_executable;
use crate::harness::{HOOK_MARKER, dataset_of_url};
use crate::model::*;

/// Some drift item of `role` lies at or under `path`.
pub fn drifted(drift: &[DriftItem], role: FileRole, path: &[String]) -> bool {
    drift.iter().any(|d| {
        d.role == role
            && (d.path.is_empty() || d.path.starts_with(path) || path.starts_with(&d.path))
    })
}

/// MCP: every entry points at the gateway or was left unprotected, and each
/// gateway entry's dataset has a running upstream.
pub fn mcp_state(servers: &[McpServerEntry], sys: &SystemState, drift_here: bool) -> PathState {
    if drift_here {
        return PathState::Broken {
            reason: ReasonCode::ChangedOutsideInumaki,
        };
    }
    let gw: Vec<&McpServerEntry> = servers.iter().filter(|s| s.gateway).collect();
    if gw.is_empty() {
        return PathState::NotConnected { reason: None };
    }
    if !sys.service_up {
        return PathState::Broken {
            reason: ReasonCode::ServiceDown,
        };
    }
    let not_running = gw.iter().any(|s| match &s.transport {
        Transport::Http { url } => dataset_of_url(url, &sys.gateway_base)
            .is_some_and(|d| !sys.datasets_running.contains(&d)),
        Transport::Stdio { .. } => false,
    });
    if not_running {
        return PathState::Broken {
            reason: ReasonCode::UpstreamNotRunning,
        };
    }
    // Preflight F8 (clippy::nonminimal_bool): a server counts when it is a
    // gateway entry, or when the user chose to leave it unprotected.
    let counted = servers
        .iter()
        .filter(|s| s.gateway || !sys.leave_unprotected.contains(&s.name))
        .count();
    PathState::Connected {
        detail: Detail {
            protected: gw.len() as u32,
            total: counted as u32,
            note: None,
        },
    }
}

/// Files: `configured` says the harness's setting names the mirror.
pub fn files_state(
    configured: bool,
    sys: &SystemState,
    drift_here: bool,
    note: Option<ReasonCode>,
) -> PathState {
    if drift_here {
        return PathState::Broken {
            reason: ReasonCode::ChangedOutsideInumaki,
        };
    }
    match &sys.folders {
        None => PathState::NotConnected {
            reason: Some(ReasonCode::MirrorUnavailable),
        },
        Some(_) if !configured => PathState::NotConnected { reason: None },
        Some(f) if f.watching == 0 => PathState::NotConnected {
            reason: Some(ReasonCode::NoFolderConnected),
        },
        Some(f) => PathState::Connected {
            detail: Detail {
                protected: f.watching,
                total: f.watching,
                note,
            },
        },
    }
}

/// Chat: the configured base URL points at `route` and the route is not failing.
pub fn chat_state(
    h: HarnessId,
    base: Option<&str>,
    route: Route,
    sys: &SystemState,
    drift_here: bool,
) -> PathState {
    if drift_here {
        return PathState::Broken {
            reason: ReasonCode::ChangedOutsideInumaki,
        };
    }
    let Some(proxy) = &sys.proxy else {
        return PathState::NotConnected {
            reason: Some(ReasonCode::ProxyUnavailable),
        };
    };
    let Some(r) = proxy.route(route) else {
        return PathState::NotConnected {
            reason: Some(ReasonCode::ProxyUnavailable),
        };
    };
    match base {
        Some(u) if u.starts_with(r.base_url.as_str()) => {
            if r.failing {
                PathState::Broken {
                    reason: ReasonCode::RouteFailing,
                }
            } else {
                let note = (!proxy.clients_seen.contains(&h)).then_some(ReasonCode::NoTrafficYet);
                PathState::Connected {
                    detail: Detail {
                        protected: 0,
                        total: 0,
                        note,
                    },
                }
            }
        }
        _ => PathState::NotConnected {
            reason: Some(ReasonCode::ChatNotProtected),
        },
    }
}

/// The words of a hook command as a POSIX shell splits them, for the
/// plain form inumaki writes (single-quoted words from `sh_quote`, the
/// `'\''` escape, bare words of safe characters). Any other shell syntax
/// (double quotes, `$`, `;`, a pipe, a line continuation) is `None`: that
/// is not a command inumaki wrote.
fn sh_words(s: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_word = true;
                loop {
                    match chars.next()? {
                        '\'' => break,
                        x => cur.push(x),
                    }
                }
            }
            '\\' => {
                in_word = true;
                match chars.next()? {
                    '\n' => return None,
                    x => cur.push(x),
                }
            }
            ' ' | '\t' => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            c if c.is_ascii_alphanumeric() || "-_./:=@%+,".contains(c) => {
                in_word = true;
                cur.push(c);
            }
            _ => return None,
        }
    }
    if in_word {
        words.push(cur);
    }
    Some(words)
}

/// The hook program and `--socket` path of a registered command of the
/// form `'<bin>' <harness> --socket '<socket>'` (what the adapters write);
/// `None` for any other command.
pub fn parse_hook_command(command: &str, h: HarnessId) -> Option<(PathBuf, PathBuf)> {
    match sh_words(command)?.as_slice() {
        [bin, harness, flag, socket] if harness == h.as_str() && flag == "--socket" => {
            Some((PathBuf::from(bin), PathBuf::from(socket)))
        }
        _ => None,
    }
}

/// The `command` of inumaki's handler in a `PostToolUse` array of matcher
/// groups (`[{matcher, hooks: [{type, command, timeout}]}]`, the same shape
/// for Claude Code and Codex): the first handler whose command contains
/// [`HOOK_MARKER`].
pub fn our_hook_command(groups: Option<&Value>) -> Option<&str> {
    groups?.as_array()?.iter().find_map(|g| {
        g.get("hooks")?.as_array()?.iter().find_map(|h| {
            h.get("command")
                .and_then(Value::as_str)
                .filter(|c| c.contains(HOOK_MARKER))
        })
    })
}

/// Two paths name the same file: equal, or equal once symlinks resolve.
fn same_path(a: &Path, b: &Path) -> bool {
    a == b
        || matches!(
            (std::fs::canonicalize(a), std::fs::canonicalize(b)),
            (Ok(x), Ok(y)) if x == y
        )
}

/// Hook (final review I1): the state of the program the harness actually
/// runs, read from the registered command in `groups` (the harness's
/// `PostToolUse` array), not from where inumaki's binaries are now.
/// Missing marker: not installed. A marker without a command inumaki could
/// have written, or a named program that is not an executable file at an
/// absolute path: [`ReasonCode::HookBinaryMissing`] (the harness would run
/// nothing and use the original output). A program or socket other than
/// `sys.hook_binary` / `sys.hook_socket` (when known), or a relative
/// socket: [`ReasonCode::HookOutdated`].
pub fn hook_state(groups: Option<&Value>, h: HarnessId, sys: &SystemState) -> HookState {
    if !groups.is_some_and(|v| v.to_string().contains(HOOK_MARKER)) {
        return HookState::NotInstalled;
    }
    let broken = |reason| HookState::Broken { reason };
    let Some((bin, socket)) = our_hook_command(groups).and_then(|c| parse_hook_command(c, h))
    else {
        return broken(ReasonCode::HookBinaryMissing);
    };
    if !bin.is_absolute() || !is_executable(&bin) {
        return broken(ReasonCode::HookBinaryMissing);
    }
    let moved = sys
        .hook_binary
        .as_deref()
        .is_some_and(|b| !same_path(b, &bin));
    let other_socket = !socket.is_absolute()
        || sys
            .hook_socket
            .as_deref()
            .is_some_and(|s| !same_path(s, &socket));
    if moved || other_socket {
        return broken(ReasonCode::HookOutdated);
    }
    HookState::Installed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hook_commands_parse_only_in_the_form_inumaki_writes() {
        let cmd = format!(
            "{} claude-code --socket {}",
            crate::harness::sh_quote(Path::new("/A pp/it's/inumaki-hook")),
            crate::harness::sh_quote(Path::new("/d/inumakid.sock"))
        );
        assert_eq!(
            parse_hook_command(&cmd, HarnessId::ClaudeCode),
            Some((
                PathBuf::from("/A pp/it's/inumaki-hook"),
                PathBuf::from("/d/inumakid.sock")
            ))
        );
        assert_eq!(parse_hook_command(&cmd, HarnessId::Codex), None);
        for other in [
            "'/b/inumaki-hook' claude-code",
            "'/b/inumaki-hook' claude-code --socket '/s' extra",
            "\"/b/inumaki-hook\" claude-code --socket '/s'",
            "'/b/inumaki-hook' claude-code --socket \"$HOME/s\"",
            "'/b/inumaki-hook' claude-code --socket '/s'; true",
            "'/b/inumaki-hook claude-code --socket /s",
        ] {
            assert_eq!(
                parse_hook_command(other, HarnessId::ClaudeCode),
                None,
                "{other}"
            );
        }
    }
}
