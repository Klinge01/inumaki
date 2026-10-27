//! The `inumaki-hook` binary: `inumaki-hook claude-code|codex [--socket
//! PATH]`, payload on stdin, replacement on stdout (nothing for pass), exit
//! 0. Without `--socket`, the socket the daemon would use for the default
//! data directory (`INUMAKI_DATA_DIR`, else the platform data dir): the
//! `[daemon] socket` of its `inumaki.toml`, else `inumakid.sock`; an
//! unreadable or invalid file blocks. The adapters always write `--socket`,
//! so the hook calls the same service the app configured.
//!
//! Exit status: 0 whenever the harness is known, also for a block, because
//! both harnesses use the original output on any other status. Malformed
//! arguments after a known harness block every result; an unknown harness
//! prints usage and exits 2 (no output format is known).

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use inumaki_client::{Client, default_data_dir, resolve_socket};
use inumaki_hook::{
    BlockClass, Blocked, DEADLINE, Harness, MAX_STDIN, decode, fail_closed, output, payload,
    run_payload, undecodable,
};

fn usage() -> ExitCode {
    let _ = std::io::stderr().write_all(b"usage: inumaki-hook claude-code|codex [--socket PATH]\n");
    ExitCode::from(2)
}

fn emit(out: Option<String>) -> ExitCode {
    if let Some(s) = out {
        let mut o = std::io::stdout().lock();
        let _ = o.write_all(s.as_bytes());
        let _ = o.write_all(b"\n");
        let _ = o.flush();
    }
    ExitCode::SUCCESS
}

fn blocked(h: Harness, name: Option<&str>, class: BlockClass) -> Option<String> {
    Some(output::block(
        h,
        name,
        &Blocked {
            class,
            kinds: Vec::new(),
        },
    ))
}

fn main() -> ExitCode {
    // Panic messages can hold `Debug` of values: print a fixed line only.
    std::panic::set_hook(Box::new(|_| {
        let _ = std::io::stderr().write_all(b"inumaki-hook: internal error\n");
    }));
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(h) = args.first().and_then(|a| Harness::parse(a)) else {
        return usage();
    };
    let socket: Result<PathBuf, &'static [u8]> =
        match (args.get(1).map(String::as_str), args.get(2), args.len()) {
            (None, _, 1) => resolve_socket(None, &default_data_dir())
                .map_err(|_| &b"inumaki-hook: config file unreadable; output withheld\n"[..]),
            (Some("--socket"), Some(p), 3) => Ok(PathBuf::from(p)),
            _ => Err(&b"inumaki-hook: bad arguments; output withheld\n"[..]),
        };
    let mut buf = Vec::new();
    let read = std::io::stdin()
        .take(MAX_STDIN as u64 + 1)
        .read_to_end(&mut buf);
    if read.is_err() || buf.len() > MAX_STDIN {
        return emit(Some(undecodable(h, &buf, BlockClass::TooLarge)));
    }
    // Decoded before the guarded run so a panic still knows the tool name.
    let Ok(decoded) = std::panic::catch_unwind(|| decode(&buf)) else {
        return emit(Some(undecodable(h, &buf, BlockClass::Internal)));
    };
    let Some(decoded) = decoded else {
        return emit(Some(undecodable(h, &buf, BlockClass::UnparsablePayload)));
    };
    let name: Option<String> = payload::tool_name(&decoded).map(str::to_string);
    let socket = match socket {
        Ok(s) => s,
        Err(msg) => {
            let _ = std::io::stderr().write_all(msg);
            return emit(blocked(h, name.as_deref(), BlockClass::Internal));
        }
    };
    let inner_name = name.clone();
    let out = fail_closed(h, name.as_deref(), move || {
        let Ok(rt) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            return blocked(h, inner_name.as_deref(), BlockClass::Internal);
        };
        rt.block_on(run_payload(h, decoded, &Client::new(socket), DEADLINE))
    });
    emit(out)
}
