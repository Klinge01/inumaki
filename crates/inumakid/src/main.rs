//! `inumakid`: run the inumaki service in the foreground.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use inumakid::StartOptions;

/// inumaki service: models loaded once, encrypted token vault, control API.
#[derive(Parser)]
#[command(name = "inumakid", version, about)]
struct Args {
    #[command(subcommand)]
    cmd: Option<Sub>,
    /// TOML config (engine tables plus the daemon's); default: <data dir>/inumaki.toml if it exists, else the embedded default.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Data directory (default: INUMAKI_DATA_DIR or the platform data dir).
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// Socket path (default: [daemon] socket inside the data directory).
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Models directory (default: INUMAKI_MODELS_DIR or the platform data dir).
    #[arg(long)]
    models_dir: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Sub {
    /// The end-to-end check's canary MCP server (started by the daemon itself).
    #[command(hide = true)]
    CanaryMcp {
        /// The check's 0600 identity file.
        #[arg(long)]
        fixture: PathBuf,
    },
}

fn main() -> ExitCode {
    let a = Args::parse();
    if let Some(Sub::CanaryMcp { fixture }) = a.cmd {
        return ExitCode::from(inumakid::check::canary_mcp::run(&fixture));
    }
    ExitCode::from(inumakid::run::run(StartOptions {
        config: a.config,
        data_dir: a.data_dir,
        socket: a.socket,
        models_dir: a.models_dir,
        clock: None,
    }))
}
