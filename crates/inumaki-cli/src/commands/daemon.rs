//! `inumaki daemon`: the service in the foreground.

use std::path::PathBuf;

use anyhow::Result;
use inumakid::StartOptions;

pub fn run(
    config: Option<PathBuf>,
    data_dir: Option<PathBuf>,
    socket: Option<PathBuf>,
    models_dir: Option<PathBuf>,
) -> Result<u8> {
    Ok(inumakid::run::run(StartOptions {
        config,
        data_dir,
        socket,
        models_dir,
        clock: None,
    }))
}
