//! `inumaki models`: list, pull, verify.

use std::path::Path;

use anyhow::{Result, bail};
use inumaki_models::manifest::{self, FileStatus, HF_BASE, Manifest};

use crate::ModelsAction;
use crate::exit;

pub fn run(config: Option<&Path>, models_dir: Option<&Path>, action: ModelsAction) -> Result<u8> {
    let cfg = super::load_config(config)?;
    let root = manifest::resolve_models_dir(models_dir, cfg.ner.models_dir.as_deref());
    let m = Manifest::embedded();
    match action {
        ModelsAction::List => {
            println!("models dir: {}", root.display());
            for e in &m.models {
                let ok = manifest::quick_check(&root, e);
                println!(
                    "{:<16} {:<17} {:<11} {:<8} {}",
                    e.name,
                    e.kind,
                    e.license,
                    if e.default { "default" } else { "" },
                    if ok { "present" } else { "not present" }
                );
            }
            // `quick_check` only compares file sizes; it does not re-hash. A file with the
            // right size but corrupted content still shows "present" here.
            println!("run `inumaki models verify` to check hashes");
            Ok(exit::OK)
        }
        ModelsAction::Pull { names } => {
            let entries: Vec<_> = if names.is_empty() {
                m.defaults()
            } else {
                let mut v = Vec::new();
                for n in &names {
                    match m.get(n) {
                        Some(e) => v.push(e),
                        None => bail!("unknown model '{n}'; see `inumaki models list`"),
                    }
                }
                v
            };
            for e in entries {
                eprintln!("pulling {} ({}, {})", e.name, e.repo, e.license);
                let mut last = 0u64;
                manifest::pull(&root, e, HF_BASE, &mut |path, done, total| {
                    let pct = done * 100 / total.max(1);
                    if pct >= last + 10 || done == total {
                        eprintln!("  {path}: {pct}%");
                        last = pct;
                    }
                })?;
            }
            eprintln!("models installed in {}", root.display());
            Ok(exit::OK)
        }
        ModelsAction::Verify => {
            let mut bad = false;
            for e in &m.models {
                for (path, st) in manifest::verify(&root, e) {
                    let s = match st {
                        FileStatus::Ok => "ok",
                        FileStatus::Missing => "missing",
                        FileStatus::Corrupt => {
                            bad = true;
                            "CORRUPT"
                        }
                    };
                    println!("{:<16} {:<28} {s}", e.name, path);
                }
            }
            Ok(if bad { exit::USAGE } else { exit::OK })
        }
    }
}
