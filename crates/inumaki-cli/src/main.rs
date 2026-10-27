//! `inumaki` command line tool.
#![allow(clippy::print_stdout, clippy::print_stderr)]

mod client;
mod commands;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// Local privacy engine: detect, tokenize, verify, rehydrate.
#[derive(Parser)]
#[command(name = "inumaki", version, about)]
struct Cli {
    /// Path to a TOML config. Default: `<data dir>/inumaki.toml` if it exists (the
    /// file the daemon reads), else the embedded `configs/default.toml`. `eval` and
    /// `bench` (except `--via-daemon`) measure the embedded config unless given one.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Profile name inside the config (see configs/default.toml). Defaults to
    /// `support-email` for `scan`/`tokenize`/`eval`/`bench`; an override for
    /// `sanitize`, the dataset's or the daemon's default profile otherwise.
    #[arg(long, global = true)]
    profile: Option<String>,
    /// Directory holding downloaded models (default: INUMAKI_MODELS_DIR or the platform data dir).
    #[arg(long, global = true)]
    models_dir: Option<PathBuf>,
    /// Daemon socket (default: [daemon] socket inside the data directory).
    #[arg(long, global = true)]
    socket: Option<PathBuf>,
    /// Data directory of the daemon (default: INUMAKI_DATA_DIR or the platform data dir).
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Connect an agent harness (Claude Code, Codex, Hermes, OpenClaw) to inumaki.
    Connect {
        #[command(subcommand)]
        action: commands::connect::ConnectAction,
    },
    /// Print detected spans (kind, offsets, confidence, source, text).
    Scan {
        /// Emit JSON instead of a table.
        #[arg(long)]
        json: bool,
        /// Detect as text of this origin: `free` (default) or `harness-static`.
        #[arg(long, value_parser = ["free", "harness-static"])]
        origin: Option<String>,
        /// File path, or `-` for stdin.
        input: PathBuf,
    },
    /// Print the sanitized text. One-shot: mappings are discarded, not restorable through the
    /// daemon. Use `sanitize` for restorable output.
    Tokenize {
        /// Print the token → original mapping to stderr. Deliberate plaintext diagnostic output.
        #[arg(long)]
        map: bool,
        /// File path, or `-` for stdin.
        input: PathBuf,
    },
    /// List, download, or verify NER models.
    Models {
        #[command(subcommand)]
        action: ModelsAction,
    },
    /// Measure detection recall, leak rate, verifier error rates and latency.
    Eval {
        /// Read documents from a JSONL corpus instead of cases + generated mails.
        #[arg(long)]
        corpus: Option<PathBuf>,
        /// Evaluate the corpus as text of this origin: `free` (default),
        /// `harness-static` (system-prompt text; rulings L98, L103), or
        /// `file-name` (file or directory name stems; ruling S3). Only
        /// with `--corpus` on the mail track, not with `--via-service`.
        #[arg(long, value_parser = ["free", "harness-static", "file-name"], requires = "corpus", conflicts_with = "via_service")]
        origin: Option<String>,
        /// Leave out the built-in hand-written cases.
        #[arg(long)]
        no_cases: bool,
        /// Number of generated mails.
        #[arg(long, default_value_t = commands::eval::DEFAULT_GENERATE)]
        generate: usize,
        /// Generator seed.
        #[arg(long, default_value_t = commands::eval::DEFAULT_SEED)]
        seed: u64,
        /// Generate without noise transforms.
        #[arg(long)]
        no_transforms: bool,
        /// Skip verifier trials.
        #[arg(long)]
        no_verifier_trials: bool,
        /// Print the report as JSON.
        #[arg(long)]
        json: bool,
        /// Fail with exit code 4 when the result regresses against this baseline.
        #[arg(long)]
        baseline: Option<PathBuf>,
        /// Write the result as a new baseline file.
        #[arg(long)]
        write_baseline: Option<PathBuf>,
        /// Write the evaluated corpus as JSONL: synthetic and hand-written case text by
        /// default, or the user's own corpus text verbatim when `--corpus` is given.
        #[arg(long)]
        dump_corpus: Option<PathBuf>,
        /// Fail with exit code 5 when the result misses these absolute targets.
        #[arg(long)]
        targets: Option<PathBuf>,
        /// Write the full JSON report (counts, rates, provenance) to this file.
        #[arg(long)]
        report_json: Option<PathBuf>,
        /// Write one line `id outcome` per evaluated document, in corpus order
        /// (`pass`, `uncertain` or `blocked`; `+residue` when released text kept
        /// a gold value). Ids only, never text. Mail track only.
        #[arg(long)]
        outcomes: Option<PathBuf>,
        /// Evaluate the pinned held-out corpus (200 documents, second generator family, seed 4242) instead of cases + generated mails.
        #[arg(long, conflicts_with_all = ["corpus", "cases_only"])]
        held_out: bool,
        /// Evaluate only the built-in hand-written cases (the curated safety suite).
        #[arg(long, conflicts_with = "corpus")]
        cases_only: bool,
        /// Evaluation track: `mail` (support-email corpus) or `tool-json`
        /// (MCP-shaped tool results, M4 spec §16.6).
        #[arg(long, value_parser = ["mail", "tool-json"], default_value = "mail")]
        track: String,
        /// Sanitize through an in-process daemon service path (the same
        /// `sanitize_blocks` the daemon serves, temporary data directory,
        /// file key) instead of a bare engine: measures release-check blocks
        /// and the cache path the gateway uses. One persistent dataset spans
        /// the whole corpus, so its block rate differs from the engine path.
        #[arg(long)]
        via_service: bool,
        /// Persistent-dataset sequences: labeled ambiguity cases through one
        /// dataset of an in-process daemon state, with restarts, a rotation,
        /// cache repeats, and grace expiry (implies --via-service; gate with
        /// `--targets crates/inumaki-eval/targets/sequence.toml`).
        #[arg(
            long,
            conflicts_with_all = ["corpus", "held_out", "cases_only", "baseline", "write_baseline", "dump_corpus"]
        )]
        sequences: bool,
        /// Documents in a `--sequences` run.
        #[arg(long, default_value_t = 300, requires = "sequences")]
        sequence_steps: usize,
        /// Seed of a `--sequences` run.
        #[arg(long, default_value_t = 777, requires = "sequences")]
        sequence_seed: u64,
    },
    /// Measure per-document latency on generated mails.
    Bench {
        /// Number of generated mails.
        #[arg(long, default_value_t = 200)]
        generate: usize,
        /// Generator seed.
        #[arg(long, default_value_t = 42)]
        seed: u64,
        /// Send each document through the running daemon instead of an in-process engine;
        /// reports a cold pass and a warm (cached) pass.
        #[arg(long)]
        via_daemon: bool,
        /// Dataset to use with --via-daemon (default: a temporary dataset,
        /// deleted afterwards). An explicit dataset is NOT cleaned up: the
        /// generated mails' synthetic identities are minted into that
        /// dataset's namespace, its known-entity detector, and its leak-check
        /// working set for the rest of the epoch (review M3). Use a
        /// throwaway dataset id when passing this explicitly.
        #[arg(long)]
        dataset: Option<String>,
        /// Drive an in-process proxy with a scripted model upstream: a
        /// 100 000-token conversation, then 50 turns of about 500 new tokens
        /// (M8 spec §14). Measured, not a gate.
        #[arg(long, conflicts_with_all = ["via_daemon", "dataset"])]
        via_proxy: bool,
        /// Wire for --via-proxy: `messages` (Anthropic, default), `responses`
        /// (OpenAI Responses with Codex-style input items) or `codex` (the
        /// same body to the Codex route).
        #[arg(long, requires = "via_proxy", value_parser = ["messages", "responses", "codex"], default_value = "messages")]
        wire: String,
    },
    /// Run the inumaki service in the foreground (same as the `inumakid` binary).
    Daemon,
    /// Show the daemon's status.
    Status {
        /// Print the raw JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show what happened at the front doors (verdicts, kinds, counts; never values).
    Activity {
        /// Only this dataset.
        #[arg(long)]
        dataset: Option<String>,
        /// Only the last N seconds.
        #[arg(long)]
        since: Option<i64>,
        /// At most N records.
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Print the raw JSON.
        #[arg(long)]
        json: bool,
        /// Verify the record chain instead of listing.
        #[arg(long)]
        verify: bool,
    },
    /// The egress journal: what an agent actually received, tokenized; originals only on a terminal with --show-values.
    Journal {
        #[command(subcommand)]
        action: commands::journal::JournalAction,
    },
    /// Manage datasets (token namespaces) in the daemon's vault.
    Dataset {
        #[command(subcommand)]
        action: DatasetAction,
    },
    /// Connected folders: add, list, status, rescan, remove.
    Folder {
        #[command(subcommand)]
        action: commands::folder::FolderAction,
    },
    /// Manage gateway bearer tokens.
    Gateway {
        #[command(subcommand)]
        action: GatewayAction,
    },
    /// Read-only local diagnostics: vault, models, profiles, datasets, contracts, tokens; fixed reasons and next steps.
    Doctor {
        /// Show one dataset only.
        #[arg(long)]
        dataset: Option<String>,
    },
    /// Sanitize text through the daemon: mappings live in the dataset (rotation and grace
    /// from `inumaki doctor`) or the session (idle expiry from `[daemon] session_ttl`);
    /// losing the vault keys makes every dataset token unrestorable. Exactly one of
    /// --dataset/--session.
    Sanitize {
        /// Dataset id (persistent namespace).
        #[arg(long)]
        dataset: Option<String>,
        /// Session id (in-memory context).
        #[arg(long)]
        session: Option<String>,
        /// Apply the redactions in this JSON file ({input_sha256, spans}) before verification.
        #[arg(long)]
        redactions: Option<PathBuf>,
        /// File path, or `-` for stdin.
        input: PathBuf,
    },
    /// Rehydrate tokens through the daemon. Exactly one of --dataset/--session.
    Rehydrate {
        /// Dataset id.
        #[arg(long)]
        dataset: Option<String>,
        /// Session id.
        #[arg(long)]
        session: Option<String>,
        /// Fail (exit 3, empty stdout) when any placeholder cannot be restored, including
        /// unknown, expired, or foreign tokens and removed-value markers.
        #[arg(long)]
        strict: bool,
        /// File path, or `-` for stdin.
        input: PathBuf,
    },
    /// Run the scripted mail tasks (M4 spec §13.1) against a TEST mailbox: wipes INBOX and the
    /// drafts folder, seeds the deterministic fixture mails, drives search, read, and draft
    /// through the dataset's gateway, verifies every draft over IMAP, and reports completion
    /// and error counts. WIPES the INBOX and drafts folder of the --user account: use a
    /// dedicated test account that the dataset's mailbox was configured with.
    MailTasks(commands::mail_tasks::Args),
    /// Inspect text locally: what would be detected, what would be done, why it would be
    /// blocked. Never sends anything, never creates mappings. Metadata by default.
    Inspect {
        /// Dataset id.
        #[arg(long)]
        dataset: String,
        /// Print the candidate text and original excerpts (requires a terminal).
        #[arg(long)]
        show_values: bool,
        /// Redactions JSON file to apply first.
        #[arg(long)]
        redactions: Option<PathBuf>,
        /// File path, or `-` for stdin.
        input: PathBuf,
    },
    /// The end-to-end check's canary MCP server (started by the daemon).
    #[command(hide = true)]
    CanaryMcp {
        /// The check's 0600 identity file.
        #[arg(long)]
        fixture: PathBuf,
    },
}

/// Actions for `inumaki dataset`.
#[derive(Subcommand)]
pub(crate) enum DatasetAction {
    /// Create a dataset.
    Add {
        /// Slug, [a-z0-9-]{1,64}.
        id: String,
        /// Display name.
        #[arg(long)]
        name: String,
        /// Profile (default: the daemon's default profile).
        #[arg(long)]
        profile: Option<String>,
        /// Epoch length in days (1..=365, default 30).
        #[arg(long)]
        rotation_days: Option<u32>,
        /// Grace period in days (0..=90, default 7).
        #[arg(long)]
        grace_days: Option<u32>,
    },
    /// List datasets.
    List,
    /// Delete a dataset with all its tokens.
    Remove {
        /// Slug.
        id: String,
    },
    /// Close the current epoch and start a new one.
    Rotate {
        /// Slug.
        id: String,
    },
    /// Configure a draft-only mailbox for a dataset (created as kind mailbox when it does not
    /// exist), then check the connection. The app password is read from --password-file or
    /// prompted without echo; never pass it on the command line.
    AddMailbox(commands::mailbox::AddArgs),
    /// Connect to the dataset's mailbox and report the folder count and drafts-folder readiness.
    CheckMailbox {
        /// Dataset id.
        id: String,
    },
    /// Remove the dataset's mailbox, its stored password, its mail handles, and the mail upstream.
    RemoveMailbox {
        /// Dataset id.
        id: String,
    },
    /// Manage the wrapped MCP servers of a dataset.
    Upstream {
        #[command(subcommand)]
        action: UpstreamAction,
    },
    /// List the entities a dataset knows: tokens with kind, first and last store use, use count.
    /// Originals only on a terminal with --show-values.
    Entities {
        /// Slug.
        id: String,
        /// Print the originals (requires a terminal).
        #[arg(long)]
        show_values: bool,
        /// At most N entities.
        #[arg(long, default_value_t = 200)]
        limit: usize,
        /// Print the raw JSON.
        #[arg(long)]
        json: bool,
    },
    /// Forget one entity: its mappings in every epoch, its known-entity entry, and cached results.
    /// The next mention mints a fresh token; journal entries show the old token as unresolved.
    Forget {
        /// Slug.
        id: String,
        /// The token to forget (from `dataset entities`).
        #[arg(long, conflicts_with = "value")]
        token: Option<String>,
        /// Read the original from a no-echo prompt (never from the command line) and resolve it
        /// through the index.
        #[arg(long)]
        value: bool,
    },
}

/// Actions for `inumaki dataset upstream`.
// `Add` carries every flag of the subcommand and dwarfs the other variants;
// clap constructs one value per invocation, never in a hot path.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
pub(crate) enum UpstreamAction {
    /// Add a wrapped server. Creates the dataset with profile `strict` when it does not exist.
    /// Secret values are never taken from the command line: name them with --secret-env / --secret-header
    /// (prompted without echo) or put them in a JSON file with --secret-env-file / --secret-headers-file.
    /// `--stdio` must be the last flag on the command line: every token after it — the child program
    /// and all its arguments, including ones that look like flags of this command (`-y`, `--verbose`,
    /// even `--http`) — is taken verbatim as the child's argv. Put every other flag before `--stdio`.
    Add {
        /// Dataset id.
        dataset: String,
        /// Upstream name, [a-z0-9_-]{1,64}.
        name: String,
        /// Child process: program followed by its arguments.
        #[arg(
            long,
            num_args = 1..,
            value_name = "CMD",
            conflicts_with = "http",
            allow_hyphen_values = true
        )]
        stdio: Vec<String>,
        /// Streamable HTTP server URL.
        #[arg(long, value_name = "URL")]
        http: Option<String>,
        /// Non-secret environment variable KEY=VALUE (stdio).
        #[arg(long, value_name = "K=V")]
        env: Vec<String>,
        /// Non-secret header NAME=VALUE (http).
        #[arg(long, value_name = "K=V")]
        header: Vec<String>,
        /// Working directory (stdio).
        #[arg(long)]
        cwd: Option<String>,
        /// The reviewed field contract (JSON file).
        #[arg(long, value_name = "FILE")]
        content_policy: Option<PathBuf>,
        /// Secret environment variable name; its value is prompted without echo.
        #[arg(long, value_name = "KEY")]
        secret_env: Vec<String>,
        /// JSON object file of secret environment variables (mode 0600 recommended).
        #[arg(long, value_name = "FILE")]
        secret_env_file: Option<PathBuf>,
        /// Secret header name; its value is prompted without echo.
        #[arg(long, value_name = "NAME")]
        secret_header: Vec<String>,
        /// JSON object file of secret headers.
        #[arg(long, value_name = "FILE")]
        secret_headers_file: Option<PathBuf>,
    },
    /// List a dataset's upstreams.
    List {
        /// Dataset id.
        dataset: String,
    },
    /// Remove an upstream and its secrets.
    Remove {
        /// Dataset id.
        dataset: String,
        /// Upstream name.
        name: String,
    },
    /// Record the upstream's current schema fingerprint as reviewed (after checking the contract still fits).
    AcceptSchema {
        /// Dataset id.
        dataset: String,
        /// Upstream name.
        name: String,
        /// Fingerprint to record; defaults to the one `status` shows for the running upstream.
        #[arg(long)]
        fingerprint: Option<String>,
    },
}

/// Actions for `inumaki gateway token`.
#[derive(Subcommand)]
pub(crate) enum GatewayAction {
    /// Bearer tokens for the TCP listener.
    Token {
        #[command(subcommand)]
        action: TokenAction,
    },
}

/// Token actions.
#[derive(Subcommand)]
pub(crate) enum TokenAction {
    /// Mint a token; printed once, never stored in clear.
    New {
        /// Label, 1 to 64 printable characters.
        label: String,
    },
    /// List tokens (labels and timestamps).
    List,
    /// Revoke a token by id.
    Revoke {
        /// Id from `list`.
        id: i64,
    },
}

/// Actions for `inumaki models`.
#[derive(Subcommand)]
pub(crate) enum ModelsAction {
    /// Show pinned models, licenses, and local status.
    List,
    /// Download models (default: all default models).
    Pull {
        /// Model names from the manifest.
        names: Vec<String>,
    },
    /// Re-hash local model files against the manifest.
    Verify,
}

/// Exit codes shared by all commands.
pub(crate) mod exit {
    pub const OK: u8 = 0;
    pub const USAGE: u8 = 2;
    pub const BLOCKED: u8 = 3;
    pub const REGRESSION: u8 = 4;
    pub const TARGET_MISSED: u8 = 5;
}

/// Whether a command without `--config` reads `<data dir>/inumaki.toml`.
/// `eval` and local `bench` runs measure the shipped configuration their
/// baselines and targets pin; the canary is the daemon's own child.
fn reads_data_dir_config(cmd: &Cmd) -> bool {
    !matches!(
        cmd,
        Cmd::Eval { .. }
            | Cmd::Bench {
                via_daemon: false,
                ..
            }
            | Cmd::CanaryMcp { .. }
    )
}

/// The origin a validated `--origin` value names; `free` when absent.
fn origin_arg(o: Option<&str>) -> inumaki_core::TextOrigin {
    o.and_then(inumaki_core::TextOrigin::from_label)
        .unwrap_or_default()
}

fn main() -> ExitCode {
    let mut cli = Cli::parse();
    if reads_data_dir_config(&cli.cmd) {
        let data_dir = inumakid::dirs::resolve_data_dir(cli.data_dir.as_deref());
        match inumakid::config::config_path(cli.config.as_deref(), &data_dir) {
            Ok(p) => cli.config = p,
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(exit::USAGE);
            }
        }
    }
    let profile = cli.profile.as_deref().unwrap_or("support-email");
    let result = match cli.cmd {
        Cmd::Scan {
            json,
            origin,
            input,
        } => commands::scan::run(
            cli.config.as_deref(),
            profile,
            cli.models_dir.as_deref(),
            &input,
            json,
            origin_arg(origin.as_deref()),
        ),
        Cmd::Tokenize { map, input } => commands::tokenize::run(
            cli.config.as_deref(),
            profile,
            cli.models_dir.as_deref(),
            &input,
            map,
        ),
        Cmd::Models { action } => {
            commands::models::run(cli.config.as_deref(), cli.models_dir.as_deref(), action)
        }
        Cmd::Eval {
            corpus,
            origin,
            no_cases,
            generate,
            seed,
            no_transforms,
            no_verifier_trials,
            json,
            baseline,
            write_baseline,
            dump_corpus,
            targets,
            report_json,
            outcomes,
            held_out,
            cases_only,
            track,
            via_service,
            sequences,
            sequence_steps,
            sequence_seed,
        } => commands::eval::run(
            cli.config.as_deref(),
            profile,
            cli.models_dir.as_deref(),
            commands::eval::EvalArgs {
                corpus,
                origin: origin_arg(origin.as_deref()),
                no_cases,
                generate,
                seed,
                no_transforms,
                no_verifier_trials,
                json,
                baseline,
                write_baseline,
                dump_corpus,
                targets,
                report_json,
                outcomes,
                held_out,
                cases_only,
                track,
                via_service,
                sequences,
                sequence_steps,
                sequence_seed,
            },
        ),
        Cmd::Bench {
            generate,
            seed,
            via_daemon,
            dataset,
            via_proxy,
            wire,
        } => {
            if via_proxy {
                commands::bench_proxy::run(
                    cli.config.as_deref(),
                    profile,
                    cli.models_dir.as_deref(),
                    seed,
                    &wire,
                )
            } else if via_daemon {
                commands::bench::run_via_daemon(
                    cli.socket.as_deref(),
                    cli.data_dir.as_deref(),
                    cli.config.as_deref(),
                    dataset.as_deref(),
                    generate,
                    seed,
                )
            } else {
                commands::bench::run(
                    cli.config.as_deref(),
                    profile,
                    cli.models_dir.as_deref(),
                    generate,
                    seed,
                )
            }
        }
        Cmd::Daemon => commands::daemon::run(
            cli.config.clone(),
            cli.data_dir.clone(),
            cli.socket.clone(),
            cli.models_dir.clone(),
        ),
        Cmd::Status { json } => commands::status::run(
            cli.socket.as_deref(),
            cli.data_dir.as_deref(),
            cli.config.as_deref(),
            json,
        ),
        Cmd::Activity {
            dataset,
            since,
            limit,
            json,
            verify,
        } => commands::activity::run(
            cli.socket.as_deref(),
            cli.data_dir.as_deref(),
            cli.config.as_deref(),
            dataset,
            since,
            limit,
            json,
            verify,
        ),
        Cmd::Journal { action } => commands::journal::run(
            cli.socket.as_deref(),
            cli.data_dir.as_deref(),
            cli.config.as_deref(),
            action,
        ),
        Cmd::Dataset { action } => commands::dataset::run(
            cli.socket.as_deref(),
            cli.data_dir.as_deref(),
            cli.config.as_deref(),
            action,
        ),
        Cmd::Folder { action } => commands::folder::run(
            cli.socket.as_deref(),
            cli.data_dir.as_deref(),
            cli.config.as_deref(),
            action,
        ),
        Cmd::Gateway { action } => commands::gateway::run(
            cli.socket.as_deref(),
            cli.data_dir.as_deref(),
            cli.config.as_deref(),
            action,
        ),
        Cmd::Doctor { dataset } => commands::doctor::run(
            cli.socket.as_deref(),
            cli.data_dir.as_deref(),
            cli.config.as_deref(),
            dataset.as_deref(),
        ),
        Cmd::Sanitize {
            dataset,
            session,
            redactions,
            input,
        } => commands::sanitize::run(
            cli.socket.as_deref(),
            cli.data_dir.as_deref(),
            cli.config.as_deref(),
            dataset.as_deref(),
            session.as_deref(),
            cli.profile.as_deref(),
            redactions.as_deref(),
            &input,
        ),
        Cmd::Rehydrate {
            dataset,
            session,
            strict,
            input,
        } => commands::rehydrate::run(
            cli.socket.as_deref(),
            cli.data_dir.as_deref(),
            cli.config.as_deref(),
            dataset.as_deref(),
            session.as_deref(),
            strict,
            &input,
        ),
        Cmd::Connect { action } => commands::connect::run(
            cli.socket.as_deref(),
            cli.data_dir.as_deref(),
            cli.config.as_deref(),
            action,
        ),
        Cmd::MailTasks(args) => commands::mail_tasks::run(
            cli.socket.as_deref(),
            cli.data_dir.as_deref(),
            cli.config.as_deref(),
            args,
        ),
        Cmd::Inspect {
            dataset,
            show_values,
            redactions,
            input,
        } => commands::inspect::run(
            cli.socket.as_deref(),
            cli.data_dir.as_deref(),
            cli.config.as_deref(),
            &dataset,
            cli.profile.as_deref(),
            show_values,
            redactions.as_deref(),
            &input,
        ),
        // Its own exit codes; stdout carries MCP frames only.
        Cmd::CanaryMcp { fixture } => return commands::canary_mcp::run(&fixture),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(exit::USAGE)
        }
    }
}
