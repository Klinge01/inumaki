// Mirrors of the Rust command DTOs (src-tauri/src/commands, harness/cards.rs,
// harness/ops.rs, harness/protect.rs, harness/connect.rs, error.rs) and of the
// inumaki-client types they return. Field names are the serde names. Where the
// merged Rust differs from the plan's first draft, the Rust wins.

/** A command error. `reason` is a fixed code and sentence (e.g. `not_supported`, a refused preview). */
export type CmdError = {
  kind: string;
  status: number | null;
  kinds: string[];
  snippet?: string;
  reason?: Reason;
};
export type HarnessId = "claude-code" | "codex" | "hermes" | "openclaw";
export type ManagedBy = "app" | "homebrew" | "deb" | "manual";
export type PathKind = "mcp" | "files" | "chat";
export type PathState = "not_connected" | "connected" | "unverified" | "unsupported" | "broken";
export type PathStatus = "passed" | "failed" | "not_checked";
export type Reason = { code: string; text: string };
export type Detail = { kind: "protected"; protected: number; total: number };
export type PathView = {
  path: PathKind;
  state: PathState;
  reason: Reason | null;
  detail: Detail | null;
  acknowledged: boolean;
  last_check: PathStatus | null;
};
/** `{"state":"pending","reason":{...}}`; pending and broken carry a fixed reason. */
export type HookState =
  | { state: "not_applicable" }
  | { state: "not_installed" }
  | { state: "installed" }
  | { state: "pending"; reason: Reason }
  | { state: "broken"; reason: Reason };
export type HarnessCard = {
  id: HarnessId;
  name: string;
  binary_found: boolean;
  version: string | null;
  tested: boolean;
  login: "oauth" | "api_key" | "unknown";
  connected: boolean;
  disconnected: boolean;
  paths: PathView[];
  hook: HookState;
  drift: number;
  /** macOS withdrew the app's access to this harness's files (TCC); render a grant-needed state. */
  grant: Reason | null;
  /** Unix seconds of this harness's last check; absent or null without one. */
  last_check_at?: number | null;
};
/** The newest check across harnesses; `failed` when any memo has a failed path. */
export type LastCheck = { at: number; failed: boolean };
export type OverviewView = {
  reachable: boolean;
  managed_by: ManagedBy | null;
  config_error?: string | null;
  cards: HarnessCard[];
  last_check?: LastCheck | null;
};
/** Lines to add to a harness's own files by hand; fetched on demand, never part of a card. */
export type ManualSetup = { lines: string; note: string };
export type FileChange = { path: string; keys: string[] };
export type RevertSummary = {
  reverted: boolean;
  exact: boolean;
  conflicts: number;
  client_header_left: boolean;
  codex_trust_left: boolean;
  /** The service was not reachable: the gateway token is revoked at its next start, not yet. */
  revocation_pending?: boolean;
};
/**
 * `warning`: fixed text when the chat route was skipped because the proxy was not running.
 * `harness_warnings`: the adapter's fixed reasons about the harness's own settings
 * (`codex_approval_never`) or what the apply installs (`hook_blocks_when_stopped`);
 * closed codes with fixed sentences, never a value from its files.
 */
export type ConnectOutcome = { note: string; warning?: string | null; harness_warnings?: Reason[] };
/** Answer of a data-source change (folders, mailboxes, the Codex opt-in). */
export type DataChange = {
  reconnect_failures: number;
  /** Fixed harness keys (`claude-code`, `codex`, ...). */
  failed_harnesses: string[];
  /** `folder_needs_access` after adding a folder macOS protects. Absent when none. */
  warning?: string;
};
export type OtherClient = {
  gateway: { name: string; url: string }[];
  token: string | null;
  proxy: [string, string][];
  /** `"X-Inumaki-Client: <value>"`, or null when the proxy serves none. */
  client_header: string | null;
  /** Fixed text: the proxy was not running, so no base URL and no header are offered. */
  proxy_warning?: string | null;
};
export type ContractState = "ready" | "none" | "invalid" | "drift";
export type ServerRow = {
  /** Opaque; every server command takes it (two scopes can share a name). */
  id: string;
  harness: HarnessId;
  name: string;
  scope: "user" | "project";
  transport: "stdio" | "http";
  protected: boolean;
  /** Protect is on but the harness file does not point at the gateway yet. */
  pending: boolean;
  dataset: string | null;
  contract: ContractState | null;
  upstream_state: string | null;
  restarts: number | null;
  upstream: string | null;
  left_unprotected: boolean;
  cannot_protect: string | null;
};
/** `harness_warnings`: the connect's fixed reasons (`codex_approval_never`, `hook_blocks_when_stopped`). */
export type ProtectOutcome = {
  dataset: string;
  reused: boolean;
  note: string;
  warning: Reason | null;
  harness_warnings?: Reason[];
};
export type UnprotectOutcome = { unreferenced_dataset: string | null; note: string };
export type ServiceView = {
  reachable: boolean;
  version: string | null;
  managed_by: ManagedBy | null;
  restart_required: boolean;
  bin_dir: string | null;
  /** The config file that names the socket cannot be used; starting the service would not help. */
  config_error?: string | null;
};
export type ModelFile = { model: string; path: string; bytes_done: number; bytes_total: number; verified: boolean };
export type ModelsJob = {
  state: "idle" | "running" | "done" | "failed";
  started_at: number | null;
  files: ModelFile[];
  error: "network" | "hash_mismatch" | "disk" | "manifest" | null;
  restart_required: boolean;
};
/** One poll of the model download: whether the app restarted its own service, else who must. */
export type ModelsPoll = { job: ModelsJob; restarted: boolean; restart_by: ManagedBy | null };
export type PathResult = {
  status: PathStatus;
  reason: string | null;
  upstream_requests: number;
  canary_in_upstream: boolean;
  tokens_seen: boolean;
  rehydrated_in_output: boolean;
};
export type CheckResults = { gateway: PathResult; mirror: PathResult; proxy: PathResult };
export type CheckReport = { id: string; harness: HarnessId | null; results: CheckResults };
/** `warning` is fixed text when the harness runs were skipped (proxy not running); never a URL or port. */
/** How a harness process ended: a closed set, no output, URL or path. */
export type ExitClass =
  | { kind: "ok" }
  | { kind: "exit_nonzero"; code: number }
  | { kind: "could_not_start" }
  | { kind: "signaled" }
  | { kind: "timed_out" };
export type HarnessRunInfo = { harness: HarnessId; exit: ExitClass };
export type CheckRun = {
  reports: CheckReport[];
  /** Absent in older builds; one entry per harness that ran. */
  runs?: HarnessRunInfo[];
  warning: string | null;
};
export type DatasetRow = { id: string; name: string; kind: "generic" | "mailbox" | "folder" };
/** Harness key → the user's chat choice; a harness without one is absent (also after a Revert). */
export type Prefs = { first_run_done: boolean; chat_opt_in: Partial<Record<HarnessId, boolean>> };
/** What the `prefs` command answers: the stored choices plus the chat value in effect per harness. */
export type PrefsView = Prefs & {
  /** The value each harness's chat switch stands for: the user's choice when there is one; else whether the active backup holds the chat route. */
  chat_effective: Partial<Record<HarnessId, boolean>>;
};

// Activity (inumaki-client types/activity.rs, types/journal.rs; commands/activity.rs)
export type ActivityRecord = {
  id: string;
  at: number;
  dataset: string;
  front_door: string;
  upstream: string | null;
  direction: string;
  verdict: string;
  checks: string[];
  kinds: { kind: string; count: number }[];
  tripwire: boolean;
  bytes: number;
  released: string | null;
};
export type ActivityList = { records: ActivityRecord[] };
export type ActivityVerify = { records: number; ok: boolean };
export type JournalEntry = { id: string; at: number; bytes: number; released: string };
/** `payload` holds originals only when `show_values` (a reveal); it may not be valid JSON, so render it as text. */
export type JournalRecord = JournalEntry & { payload: string; show_values: boolean; unresolved: number; label: string };
/** `original` only in a reveal. */
export type Entity = {
  token: string;
  kind: string;
  first_use: number;
  last_use: number;
  uses: number;
  epoch_id: number;
  current_epoch: boolean;
  original?: string;
};
/** `purge_pending`: the mapping is gone, the daemon's log purge still runs (a success, not "0 forgotten"). */
export type ForgetOutcome = { kinds: string[]; tokens: number; rows: number; purge_pending: boolean };

// Inspect & recover (types/engine.rs; commands/inspect.rs)
export type InspectSpan = { start: number; end: number; kind: string; action: string; source: string; original?: string };
export type InspectBody = {
  label: string;
  outcome: string;
  profile: string;
  retried: boolean;
  /** Offsets are UTF-8 bytes into InspectView.text. */
  spans: InspectSpan[];
  reasons: { kind: string; check: string }[];
  replacements: number;
  candidate?: string;
  limitations: string[];
  expiry: { rotation_days: number; grace_days: number; epoch_started_at: number };
};
/** `text` is the NFC form the daemon inspected: the view shows and slices exactly this string. */
export type InspectView = { text: string; body: InspectBody };
export type Redaction = { start: number; end: number; kind: string; action: "tokenize" | "remove" };
export type SanitizeResponse = {
  outcome: string;
  text: string;
  replacements: number;
  kinds: string[];
  reasons: { kind: string; check: string }[];
  cached: boolean;
  latency_ms: number;
};

// Email, Folders, Settings (commands/email.rs, folders.rs, settings.rs; measured.rs)
export type MailboxPreset = "gmail" | "outlook" | "generic";
/** What a mailbox card shows: no password, no vault secret name. */
export type MailboxView = {
  preset: MailboxPreset;
  imap_host: string;
  imap_port: number;
  imap_tls: boolean;
  username: string;
  drafts_folder: string | null;
  from_address: string | null;
  handles: number;
};
/** `mailbox` is null when the daemon could not read it. */
export type MailboxCard = { dataset: string; display_name: string; entry_name: string; mailbox: MailboxView | null };
export type MailboxCheck = {
  folders: number;
  drafts_folder_resolved: boolean;
  drafts_folder_will_be_created: boolean;
  drafts_folder_configured: boolean;
};
/** The Add form. `password` is sent once and never kept (see views/Email.tsx). */
export type MailboxForm = {
  preset: MailboxPreset;
  username: string;
  password: string;
  imap_host?: string;
  imap_port?: number;
  display_name: string;
};
export type MailboxAdded = { card: MailboxCard; reconnect_failures: number; failed_harnesses: string[] };
export type FolderState = "scanning" | "watching" | "stopped" | "failed" | "pending";
export type FolderRow = {
  dataset: string;
  /** The user's own source directory. */
  source: string;
  /** The sanitized mirror directory (local path, shown to the local user only). */
  mirror: string;
  /** The agent-writable outbox inside the mirror (local path). */
  outbox: string;
  /** Where restored outbox files go (local path); "" when unknown (older service). */
  outbox_destination: string;
  state: FolderState;
  /** Fixed code and sentence of a failed folder. */
  error: Reason | null;
  files: { source: number; mirrored: number; blocked: number; unsupported: number; pending: number };
  outbox_files: { rehydrated: number; with_unresolved: number; pending: number };
  /** Unix seconds. */
  last_mirrored_at: number | null;
  remirror_pending: boolean;
};
export type FoldersView = { mirror_root: string; folders: FolderRow[] };
export type Measured = {
  profile: string;
  docs: number;
  leak_docs: number;
  accepted_leak_docs: number;
  p50_ms: number;
  p95_ms: number;
  platform: string;
  commit: string;
  /** Integer unix seconds. */
  evaluated_at: number;
};
export type BackupRow = {
  harness: string;
  /** `created_at` is null when the id's time cannot be read ("unknown"). */
  backup: { id: string; created_at: number | null };
  /** The live Connect backup: Revert restores it; it is not deletable. */
  live: boolean;
};
export type SettingsView = {
  version: string;
  profiles: { name: string; available: boolean; reason?: string }[];
  backups: BackupRow[];
  app_log: string;
  measured: Measured[];
  updates: string;
  /** state.json is the source of truth for the controlled inputs. */
  prefs: Prefs;
};
