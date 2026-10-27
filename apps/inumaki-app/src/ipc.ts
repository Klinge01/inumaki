// Typed wrappers over the Tauri commands in src-tauri/src/ipc.rs. Argument
// keys are camelCase: Tauri converts the Rust snake_case parameter names.
// The UI holds no socket, file, or shell access: every path is one of these.
import { invoke } from "@tauri-apps/api/core";
import type {
  ActivityList,
  ActivityVerify,
  CheckRun,
  CmdError,
  ConnectOutcome,
  DataChange,
  DatasetRow,
  Entity,
  FileChange,
  FoldersView,
  ForgetOutcome,
  HarnessId,
  InspectView,
  JournalEntry,
  JournalRecord,
  ManualSetup,
  MailboxAdded,
  MailboxCheck,
  MailboxForm,
  MailboxPreset,
  MailboxCard,
  ModelsJob,
  ModelsPoll,
  OtherClient,
  OverviewView,
  PathKind,
  PrefsView,
  ProtectOutcome,
  Redaction,
  RevertSummary,
  SanitizeResponse,
  ServerRow,
  ServiceView,
  SettingsView,
  UnprotectOutcome,
} from "./types";

export type { CmdError } from "./types";

export function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  return invoke<T>(cmd, args);
}

/** A rejected `invoke` is the serialized `CmdError`; anything else becomes a generic one. */
export function asCmdError(e: unknown): CmdError {
  if (typeof e === "object" && e !== null && typeof (e as CmdError).kind === "string") {
    const c = e as CmdError;
    return { ...c, kinds: Array.isArray(c.kinds) ? c.kinds : [], status: c.status ?? null };
  }
  return { kind: "error", status: null, kinds: [] };
}

export function isNotAvailable(e: unknown): boolean {
  return typeof e === "object" && e !== null && (e as CmdError).kind === "not_available";
}

// Overview and harnesses
export const overview = () => call<OverviewView>("overview");
export const refresh = () => call<OverviewView>("refresh");
export const acknowledge = (harness: HarnessId, path: PathKind) => call<void>("acknowledge", { harness, path });
export const manualSetup = (harness: HarnessId) => call<ManualSetup | null>("manual_setup", { harness });
export const previewConnect = (harness: HarnessId) => call<FileChange[]>("preview_connect", { harness });
export const connect = (harness: HarnessId) => call<ConnectOutcome>("connect", { harness });
export const revert = (harness: HarnessId) => call<RevertSummary>("revert", { harness });
export const reconnect = (harness: HarnessId) => call<ConnectOutcome>("reconnect", { harness });
export const otherClient = () => call<OtherClient>("other_client");
export const revokeOtherClient = () => call<void>("revoke_other_client");
export const setChatOptIn = (harness: HarnessId, on: boolean) => call<DataChange>("set_chat_opt_in", { harness, on });

// MCP servers: `id` is ServerRow.id (opaque), never the name.
export const mcpServers = () => call<ServerRow[]>("mcp_servers");
export const protect = (harness: HarnessId, id: string) => call<ProtectOutcome>("protect", { harness, id });
export const unprotect = (harness: HarnessId, id: string) => call<UnprotectOutcome>("unprotect", { harness, id });
export const removeProtectedDataset = (dataset: string) => call<void>("remove_protected_dataset", { dataset });
export const leaveUnprotected = (harness: HarnessId, id: string, on: boolean) =>
  call<void>("leave_unprotected", { harness, id, on });
export const acceptSchema = (dataset: string, upstream: string) => call<void>("accept_schema", { dataset, upstream });

// Settings, first run
export const serviceInfo = () => call<ServiceView>("service_info");
export const modelsStatus = () => call<ModelsJob>("models_status");
// The service and the model download (M6-3): only a service the app installed is ever changed.
export const serviceInstall = () => call<void>("service_install");
export const serviceRemove = () => call<void>("service_remove");
export const serviceRestart = () => call<void>("service_restart");
export const modelsPullStart = () => call<ModelsJob>("models_pull_start");
export const modelsPullPoll = () => call<ModelsPoll>("models_pull_poll");
// The end-to-end check (M6-3): reports carry statuses, reason codes, and booleans only.
export const runCheck = () => call<CheckRun>("run_check");
export const prefs = () => call<PrefsView>("prefs");
export const setFirstRunDone = () => call<void>("set_first_run_done");
export const datasets = () => call<DatasetRow[]>("datasets");

// Activity. `reveal`/`showValues` true is the one way originals reach the UI:
// only from an explicit click, into a useReveal hook.
export const activity = (dataset: string | null, limit: number) => call<ActivityList>("activity", { dataset, limit });
export const verifyActivity = () => call<ActivityVerify>("verify_activity");
export const journal = (dataset: string) => call<{ entries: JournalEntry[] }>("journal", { dataset, since: null });
export const journalRecord = (dataset: string, record: string, reveal: boolean) =>
  call<JournalRecord>("journal_record", { dataset, record, reveal });
export const entities = (dataset: string, reveal: boolean) => call<{ entities: Entity[] }>("entities", { dataset, reveal });
export const forgetToken = (dataset: string, token: string) => call<ForgetOutcome>("forget_token", { dataset, token });
export const forgetValue = (dataset: string, value: string) => call<ForgetOutcome>("forget_value", { dataset, value });

// Inspect & recover: the command NFC-normalizes and returns the text the offsets refer to.
export const inspectText = (dataset: string, text: string, showValues: boolean) =>
  call<InspectView>("inspect_text", { dataset, text, showValues });
export const openTextFile = () => call<string | null>("open_text_file");
export const sanitizeWith = (dataset: string, text: string, spans: Redaction[]) =>
  call<SanitizeResponse>("sanitize_with", { dataset, text, spans });

// Email. The password in `addMailbox`/`replaceMailboxPassword` is the one place it crosses the
// IPC: the caller clears its own copy before awaiting (views/Email.tsx).
export const mailboxes = () => call<MailboxCard[]>("mailboxes");
export const addMailbox = (form: MailboxForm) => call<MailboxAdded>("add_mailbox", { form });
export const checkMailbox = (dataset: string) => call<MailboxCheck>("check_mailbox", { dataset });
export const replaceMailboxPassword = (dataset: string, password: string) =>
  call<void>("replace_mailbox_password", { dataset, password });
export const removeMailbox = (dataset: string) => call<DataChange>("remove_mailbox", { dataset });
export const openMailHelp = (preset: MailboxPreset) => call<void>("open_mail_help", { preset });

// Folders. The picker opens in Rust: the UI never passes a path (add) or names one (reveal takes the dataset id).
export const folders = () => call<FoldersView>("folders");
/** `null` when the user cancels the picker. */
export const addFolder = () => call<DataChange | null>("add_folder");
export const rescanFolder = (dataset: string) => call<{ queued: number }>("rescan_folder", { dataset });
export const removeFolder = (dataset: string) => call<DataChange>("remove_folder", { dataset });
export const revealMirror = (dataset: string) => call<void>("reveal_mirror", { dataset });
/** Shows a folder's outbox destination; the service names the path, never the UI. */
export const revealOutbox = (dataset: string) => call<void>("reveal_outbox", { dataset });

// Settings
export const settings = () => call<SettingsView>("settings");
export const deleteBackup = (harness: string, id: string) => call<void>("delete_backup", { harness, id });
