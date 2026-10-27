import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { listen } from "@tauri-apps/api/event";
import * as ipc from "../ipc";
import type {
  BackupRow,
  CmdError,
  FileChange,
  FoldersView,
  HarnessCard,
  HarnessId,
  ManualSetup,
  OverviewView,
  PathKind,
  PathView,
  PrefsView,
  ServerRow,
} from "../types";
import { CheckBox, CheckResult } from "../components/CheckBox";
import { CopyButton } from "../components/CopyButton";
import { DataChangeNote } from "../components/DataChangeNote";
import { ErrorLine } from "../components/ErrorLine";
import { CheckSlot, PathSection, Tick } from "../components/PathSection";
import { OrphanNotice, ServerTable, useServerActions } from "../components/ServerTable";
import { ServiceState, serviceDown } from "../components/ServiceState";
import { Skeleton } from "../components/Skeleton";
import { Toolbar, ViewBody } from "../components/Toolbar";
import { Confirm } from "../components/Confirm";
import { ConnectSheet } from "../components/ConnectSheet";
import { Notice, NoticeIcon } from "../components/Notice";
import { useHarnessActions, type HarnessActions } from "../harnessActions";
import {
  CHAT_ON_PARTS,
  CHAT_TEXT,
  CLAUDE_AFTER_NOTE,
  GOES_AROUND,
  GUIDE_BASE_URL,
  HARNESS_BINARY,
  HARNESS_MONOGRAM,
  HARNESS_NAME,
  chatLabel,
  chatProvider,
  chatSwitchable,
  loginLabel,
  needsManualSetup,
  serverChangesNote,
} from "../harnessText";
import { useCheckRun } from "../checkRun";
import { useNavigate } from "../nav";
import { hookStatus, pathStatus, sectionTitle } from "../status";
import { basename } from "../paths";
import { formatCheckTime } from "../time";

const DATE = new Intl.DateTimeFormat(undefined, { dateStyle: "medium" });
const formatDate = (at: number) => DATE.format(new Date(at * 1000));

/**
 * A side-column load (plan R13): loading, nothing to show (`not_available`, or not asked for), the
 * answer, a refused preview, or another error that the section shows as an `ErrorLine`.
 */
type Slot<T> =
  | { state: "loading" }
  | { state: "none" }
  | { state: "ok"; value: T }
  | { state: "refused" }
  | { state: "error"; error: CmdError };

function slotFrom<T>(e: unknown): Slot<T> {
  const error = ipc.asCmdError(e);
  if (error.kind === "not_available") return { state: "none" };
  if (error.kind === "cannot_edit_safely") return { state: "refused" };
  // No snippet is sent for a preview today; none is kept if one ever is.
  return { state: "error", error: { ...error, snippet: undefined } };
}

/**
 * What the side column and the header read besides the card: this harness's live backup (from
 * `settings`) and, for a connected harness, the files Connect changed (`preview_connect`). Loaded on
 * mount and after each action (`rev`: harness and server actions), never per snapshot.
 */
function useSetup(card: HarnessCard, rev: number) {
  const [backup, setBackup] = useState<Slot<BackupRow | null>>({ state: "loading" });
  const [files, setFiles] = useState<Slot<FileChange[]>>({ state: "loading" });
  const id = card.id;
  const listFiles = card.connected && !card.disconnected;
  useEffect(() => {
    let cancelled = false;
    void ipc.settings().then(
      // Only this harness's live backup is kept: no log path, no other harness's rows.
      (s) => !cancelled && setBackup({ state: "ok", value: s.backups.find((b) => b.live && b.harness === id) ?? null }),
      (e) => !cancelled && setBackup(slotFrom(e)),
    );
    return () => {
      cancelled = true;
    };
  }, [id, rev]);
  useEffect(() => {
    if (!listFiles) {
      setFiles({ state: "none" });
      return;
    }
    let cancelled = false;
    setFiles({ state: "loading" });
    void ipc.previewConnect(id).then(
      (f) => !cancelled && setFiles({ state: "ok", value: f }),
      (e) => !cancelled && setFiles(slotFrom(e)),
    );
    return () => {
      cancelled = true;
    };
  }, [id, listFiles, rev]);
  return { backup, files };
}

/**
 * `down`: the service cannot be used (spec section 5), so nothing is filtered. A connected harness then
 * reads "Not filtered now" (the spec section 3 word for a harness whose paths are not filtered), and
 * neither the Easy-mode line nor the connected date suggests otherwise.
 */
function Header({ card, connectedAt, down }: { card: HarnessCard; connectedAt: number | null; down: boolean }) {
  const live = card.connected && !card.disconnected;
  const pill = card.disconnected ? (
    <span className="pill red">Disconnected</span>
  ) : live && down ? (
    <span className="pill">Not filtered now</span>
  ) : live ? (
    <span className="pill">Connected</span>
  ) : (
    <span className="pill">Not connected</span>
  );
  return (
    <>
      <div className="conn-head">
        <span className="monogram" aria-hidden="true">
          {HARNESS_MONOGRAM[card.id]}
        </span>
        <div className="conn-title">
          <h3>{card.name}</h3>
          <div className="meta">
            {!card.binary_found ? (
              <span>Configured, program not found.</span>
            ) : card.version === null ? (
              <span className="version-unknown">
                Version not detected
                <NoticeIcon kind="info" />
              </span>
            ) : (
              <>
                <span className="mono">{card.version}</span>
                {card.tested ? <span className="chip accent">Tested version</span> : <span className="chip amber">Untested version</span>}
              </>
            )}
            <span>{loginLabel(card)}</span>
            {connectedAt !== null && !down && <span>{`Connected ${formatDate(connectedAt)}`}</span>}
          </div>
        </div>
        {pill}
      </div>
      {live && !down && <p className="easy-line">{GOES_AROUND}</p>}
    </>
  );
}

/** The notices of spec section 6.2, in its order. Each states a fact that holds without the service too. */
function Notices({
  card,
  a,
  onRefresh,
  onRevert,
}: {
  card: HarnessCard;
  a: HarnessActions;
  onRefresh: () => void;
  onRevert: () => void;
}) {
  const reconnect = (primary: boolean) => (
    <button type="button" className={primary ? "primary" : undefined} disabled={a.busy} onClick={() => void a.doReconnect()}>
      Reconnect
    </button>
  );
  const checkAgain = (
    <button type="button" onClick={onRefresh}>
      Check again
    </button>
  );
  return (
    <>
      {card.disconnected && (
        <Notice
          kind="red"
          role="alert"
          title="Disconnected."
          action={
            <>
              {reconnect(true)}
              <button type="button" className="danger" disabled={a.busy} onClick={onRevert}>
                Revert…
              </button>
            </>
          }
        >
          {`The last Reconnect failed, so ${card.name}'s protected servers talk to the original servers again, unfiltered. Reconnect, or Revert to restore ${card.name}'s own settings.`}
        </Notice>
      )}
      {a.headerLeft && (
        <Notice
          kind="red"
          title={`One line is left in ${card.name}'s configuration.`}
          action={
            <button type="button" onClick={() => a.setHeaderLeft(false)}>
              I removed the line
            </button>
          }
        >
          <ErrorLine error={{ kind: "client_header_left", status: null, kinds: [] }} />
        </Notice>
      )}
      {card.grant && (
        <Notice kind="amber" role="status" title={`macOS withdrew access to ${card.name}'s files.`} action={checkAgain}>
          {card.grant.text}
        </Notice>
      )}
      {card.hook.state === "pending" && (
        <Notice kind="amber" title="The hook waits for your trust." action={checkAgain}>
          {card.hook.reason.text}
        </Notice>
      )}
      {card.hook.state === "broken" && (
        <Notice kind="red" title="The hook is broken." action={reconnect(false)}>
          {card.hook.reason.text}
        </Notice>
      )}
      {card.drift > 0 && (
        <Notice
          kind="amber"
          title={`${card.drift} ${card.drift === 1 ? "setting was" : "settings were"} changed outside inumaki.`}
          action={reconnect(false)}
        >
          Reconnect to put inumaki&apos;s entries back. Nothing else in the file is touched.
        </Notice>
      )}
      {card.binary_found && card.version === null && (
        <Notice kind="info" title="Version not detected">
          <p>
            inumaki runs <code>{HARNESS_BINARY[card.id]} --version</code> to match a tested version and got no answer it
            could read. What is filtered doesn&apos;t depend on it; the check still runs every path.
          </p>
        </Notice>
      )}
    </>
  );
}

/** A section's own load (plan R13): on mount and after each action (`rev`), never per snapshot. `f` must be stable. */
function useLoad<T>(f: () => Promise<T>, rev: number): Slot<T> {
  const [slot, setSlot] = useState<Slot<T>>({ state: "loading" });
  useEffect(() => {
    let cancelled = false;
    void f().then(
      (v) => !cancelled && setSlot({ state: "ok", value: v }),
      (e) => !cancelled && setSlot(slotFrom(e)),
    );
    return () => {
      cancelled = true;
    };
  }, [f, rev]);
  return slot;
}

/**
 * The lines the user adds by hand (spec section 6.3), inside the section of the path that needs them.
 * Fetched on demand only, and dropped when the window hides (`useHarnessActions`).
 */
function ManualLines({ name, manual, onHide }: { name: string; manual: ManualSetup | "none"; onHide: () => void }) {
  if (manual === "none") {
    return <p className="muted">Nothing to add by hand right now. Check that the service is running.</p>;
  }
  return (
    <div className="manual-lines">
      <p>{`Add this to ${name}'s own settings. inumaki doesn't write it and never removes it.`}</p>
      <pre className="card">{manual.lines}</pre>
      <CopyButton text={manual.lines} label="Copy the lines" />
      <p className="muted">{manual.note}</p>
      <button type="button" onClick={onHide}>
        Hide the lines
      </button>
    </div>
  );
}

/**
 * What a path offers by hand: "Acknowledge" for an unsupported path not yet acknowledged, "Show the lines to add"
 * where the adapters ask for manual setup, and the lines once asked for. `null` when there is nothing.
 */
function pathControls(card: HarnessCard, view: PathView, a: HarnessActions): ReactNode {
  const ack = view.state === "unsupported" && !view.acknowledged;
  const manualButton = needsManualSetup(view);
  // One harness has at most one path whose lines are added by hand; they show under that path.
  const lines = a.manual !== null && card.paths.find(needsManualSetup)?.path === view.path;
  if (!ack && !manualButton && !lines) return null;
  return (
    <div key="controls" className="sec-pad">
      {(ack || manualButton) && (
        <div className="actions">
          {manualButton && (
            <button type="button" onClick={() => void a.doManualSetup()}>
              Show the lines to add
            </button>
          )}
          {ack && (
            <button type="button" className="text" disabled={a.busy} onClick={() => void a.doAcknowledge(view.path)}>
              Acknowledge
            </button>
          )}
        </div>
      )}
      {lines && a.manual !== null && <ManualLines name={card.name} manual={a.manual} onHide={a.hideManual} />}
    </div>
  );
}

/** Children for `PathSection`: `null` when every part is empty, so no empty body frame is drawn. */
function bodyOf(...parts: ReactNode[]): ReactNode {
  const shown = parts.filter((p) => p !== null && p !== undefined && p !== false);
  return shown.length > 0 ? <>{shown}</> : null;
}

/**
 * MCP tools (spec section 6.3): this harness's server rows with the MCP view's actions. A server action
 * re-reads the rows, then the card and the setup column (`onServerChange`).
 */
function McpSection({
  card,
  view,
  a,
  rev,
  onServerChange,
}: {
  card: HarnessCard;
  view: PathView;
  a: HarnessActions;
  rev: number;
  onServerChange: () => Promise<void>;
}) {
  const navigate = useNavigate();
  const [rows, setRows] = useState<ServerRow[] | null>(null);
  const load = useCallback(() => ipc.mcpServers().then(setRows), []);
  const actions = useServerActions(load, onServerChange);
  const { reload } = actions;
  useEffect(() => {
    void reload();
  }, [reload, rev]);
  const { tone, word } = pathStatus(view, card);
  const live = card.connected && !card.disconnected;
  const d = view.detail;
  // "Run behind inumaki" holds only while the harness is connected; a disconnected one talks to the originals.
  const line =
    view.reason?.text ??
    (live && view.state === "connected" && d && d.total > 0
      ? `${d.protected} of ${d.total} ${d.total === 1 ? "server runs" : "servers run"} behind inumaki. Their credentials are in the local vault, and ${card.name} sees the same tool names.`
      : null);
  // Rows say "protected, running": true of the service, not of a disconnected harness, whose servers talk to the
  // originals. They show only while the harness is live; Unprotect stays reachable under "All MCP servers".
  const mine = live ? (rows ?? []).filter((r) => r.harness === card.id) : [];
  // A service without the server list shows nothing; any other failure shows here.
  const error = actions.error && actions.error.kind !== "not_available" ? actions.error : null;
  const body = bodyOf(
    mine.length > 0 && <ServerTable key="rows" rows={mine} actions={actions} showHarness={false} />,
    (actions.note || error) && (
      <div key="result" className="sec-pad">
        {actions.note && <p role="status">{actions.note}</p>}
        {error && <ErrorLine error={error} />}
      </div>
    ),
    actions.orphan && (
      <div key="orphan" className="sec-pad">
        <OrphanNotice actions={actions} />
      </div>
    ),
    pathControls(card, view, a),
  );
  return (
    <PathSection
      id={`${card.id}-mcp`}
      tone={tone}
      title={sectionTitle("MCP tools", word)}
      line={line}
      right={<CheckSlot card={card} view={view} />}
      footer={
        <>
          <span className="foot-text">{card.id === "claude-code" ? CLAUDE_AFTER_NOTE : serverChangesNote(card.name)}</span>
          <button type="button" className="text" onClick={() => navigate("mcp")}>
            All MCP servers ›
          </button>
        </>
      }
    >
      {body}
    </PathSection>
  );
}

/** Where restored results land, for the Codex outbox line (plan R18): one destination by name, several by count. */
function outboxLine(name: string, list: FoldersView | null): ReactNode {
  const dests = new Set((list?.folders ?? []).map((f) => f.outbox_destination).filter((d) => d !== ""));
  const writable = `Writable for ${name}.`;
  if (dests.size === 0) return writable;
  if (dests.size === 1) {
    return (
      <>
        {`${writable} Results land in `}
        <span className="mono">{[...dests][0]}</span>.
      </>
    );
  }
  return `${writable} Results land in ${dests.size} destinations, listed under Folders.`;
}

/**
 * Files (spec section 6.3) in three variants: on (the folder table), unverified (what that means, the
 * mirror and the outbox), unsupported (the reason, the lines to add, Acknowledge). The folder list is
 * the same for every harness: every connected harness sees the same mirror.
 */
function FilesSection({ card, view, a, rev }: { card: HarnessCard; view: PathView; a: HarnessActions; rev: number }) {
  const navigate = useNavigate();
  const folders = useLoad(ipc.folders, rev);
  const { tone, word } = pathStatus(view, card);
  const live = card.connected && !card.disconnected;
  const on = live && view.state === "connected";
  const unverified = live && view.state === "unverified";
  const line =
    view.reason?.text ??
    (on ? `${card.name} reads the sanitized mirror. What it saves to the mirror's outbox comes back with the real values.` : null);
  const list = folders.state === "ok" ? folders.value : null;
  let main: ReactNode = null;
  if (on && folders.state === "loading") {
    main = (
      <div key="loading" className="sec-pad">
        <Skeleton lines={2} />
      </div>
    );
  } else if (on && list && list.folders.length === 0) {
    main = (
      <p key="empty" className="sec-pad muted">
        No folders yet
      </p>
    );
  } else if (on && list) {
    const anyDest = list.folders.some((f) => f.outbox_destination !== "");
    main = (
      <table key="folders" className="grid">
        <thead>
          <tr>
            <th>Folder</th>
            <th>{`${card.name} reads`}</th>
            {anyDest && <th>Restored results land in</th>}
          </tr>
        </thead>
        <tbody>
          {list.folders.map((f) => (
            <tr key={f.dataset}>
              <td>
                <div>{basename(f.source)}</div>
                <div className="muted">{`${f.files.mirrored} of ${f.files.source} mirrored`}</div>
              </td>
              <td className="mono">{f.mirror}</td>
              {anyDest && <td className="mono">{f.outbox_destination}</td>}
            </tr>
          ))}
        </tbody>
      </table>
    );
  } else if (unverified) {
    const n = list?.folders.length ?? 0;
    main = (
      <dl key="unverified" className="dl sec-pad">
        <div className="dl-row">
          <dt>What this means</dt>
          <dd>{`${card.name} reads the mirror when an agent uses it, but it can still open your original folders if asked to.`}</dd>
        </div>
        {list && (
          <div className="dl-row">
            <dt>Mirror</dt>
            <dd>
              <span className="mono">{list.mirror_root}</span>
              {`, ${n} ${n === 1 ? "folder" : "folders"}`}
            </dd>
          </div>
        )}
        <div className="dl-row">
          <dt>Outbox</dt>
          <dd>{outboxLine(card.name, list)}</dd>
        </div>
      </dl>
    );
  }
  const body = bodyOf(
    main,
    (on || unverified) && folders.state === "error" && (
      <div key="error" className="sec-pad">
        <ErrorLine error={folders.error} />
      </div>
    ),
    pathControls(card, view, a),
  );
  return (
    <PathSection
      id={`${card.id}-files`}
      tone={tone}
      title={sectionTitle("Files", word)}
      line={line}
      right={<CheckSlot card={card} view={view} />}
      footer={
        on && (
          <>
            <span className="foot-text">Every connected harness sees the same mirror.</span>
            <button type="button" className="text" onClick={() => navigate("folders")}>
              All folders ›
            </button>
          </>
        )
      }
    >
      {body}
    </PathSection>
  );
}

/** Where an unfiltered chat goes, for the Off body's "Goes to" (plan R26). */
const chatDestination = (card: HarnessCard) => chatProvider(card) ?? "ChatGPT";

/** The Off line (plan R26): where the chat goes instead. A statement of fact, never a protection claim. */
function chatOffLine(card: HarnessCard): string {
  const provider = chatProvider(card);
  return provider === null
    ? "Codex with a ChatGPT login talks to ChatGPT directly and isn't filtered."
    : `${card.name} talks to ${provider} directly. inumaki doesn't see chat text.`;
}

/**
 * The chat switch (plan R9). Its accessible name is the full label; the visible "Filter chat" is a short
 * form for sighted users. It shows the value in effect and changes only after the confirm and the reload.
 */
function ChatSwitch({ card, chat, busy, onChat }: { card: HarnessCard; chat: boolean; busy: boolean; onChat: (on: boolean) => void }) {
  const labelId = `${card.id}-chat-label`;
  const inputId = `${card.id}-chat-switch`;
  return (
    <span className="chat-switch">
      <span id={labelId} className="sr-only">
        {chatLabel(card)}
      </span>
      <input
        id={inputId}
        type="checkbox"
        role="switch"
        className="switch"
        aria-labelledby={labelId}
        checked={chat}
        disabled={busy || !card.connected}
        onChange={(e) => onChat(e.target.checked)}
      />
      <label htmlFor={inputId} aria-hidden="true">
        Filter chat
      </label>
      {!card.connected && <span className="sec-hint">Connect first</span>}
    </span>
  );
}

/** A card without a chat path reads as not routed: never as filtered. */
const UNROUTED: PathView = { path: "chat", state: "not_connected", reason: null, detail: null, acknowledged: false, last_check: null };

/**
 * Chat (spec section 6.3). Off on a connected harness is the user's choice and says where the chat goes
 * instead; it shows no check result (the check routes through its own configuration, so its "passed" says
 * nothing about a chat that is not routed). On says the chat goes through inumaki. Every other state
 * (needs one line you add, unsupported, broken, disconnected, not connected) takes the status grammar's
 * title and the path's reason.
 */
function ChatSection({
  card,
  view,
  chat,
  a,
  onChat,
}: {
  card: HarnessCard;
  view: PathView | undefined;
  chat: boolean;
  a: HarnessActions;
  onChat: (on: boolean) => void;
}) {
  const v = view ?? UNROUTED;
  const { tone, word } = pathStatus(v, card);
  const switchable = chatSwitchable(card);
  const live = card.connected && !card.disconnected;
  const off = live && v.state === "not_connected";
  const on = live && v.state === "connected";
  const line = off ? chatOffLine(card) : on ? "Chat goes through inumaki." : (v.reason?.text ?? null);
  const reason = (off || on) && v.reason && (
    <p key="reason" className="sec-pad muted">
      {v.reason.text}
    </p>
  );
  let main: ReactNode = null;
  if (off) {
    main = (
      <dl key="off" className="dl sec-pad">
        <div className="dl-row">
          <dt>Goes to</dt>
          <dd>{`${chatDestination(card)}, directly`}</dd>
        </div>
        {switchable && (
          <div className="dl-row">
            <dt>If you turn it on</dt>
            <dd>{CHAT_TEXT[card.id].on}</dd>
          </div>
        )}
        <div className="dl-row">
          <dt>Last check</dt>
          <dd>Not checked while chat is off</dd>
        </div>
      </dl>
    );
  } else if (on && switchable) {
    main = (
      <dl key="on" className="dl sec-pad">
        <div className="dl-row">
          <dt>If you turn it off</dt>
          <dd>{CHAT_TEXT[card.id].off}</dd>
        </div>
      </dl>
    );
  }
  const body = off ? bodyOf(reason, main, pathControls(card, v, a)) : bodyOf(main, reason, pathControls(card, v, a));
  return (
    <PathSection
      id={`${card.id}-chat`}
      tone={tone}
      title={sectionTitle("Chat", word)}
      line={line}
      right={
        <span className="sec-right">
          {!off && <CheckSlot card={card} view={v} />}
          {switchable && <ChatSwitch card={card} chat={chat} busy={a.busy} onChat={onChat} />}
        </span>
      }
    >
      {body}
    </PathSection>
  );
}

/** The tool-result hook (spec section 6.3); nothing for a harness without one. */
function HookSection({ card }: { card: HarnessCard }) {
  const h = hookStatus(card.hook);
  if (!h) return null;
  const line = card.hook.state === "installed" ? `Checks some tool results before ${card.name} sends them to the model.` : h.reason;
  return <PathSection id={`${card.id}-hook`} tone={h.tone} title={sectionTitle("Tool-result hook", h.word)} line={line} />;
}

/** The path sections in the spec's order: MCP tools, Files, Chat, then the tool-result hook. */
function PathArea({
  card,
  chat,
  a,
  rev,
  onServerChange,
  onChat,
}: {
  card: HarnessCard;
  chat: boolean;
  a: HarnessActions;
  rev: number;
  onServerChange: () => Promise<void>;
  onChat: (on: boolean) => void;
}) {
  const path = (k: PathKind) => card.paths.find((p) => p.path === k);
  const mcp = path("mcp");
  const files = path("files");
  const chatPath = path("chat");
  return (
    <>
      {mcp && <McpSection card={card} view={mcp} a={a} rev={rev} onServerChange={onServerChange} />}
      {files && <FilesSection card={card} view={files} a={a} rev={rev} />}
      {(chatPath || chatSwitchable(card)) && <ChatSection card={card} view={chatPath} chat={chat} a={a} onChat={onChat} />}
      <HookSection card={card} />
    </>
  );
}

const CHECK_ROWS: [PathKind, string][] = [
  ["mcp", "MCP tools"],
  ["files", "Files"],
  ["chat", "Chat"],
];

/**
 * The last check of this harness (spec section 6.4 item 2, plan R8). A result counts only while the
 * harness is connected: a disconnected harness shows no stored result (B5), and the memo a Revert
 * left behind says nothing about a harness that is not connected.
 */
function LastCheck({ card }: { card: HarnessCard }) {
  const live = card.connected && !card.disconnected;
  const check = useCheckRun();
  let body: ReactNode;
  if (card.disconnected) body = <p className="side-line">No check since the disconnect</p>;
  else if (!live) body = <p className="side-line">Not checked</p>;
  else {
    body = (
      <dl className="dl">
        {CHECK_ROWS.map(([k, label]) => {
          const p = card.paths.find((v) => v.path === k);
          if (!p) return null;
          // The check uses its own route: its chat result says nothing about a chat that is not routed.
          const unrouted = k === "chat" && p.state === "not_connected";
          return (
            <div key={k} className="dl-row">
              <dt>{label}</dt>
              <dd>
                <CheckResult status={unrouted ? null : p.last_check} />
              </dd>
            </div>
          );
        })}
      </dl>
    );
  }
  return (
    <section className="side-section" aria-labelledby={`${card.id}-check`}>
      <h4 id={`${card.id}-check`}>Last check</h4>
      {live && card.last_check_at != null && (
        <p className="side-sub">{`${formatCheckTime(card.last_check_at)}, made-up test data only`}</p>
      )}
      {body}
      {/* A run answers for connected harnesses only: a disconnected one never shows a Passed (B5). */}
      {live && (
        <>
          <button type="button" className="sm check-run" disabled={check.running} onClick={() => void check.start()}>
            Run the check
          </button>
          <CheckBox harness={card.id} />
        </>
      )}
    </section>
  );
}

function Setup({ card, backup, files }: { card: HarnessCard } & ReturnType<typeof useSetup>) {
  return (
    <section className="side-section" aria-labelledby={`${card.id}-setup`}>
      <h4 id={`${card.id}-setup`}>Setup</h4>
      <p className="side-sub">What Connect changed. A backup was made first.</p>
      {files.state === "loading" && <Skeleton lines={2} />}
      {files.state === "ok" && (
        <ul className="file-list">
          {files.value.map((c) => (
            <li key={c.path}>
              <span className="mono">{c.path}</span>
              <span className="file-keys">{c.keys.join(", ")}</span>
            </li>
          ))}
        </ul>
      )}
      {files.state === "refused" && <p className="side-line">inumaki couldn&apos;t read the files to list them.</p>}
      {files.state === "error" && <ErrorLine error={files.error} />}
      <dl className="dl">
        {backup.state === "ok" && (
          <div className="dl-row">
            <dt>Backup</dt>
            <dd>
              {backup.value ? (
                <>
                  {backup.value.backup.created_at !== null && <div>{formatDate(backup.value.backup.created_at)}</div>}
                  <div className="muted">Revert restores it</div>
                </>
              ) : (
                <span className="muted">No live backup</span>
              )}
            </dd>
          </div>
        )}
        <div className="dl-row">
          <dt>Drift</dt>
          <dd>
            {card.drift > 0 ? (
              <span className="res warn">{`${card.drift} ${card.drift === 1 ? "setting" : "settings"} changed`}</span>
            ) : (
              <span className="res pass">
                <Tick /> No changes outside inumaki
              </span>
            )}
          </dd>
        </div>
      </dl>
      {backup.state === "error" && <ErrorLine error={backup.error} />}
    </section>
  );
}

function SideColumn({ card, setup }: { card: HarnessCard; setup: ReturnType<typeof useSetup> }) {
  const linked = card.connected || card.disconnected;
  return (
    <aside className="side">
      {linked && <Setup card={card} {...setup} />}
      <LastCheck card={card} />
      {GUIDE_BASE_URL !== null && (
        <a className="text guide" href={`${GUIDE_BASE_URL}${card.id}.md`} target="_blank" rel="noreferrer">
          {`${card.name} guide`}
        </a>
      )}
    </aside>
  );
}

function ConnectionPage({
  card,
  view,
  chat,
  error,
  load,
  refresh,
}: {
  card: HarnessCard;
  view: OverviewView;
  /** This harness's chat is wanted (the `prefs` effective value). */
  chat: boolean;
  error: CmdError | null;
  load: () => Promise<void>;
  refresh: () => void;
}) {
  // Bumped after every harness action, so the sections and the side column reload then (and never per snapshot).
  const [rev, setRev] = useState(0);
  // Bumped after a server action: the MCP section re-read its rows itself; the card and the setup column follow.
  const [serverRev, setServerRev] = useState(0);
  const onChange = useCallback(async () => {
    await load();
    setRev((r) => r + 1);
  }, [load]);
  const onServerChange = useCallback(async () => {
    await load();
    setServerRev((r) => r + 1);
  }, [load]);
  const a = useHarnessActions(card, onChange);
  // Both counters only grow, so their sum changes whenever either does.
  const setup = useSetup(card, rev + serverRev);
  const [confirmRevert, setConfirmRevert] = useState(false);
  // The value the user is about to set on the chat switch; null while no confirm is open.
  const [confirmChat, setConfirmChat] = useState<boolean | null>(null);

  const down = serviceDown(view);
  // The not-running notice already says it: not a second time as an error line (plan A8).
  const showError = error && !(down && error.kind === "service_unreachable");
  const linked = card.connected || card.disconnected;
  const needsReconnect =
    card.disconnected || card.drift > 0 || card.hook.state === "broken" || card.paths.some((p) => p.state === "broken");
  const backup = setup.backup.state === "ok" ? setup.backup.value : null;
  const connectedAt = card.connected && !card.disconnected && !down ? (backup?.backup.created_at ?? null) : null;

  const actions = linked ? (
    <>
      <button type="button" className={needsReconnect ? "primary" : undefined} disabled={a.busy} onClick={() => void a.doReconnect()}>
        Reconnect
      </button>
      <button type="button" className="danger" disabled={a.busy} onClick={() => setConfirmRevert(true)}>
        Revert…
      </button>
    </>
  ) : (
    <button type="button" className="primary" disabled={a.busy} onClick={() => void a.startConnect()}>
      Connect…
    </button>
  );

  return (
    <section>
      <Toolbar title={card.name} actions={actions} />
      <div className={down ? undefined : "cols"}>
        <div className="view">
          {showError && <ErrorLine error={error} />}
          <ServiceState view={view} onRefresh={refresh} except={card.id} />
          <Header card={card} connectedAt={connectedAt} down={down} />
          <Notices card={card} a={a} onRefresh={refresh} onRevert={() => setConfirmRevert(true)} />
          {a.note &&
            (a.noteWarned ? (
              <Notice kind="amber" role="status">
                {a.note}
              </Notice>
            ) : (
              <p className="action-note" role="status">
                {a.note}
              </p>
            ))}
          <DataChangeNote change={a.change} />
          {a.error && <ErrorLine error={a.error} />}
          {/* Without a usable service nothing is filtered: no path status that could read as filtered (plan A8). */}
          {!down && (
            <PathArea card={card} chat={chat} a={a} rev={rev} onServerChange={onServerChange} onChat={setConfirmChat} />
          )}
        </div>
        {!down && <SideColumn card={card} setup={setup} />}
      </div>
      {(a.preview || a.refused) && (
        <ConnectSheet
          card={card}
          preview={a.preview}
          refused={a.refused}
          chat={chat}
          busy={a.busy}
          onConnect={() => void a.doConnect()}
          onCancel={a.cancelConnect}
        />
      )}
      {confirmRevert && (
        <Confirm
          verb="Revert"
          title={`Revert ${card.name}?`}
          text={`Restore ${card.name}'s configuration from the backup and revoke its inumaki token.${
            chat ? ` ${CHAT_TEXT[card.id].off}` : ""
          }`}
          onYes={() => {
            setConfirmRevert(false);
            void a.doRevert();
          }}
          onNo={() => setConfirmRevert(false)}
        />
      )}
      {confirmChat === true && (
        <Confirm
          verb="Turn on"
          title={`Filter ${card.name} chat through inumaki?`}
          text={CHAT_ON_PARTS[card.id].lead}
          onYes={() => {
            setConfirmChat(null);
            void a.doChat(true);
          }}
          onNo={() => setConfirmChat(null)}
        >
          <Notice kind="amber">{CHAT_ON_PARTS[card.id].note}</Notice>
        </Confirm>
      )}
      {confirmChat === false && (
        <Confirm
          verb="Turn off"
          title={`Stop filtering ${card.name} chat?`}
          text={CHAT_TEXT[card.id].off}
          onYes={() => {
            setConfirmChat(null);
            void a.doChat(false);
          }}
          onNo={() => setConfirmChat(null)}
        />
      )}
    </section>
  );
}

/** One harness's connection page: the same numbered `prefs` + `overview` load and `snapshot` listener as the Overview. */
export function Connection({ harness }: { harness: HarnessId }) {
  const [view, setView] = useState<OverviewView | null>(null);
  const [chat, setChat] = useState<PrefsView["chat_effective"]>({});
  const [error, setError] = useState<CmdError | null>(null);
  const apply = useCallback((v: OverviewView) => {
    setError(null);
    setView(v);
  }, []);
  // Each load is numbered; an answer from a load that a newer one overtook is dropped.
  const loads = useRef(0);
  const load = useCallback(async () => {
    const n = ++loads.current;
    const [p, v] = await Promise.allSettled([ipc.prefs(), ipc.overview()]);
    if (n !== loads.current) return;
    if (p.status === "fulfilled") {
      setChat(p.value.chat_effective);
    }
    if (v.status === "fulfilled") setView(v.value);
    // A switch whose value could not be read must not pass silently for the current one.
    const failed = v.status === "rejected" ? v : p.status === "rejected" ? p : null;
    setError(failed ? ipc.asCmdError(failed.reason) : null);
  }, []);
  const refresh = useCallback(() => {
    void ipc.refresh().then(apply, (e) => setError(ipc.asCmdError(e)));
  }, [apply]);
  useEffect(() => {
    void load();
    let cancelled = false;
    let un: (() => void) | undefined;
    listen("snapshot", () => void load()).then(
      (u) => {
        if (cancelled) u();
        else un = u;
      },
      () => undefined,
    );
    return () => {
      cancelled = true;
      un?.();
    };
  }, [load]);
  const title = HARNESS_NAME[harness];
  if (!view) {
    return (
      <section>
        <Toolbar title={title} />
        <ViewBody>
          {error ? (
            <ErrorLine error={error} />
          ) : (
            <div className="box">
              <Skeleton lines={3} />
            </div>
          )}
        </ViewBody>
      </section>
    );
  }
  const card = view.cards.find((c) => c.id === harness);
  if (!card) {
    const showError = error && !(serviceDown(view) && error.kind === "service_unreachable");
    return (
      <section>
        <Toolbar title={title} />
        <ViewBody>
          {showError && <ErrorLine error={error} />}
          <ServiceState view={view} onRefresh={refresh} except={harness} />
          <p className="muted">{title} isn&apos;t detected on this Mac.</p>
        </ViewBody>
      </section>
    );
  }
  return (
    <ConnectionPage card={card} view={view} chat={chat[card.id] ?? false} error={error} load={load} refresh={refresh} />
  );
}
