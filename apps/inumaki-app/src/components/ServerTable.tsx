import { Fragment, useCallback, useState } from "react";
import * as ipc from "../ipc";
import type { CmdError, HarnessId, Reason, ServerRow } from "../types";
import { useWindowHidden } from "../useWindowHidden";
import { HARNESS_NAME } from "../harnessText";
import { Glyph, type Tone } from "./Glyph";
import { Notice } from "./Notice";

/**
 * The state cell (spec section 7.1): the glyph tone, the word, and an optional second line. A protected
 * server of a disconnected harness is not filtered: that harness talks to the original server again.
 */
function serverState(
  r: ServerRow,
  disconnected?: ReadonlySet<HarnessId>,
): {
  tone: Tone;
  word: string;
  sub?: string;
  quiet?: boolean;
} {
  if (r.protected && disconnected?.has(r.harness)) {
    const name = HARNESS_NAME[r.harness];
    return {
      tone: "off",
      word: "Not filtered now",
      sub: `${name} is disconnected, so this server talks to the original again. Reconnect ${name} on its page.`,
    };
  }
  if (r.protected) {
    const restarts = r.restarts ? `, ${r.restarts} ${r.restarts === 1 ? "restart" : "restarts"}` : "";
    const up = r.upstream_state ? `, ${r.upstream_state}` : "";
    // Set up, but the upstream is not (yet) running: inumaki cannot confirm it, so not the plain "on".
    const tone: Tone = r.upstream_state && r.upstream_state !== "running" ? "unv" : "on";
    return { tone, word: `Protected${up}${restarts}` };
  }
  if (r.pending) {
    const name = HARNESS_NAME[r.harness];
    return {
      tone: "unv",
      word: `Waiting for ${name}`,
      sub: `Reconnect ${name} on its page to write it.`,
    };
  }
  if (r.left_unprotected) return { tone: "off", word: "Left unprotected", quiet: true };
  if (r.cannot_protect) return { tone: "na", word: "Can't protect yet", sub: r.cannot_protect };
  return { tone: "off", word: "Not protected" };
}

export type ServerActions = ReturnType<typeof useServerActions>;

/**
 * The state and actions behind a list of MCP server rows. `load` re-reads the rows (it rejects when the read fails);
 * it runs after every action, and a failed read becomes the error. A reload never clears an error: it would wipe the
 * error of the action that just failed (a snippet, a disconnected harness). `run` and `refresh` clear it.
 *
 * `load` must be stable (wrap it in `useCallback`): `reload` depends on it, and callers run `reload` from an effect.
 * `onAfter`, when given, runs after each action's reload (the connection page re-reads its card and setup then).
 */
export function useServerActions(load: () => Promise<unknown>, onAfter?: () => Promise<void>) {
  const [error, setError] = useState<CmdError | null>(null);
  const [orphan, setOrphan] = useState<string | null>(null);
  // The name of the server whose Unprotect left the dataset unused (shown in the notice; the slug never is).
  const [orphanServer, setOrphanServer] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  // Per row id: the fixed warning of the Protect that just ran (a credential outside a credential-named field).
  const [warnings, setWarnings] = useState<Record<string, Reason>>({});
  const [busy, setBusy] = useState(false);
  const reload = useCallback(() => load().then(undefined, (e) => setError(ipc.asCmdError(e))), [load]);
  // A snippet is a credential-bearing text that cannot be re-read: not left on a hidden window.
  useWindowHidden(() => setError((e) => (e?.snippet ? null : e)));
  const run = async (f: () => Promise<void>) => {
    setError(null);
    setNote(null);
    setBusy(true);
    try {
      await f();
    } catch (e) {
      setError(ipc.asCmdError(e));
    } finally {
      setBusy(false);
      await reload();
      await onAfter?.();
    }
  };
  const refresh = () => {
    setError(null);
    setNote(null);
    void reload();
  };
  const clearWarning = (id: string) =>
    setWarnings((w) => {
      const rest = { ...w };
      delete rest[id];
      return rest;
    });
  const protect = (r: ServerRow) =>
    run(async () => {
      const out = await ipc.protect(r.harness, r.id);
      setNote([out.note, ...(out.harness_warnings ?? []).map((w) => `Warning: ${w.text}`)].join(" "));
      if (out.warning) setWarnings((w) => ({ ...w, [r.id]: out.warning as Reason }));
    });
  const unprotect = (r: ServerRow) =>
    run(async () => {
      const out = await ipc.unprotect(r.harness, r.id);
      clearWarning(r.id);
      setNote(out.note);
      setOrphan(out.unreferenced_dataset);
      setOrphanServer(out.unreferenced_dataset ? r.name : null);
    });
  const leaveUnprotected = (r: ServerRow) => run(() => ipc.leaveUnprotected(r.harness, r.id, !r.left_unprotected));
  const acceptSchema = (dataset: string, upstream: string) => run(() => ipc.acceptSchema(dataset, upstream));
  const deleteOrphan = () => {
    if (!orphan) return;
    const d = orphan;
    setOrphan(null);
    setOrphanServer(null);
    void run(() => ipc.removeProtectedDataset(d));
  };
  const keepOrphan = () => {
    setOrphan(null);
    setOrphanServer(null);
  };
  return {
    error,
    orphan,
    orphanServer,
    note,
    warnings,
    busy,
    reload,
    refresh,
    protect,
    unprotect,
    leaveUnprotected,
    acceptSchema,
    deleteOrphan,
    keepOrphan,
  };
}

/**
 * The inline notice after an Unprotect left a dataset with no user (spec section 7.1). Keep has the focus: a stray
 * Enter does not delete anything. Escape keeps too.
 */
export function OrphanNotice({ actions }: { actions: ServerActions }) {
  if (!actions.orphan) return null;
  return (
    <div onKeyDown={(e) => e.key === "Escape" && actions.keepOrphan()}>
      <Notice
        kind="amber"
        title={`No harness uses ${actions.orphanServer ?? "this server"}'s dataset any more.`}
        action={
          <>
            <button type="button" className="sm" autoFocus onClick={actions.keepOrphan}>
              Keep
            </button>
            <button type="button" className="sm danger" disabled={actions.busy} onClick={actions.deleteOrphan}>
              Delete
            </button>
          </>
        }
      >
        Delete the dataset and the credentials stored for it? The server itself isn&apos;t touched.
      </Notice>
    </div>
  );
}

function ServerRowView({
  r,
  actions,
  disconnected,
}: {
  r: ServerRow;
  actions: ServerActions;
  disconnected?: ReadonlySet<HarnessId>;
}) {
  const { busy, warnings } = actions;
  const s = serverState(r, disconnected);
  const listed = !r.protected && !r.pending;
  return (
    <tr>
      <td>
        <span className="server-name">{r.name}</span>
        {r.scope === "project" && <span className="chip">project</span>}
        <div className="server-sub">{`${r.transport}, ${r.scope}`}</div>
        {warnings[r.id] && (
          <Notice kind="amber" role="alert">
            {warnings[r.id].text}
          </Notice>
        )}
      </td>
      <td>
        <span className={`server-state${s.quiet ? " quiet" : ""}`}>
          <Glyph tone={s.tone} />
          {s.word}
        </span>
        {s.sub && <div className="server-note">{s.sub}</div>}
      </td>
      <td>
        {r.contract === "ready" && "Unchanged"}
        {r.contract === "drift" && (
          <>
            <span className="chip amber">Changed</span>
            {r.dataset && r.upstream && (
              <button
                type="button"
                className="text sm"
                disabled={busy}
                onClick={() => void actions.acceptSchema(r.dataset as string, r.upstream as string)}
              >
                Accept current list
              </button>
            )}
          </>
        )}
        {r.contract !== "ready" && r.contract !== "drift" && "–"}
      </td>
      <td className="actions">
        {listed && !r.cannot_protect && (
          <button type="button" className="primary sm" disabled={busy} onClick={() => void actions.protect(r)}>
            Protect
          </button>
        )}
        {(r.protected || r.pending) && (
          <button type="button" className="sm" disabled={busy} onClick={() => void actions.unprotect(r)}>
            Unprotect
          </button>
        )}
        {listed && (
          <button type="button" className="text sm" disabled={busy} onClick={() => void actions.leaveUnprotected(r)}>
            {r.left_unprotected ? "Undo" : "Leave unprotected"}
          </button>
        )}
      </td>
    </tr>
  );
}

/**
 * The server rows with their actions. With `showHarness` (the MCP view) the rows are grouped under one row per
 * harness; without it (a page about one harness) the table is flat. `disconnected` names the harnesses whose
 * protected servers are not filtered now.
 */
export function ServerTable({
  rows,
  actions,
  showHarness = true,
  disconnected,
}: {
  rows: ServerRow[];
  actions: ServerActions;
  showHarness?: boolean;
  disconnected?: ReadonlySet<HarnessId>;
}) {
  const groups: { harness: ServerRow["harness"]; rows: ServerRow[] }[] = [];
  for (const r of rows) {
    const g = groups.find((x) => x.harness === r.harness);
    if (g) g.rows.push(r);
    else groups.push({ harness: r.harness, rows: [r] });
  }
  return (
    <table className="grid servers">
      <thead>
        <tr>
          <th>Server</th>
          <th>State</th>
          <th>Tool list</th>
          <th>
            <span className="sr-only">Actions</span>
          </th>
        </tr>
      </thead>
      <tbody>
        {groups.map((g) => (
          <Fragment key={g.harness}>
            {showHarness && (
              <tr className="group">
                <th colSpan={4} scope="colgroup">
                  {HARNESS_NAME[g.harness]}
                </th>
              </tr>
            )}
            {g.rows.map((r) => (
              <ServerRowView key={r.id} r={r} actions={actions} disconnected={disconnected} />
            ))}
          </Fragment>
        ))}
      </tbody>
    </table>
  );
}
