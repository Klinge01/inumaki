import { useCallback, useEffect, useState } from "react";
import * as ipc from "../ipc";
import type { CmdError, DataChange, FolderRow, FoldersView } from "../types";
import { ErrorLine } from "../components/ErrorLine";
import { Toolbar, ViewBody } from "../components/Toolbar";
import { NotAvailable } from "../components/NotAvailable";
import { Confirm } from "../components/Confirm";
import { DataChangeNote } from "../components/DataChangeNote";
import { Glyph, type Tone } from "../components/Glyph";
import { Notice } from "../components/Notice";
import { Skeleton } from "../components/Skeleton";
import { basename } from "../paths";
import { formatCheckTime } from "../time";

type Heading = "h3" | "h4";

/** Shown for a `pending` folder instead of any error: not a failure, the user has to answer a macOS prompt. */
const PENDING_TEXT = "macOS is asking whether inumaki may read this folder. Answer the prompt to continue.";

const MAC_HINT =
  "If the folder is in Desktop, Documents, Downloads, iCloud Drive, or on an external volume, macOS may ask you to allow inumaki to read it. Allow it, then rescan the folder.";

/**
 * How many restored files each folder had when this session last looked (counts only, no paths).
 * Seeded on a folder's first load of the session; the new-results notice shows growth over it until
 * the user opens the destination (plan R18). Module-level, so it survives a switch between views.
 */
const seenRestored = new Map<string, number>();

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

function FolderIcon() {
  // Decorative inline SVG: the folder name carries the meaning.
  return (
    <svg width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
      <path d="M2 5.5a1.5 1.5 0 0 1 1.5-1.5h3l1.5 1.7h6.5A1.5 1.5 0 0 1 16 7.2v6.3a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 2 13.5z" strokeLinejoin="round" />
    </svg>
  );
}

/** The pill's tone and word, and the lower-case state word of the secondary line. */
function stateWords(f: FolderRow): { tone: Tone; pill: string; word: string } {
  if (f.state === "pending") return { tone: "unv", pill: "Waiting for access", word: "waiting for access" };
  if (f.state === "failed") return { tone: "bad", pill: "Failed", word: "failed" };
  if (f.state === "scanning" || f.remirror_pending) return { tone: "unv", pill: "Mirroring", word: "mirroring" };
  if (f.state === "stopped") return { tone: "off", pill: "Stopped", word: "stopped" };
  return { tone: "protected", pill: "Watching", word: "watching" };
}

function Card({
  f,
  H,
  busy,
  onStart,
  onRemoved,
  onDone,
}: {
  f: FolderRow;
  H: Heading;
  busy: boolean;
  onStart: () => void;
  onRemoved: (c: DataChange) => void;
  onDone: () => void;
}) {
  const [confirm, setConfirm] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<CmdError | null>(null);
  const run = async (g: () => Promise<void>) => {
    onStart();
    setError(null);
    setNote(null);
    try {
      await g();
    } catch (e) {
      setError(ipc.asCmdError(e));
    } finally {
      onDone();
    }
  };
  const o = f.outbox_files;
  const pending = f.state === "pending";
  const failed = f.state === "failed";
  const { tone, pill, word } = stateWords(f);
  const mirroring = !pending && !failed && (f.state === "scanning" || f.remirror_pending);
  // An older service reports no destination: the destination rows and the buttons that need it go away.
  const dest = f.outbox_destination;
  const hasDest = dest !== "";
  const redError = !pending && f.error !== null;
  const baseline = seenRestored.get(f.dataset) ?? o.rehydrated;
  const fresh = Math.max(0, o.rehydrated - baseline);
  const last = f.last_mirrored_at !== null ? formatCheckTime(f.last_mirrored_at) : null;
  const reveal = (g: () => Promise<void>) => void run(g);
  return (
    <section className={`card folder${failed || redError ? " bad" : ""}`}>
      <div className="head folder-head">
        <span className="folder-icon">
          <FolderIcon />
        </span>
        <div className="folder-title">
          <H className="folder-name">{basename(f.source)}</H>
          <p className="folder-state">{last ? `${word}, last mirrored ${last}` : word}</p>
        </div>
        <span className="pill">
          <Glyph tone={tone} />
          {pill}
        </span>
        <div className="actions folder-actions">
          <button
            type="button"
            className={failed ? "primary" : undefined}
            disabled={busy}
            onClick={() =>
              void run(async () => {
                const r = await ipc.rescanFolder(f.dataset);
                setNote(`Rescan queued: ${r.queued} ${r.queued === 1 ? "file" : "files"}.`);
              })
            }
          >
            Rescan
          </button>
          <button type="button" className="danger" disabled={busy} onClick={() => setConfirm(true)}>
            Remove…
          </button>
        </div>
      </div>
      {pending && (
        <Notice kind="amber">
          <p role="status">{PENDING_TEXT}</p>
          <p>While it&apos;s open, other folders wait too.</p>
        </Notice>
      )}
      {redError && f.error && (
        <Notice
          kind="red"
          role="alert"
          title={f.error.code === "folder_outbox_unwritable" ? "Restored files can't be written." : undefined}
        >
          {f.error.code === "folder_outbox_unwritable" ? (
            <>
              <p>{f.error.text}</p>
              {hasDest && (
                <p>
                  Destination: <span className="mono">{dest}</span>
                </p>
              )}
            </>
          ) : (
            f.error.text
          )}
        </Notice>
      )}
      {fresh > 0 && hasDest && (
        <Notice
          kind="info"
          action={
            <button
              type="button"
              disabled={busy}
              onClick={() =>
                reveal(async () => {
                  await ipc.revealOutbox(f.dataset);
                  seenRestored.set(f.dataset, o.rehydrated);
                })
              }
            >
              Show in Finder
            </button>
          }
        >
          <p>
            {plural(fresh, "new restored file", "new restored files")} in <span className="mono">{dest}</span>
          </p>
        </Notice>
      )}
      {mirroring && (
        <div className="folder-progress">
          <div
            className={`progress${f.files.source === 0 ? " indeterminate" : ""}`}
            role="progressbar"
            aria-label="Files mirrored"
            aria-valuemin={0}
            aria-valuemax={f.files.source}
            aria-valuenow={f.files.mirrored}
          >
            <span
              style={f.files.source === 0 ? undefined : { width: `${Math.min(100, (f.files.mirrored / f.files.source) * 100)}%` }}
            />
          </div>
          <p className="muted">
            {`${f.files.mirrored} of ${f.files.source} mirrored`}
            {hasDest ? " · Results go to " : ""}
            {hasDest && <span className="mono">{dest}</span>}
          </p>
        </div>
      )}
      <div className="flow">
        <div className="stop">
          <p className="stop-label">Your folder</p>
          <p className="mono stop-path">{f.source}</p>
          <p className="stop-text">Read only. inumaki never changes it.</p>
          <p className="stop-counts">
            <span>{plural(f.files.source, "file", "files")}</span>
          </p>
        </div>
        <span className="flow-arrow" aria-hidden="true">
          →
        </span>
        <div className="stop well">
          <p className="stop-label">Sanitized mirror</p>
          <p className="mono stop-path">{f.mirror}</p>
          <p className="stop-text">Agents read this copy, with identifiers replaced by tokens.</p>
          <p className="stop-counts">
            <span>{`${f.files.mirrored} mirrored`}</span>
            <span>{`${f.files.blocked} blocked`}</span>
            <span>{`${f.files.unsupported} unsupported`}</span>
            <span>{`${f.files.pending} pending`}</span>
          </p>
          <button type="button" disabled={busy} onClick={() => reveal(() => ipc.revealMirror(f.dataset))}>
            Show the mirror
          </button>
        </div>
        <span className="flow-arrow" aria-hidden="true">
          →
        </span>
        <div className="stop accent">
          <p className="stop-label">Restored results</p>
          {hasDest && <p className="mono stop-path">{dest}</p>}
          <p className="stop-text">What agents save to the mirror&apos;s outbox lands here with the real values back.</p>
          <p className="stop-counts">
            <span>{`${o.rehydrated} restored`}</span>
            <span>{`${o.with_unresolved} with unresolved tokens`}</span>
            {o.pending > 0 && <span>{`${o.pending} pending`}</span>}
          </p>
          <button
            type="button"
            disabled={busy || !hasDest || o.rehydrated === 0}
            onClick={() =>
              reveal(async () => {
                await ipc.revealOutbox(f.dataset);
                seenRestored.set(f.dataset, o.rehydrated);
              })
            }
          >
            Show restored files
          </button>
        </div>
      </div>
      {confirm && (
        <Confirm
          verb="Remove"
          text="Stop mirroring this folder and delete the mirror? Your folder is not touched."
          onYes={() => {
            setConfirm(false);
            void run(async () => {
              const c = await ipc.removeFolder(f.dataset);
              // A folder added again later starts a fresh baseline.
              seenRestored.delete(f.dataset);
              onRemoved(c);
            });
          }}
          onNo={() => setConfirm(false)}
        />
      )}
      {note && <p role="status">{note}</p>}
      {error && <ErrorLine error={error} />}
    </section>
  );
}

export function Folders({ embedded = false }: { embedded?: boolean }) {
  const CardH: Heading = embedded ? "h4" : "h3";
  const [body, setBody] = useState<FoldersView | null>(null);
  // Kept apart: a reload must not clear the error of the action that just failed.
  const [loadError, setLoadError] = useState<CmdError | null>(null);
  const [actionError, setActionError] = useState<CmdError | null>(null);
  const [change, setChange] = useState<DataChange | null>(null);
  const [busy, setBusy] = useState(false);
  const load = useCallback(
    () =>
      ipc.folders().then(
        (b) => {
          // Seed the baseline on a folder's first load of the session: only later growth is "new". When
          // the outbox shrank (emptied), the baseline follows it down, so the next result is announced.
          for (const f of b.folders) {
            const prev = seenRestored.get(f.dataset);
            if (prev === undefined || f.outbox_files.rehydrated < prev) seenRestored.set(f.dataset, f.outbox_files.rehydrated);
          }
          setLoadError(null);
          setBody(b);
        },
        (e) => setLoadError(ipc.asCmdError(e)),
      ),
    [],
  );
  useEffect(() => {
    void load();
  }, [load]);
  const start = () => {
    setChange(null);
    setActionError(null);
    setBusy(true);
  };
  const done = () => {
    setBusy(false);
    void load();
  };
  const add = async () => {
    start();
    try {
      // `null`: the user cancelled the picker.
      setChange(await ipc.addFolder());
    } catch (e) {
      setActionError(ipc.asCmdError(e));
    } finally {
      done();
    }
  };
  if (loadError && ipc.isNotAvailable(loadError)) {
    return (
      <section>
        <Toolbar title="Folders" embedded={embedded} />
        <ViewBody embedded={embedded}>
          <NotAvailable what="Folders" />
        </ViewBody>
      </section>
    );
  }
  return (
    <section>
      <Toolbar
        title="Folders"
        embedded={embedded}
        actions={
          <>
            <button type="button" disabled={busy} onClick={() => void load()}>
              Refresh
            </button>
            <button type="button" className="primary" disabled={busy} onClick={() => void add()}>
              Add a folder…
            </button>
          </>
        }
      />
      <ViewBody embedded={embedded}>
        <p className="muted">
          {`Sanitized copies live under ${body?.mirror_root ?? "inumaki's data folder"}. Restored results land in each folder's destination, shown on its card.`}
        </p>
        <DataChangeNote change={change} />
        {!body && !loadError && (
          <div className="box">
            <Skeleton lines={3} />
          </div>
        )}
        {body?.folders.length === 0 && (
          <div className="empty-state">
            <h3>No folders yet</h3>
            <p>
              Add a folder and agents get a sanitized copy to read instead of the real files. What they write back is
              restored into <span className="mono">~/Inumaki Outbox</span>.
            </p>
            <div className="actions">
              <button type="button" className="primary" disabled={busy} onClick={() => void add()}>
                Add a folder…
              </button>
            </div>
            <p>{MAC_HINT}</p>
          </div>
        )}
        {body?.folders.map((f) => (
          <Card key={f.dataset} f={f} H={CardH} busy={busy} onStart={start} onRemoved={setChange} onDone={done} />
        ))}
        {body && body.folders.length > 0 && <p className="muted">{MAC_HINT}</p>}
        {actionError && <ErrorLine error={actionError} />}
        {loadError && <ErrorLine error={loadError} />}
      </ViewBody>
    </section>
  );
}
