import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { listen } from "@tauri-apps/api/event";
import * as ipc from "../ipc";
import type { CmdError, HarnessCard, OverviewView, PathKind, PrefsView, ServerRow } from "../types";
import { CheckBox } from "../components/CheckBox";
import { ConnectSheet } from "../components/ConnectSheet";
import { ErrorLine } from "../components/ErrorLine";
import { Glyph } from "../components/Glyph";
import { ServiceState, serviceDown } from "../components/ServiceState";
import { Skeleton } from "../components/Skeleton";
import { Toolbar, ViewBody } from "../components/Toolbar";
import { checkFailed, useCheckRun } from "../checkRun";
import { useHarnessActions } from "../harnessActions";
import { HARNESS_MONOGRAM } from "../harnessText";
import { useNavigate, type ViewId } from "../nav";
import { isFiltered, pathStatus, protectedCount, rowSentence } from "../status";
import { formatCheckTime } from "../time";

const PATH_LABEL: Record<PathKind, string> = { mcp: "MCP", files: "Files", chat: "Chat" };

const Chevron = () => (
  <svg className="chevron" width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="m6 3 5 5-5 5" />
  </svg>
);

/** The row's open area: a button that navigates, or (first run, nothing to navigate to) a plain block. */
function RowOpen({ to, embedded, children }: { to: ViewId; embedded: boolean; children: ReactNode }) {
  const navigate = useNavigate();
  if (embedded) return <div className="row-open">{children}</div>;
  return (
    <button type="button" className="row-open" onClick={() => navigate(to)}>
      {children}
    </button>
  );
}

function ConnectionRow({
  card,
  chat,
  onChange,
  embedded,
}: {
  card: HarnessCard;
  chat: boolean;
  onChange: () => Promise<void>;
  embedded: boolean;
}) {
  const a = useHarnessActions(card, onChange);
  const s = rowSentence(card);
  const notConnected = !card.connected && !card.disconnected;
  return (
    <div className="row-wrap">
      <div className={`row${card.disconnected ? " disconnected" : ""}`}>
        <RowOpen to={`connection:${card.id}`} embedded={embedded}>
          <span className="monogram" aria-hidden="true">
            {HARNESS_MONOGRAM[card.id]}
          </span>
          <span className="row-text">
            <span className="row-name">{card.name}</span>
            <span className={`row-sentence ${s.tone}`}>{s.text}</span>
          </span>
          {(card.connected || card.disconnected) && (
            <span className="mini-glyphs">
              {card.paths.map((p) => {
                const st = pathStatus(p, card);
                return (
                  <span key={p.path} className="mini" role="img" aria-label={`${PATH_LABEL[p.path]}: ${st.word}`}>
                    <Glyph tone={st.tone} />
                    {PATH_LABEL[p.path]}
                  </span>
                );
              })}
            </span>
          )}
          {!embedded && <Chevron />}
        </RowOpen>
        {card.disconnected && (
          <button type="button" className="primary" disabled={a.busy} onClick={() => void a.doReconnect()}>
            Reconnect
          </button>
        )}
        {notConnected && (
          <button type="button" className="primary" disabled={a.busy} onClick={() => void a.startConnect()}>
            Connect…
          </button>
        )}
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
      {a.note && <p role="status">{a.note}</p>}
      {a.error && <ErrorLine error={a.error} />}
    </div>
  );
}

function ShieldIcon() {
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M12 3 4.5 6v5.5c0 4.5 3.2 8 7.5 9.5 4.3-1.5 7.5-5 7.5-9.5V6z" />
      <path d="m9 12 2.2 2.2L15.5 10" />
    </svg>
  );
}

function LastCheckSide({ last }: { last: OverviewView["last_check"] }) {
  if (!last) return <div className="last-check muted">No check yet</div>;
  return (
    <div className="last-check">
      <div className={last.failed ? "last-fail" : "last-pass"}>
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          {last.failed ? <path d="m4 4 8 8M12 4l-8 8" /> : <path d="m3 8.5 3.2 3.2L13 4.8" />}
        </svg>{" "}
        {last.failed ? "Last check failed" : "Last check passed"}
      </div>
      <div className="muted">{formatCheckTime(last.at)}</div>
    </div>
  );
}

type Counts = { mcp: string | null; email: number | null; folders: number | null };
type Loaded = { mcp: ServerRow[] | null; email: number | null; folders: number | null };

function Summary({ view }: { view: OverviewView }) {
  const n = view.cards.filter(isFiltered).length;
  const reconnect = view.cards.some((c) => c.disconnected);
  return (
    <div className="box summary">
      <span className="shield" aria-hidden="true">
        <ShieldIcon />
      </span>
      <div className="summary-text">
        <h3>{n === 0 ? "No connections filtered yet" : `${n} ${n === 1 ? "connection" : "connections"} filtered in Easy mode`}</h3>
        <p className="muted">
          {n === 0
            ? reconnect
              ? "Reconnect the disconnected harness below to filter its tools and files."
              : view.cards.some((c) => c.connected)
                ? "Nothing is filtered in Easy mode yet. The rows below say why."
                : "Connect a harness below to filter its tools and files."
            : "An agent that deliberately goes around inumaki can still succeed."}
        </p>
      </div>
      <LastCheckSide last={view.last_check} />
    </div>
  );
}

function DataSources({ counts }: { counts: Counts }) {
  const navigate = useNavigate();
  const cells: { to: ViewId; n: string; label: string }[] = [];
  if (counts.mcp) cells.push({ to: "mcp", n: counts.mcp, label: "protected" });
  if (counts.email !== null) {
    cells.push({ to: "email", n: String(counts.email), label: counts.email === 1 ? "mailbox, drafts only" : "mailboxes, drafts only" });
  }
  if (counts.folders !== null) cells.push({ to: "folders", n: String(counts.folders), label: "watched" });
  if (cells.length === 0) return null;
  return (
    <>
      <h3 className="section-title">Data sources</h3>
      <div className="box cell-grid">
        {cells.map((c) => (
          <button key={c.to} type="button" onClick={() => navigate(c.to)}>
            <span className="cell-n num">{c.n}</span>
            <span className="cell-label">{c.label}</span>
          </button>
        ))}
      </div>
    </>
  );
}

export function Overview({ embedded = false }: { embedded?: boolean }) {
  const [view, setView] = useState<OverviewView | null>(null);
  const [chat, setChat] = useState<PrefsView["chat_effective"]>({});
  const [error, setError] = useState<CmdError | null>(null);
  // A cell is hidden when its command fails (not_available on an older service, or no service at all).
  const [loaded, setLoaded] = useState<Loaded>({ mcp: null, email: null, folders: null });
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
  // The data-source cells (not in first run): on mount and whenever the service becomes reachable.
  const reachable = view?.reachable ?? false;
  useEffect(() => {
    if (embedded || !reachable) return;
    let cancelled = false;
    void Promise.allSettled([ipc.mcpServers(), ipc.mailboxes(), ipc.folders()]).then(([m, e, f]) => {
      if (cancelled) return;
      setLoaded({
        mcp: m.status === "fulfilled" ? m.value : null,
        email: e.status === "fulfilled" ? e.value.length : null,
        folders: f.status === "fulfilled" ? f.value.folders.length : null,
      });
    });
    return () => {
      cancelled = true;
    };
  }, [embedded, reachable]);

  const check = useCheckRun();
  const toolbar = (
    <Toolbar
      title="Overview"
      embedded={embedded}
      actions={
        <>
          {/* First run has its own check step. */}
          {!embedded && (
            <button type="button" className="primary" disabled={check.running} onClick={() => void check.start()}>
              Run the check
            </button>
          )}
          <button type="button" onClick={refresh}>
            Refresh
          </button>
        </>
      }
    />
  );
  if (!view) {
    return (
      <section>
        {toolbar}
        <ViewBody embedded={embedded}>
          {error ? (
            <ErrorLine error={error} />
          ) : (
            <div className="box summary">
              <Skeleton lines={3} />
            </div>
          )}
        </ViewBody>
      </section>
    );
  }
  const down = serviceDown(view);
  const counts: Counts = { ...loaded, mcp: loaded.mcp ? protectedCount(loaded.mcp, view.cards) : null };
  // The empty state already says the service is not running: not a second time as an error line.
  const showError = error && !(down && error.kind === "service_unreachable");
  return (
    <section>
      {toolbar}
      <ViewBody embedded={embedded}>
        {showError && <ErrorLine error={error} />}
        <ServiceState view={view} onRefresh={refresh} embedded={embedded} />
        {!down && (
          <>
            {!embedded && <Summary view={view} />}
            <h3 className="section-title">Connections</h3>
            {view.cards.length === 0 && <p className="muted">No agent harness found on this Mac.</p>}
            {view.cards.map((c) => (
              <ConnectionRow key={c.id} card={c} chat={chat[c.id] ?? false} onChange={load} embedded={embedded} />
            ))}
            {!embedded && (
              <div className="row-wrap">
                <div className="row">
                  <RowOpen to="connection:other" embedded={false}>
                    <span className="monogram" aria-hidden="true">
                      <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" aria-hidden="true">
                        <path d="M6.5 9.5a3 3 0 0 0 4.2 0l2-2a3 3 0 0 0-4.2-4.2l-.7.7" />
                        <path d="M9.5 6.5a3 3 0 0 0-4.2 0l-2 2a3 3 0 0 0 4.2 4.2l.7-.7" />
                      </svg>
                    </span>
                    <span className="row-text">
                      <span className="row-name">Other client</span>
                      <span className="row-sentence plain">For any client that takes an MCP server URL or a model base URL.</span>
                    </span>
                    <Chevron />
                  </RowOpen>
                </div>
              </div>
            )}
            {!embedded && <DataSources counts={counts} />}
            {/* Only while it runs or after a failure; a pass shows in the summary. */}
            {!embedded && (check.running || checkFailed(check)) && <CheckBox />}
          </>
        )}
      </ViewBody>
    </section>
  );
}
