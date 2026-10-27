import { useCallback, useEffect, useRef, useState, type KeyboardEvent } from "react";
import * as ipc from "../../ipc";
import type { CmdError, Entity, ForgetOutcome } from "../../types";
import { REVEAL_LABEL, useReveal } from "../../reveal";
import { useWindowHidden } from "../../useWindowHidden";
import { ErrorLine } from "../../components/ErrorLine";
import { NotAvailable } from "../../components/NotAvailable";
import { Notice, type NoticeKind } from "../../components/Notice";
import { RevealCountdown } from "../../components/RevealPanel";
import { Skeleton } from "../../components/Skeleton";
import { Tick } from "../../components/PathSection";
import { when } from "./source";

const NOTHING = "Nothing to forget.";
const PAUSED_HINT = "Forget is paused while originals are visible, so a forgotten value never stays on screen.";
const PAUSED_ID = "entities-forget-paused";

/** What a forget did, in words. A pending purge is a success, never "0 forgotten". */
export function forgetText(o: ForgetOutcome): string {
  if (o.purge_pending) return "Forgotten, cleanup pending.";
  if (o.tokens === 0) return NOTHING;
  return `Forgot ${o.tokens} ${o.tokens === 1 ? "token" : "tokens"}${o.kinds.length ? ` (${o.kinds.join(", ")})` : ""}.`;
}

/** A clock, for a pending cleanup and the chat source's empty state. Decorative. */
const ClockIcon = ({ size = 16 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" aria-hidden="true">
    <circle cx="8" cy="8" r="6" />
    <path d="M8 4.8V8l2.2 1.4" />
  </svg>
);

type Result = { kind?: NoticeKind; icon?: "tick" | "clock"; title: string; body: string };

/** The result notice of a forget (spec section 7.4). The title is `forgetText`; the typed value is never echoed. */
function forgetResult(o: ForgetOutcome, source: string): Result {
  const title = forgetText(o);
  if (o.purge_pending) return { icon: "clock", title, body: "The mapping is gone; the service is removing the token from its logs." };
  if (o.tokens === 0) return nothingResult(source);
  return { icon: "tick", title, body: "Earlier text with this token can no longer be restored. The list below is up to date." };
}

const nothingResult = (source: string): Result => ({
  kind: "info",
  title: NOTHING,
  body: `No token in ${source} matches. It may have been forgotten already, or it belongs to another data source.`,
});

/**
 * The Known entities tab (spec section 7.4): one source's tokens, a reveal of their originals, and
 * forget, inline per row or by a typed value. Privacy rules:
 * - originals come only through `useReveal` and show only in the revealed column;
 * - while they are visible, row forgets are paused (plan R15), and any forget clears the reveal when
 *   it starts, so a forgotten value never stays on screen;
 * - after every forget, success or error, the list reloads at once, so a stale row never stays;
 * - the typed value lives only in the input element (uncontrolled, so React never mirrors it into the
 *   DOM `value` attribute): read once on send, and cleared on send and when the window hides.
 */
export function Entities({ dataset, source }: { dataset: string; source: string }) {
  const [list, setList] = useState<Entity[] | null>(null);
  const [loadError, setLoadError] = useState<CmdError | null>(null);
  const [error, setError] = useState<CmdError | null>(null);
  const reveal = useReveal<Entity[]>();
  // The token whose row asks "Forget this …?" (an opaque token, kept in component state only).
  const [confirm, setConfirm] = useState<string | null>(null);
  const valueRef = useRef<HTMLInputElement>(null);
  const [hasValue, setHasValue] = useState(false);
  const clearValue = () => {
    if (valueRef.current) valueRef.current.value = "";
    setHasValue(false);
  };
  const [result, setResult] = useState<Result | null>(null);
  // While a forget runs, no reveal: it could show the original being forgotten.
  const [forgetting, setForgetting] = useState(false);
  // A typed value is an original too: it does not stay in the field unattended (window hide and
  // visibilitychange to hidden, both through useWindowHidden).
  useWindowHidden(clearValue);
  // Only the newest load may set the list: an older answer could bring back a forgotten row.
  const seq = useRef(0);
  const load = useCallback(() => {
    const n = ++seq.current;
    return ipc.entities(dataset, false).then(
      (l) => {
        if (n !== seq.current) return;
        setLoadError(null);
        setList(l.entities);
      },
      (e) => {
        if (n !== seq.current) return;
        // No stale list stays on screen beside the error.
        setList(null);
        setLoadError(ipc.asCmdError(e));
      },
    );
  }, [dataset]);
  useEffect(() => void load(), [load]);
  if (loadError && ipc.isNotAvailable(loadError)) return <NotAvailable what="The entity list" />;
  const revealed = reveal.value !== null;
  const shown = reveal.value ?? list ?? [];
  const forgotten = (p: Promise<ForgetOutcome>) => {
    setError(null);
    setResult(null);
    setConfirm(null);
    // A forgotten entity's revealed original must not stay on screen.
    reveal.clear();
    setForgetting(true);
    p.then(
      (o) => {
        reveal.clear();
        setResult(forgetResult(o, source));
      },
      (e) => {
        const err = ipc.asCmdError(e);
        if (err.kind === "not_found") setResult(nothingResult(source));
        else setError(err);
      },
    ).finally(() => {
      setForgetting(false);
      // Success or error: the list is read again at once (B8).
      void load();
    });
  };
  const onConfirmKey = (e: KeyboardEvent<HTMLTableRowElement>) => {
    if (e.key === "Escape") setConfirm(null);
  };
  const count = list?.length;
  return (
    <>
      {result && (
        <Notice
          kind={result.kind}
          icon={result.icon === "tick" ? <Tick /> : result.icon === "clock" ? <ClockIcon /> : undefined}
          title={result.title}
          role="status"
        >
          {result.body}
        </Notice>
      )}
      {error && <ErrorLine error={error} />}
      <div className="box entities">
        <div className="box-head">
          <h3>{count === undefined ? "Known entities" : `${count} known ${count === 1 ? "entity" : "entities"}`}</h3>
          {revealed && <RevealCountdown reveal={reveal} />}
          <button
            type="button"
            className="sm head-end"
            disabled={forgetting}
            onClick={() => {
              setError(null);
              setConfirm(null);
              reveal
                .request(() => ipc.entities(dataset, true).then((l) => l.entities))
                .catch((e) => setError(ipc.asCmdError(e)));
            }}
          >
            Reveal originals for 60 s
          </button>
        </div>
        {/* While originals are visible, this is the revealed region: hatched, named by the fixed label. */}
        <div
          className={revealed ? "entities-body revealed-region" : "entities-body"}
          role={revealed ? "region" : undefined}
          aria-label={revealed ? REVEAL_LABEL : undefined}
        >
          {revealed && (
            <>
              <p className="reveal-label">{REVEAL_LABEL}</p>
              <p className="muted" id={PAUSED_ID}>
                {PAUSED_HINT}
              </p>
            </>
          )}
          {list === null && !loadError && <Skeleton lines={3} />}
          {list?.length === 0 && !revealed && <p className="muted box-pad">No known entities.</p>}
          {shown.length > 0 && (
            <table className="grid">
              <thead>
                <tr>
                  <th>Token</th>
                  <th>Kind</th>
                  <th>Uses</th>
                  <th>Last used</th>
                  {revealed && <th>Original</th>}
                  <th>
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {shown.map((e) =>
                  confirm === e.token && !revealed ? (
                    <tr key={e.token} className="confirm" onKeyDown={onConfirmKey}>
                      <td>
                        <span className="token">{e.token}</span>
                      </td>
                      <td colSpan={3}>{`Forget this ${e.kind}? Earlier sanitized text with its token can't be restored.`}</td>
                      <td className="actions">
                        <button type="button" className="sm" autoFocus onClick={() => setConfirm(null)}>
                          Cancel
                        </button>
                        <button
                          type="button"
                          className="sm danger"
                          disabled={forgetting}
                          onClick={() => forgotten(ipc.forgetToken(dataset, e.token))}
                        >
                          Forget
                        </button>
                      </td>
                    </tr>
                  ) : (
                    <tr key={e.token}>
                      <td>
                        <span className="token">{e.token}</span>
                      </td>
                      <td>
                        {e.kind}
                        {!e.current_epoch && <span className="chip older">older rotation</span>}
                      </td>
                      <td>{e.uses}</td>
                      <td>{when(e.last_use)}</td>
                      {revealed && <td className="revealed">{e.original ?? ""}</td>}
                      <td className="actions">
                        <button
                          type="button"
                          className="sm"
                          disabled={revealed || forgetting}
                          aria-describedby={revealed ? PAUSED_ID : undefined}
                          onClick={() => setConfirm(e.token)}
                        >
                          Forget…
                        </button>
                      </td>
                    </tr>
                  ),
                )}
              </tbody>
            </table>
          )}
        </div>
        <div className="box-foot forget-value">
          <input
            type="password"
            autoComplete="off"
            aria-label="Forget by value"
            placeholder="Forget by value (typed value is hidden)"
            ref={valueRef}
            onChange={(e) => setHasValue(e.target.value !== "")}
          />
          <button
            type="button"
            className="sm"
            disabled={!hasValue || forgetting}
            onClick={() => {
              const v = valueRef.current?.value ?? "";
              if (v === "") return;
              clearValue();
              forgotten(ipc.forgetValue(dataset, v));
            }}
          >
            Forget
          </button>
          <span>The field clears when the window hides.</span>
        </div>
      </div>
      {loadError && <ErrorLine error={loadError} />}
    </>
  );
}

/**
 * The chat source keeps no entities (spec section 7.4): each chat session's tokens live in memory and
 * go with the session. Nothing is asked of the service here, and there is no forget by value.
 */
export function ChatEntities({ onShowRecords }: { onShowRecords: () => void }) {
  return (
    <div className="empty-state">
      <span className="empty-tile" aria-hidden="true">
        <ClockIcon size={20} />
      </span>
      <h3>Chat keeps no entities</h3>
      <p>
        Each chat session gets its own tokens. They live in memory and are gone when the session ends, so there is
        nothing here to list or forget. Records and the journal for chat are still kept.
      </p>
      <div className="actions">
        <button type="button" onClick={onShowRecords}>
          Show chat records
        </button>
      </div>
    </div>
  );
}
