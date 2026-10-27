import { useEffect, useMemo, useRef, useState } from "react";
import * as ipc from "../../ipc";
import type { ActivityRecord, CmdError, JournalEntry } from "../../types";
import { useReveal } from "../../reveal";
import { ErrorLine } from "../../components/ErrorLine";
import { Glyph } from "../../components/Glyph";
import { RevealBox } from "../../components/RevealBox";
import { Skeleton } from "../../components/Skeleton";
import { CHAT_DATASET, when } from "./source";
import { byDigest, checkWords, linkFor, size, verdict, what } from "./record";
import { useLinkData } from "./data";
import { Payload, useAsSent } from "./Payload";

/** The verdict word with its glyph. */
function Result({ r }: { r: ActivityRecord }) {
  const v = verdict(r);
  return (
    <span className="status-word">
      <Glyph tone={v.tone} />
      {v.word}
    </span>
  );
}

/** Kind chips, "Nothing found" when none; chat records add "session tokens" (their tokens live per session). */
function Found({ r }: { r: ActivityRecord }) {
  return (
    <span className="found">
      {r.kinds.length === 0 && <span>Nothing found</span>}
      {r.kinds.map((k, i) => (
        <span key={i} className="kind">
          {k.kind} <b>{k.count}</b>
        </span>
      ))}
      {r.dataset === CHAT_DATASET && <span className="chip">session tokens</span>}
    </span>
  );
}

/**
 * The selected record's facts and, for one source, its payload as sent (tokens only) or revealed
 * (useReveal, 60 s). Keyed by the record, so selecting another record drops both.
 */
function Detail({
  r,
  entry,
  dataset,
  source,
  onOpenEntry,
}: {
  r: ActivityRecord;
  entry: JournalEntry | null;
  dataset: string | null;
  source: string;
  onOpenEntry: (id: string) => void;
}) {
  const [error, setError] = useState<CmdError | null>(null);
  const reveal = useReveal<string>();
  const asSent = useAsSent(dataset ?? "", setError);
  const checks = checkWords(r);
  const released = entry ? `${size(entry.bytes)} to the agent's model` : r.verdict === "released" ? "–" : "Not sent";
  return (
    <aside className="box detail" aria-label="Record details">
      <h3>{what(r)}</h3>
      <p className="detail-meta">{`${source}, ${when(r.at)}`}</p>
      <dl className="dl">
        <dt>Result</dt>
        <dd>
          <Result r={r} />
        </dd>
        <dt>Checks that fired</dt>
        <dd>{checks.length ? checks.join(", ") : "None"}</dd>
        <dt>Found</dt>
        <dd>
          <Found r={r} />
        </dd>
        <dt>Released</dt>
        <dd>{released}</dd>
      </dl>
      {dataset === null && <p className="muted">Pick the source to see the payload.</p>}
      {dataset !== null && entry && (
        <>
          <div className="actions">
            <button
              type="button"
              onClick={() => {
                setError(null);
                reveal.clear();
                asSent.show(entry.id);
              }}
            >
              As sent
            </button>
            <button
              type="button"
              onClick={() => {
                setError(null);
                asSent.clear();
                reveal
                  .request(() => ipc.journalRecord(dataset, entry.id, true).then((x) => x.payload))
                  .catch((e) => setError(ipc.asCmdError(e)));
              }}
            >
              Reveal originals
            </button>
            <button type="button" className="text" onClick={() => onOpenEntry(entry.id)}>
              Open in journal
            </button>
          </div>
          {asSent.value && <Payload text={asSent.value.payload} />}
          {reveal.value !== null && <RevealBox text={reveal.value} reveal={reveal} />}
        </>
      )}
      {error && <ErrorLine error={error} />}
    </aside>
  );
}

/**
 * The Records tab (spec section 7.4): the records of one source or of all, a detail pane for the
 * selected one, and for one source the link from a record to the journal entry it released (section 9.2).
 */
export function Records({
  dataset,
  source,
  selected,
  onSelect,
  onOpenEntry,
}: {
  dataset: string | null;
  /** How a record's source is named in the detail pane. */
  source: (id: string) => string;
  selected: string | null;
  onSelect: (id: string) => void;
  onOpenEntry: (id: string) => void;
}) {
  const { records, recordsError, entries, entriesError } = useLinkData(dataset);
  const index = useMemo(() => byDigest(entries ?? []), [entries]);
  const link = (r: ActivityRecord) => (dataset ? linkFor(r, index) : null);
  const current = records?.find((r) => r.id === selected) ?? null;
  const row = useRef<HTMLTableRowElement | null>(null);
  const loaded = records !== null;
  // A record arrived at from the journal is scrolled into view once the list is there.
  useEffect(() => {
    if (loaded) row.current?.scrollIntoView?.({ block: "nearest" });
  }, [loaded]);
  const open = (r: ActivityRecord, entryId: string) => {
    onSelect(r.id);
    onOpenEntry(entryId);
  };
  return (
    <>
      <div className="records-cols">
        <div className="box">
          {records === null && !recordsError && <Skeleton lines={4} />}
          {records?.length === 0 && <p className="muted box-pad">No records yet.</p>}
          {records && records.length > 0 && (
            <table className="grid records">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>What</th>
                  <th>Result</th>
                  <th>Found</th>
                  <th>Released</th>
                </tr>
              </thead>
              <tbody>
                {records.map((r) => {
                  const e = link(r);
                  const on = r.id === selected;
                  const checks = checkWords(r);
                  return (
                    <tr
                      key={r.id}
                      ref={on ? row : undefined}
                      className={on ? "selected" : undefined}
                      aria-current={on ? "true" : undefined}
                      onClick={() => onSelect(r.id)}
                    >
                      <td>
                        <button type="button" className="row-pick" onClick={() => onSelect(r.id)}>
                          {when(r.at)}
                        </button>
                      </td>
                      <td>{what(r)}</td>
                      <td>
                        <Result r={r} />
                        {checks.length > 0 && <div className="checks">{checks.join(", ")}</div>}
                      </td>
                      <td>
                        <Found r={r} />
                      </td>
                      <td>
                        {e ? (
                          <button type="button" className="text sm" onClick={() => open(r, e.id)}>
                            {size(e.bytes)}
                          </button>
                        ) : r.verdict === "released" ? (
                          "–"
                        ) : (
                          "Not sent"
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
        {current ? (
          <Detail
            key={current.id}
            r={current}
            entry={link(current)}
            dataset={dataset}
            source={source(current.dataset)}
            onOpenEntry={(id) => open(current, id)}
          />
        ) : (
          records &&
          records.length > 0 && (
            <aside className="box detail">
              <p className="muted">Pick a record to see what was found and released.</p>
            </aside>
          )
        )}
      </div>
      {recordsError && <ErrorLine error={recordsError} />}
      {entriesError && !ipc.isNotAvailable(entriesError) && <ErrorLine error={entriesError} />}
    </>
  );
}
