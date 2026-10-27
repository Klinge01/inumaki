import { useEffect, useMemo, useRef, useState } from "react";
import * as ipc from "../../ipc";
import type { CmdError } from "../../types";
import { useReveal } from "../../reveal";
import { ErrorLine } from "../../components/ErrorLine";
import { NotAvailable } from "../../components/NotAvailable";
import { RevealBox } from "../../components/RevealBox";
import { Skeleton } from "../../components/Skeleton";
import { when } from "./source";
import { recordsByEntry, size, what } from "./record";
import { useLinkData } from "./data";
import { Payload, useAsSent } from "./Payload";

/**
 * The Journal tab (spec section 7.4): what was released for one source, each entry linked back to the
 * record that released it (section 9.2), as sent (tokens) or, on request, revealed (useReveal, 60 s).
 * Selecting another entry drops both.
 */
export function Journal({
  dataset,
  selected,
  onSelect,
  onOpenRecord,
}: {
  dataset: string;
  selected: string | null;
  onSelect: (id: string) => void;
  onOpenRecord: (id: string) => void;
}) {
  const { records, recordsError, entries, entriesError } = useLinkData(dataset);
  const [error, setError] = useState<CmdError | null>(null);
  const reveal = useReveal<string>();
  const asSent = useAsSent(dataset, setError);
  const from = useMemo(() => recordsByEntry(records ?? [], entries ?? []), [records, entries]);
  const row = useRef<HTMLTableRowElement | null>(null);
  const loaded = entries !== null;
  // The entry arrived at from a record is scrolled into view once the list is there.
  useEffect(() => {
    if (loaded) row.current?.scrollIntoView?.({ block: "nearest" });
  }, [loaded]);
  if (entriesError && ipc.isNotAvailable(entriesError)) return <NotAvailable what="The egress journal" />;
  const select = (id: string) => {
    if (id !== selected) {
      reveal.clear();
      asSent.clear();
    }
    onSelect(id);
  };
  const showSent = (id: string) => {
    select(id);
    setError(null);
    reveal.clear();
    asSent.show(id);
  };
  const showOriginals = (id: string) => {
    select(id);
    setError(null);
    asSent.clear();
    reveal
      .request(() => ipc.journalRecord(dataset, id, true).then((r) => r.payload))
      .catch((e) => setError(ipc.asCmdError(e)));
  };
  return (
    <>
      <div className="box">
        {entries === null && !entriesError && <Skeleton lines={3} />}
        {entries?.length === 0 && !entriesError && <p className="muted box-pad">Nothing released yet.</p>}
        {entries && entries.length > 0 && (
          <table className="grid">
            <thead>
              <tr>
                <th>Released</th>
                <th>Size</th>
                <th>From record</th>
                <th>
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => {
                const on = e.id === selected;
                const r = from.get(e.id);
                return (
                  <tr
                    key={e.id}
                    ref={on ? row : undefined}
                    className={on ? "selected" : undefined}
                    aria-current={on ? "true" : undefined}
                  >
                    <td>
                      <button type="button" className="row-pick" onClick={() => select(e.id)}>
                        {when(e.at)}
                      </button>
                    </td>
                    <td>{size(e.bytes)}</td>
                    <td>
                      {r ? (
                        <button type="button" className="text sm" onClick={() => onOpenRecord(r.id)}>
                          {what(r)}
                        </button>
                      ) : (
                        "–"
                      )}
                    </td>
                    <td className="actions">
                      <button type="button" className="sm" onClick={() => showSent(e.id)}>
                        As sent
                      </button>
                      <button type="button" className="sm" onClick={() => showOriginals(e.id)}>
                        Reveal originals
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
      {asSent.value && <Payload text={asSent.value.payload} />}
      {reveal.value !== null && <RevealBox text={reveal.value} reveal={reveal} />}
      {entriesError && <ErrorLine error={entriesError} />}
      {recordsError && !ipc.isNotAvailable(recordsError) && <ErrorLine error={recordsError} />}
      {error && <ErrorLine error={error} />}
    </>
  );
}
