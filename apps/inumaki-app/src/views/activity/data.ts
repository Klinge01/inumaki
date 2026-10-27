import { useEffect, useState } from "react";
import * as ipc from "../../ipc";
import type { ActivityRecord, CmdError, JournalEntry } from "../../types";

export type LinkData = {
  records: ActivityRecord[] | null;
  recordsError: CmdError | null;
  /** Always `[]` under All sources: links need the record's source (spec section 9.2). */
  entries: JournalEntry[] | null;
  entriesError: CmdError | null;
};

/**
 * The records (`activity(dataset, 200)`) and, for one source, its journal entries beside them, so a
 * record can link to the entry of what it released and back (spec section 9.2). A slow answer for a
 * panel that is gone, or for another source, does not land anywhere.
 */
export function useLinkData(dataset: string | null): LinkData {
  const [data, setData] = useState<LinkData>({
    records: null,
    recordsError: null,
    entries: dataset ? null : [],
    entriesError: null,
  });
  useEffect(() => {
    let stale = false;
    const put = (patch: Partial<LinkData>) => {
      if (!stale) setData((d) => ({ ...d, ...patch }));
    };
    ipc.activity(dataset, 200).then(
      (l) => put({ records: l.records }),
      (e) => put({ recordsError: ipc.asCmdError(e) }),
    );
    if (dataset) {
      ipc.journal(dataset).then(
        (j) => put({ entries: j.entries }),
        (e) => put({ entries: [], entriesError: ipc.asCmdError(e) }),
      );
    }
    return () => {
      stale = true;
    };
  }, [dataset]);
  return data;
}
