import { useCallback, useState } from "react";
import type { HarnessId } from "./types";

// A Revert that left the client header in a harness file leaves nothing in the
// daemon to look at, so the warning must outlive a reload and a view switch:
// it is kept here (harness ids only, no values) until the user dismisses it or
// a Connect writes the header on purpose.
let headerLeftIds: ReadonlySet<HarnessId> = new Set();

export function useHeaderLeft(): [ReadonlySet<HarnessId>, (id: HarnessId, on: boolean) => void] {
  const [ids, setIds] = useState(headerLeftIds);
  const set = useCallback((id: HarnessId, on: boolean) => {
    const next = new Set(headerLeftIds);
    if (on) next.add(id);
    else next.delete(id);
    headerLeftIds = next;
    setIds(next);
  }, []);
  return [ids, set];
}

