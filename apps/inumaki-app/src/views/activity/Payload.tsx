import { useCallback, useRef, useState } from "react";
import * as ipc from "../../ipc";
import type { CmdError } from "../../types";
import { useWindowHidden } from "../../useWindowHidden";

// A token as the engine writes it with the default delimiters (inumaki-core `Rehydrator::pattern`):
// `<LABEL_hex>`, `<LABEL_hex_hh>`, or `<LABEL_REMOVED>`. One capture group, so `split` keeps the tokens.
const TOKEN_SPLIT = /(<[A-Z][A-Z0-9_]*_(?:[0-9a-f]{4,12}(?:_[0-9a-f]{2})?|REMOVED)>)/;

/**
 * A released payload as sent: text, with each token as a token chip. The payload may not be JSON, so it
 * is rendered as text nodes only (never as HTML).
 */
export function Payload({ text }: { text: string }) {
  return (
    <pre className="payload">
      {text.split(TOKEN_SPLIT).map((part, i) =>
        i % 2 === 1 ? (
          <span key={i} className="token">
            {part}
          </span>
        ) : (
          part
        ),
      )}
    </pre>
  );
}

/**
 * The payload of one journal entry as sent (`journal_record(…, reveal: false)`: tokens only, no
 * originals), held only in this hook's state. It goes when the window hides, on `clear`, and with the
 * component; an answer that arrives after any of those is dropped.
 */
export function useAsSent(dataset: string, onError: (e: CmdError) => void) {
  const [value, setValue] = useState<{ id: string; payload: string } | null>(null);
  const generation = useRef(0);
  const clear = useCallback(() => {
    generation.current += 1;
    setValue(null);
  }, []);
  useWindowHidden(clear);
  const show = (id: string) => {
    clear();
    const asked = generation.current;
    ipc.journalRecord(dataset, id, false).then(
      (r) => {
        if (asked === generation.current && document.visibilityState !== "hidden") setValue({ id, payload: r.payload });
      },
      (e) => {
        if (asked === generation.current) onError(ipc.asCmdError(e));
      },
    );
  };
  return { value, show, clear };
}
