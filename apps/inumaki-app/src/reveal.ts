// Local reveal of originals (M6 spec §6.5): one item at a time, a fixed
// label, gone after 60 s, on navigation (the view unmounts), and when the
// window hides. The value lives only in this hook's React state: never in
// storage, the state file, logs, or the clipboard (RevealBox's Copy button
// is the one explicit way out).
//
// A reveal must not outlive its reason. `request` ties an answer to the
// click that asked for it: anything that ends the reveal meanwhile (a clear,
// a newer reveal, the window hiding, an unmount) drops the late answer.
import { useCallback, useEffect, useRef, useState } from "react";
import { useWindowHidden } from "./useWindowHidden";

export const REVEAL_LABEL = "originals revealed locally — not for transmission";
export const REVEAL_MS = 60_000;

export type Reveal<T> = {
  value: T | null;
  /** Shows `v` for REVEAL_MS; ignored while the view is unmounted or the document is hidden. */
  show: (v: T) => void;
  clear: () => void;
  /** Ends any current reveal, then shows `fetch`'s answer unless the reveal ended meanwhile. */
  request: (fetch: () => Promise<T>) => Promise<boolean>;
};

export function useReveal<T>(): Reveal<T> {
  const [value, setValue] = useState<T | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  // Bumped by everything that ends a reveal; a pending request compares it.
  const generation = useRef(0);
  const mounted = useRef(false);

  const stopTimer = useCallback(() => {
    if (timer.current !== undefined) clearTimeout(timer.current);
    timer.current = undefined;
  }, []);
  const clear = useCallback(() => {
    generation.current += 1;
    stopTimer();
    setValue(null);
  }, [stopTimer]);
  // Puts `v` on screen for REVEAL_MS; callers have settled the generation.
  const display = useCallback(
    (v: T) => {
      if (!mounted.current || document.visibilityState === "hidden") return;
      stopTimer();
      setValue(v);
      timer.current = setTimeout(() => {
        timer.current = undefined;
        generation.current += 1;
        setValue(null);
      }, REVEAL_MS);
    },
    [stopTimer],
  );
  // A direct show is a newer reveal: an older pending request must not replace it.
  const show = useCallback(
    (v: T) => {
      generation.current += 1;
      display(v);
    },
    [display],
  );
  const request = useCallback(
    async (fetch: () => Promise<T>) => {
      clear();
      const asked = generation.current;
      const v = await fetch();
      if (asked !== generation.current || !mounted.current || document.visibilityState === "hidden") return false;
      display(v);
      return true;
    },
    [clear, display],
  );

  useWindowHidden(clear);
  useEffect(() => {
    mounted.current = true;
    const onVisibility = () => {
      if (document.visibilityState === "hidden") clear();
    };
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      mounted.current = false;
      generation.current += 1;
      document.removeEventListener("visibilitychange", onVisibility);
      stopTimer();
    };
  }, [clear, stopTimer]);

  return { value, show, clear, request };
}
