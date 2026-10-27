import { useEffect, useRef } from "react";
import { listen } from "@tauri-apps/api/event";

/**
 * Calls `onHidden` when the app hides its window (the `window-hidden` event of
 * src-tauri/src/lib.rs, sent on close) and when the page becomes hidden
 * (`visibilitychange`: minimize, Cmd+H, which send no event). Views use it to
 * drop what cannot be re-read and must not sit on screen unattended: a
 * gateway token, a configuration snippet, a typed password.
 */
export function useWindowHidden(onHidden: () => void): void {
  const cb = useRef(onHidden);
  useEffect(() => {
    cb.current = onHidden;
  });
  useEffect(() => {
    let cancelled = false;
    let un: (() => void) | undefined;
    listen("window-hidden", () => cb.current()).then(
      (u) => {
        if (cancelled) u();
        else un = u;
      },
      () => undefined,
    );
    const onVisibility = () => {
      if (document.visibilityState === "hidden") cb.current();
    };
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      cancelled = true;
      un?.();
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, []);
}
