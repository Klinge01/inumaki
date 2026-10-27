import { useEffect, useId, useRef, useState, type ReactNode } from "react";

const FOCUSABLE =
  'button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),a[href],[tabindex]:not([tabindex="-1"])';

/**
 * A sheet: a dim layer over the content and a panel hanging from the toolbar (spec section 6.5).
 * The title names the panel; without a title, `label` is the accessible name. Escape calls `onClose`.
 * The caller puts the default focus (Cancel) in `actions`, so a stray Enter never confirms. Tab stays
 * inside the panel, and when the sheet closes the focus goes back to the element that opened it.
 */
export function Sheet({
  title,
  label,
  onClose,
  children,
  actions,
}: {
  title?: string;
  label: string;
  onClose: () => void;
  children?: ReactNode;
  actions?: ReactNode;
}) {
  // Captured during the first render, before the panel's autoFocus moves the focus.
  const [opener] = useState(() =>
    document.activeElement instanceof HTMLElement && document.activeElement !== document.body
      ? document.activeElement
      : null,
  );
  const close = useRef(onClose);
  useEffect(() => {
    close.current = onClose;
  });
  const panel = useRef<HTMLDivElement>(null);
  const titleId = useId();
  useEffect(() => {
    const node = panel.current;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        close.current();
        return;
      }
      if (e.key !== "Tab" || !panel.current) return;
      const items = Array.from(panel.current.querySelectorAll<HTMLElement>(FOCUSABLE));
      if (items.length === 0) {
        e.preventDefault();
        return;
      }
      const first = items[0];
      const last = items[items.length - 1];
      const active = document.activeElement;
      const outside = !(active instanceof Node) || !panel.current.contains(active);
      if (e.shiftKey) {
        if (outside || active === first) {
          e.preventDefault();
          last.focus();
        }
      } else if (outside || active === last) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      // Only on a real close (the panel left the page), not on StrictMode's test unmount.
      if (node && !node.isConnected && opener?.isConnected) opener.focus();
    };
  }, [opener]);
  return (
    <div className="sheet-dim">
      <div
        ref={panel}
        className="sheet"
        role="alertdialog"
        aria-modal="true"
        aria-labelledby={title ? titleId : undefined}
        aria-label={title ? undefined : label}
      >
        {title && <h2 id={titleId}>{title}</h2>}
        {children}
        {actions && <div className="actions">{actions}</div>}
      </div>
    </div>
  );
}
