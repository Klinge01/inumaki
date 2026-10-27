import { useEffect, useState, type CSSProperties, type ReactNode } from "react";
import { REVEAL_LABEL, REVEAL_MS } from "../reveal";

/** "m:ss" for the time left, rounded up so the pill never reads 0:00 while originals are still shown. */
function clock(ms: number): string {
  const s = Math.ceil(Math.max(0, ms) / 1000);
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

/**
 * The countdown pill and "Hide now" (spec section 8.2). The pill counts from its own mount, or from the
 * moment `reveal.value` changes to another reveal (plan R23); `useReveal` stays the clock that actually
 * takes the originals away. `RevealPanel` shows it in its own head; a box that reveals in place (the
 * Known entities table) shows it in the box header.
 */
export function RevealCountdown({ reveal }: { reveal: { value: unknown; clear: () => void } }) {
  const [left, setLeft] = useState(REVEAL_MS);
  const stamp = reveal.value;
  useEffect(() => {
    const start = Date.now();
    setLeft(REVEAL_MS);
    const t = setInterval(() => setLeft(Math.max(0, REVEAL_MS - (Date.now() - start))), 500);
    return () => clearInterval(t);
  }, [stamp]);
  // The ring's share left: a dynamic value, so it goes through React's style prop (CSP style-src 'self').
  const ring = { "--p": String(left / REVEAL_MS) } as CSSProperties;
  return (
    <>
      <span className="countdown">
        <span className="ring" style={ring} aria-hidden="true" />
        {`Originals visible, ${clock(left)}`}
      </span>
      <button type="button" className="sm" onClick={reveal.clear}>
        Hide now
      </button>
    </>
  );
}

/**
 * The hatched region that holds revealed originals (spec section 8.2): the fixed label, a countdown
 * pill, and "Hide now". Callers render the panel only while `reveal.value` is set, so it goes with
 * the reveal.
 *
 * Nothing about the revealed value is written into an attribute: the region's name is the fixed label.
 * The clipboard gets originals only through an explicit `CopyButton` among the children (spec section 6.5).
 */
export function RevealPanel({
  reveal,
  children,
}: {
  reveal: { value: unknown; clear: () => void };
  children?: ReactNode;
}) {
  return (
    <div className="reveal-panel revealed" role="region" aria-label={REVEAL_LABEL}>
      <div className="reveal-head">
        <span className="reveal-label">{REVEAL_LABEL}</span>
        <RevealCountdown reveal={reveal} />
      </div>
      {children}
    </div>
  );
}
