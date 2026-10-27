import type { ReactNode } from "react";
import type { HarnessCard, PathView } from "../types";
import { formatCheckTime } from "../time";
import { Glyph, type Tone } from "./Glyph";

export const Tick = () => (
  <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="m3 8.5 3.2 3.2L13 4.8" />
  </svg>
);

export const Cross = () => (
  <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
    <path d="m4 4 8 8M12 4l-8 8" />
  </svg>
);

/**
 * The check result in a path section's header (spec section 6.3, plan R8). A stored result counts only
 * while the harness is connected: a disconnected harness says "No check since the disconnect" and never
 * shows the stored result (B5); a harness that is not connected shows nothing (a memo left after a
 * Revert is stale too).
 */
export function CheckSlot({ card, view }: { card: HarnessCard; view: PathView }) {
  if (card.disconnected) return <span className="sec-check none">No check since the disconnect</span>;
  if (!card.connected) return null;
  if (view.last_check === "passed") {
    return (
      <span className="sec-check res pass">
        <Tick /> {card.last_check_at != null ? `Check passed ${formatCheckTime(card.last_check_at)}` : "Check passed"}
      </span>
    );
  }
  if (view.last_check === "failed") {
    return (
      <span className="sec-check res fail">
        <Cross /> Check failed
      </span>
    );
  }
  return null;
}

/**
 * One path's box on the connection page (spec section 6.3): a header with the glyph, the title
 * ("MCP tools: on"), the path's reason or a default line, and a right slot (the check result); then
 * an optional body and an optional footer in `--well`. Pass `children` only when there is a body:
 * an empty body still draws its frame.
 */
export function PathSection({
  id,
  tone,
  title,
  line,
  right,
  footer,
  children,
}: {
  /** Unique on the page; names the header for the section's accessible name. */
  id: string;
  tone: Tone;
  title: string;
  line?: string | null;
  right?: ReactNode;
  footer?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <section className="box path-section" aria-labelledby={id}>
      <div className="box-head sec-head">
        <Glyph tone={tone} />
        <div className="sec-text">
          <h4 id={id} className="sec-title">
            {title}
          </h4>
          {line && <p className="sec-line">{line}</p>}
        </div>
        {right}
      </div>
      {/* No padding of its own: a table runs edge to edge, other content sits in `.sec-pad`. */}
      {children && <div className="sec-body">{children}</div>}
      {footer && <div className="box-foot">{footer}</div>}
    </section>
  );
}
