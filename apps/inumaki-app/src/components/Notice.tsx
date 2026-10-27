import type { ReactNode } from "react";

export type NoticeKind = "info" | "amber" | "red";

export function NoticeIcon({ kind }: { kind?: NoticeKind }) {
  // Decorative inline SVG: the notice text carries the meaning.
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
      {kind === "amber" || kind === "red" ? (
        <>
          <path d="M8 2 14.5 13.5h-13z" strokeLinejoin="round" />
          <path d="M8 6.5v3.2M8 11.5v.2" strokeLinecap="round" />
        </>
      ) : (
        <>
          <circle cx="8" cy="8" r="6" />
          <path d="M8 7.2v3.6M8 5.2v.2" strokeLinecap="round" />
        </>
      )}
    </svg>
  );
}

/**
 * A notice: icon, body, optional action (spec section 8.1). Plain without `kind`.
 * The title and a string body each render in a `<p>`. `icon` replaces the kind's icon (a tick, a clock).
 *
 * `role` is set only when the caller passes it (tests rely on exactly one alert or status), and it
 * sits on the element that holds the sentence: the title, else a string body, else the container.
 * Tests read the role off the text node's parent, and the body is a sibling of the title (plan A4).
 */
export function Notice({
  kind,
  title,
  role,
  icon,
  action,
  children,
}: {
  kind?: NoticeKind;
  icon?: ReactNode;
  title?: string;
  role?: "alert" | "status";
  action?: ReactNode;
  children?: ReactNode;
}) {
  const stringBody = typeof children === "string";
  const onTitle = role && title ? role : undefined;
  const onBody = role && !title && stringBody ? role : undefined;
  const onBox = role && !onTitle && !onBody ? role : undefined;
  return (
    <div className={`notice notice-grid${kind ? ` ${kind}` : ""}`} role={onBox}>
      <span className="notice-icon">
        {icon ?? <NoticeIcon kind={kind} />}
      </span>
      <div className="notice-body">
        {title && (
          <p className="notice-title" role={onTitle}>
            {title}
          </p>
        )}
        {stringBody ? <p role={onBody}>{children}</p> : children}
      </div>
      {action && <div className="notice-action">{action}</div>}
    </div>
  );
}
