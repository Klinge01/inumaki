import type { ReactNode } from "react";

/** A Settings group (spec section 7.6): a small title, a box of rows, an optional footnote. */
export function Group({ title, foot, children }: { title: string; foot?: ReactNode; children: ReactNode }) {
  return (
    <section className="set-group">
      <h3 className="set-title">{title}</h3>
      <div className="box">{children}</div>
      {foot && <div className="set-foot">{foot}</div>}
    </section>
  );
}

/** One 44 px row: label and secondary line on the left, a chip or actions (`end`) on the right. */
export function Row({
  label,
  sub,
  end,
  children,
}: {
  label: ReactNode;
  sub?: ReactNode;
  end?: ReactNode;
  /** Full-width content under the row's text (a progress bar, a code block). */
  children?: ReactNode;
}) {
  return (
    <div className="set-row">
      <div className="set-text">
        <div className="set-label">{label}</div>
        {sub && <div className="set-sub">{sub}</div>}
        {children}
      </div>
      {end && <div className="set-end">{end}</div>}
    </div>
  );
}
