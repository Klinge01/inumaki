import type { ReactNode } from "react";

/**
 * A view's first child (spec section 4, plan R2): the view title on the left, the view's actions
 * (Refresh and the like) on the right. `embedded` (first run) renders a plain `h3` and the
 * actions, without the 50 px bar.
 */
export function Toolbar({ title, actions, embedded = false }: { title: string; actions?: ReactNode; embedded?: boolean }) {
  if (embedded) {
    return (
      <div className="head">
        <h3>{title}</h3>
        {actions}
      </div>
    );
  }
  return (
    <header className="toolbar">
      <h2>{title}</h2>
      {actions && <div className="actions">{actions}</div>}
    </header>
  );
}

/** The padded content below a view's toolbar; embedded (first run) views sit in the step and need no padding. */
export function ViewBody({ embedded = false, children }: { embedded?: boolean; children?: ReactNode }) {
  return <div className={embedded ? undefined : "view"}>{children}</div>;
}
