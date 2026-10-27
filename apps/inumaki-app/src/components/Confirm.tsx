import type { ReactNode } from "react";
import { Sheet } from "./Sheet";

/**
 * A confirmation sheet. The confirm button carries a real verb ("Revert", "Turn on"), never "Yes".
 * `children` is the note slot under the body (for example the amber notice of the chat-on sheet).
 * Revert, Forget, Remove, and Delete are destructive and get the `danger` class; the rest are primary.
 */
const DESTRUCTIVE = new Set(["Revert", "Forget", "Remove", "Delete"]);

export function Confirm({
  title,
  text,
  verb,
  onYes,
  onNo,
  children,
}: {
  title?: string;
  text: string;
  verb: string;
  onYes: () => void;
  onNo: () => void;
  children?: ReactNode;
}) {
  return (
    <Sheet
      title={title}
      label={text}
      onClose={onNo}
      actions={
        <>
          {/* Cancel is the default focus: a stray Enter does not confirm. */}
          <button type="button" autoFocus onClick={onNo}>
            Cancel
          </button>
          <button type="button" className={DESTRUCTIVE.has(verb) ? "danger" : "primary"} onClick={onYes}>
            {verb}
          </button>
        </>
      }
    >
      <p>{text}</p>
      {children}
    </Sheet>
  );
}
