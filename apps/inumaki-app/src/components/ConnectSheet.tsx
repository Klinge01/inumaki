import type { FileChange, HarnessCard } from "../types";
import { Sheet } from "./Sheet";
import { CHAT_CONNECT_NOTE, CHAT_TEXT, CLAUDE_CONNECT_NOTE } from "../harnessText";

/**
 * The Connect sheet (spec section 6.5): the files Connect changes and the harness note, or the reason the
 * preview was refused (Connect then answers with the lines to add by hand). The note precedes the button.
 */
export function ConnectSheet({
  card,
  preview,
  refused,
  chat,
  busy,
  onConnect,
  onCancel,
}: {
  card: HarnessCard;
  preview: FileChange[] | null;
  refused: string | null;
  /** This harness's chat is wanted (the `prefs` effective value). */
  chat: boolean;
  busy: boolean;
  onConnect: () => void;
  onCancel: () => void;
}) {
  const title = `Connect ${card.name}?`;
  return (
    <Sheet
      title={title}
      label={title}
      onClose={onCancel}
      actions={
        <>
          {/* Cancel is the default focus: a stray Enter does not connect. */}
          <button type="button" autoFocus onClick={onCancel}>
            Cancel
          </button>
          <button type="button" className="primary" disabled={busy} onClick={onConnect}>
            Connect
          </button>
        </>
      }
    >
      {refused ? (
        <p>{refused}</p>
      ) : (
        <>
          <p>inumaki changes these files. It makes a backup first, and Revert restores it.</p>
          <ul className="file-list">
            {(preview ?? []).map((c) => (
              <li key={c.path}>
                <span className="mono">{c.path}</span>
                <span className="file-keys">{c.keys.join(", ")}</span>
              </li>
            ))}
          </ul>
          <p>{card.id === "claude-code" ? CLAUDE_CONNECT_NOTE : CHAT_CONNECT_NOTE}</p>
          {chat && <p>{CHAT_TEXT[card.id].on}</p>}
        </>
      )}
    </Sheet>
  );
}
