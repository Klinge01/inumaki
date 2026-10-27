import { CopyButton } from "./CopyButton";
import { RevealPanel } from "./RevealPanel";

/**
 * A revealed original as text, inside the reveal panel (spec section 8.2). The clipboard gets it only
 * through the explicit Copy button (spec section 6.5).
 */
export function RevealBox({ text, reveal }: { text: string; reveal: { value: unknown; clear: () => void } }) {
  return (
    <RevealPanel reveal={reveal}>
      <div className="reveal-text">{text}</div>
      <div className="actions">
        <CopyButton text={text} />
      </div>
    </RevealPanel>
  );
}
