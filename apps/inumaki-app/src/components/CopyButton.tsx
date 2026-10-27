import { useState } from "react";

/** Copies `text` to the clipboard on a click; says so when the webview refuses. */
export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [state, setState] = useState<"idle" | "done" | "failed">("idle");
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setState("done");
    } catch {
      setState("failed");
    }
  };
  return (
    <>
      <button type="button" onClick={() => void copy()}>
        {label}
      </button>
      <span className="muted" role="status">
        {state === "done" ? " Copied." : state === "failed" ? " Copy failed; select the text instead." : ""}
      </span>
    </>
  );
}
