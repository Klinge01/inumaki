import type { DataChange } from "../types";
import { Notice } from "./Notice";

/** What a data-source change left over: failed Reconnects and the macOS folder-access note. */
export function DataChangeNote({ change }: { change: DataChange | null | undefined }) {
  if (!change) return null;
  const n = change.reconnect_failures;
  return (
    <>
      {n > 0 && (
        <Notice kind="red" role="alert">
          {`${n} ${n === 1 ? "harness" : "harnesses"} could not be updated${
            change.failed_harnesses.length > 0 ? ` (${change.failed_harnesses.join(", ")})` : ""
          }. Its protected servers may talk to the originals again; reconnect it from Overview.`}
        </Notice>
      )}
      {change.warning === "folder_needs_access" && (
        <Notice kind="amber" role="status">
          This folder is one macOS protects (Desktop, Documents, Downloads, iCloud Drive, or an external volume). macOS may
          ask you to allow inumaki to read it; allow it, then rescan the folder.
        </Notice>
      )}
    </>
  );
}
