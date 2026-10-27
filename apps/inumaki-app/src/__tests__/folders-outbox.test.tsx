// B7: a folder card shows where restored files land, and the buttons that open it pass only the dataset id.
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mock = vi.hoisted(() => ({
  calls: [] as { cmd: string; args?: Record<string, unknown> }[],
  handlers: {} as Record<string, (args?: Record<string, unknown>) => unknown>,
}));

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (cmd: string, args?: Record<string, unknown>) => {
    mock.calls.push({ cmd, args });
    const h = mock.handlers[cmd];
    return h ? Promise.resolve().then(() => h(args)) : Promise.reject({ kind: "not_available", status: 404, kinds: [] });
  },
}));
vi.mock("@tauri-apps/api/event", () => ({ listen: () => Promise.resolve(() => undefined) }));

import { Folders } from "../views/Folders";
import type { FolderRow, FoldersView } from "../types";

const row = (over: Partial<FolderRow> = {}): FolderRow => ({
  dataset: "folder-1",
  source: "/Users/x/Docs",
  mirror: "/m/a1",
  outbox: "/m/a1/outbox",
  outbox_destination: "/Users/x/Inumaki Outbox/Docs",
  state: "watching",
  error: null,
  files: { source: 3, mirrored: 3, blocked: 0, unsupported: 0, pending: 0 },
  outbox_files: { rehydrated: 0, with_unresolved: 0, pending: 0 },
  last_mirrored_at: null,
  remirror_pending: false,
  ...over,
});
const view = (...folders: FolderRow[]): FoldersView => ({ mirror_root: "/m", folders });
const count = (cmd: string) => mock.calls.filter((c) => c.cmd === cmd).length;

beforeEach(() => {
  mock.calls.length = 0;
  mock.handlers = {};
});
afterEach(cleanup);

describe("folder cards show where restored files land (B7)", () => {
  it("shows outbox_destination and reveals it by dataset id once files were restored", async () => {
    mock.handlers.folders = () => view(row({ outbox_files: { rehydrated: 2, with_unresolved: 1, pending: 0 } }));
    mock.handlers.reveal_outbox = () => undefined;
    render(<Folders />);
    expect(await screen.findByText("/Users/x/Inumaki Outbox/Docs")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Show restored files" }));
    await waitFor(() => expect(count("reveal_outbox")).toBe(1));
    expect(mock.calls.find((c) => c.cmd === "reveal_outbox")?.args).toEqual({ dataset: "folder-1" });
  });

  it("disables Show restored files while nothing was restored", async () => {
    mock.handlers.folders = () => view(row());
    render(<Folders />);
    const b = await screen.findByRole("button", { name: "Show restored files" });
    expect((b as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(b);
    expect(count("reveal_outbox")).toBe(0);
  });

  it("an older service reports no destination: no destination text and the button stays disabled", async () => {
    mock.handlers.folders = () =>
      view(row({ dataset: "folder-old", outbox_destination: "", outbox_files: { rehydrated: 4, with_unresolved: 0, pending: 0 } }));
    render(<Folders />);
    const b = await screen.findByRole("button", { name: "Show restored files" });
    expect((b as HTMLButtonElement).disabled).toBe(true);
    expect(document.body.textContent).not.toContain("Results go to");
    expect(screen.queryByText(/new restored file/)).toBeNull();
  });

  it("announces restored files that appeared after the first load of the session", async () => {
    let n = 1;
    mock.handlers.folders = () => view(row({ dataset: "folder-new", outbox_files: { rehydrated: n, with_unresolved: 0, pending: 0 } }));
    render(<Folders />);
    await screen.findByRole("button", { name: "Show restored files" });
    expect(screen.queryByText(/new restored file/)).toBeNull();
    n = 4;
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    expect((await screen.findByText(/3 new restored files in/)).textContent).toContain("/Users/x/Inumaki Outbox/Docs");
  });

  it("a folder whose restored files cannot be written names the destination", async () => {
    mock.handlers.folders = () =>
      view(
        row({
          dataset: "folder-bad",
          state: "failed",
          error: { code: "folder_outbox_unwritable", text: "inumaki cannot write files from the outbox to the destination folder." },
        }),
      );
    render(<Folders />);
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toBe("Restored files can't be written.");
    expect(document.body.textContent).toContain("Destination: /Users/x/Inumaki Outbox/Docs");
    expect(document.querySelector('[data-tone="bad"]')).not.toBeNull();
  });
});
