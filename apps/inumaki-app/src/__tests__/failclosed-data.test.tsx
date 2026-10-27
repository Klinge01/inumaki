// Fail-closed for the data views: a failed action keeps its error through the reload that
// follows it (load and action errors are separate state), and never shows a success note.
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mock = vi.hoisted(() => ({
  calls: [] as string[],
  handlers: {} as Record<string, (args?: Record<string, unknown>) => unknown>,
}));

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (cmd: string, args?: Record<string, unknown>) => {
    mock.calls.push(cmd);
    const h = mock.handlers[cmd];
    return h ? Promise.resolve().then(() => h(args)) : Promise.reject({ kind: "not_available", status: 404, kinds: [] });
  },
}));
vi.mock("@tauri-apps/api/event", () => ({ listen: () => Promise.resolve(() => undefined) }));

import { Folders } from "../views/Folders";
import { Settings } from "../views/Settings";
import type { FoldersView, SettingsView } from "../types";

const count = (cmd: string) => mock.calls.filter((c) => c === cmd).length;
const err = (kind: string) => Promise.reject({ kind, status: null, kinds: [] });

const foldersView: FoldersView = {
  mirror_root: "/m",
  folders: [
    {
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
    },
  ],
};

const settingsView = (): SettingsView => ({
  version: "0.1.0",
  profiles: [],
  backups: [{ harness: "claude-code", backup: { id: "b1", created_at: null }, live: false }],
  app_log: "/log",
  measured: [],
  updates: "by hand",
  prefs: { first_run_done: true, chat_opt_in: {} },
});

beforeEach(() => {
  mock.calls.length = 0;
  mock.handlers = {};
});
afterEach(cleanup);

describe("fail-closed data views", () => {
  it("a rejected remove_folder keeps its error after the reload and shows no success", async () => {
    mock.handlers.folders = () => foldersView;
    mock.handlers.remove_folder = () => err("changed_meanwhile");
    render(<Folders />);
    fireEvent.click(await screen.findByRole("button", { name: "Remove…" }));
    fireEvent.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Remove" }));
    await waitFor(() => expect(count("remove_folder")).toBe(1));
    await waitFor(() => expect(count("folders")).toBeGreaterThanOrEqual(2));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("changed its configuration");
    expect(screen.queryByText(/queued|could not be updated/)).toBeNull();
  });

  it("a busy removal says try again, keeps the card and shows no success; a retry works", async () => {
    mock.handlers.folders = () => foldersView;
    mock.handlers.remove_folder = () => err("folder_busy");
    render(<Folders />);
    fireEvent.click(await screen.findByRole("button", { name: "Remove…" }));
    fireEvent.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Remove" }));
    await waitFor(() => expect(count("remove_folder")).toBe(1));
    await waitFor(() => expect(count("folders")).toBeGreaterThanOrEqual(2));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("Try again in a moment");
    expect(screen.getByText("/Users/x/Docs")).toBeTruthy();
    expect(screen.queryByText(/queued|could not be updated/)).toBeNull();
    mock.handlers.remove_folder = () => ({ reconnect_failures: 0, failed_harnesses: [] });
    fireEvent.click(await screen.findByRole("button", { name: "Remove…" }));
    fireEvent.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Remove" }));
    await waitFor(() => expect(count("remove_folder")).toBe(2));
    await waitFor(() => expect(screen.queryByRole("alert")).toBeNull());
  });

  it("a pending folder shows the fixed prompt sentence, no red alert and no stale error", async () => {
    mock.handlers.folders = () => ({
      ...foldersView,
      folders: [{ ...foldersView.folders[0], state: "pending", error: null, remirror_pending: true }],
    });
    render(<Folders />);
    expect(
      await screen.findByText("macOS is asking whether inumaki may read this folder. Answer the prompt to continue."),
    ).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
    expect(document.querySelector('[data-tone="bad"], .notice.red')).toBeNull();
    expect(document.body.textContent).not.toContain("pending (updating)");
    expect(screen.getByRole("button", { name: "Rescan" })).toBeTruthy();
  });

  it("a rejected add_folder keeps its error after the reload and shows no success", async () => {
    mock.handlers.folders = () => foldersView;
    mock.handlers.add_folder = () => err("file_unwritable");
    render(<Folders />);
    fireEvent.click(await screen.findByRole("button", { name: "Add a folder…" }));
    await waitFor(() => expect(count("add_folder")).toBe(1));
    await waitFor(() => expect(count("folders")).toBeGreaterThanOrEqual(2));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("could not write");
    expect(screen.queryByText(/could not be updated/)).toBeNull();
  });

  it("a rejected delete_backup keeps its error after the reload", async () => {
    mock.handlers.settings = () => settingsView();
    mock.handlers.delete_backup = () => err("backup_in_use");
    render(<Settings />);
    fireEvent.click(await screen.findByRole("button", { name: "Delete…" }));
    fireEvent.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(count("delete_backup")).toBe(1));
    await waitFor(() => expect(count("settings")).toBeGreaterThanOrEqual(2));
    expect((await screen.findByText(/in use or is being cleaned up/)).getAttribute("role")).toBe("alert");
  });

  it("Settings has no chat switch: each harness's one switch is on its connection page", async () => {
    mock.handlers.settings = () => settingsView();
    render(<Settings />);
    await screen.findByRole("button", { name: "Delete…" });
    expect(screen.queryByRole("switch")).toBeNull();
    expect(screen.queryByRole("checkbox")).toBeNull();
  });

  it("stale cards cannot be acted on while the last read has failed", async () => {
    let n = 0;
    mock.handlers.settings = () => (n++ === 0 ? settingsView() : err("service_unreachable"));
    render(<Settings />);
    await screen.findByRole("button", { name: "Delete…" });
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    await screen.findByText(/The inumaki service is not running/);
    expect((screen.getByRole("button", { name: "Delete…" }) as HTMLButtonElement).disabled).toBe(true);
  });
});
