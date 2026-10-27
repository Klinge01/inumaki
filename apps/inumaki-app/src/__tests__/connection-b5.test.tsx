// The connection page never shows a stale check result (B5), never reads as healthy while the service is
// down, and reads its side data on mount and after actions, not per snapshot (spec sections 6.3, 6.4, 9.4).
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mock = vi.hoisted(() => ({
  calls: [] as string[],
  handlers: {} as Record<string, (args?: Record<string, unknown>) => unknown>,
  snapshot: null as null | (() => void),
}));

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (cmd: string, args?: Record<string, unknown>) => {
    mock.calls.push(cmd);
    const h = mock.handlers[cmd];
    return h ? Promise.resolve().then(() => h(args)) : Promise.reject({ kind: "not_available", status: 404, kinds: [] });
  },
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: (event: string, h: () => void) => {
    if (event === "snapshot") mock.snapshot = h;
    return Promise.resolve(() => undefined);
  },
}));

import { clearCheckRun } from "../checkRun";
import { GOES_AROUND } from "../harnessText";
import { Connection } from "../views/Connection";
import type { HarnessCard, PathKind, PathView } from "../types";

const count = (cmd: string) => mock.calls.filter((c) => c === cmd).length;

// Reason texts deliberately free of the word the B5 test looks for.
const path = (k: PathKind, over: Partial<PathView> = {}): PathView => ({
  path: k,
  state: "connected",
  reason: null,
  detail: k === "mcp" ? { kind: "protected", protected: 1, total: 1 } : null,
  acknowledged: false,
  last_check: "passed",
  ...over,
});

const card = (over: Partial<HarnessCard> = {}): HarnessCard => ({
  id: "claude-code",
  name: "Claude Code",
  binary_found: true,
  version: "2.0.0",
  tested: true,
  login: "api_key",
  connected: true,
  disconnected: false,
  paths: [path("mcp"), path("files"), path("chat")],
  hook: { state: "installed" },
  drift: 0,
  grant: null,
  last_check_at: 1_760_000_000,
  ...over,
});

const serve = (c: HarnessCard, reachable = true) => {
  // A fresh card object per load, as from the service: an effect keyed on the card object would re-run.
  mock.handlers.overview = () => ({ reachable, managed_by: "app", cards: [structuredClone(c)] });
};

beforeEach(() => {
  mock.calls.length = 0;
  mock.snapshot = null;
  mock.handlers = {
    prefs: () => ({ first_run_done: true, chat_opt_in: {}, chat_effective: {} }),
    mcp_servers: () => [
      {
        id: "k1",
        harness: "claude-code",
        name: "crm-server",
        scope: "user",
        transport: "stdio",
        protected: true,
        pending: false,
        dataset: "mcp-crm",
        contract: "ready",
        upstream_state: "running",
        restarts: 0,
        upstream: "crm",
        left_unprotected: false,
        cannot_protect: null,
      },
    ],
    folders: () => ({
      mirror_root: "/m",
      folders: [
        {
          dataset: "folder-docs",
          source: "/Users/u/Docs",
          mirror: "/m/docs",
          outbox: "/m/docs/outbox",
          outbox_destination: "/Users/u/Inumaki Outbox/Docs",
          state: "watching",
          error: null,
          files: { source: 4, mirrored: 4, blocked: 0, unsupported: 0, pending: 0 },
          outbox_files: { rehydrated: 0, with_unresolved: 0, pending: 0 },
          last_mirrored_at: null,
          remirror_pending: false,
        },
      ],
    }),
    settings: () => ({
      backups: [{ harness: "claude-code", live: true, backup: { created_at: 1_759_000_000 } }],
    }),
    preview_connect: () => [{ path: "/x/settings.json", keys: ["mcpServers"] }],
  };
});
afterEach(() => {
  cleanup();
  // The check run is a module-level store: no test leaves a run behind for the next.
  clearCheckRun();
});

describe("connection page", () => {
  it("a disconnected harness shows no stored check result anywhere (B5)", async () => {
    serve(card({ disconnected: true }));
    render(<Connection harness="claude-code" />);
    // Every load has answered: the server rows, the folders, the backup (side column).
    await waitFor(() => expect(count("mcp_servers") + count("folders") + count("settings")).toBe(3));
    await act(async () => undefined);
    for (const name of ["MCP tools: not filtered now", "Files: not filtered now"]) {
      const section = screen.getByRole("region", { name });
      expect(within(section).getByText("No check since the disconnect")).toBeTruthy();
    }
    expect(screen.getByText("Last check")).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/passed/i);
    // The service's "protected, running" is not true of a harness whose servers talk to the originals.
    expect(screen.queryByText(/^protected/i)).toBeNull();
  });

  it("a connected harness shows the check result in its sections", async () => {
    serve(card());
    render(<Connection harness="claude-code" />);
    const section = await screen.findByRole("region", { name: "MCP tools: on" });
    expect(within(section).getByText(/^Check passed/)).toBeTruthy();
  });

  it("reads preview_connect, the server rows, and the folders once on mount, not again on a snapshot", async () => {
    serve(card());
    render(<Connection harness="claude-code" />);
    await screen.findByText("crm-server");
    await waitFor(() => expect(count("preview_connect")).toBe(1));
    expect(mock.snapshot).not.toBeNull();
    await act(async () => mock.snapshot?.());
    await waitFor(() => expect(count("overview")).toBe(2));
    expect(count("preview_connect")).toBe(1);
    expect(count("mcp_servers")).toBe(1);
    expect(count("folders")).toBe(1);
    expect(count("settings")).toBe(1);
  });

  it("while the service is down a connected harness does not read as connected", async () => {
    serve(card(), false);
    mock.handlers.prefs = () => Promise.reject({ kind: "service_unreachable", status: null, kinds: [] });
    render(<Connection harness="claude-code" />);
    expect(await screen.findByText("Not filtered now")).toBeTruthy();
    expect(screen.queryByText("Connected")).toBeNull();
    expect(screen.queryByText(GOES_AROUND)).toBeNull();
    expect(screen.queryByText(/^Connected /)).toBeNull();
  });

  it("a Reconnect makes the shared check run stale: its Passed does not come back", async () => {
    const passed = { status: "passed", reason: null, upstream_requests: 1, canary_in_upstream: false, tokens_seen: true, rehydrated_in_output: true };
    serve(card());
    mock.handlers.run_check = () => ({
      reports: [{ id: "r1", harness: "claude-code", results: { gateway: passed, mirror: passed, proxy: passed } }],
      warning: null,
    });
    mock.handlers.reconnect = () => ({ note: "Takes effect in the next session." });
    render(<Connection harness="claude-code" />);
    fireEvent.click(await screen.findByRole("button", { name: "Run the check" }));
    const box = await screen.findByRole("region", { name: "End-to-end check" });
    await waitFor(() => expect(within(box).getAllByText(/Passed/).length).toBeGreaterThan(0));
    fireEvent.click(screen.getByRole("button", { name: "Reconnect" }));
    await waitFor(() => expect(count("reconnect")).toBe(1));
    await waitFor(() => expect(screen.queryByRole("region", { name: "End-to-end check" })).toBeNull());
  });
});
