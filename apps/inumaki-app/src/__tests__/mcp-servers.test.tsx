// The MCP servers view: the orphaned-dataset notice (inline, Keep focused, no slug) and the grouped states.
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
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

import { McpServers } from "../views/McpServers";
import type { ServerRow } from "../types";

const row = (over: Partial<ServerRow>): ServerRow => ({
  id: "k1",
  harness: "claude-code",
  name: "files",
  scope: "user",
  transport: "stdio",
  protected: false,
  pending: false,
  dataset: null,
  contract: null,
  upstream_state: null,
  restarts: null,
  upstream: null,
  left_unprotected: false,
  cannot_protect: null,
  ...over,
});

beforeEach(() => {
  mock.calls.length = 0;
  mock.handlers = {};
});
afterEach(cleanup);

describe("MCP servers", () => {
  it("an Unprotect that frees a dataset asks inline, keeps by default, and never shows the dataset's name", async () => {
    mock.handlers.mcp_servers = () => [row({ protected: true, dataset: "mcp-secret-slug", upstream_state: "running" })];
    mock.handlers.unprotect = () => ({ unreferenced_dataset: "mcp-secret-slug", note: "Done." });
    mock.handlers.remove_protected_dataset = () => undefined;
    render(<McpServers />);
    fireEvent.click(await screen.findByRole("button", { name: "Unprotect" }));
    expect(await screen.findByText("No harness uses files's dataset any more.")).toBeTruthy();
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Keep" }));
    expect(document.body.textContent).not.toContain("mcp-secret-slug");
    expect(mock.calls).not.toContain("remove_protected_dataset");
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(mock.calls).toContain("remove_protected_dataset"));
  });

  it("Keep leaves the dataset alone", async () => {
    mock.handlers.mcp_servers = () => [row({ protected: true, dataset: "mcp-x" })];
    mock.handlers.unprotect = () => ({ unreferenced_dataset: "mcp-x", note: "Done." });
    render(<McpServers />);
    fireEvent.click(await screen.findByRole("button", { name: "Unprotect" }));
    fireEvent.click(await screen.findByRole("button", { name: "Keep" }));
    await waitFor(() => expect(screen.queryByRole("button", { name: "Keep" })).toBeNull());
    expect(mock.calls).not.toContain("remove_protected_dataset");
  });

  it("a server waiting for its harness says so and points to the harness page, not 'protected'", async () => {
    mock.handlers.mcp_servers = () => [row({ pending: true })];
    render(<McpServers />);
    expect(await screen.findByText("Waiting for Claude Code")).toBeTruthy();
    expect(screen.getByText("Reconnect Claude Code on its page to write it.")).toBeTruthy();
    expect(screen.queryByText(/^Protected/)).toBeNull();
  });

  it("a protected server of a disconnected harness reads Not filtered now, and Unprotect stays", async () => {
    mock.handlers.mcp_servers = () => [row({ protected: true, dataset: "mcp-x", upstream_state: "running" })];
    mock.handlers.overview = () => ({
      reachable: true,
      managed_by: "app",
      cards: [
        {
          id: "claude-code",
          name: "Claude Code",
          binary_found: true,
          version: "2.0.0",
          tested: true,
          login: "api_key",
          connected: false,
          disconnected: true,
          paths: [],
          hook: { state: "not_applicable" },
          drift: 0,
          grant: null,
        },
      ],
    });
    render(<McpServers />);
    expect(await screen.findByText("Not filtered now")).toBeTruthy();
    expect(
      screen.getByText("Claude Code is disconnected, so this server talks to the original again. Reconnect Claude Code on its page."),
    ).toBeTruthy();
    expect(screen.queryByText(/^Protected/)).toBeNull();
    expect(screen.getByRole("button", { name: "Unprotect" })).toBeTruthy();
  });
});
