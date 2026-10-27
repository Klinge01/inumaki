// The sidebar's MCP count fails closed: no "P of T" until the overview is known, and a disconnected
// harness's protected servers are never counted as protected.
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mock = vi.hoisted(() => ({
  handlers: {} as Record<string, (args?: Record<string, unknown>) => unknown>,
}));

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (cmd: string, args?: Record<string, unknown>) => {
    const h = mock.handlers[cmd];
    return h ? Promise.resolve().then(() => h(args)) : Promise.reject({ kind: "not_available", status: 404, kinds: [] });
  },
}));
vi.mock("@tauri-apps/api/event", () => ({ listen: () => Promise.resolve(() => undefined) }));

import { Sidebar } from "../components/Sidebar";
import type { HarnessCard } from "../types";

const card = (extra: Partial<HarnessCard> = {}): HarnessCard => ({
  id: "claude-code",
  name: "Claude Code",
  binary_found: true,
  version: "2.0.0",
  tested: true,
  login: "api_key",
  connected: true,
  disconnected: false,
  paths: [],
  hook: { state: "not_applicable" },
  drift: 0,
  grant: null,
  ...extra,
});

beforeEach(() => {
  mock.handlers = {
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
    mailboxes: () => [],
    folders: () => ({ mirror_root: "", folders: [] }),
    service_info: () => {
      throw { kind: "service_unreachable", status: null, kinds: [] };
    },
  };
});
afterEach(cleanup);

describe("sidebar MCP count", () => {
  it("shows no MCP count while the overview is unknown or failed", async () => {
    mock.handlers.overview = () => {
      throw { kind: "service_unreachable", status: null, kinds: [] };
    };
    render(<Sidebar view="overview" onSelect={() => undefined} />);
    expect(await screen.findAllByText("0")).toHaveLength(2); // Email and Folders counts are applied (R8)
    expect(screen.queryByText(/^\d+ of \d+$/)).toBeNull();
  });

  it("does not count a disconnected harness's protected servers", async () => {
    mock.handlers.overview = () => ({
      reachable: true,
      managed_by: "app",
      cards: [card({ id: "claude-code", disconnected: true })],
    });
    render(<Sidebar view="overview" onSelect={() => undefined} />);
    expect(await screen.findByText("0 of 1")).toBeTruthy();
  });
});
