// A config file that cannot name the socket: Overview says so, and does not
// offer the grey "service is not running" advice.
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

import { Overview } from "../views/Overview";

beforeEach(() => {
  mock.handlers = { prefs: () => ({ first_run_done: true, chat_opt_in: {}, chat_effective: {} }) };
});
afterEach(cleanup);

describe("config error", () => {
  it("Overview shows the config error as an alert, not the not-running notice", async () => {
    mock.handlers.overview = () => ({
      reachable: false,
      managed_by: null,
      config_error: "config file /d/inumaki.toml: is not valid TOML",
      cards: [],
    });
    render(<Overview />);
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("inumaki.toml: is not valid TOML");
    expect(screen.queryByText(/service is not running/)).toBeNull();
  });
});
