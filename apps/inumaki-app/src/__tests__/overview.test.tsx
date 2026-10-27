// The Overview must not let data pass unfiltered unnoticed: a disconnected harness says so in its own
// row, a stopped service replaces the harness list, and an unverified path is never called filtered.
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
import { rowSentence } from "../status";
import type { HarnessCard, OverviewView, PathView } from "../types";

const path = (p: PathView["path"], state: PathView["state"], extra: Partial<PathView> = {}): PathView => ({
  path: p,
  state,
  reason: null,
  detail: null,
  acknowledged: false,
  last_check: null,
  ...extra,
});

const card = (extra: Partial<HarnessCard> = {}): HarnessCard => ({
  id: "claude-code",
  name: "Claude Code",
  binary_found: true,
  version: "2.0.0",
  tested: true,
  login: "api_key",
  connected: true,
  disconnected: false,
  paths: [path("mcp", "connected"), path("files", "connected"), path("chat", "not_connected")],
  hook: { state: "not_applicable" },
  drift: 0,
  grant: null,
  ...extra,
});

const serve = (v: Partial<OverviewView>) => {
  mock.handlers.overview = () => ({ reachable: true, managed_by: "app", cards: [], ...v });
};

beforeEach(() => {
  mock.handlers = { prefs: () => ({ first_run_done: true, chat_opt_in: {}, chat_effective: {} }) };
});
afterEach(cleanup);

describe("Overview rows", () => {
  it("a disconnected harness says its servers are unfiltered and offers Reconnect, and is not counted as filtered", async () => {
    serve({ cards: [card({ disconnected: true })] });
    render(<Overview />);
    expect(await screen.findByText("Disconnected. Its protected servers talk to the originals again, unfiltered.")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Reconnect" })).toBeTruthy();
    expect(screen.queryByText(/connections? filtered in Easy mode/)).toBeNull();
    // No path of a disconnected harness reads as filtering.
    for (const label of ["MCP", "Files", "Chat"]) {
      expect(screen.getByRole("img", { name: `${label}: Not filtered now` })).toBeTruthy();
    }
  });

  it("the MCP count does not count a disconnected harness's protected servers", async () => {
    serve({ cards: [card({ disconnected: true })] });
    mock.handlers.mcp_servers = () => [
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
    ];
    mock.handlers.mailboxes = () => [];
    mock.handlers.folders = () => ({ mirror_root: "", folders: [] });
    render(<Overview />);
    expect(await screen.findByText("0 of 1")).toBeTruthy();
    expect(screen.queryByText("1 of 1")).toBeNull();
  });

  it("a stopped service shows the not-running state and no harness rows", async () => {
    serve({ reachable: false, managed_by: null, cards: [card()] });
    render(<Overview />);
    expect(await screen.findByText("The inumaki service is not running")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Start the service" })).toBeTruthy();
    expect(screen.queryByText("Claude Code")).toBeNull();
    expect(screen.queryByText(/filtered in Easy mode/)).toBeNull();
  });

  it("a stopped service still says a disconnected harness is unfiltered", async () => {
    serve({ reachable: false, managed_by: null, cards: [card({ disconnected: true })] });
    render(<Overview />);
    expect(
      await screen.findByText("Claude Code is disconnected: its protected servers talk to the originals again, unfiltered."),
    ).toBeTruthy();
  });

  it("a config error hides the rows but still says a disconnected harness is unfiltered", async () => {
    serve({ reachable: false, managed_by: null, config_error: "config file /d/inumaki.toml: is not valid TOML", cards: [card({ disconnected: true })] });
    render(<Overview />);
    expect(
      await screen.findByText("Claude Code is disconnected: its protected servers talk to the originals again, unfiltered."),
    ).toBeTruthy();
    expect(screen.queryByText("Claude Code")).toBeNull();
    expect(screen.queryByRole("img")).toBeNull();
    expect(screen.queryByText("Data sources")).toBeNull();
  });

  it("a card whose last check failed is not counted as filtered", async () => {
    const failed = card({ paths: [path("mcp", "connected", { last_check: "failed" }), path("files", "connected"), path("chat", "not_connected")] });
    serve({ cards: [failed] });
    render(<Overview />);
    expect(await screen.findByText("The last check of MCP tools failed.")).toBeTruthy();
    expect(screen.getByText("No connections filtered yet")).toBeTruthy();
  });

  it("L105: a connected card with a broken path is not counted as filtered, and the empty line says why", async () => {
    const broken = card({
      paths: [
        path("mcp", "broken", { reason: { code: "x", text: "The gateway entry is missing." } }),
        path("files", "connected"),
        path("chat", "not_connected"),
      ],
    });
    serve({ cards: [broken] });
    render(<Overview />);
    expect(await screen.findByText("The gateway entry is missing.")).toBeTruthy();
    expect(screen.getByText("No connections filtered yet")).toBeTruthy();
    expect(screen.queryByText(/connections? filtered in Easy mode/)).toBeNull();
    expect(screen.getByText("Nothing is filtered in Easy mode yet. The rows below say why.")).toBeTruthy();
  });

  it("L105: a connected card with a broken hook is not counted as filtered", async () => {
    serve({ cards: [card({ hook: { state: "broken", reason: { code: "h", text: "The hook is broken." } } })] });
    render(<Overview />);
    expect(await screen.findByText("The hook is broken.")).toBeTruthy();
    expect(screen.getByText("No connections filtered yet")).toBeTruthy();
    expect(screen.queryByText(/connections? filtered in Easy mode/)).toBeNull();
    expect(screen.getByText("Nothing is filtered in Easy mode yet. The rows below say why.")).toBeTruthy();
  });

  it("when every harness is disconnected the empty line says Reconnect", async () => {
    serve({ cards: [card({ disconnected: true })] });
    render(<Overview />);
    expect(await screen.findByText(/^Reconnect the disconnected harness/)).toBeTruthy();
  });

  it("a service managed elsewhere is not started from here", async () => {
    serve({ reachable: false, managed_by: "homebrew", cards: [] });
    render(<Overview />);
    await screen.findByText("The inumaki service is not running");
    expect(screen.queryByRole("button", { name: "Start the service" })).toBeNull();
  });

  it("a harness that is not connected offers Connect… and no status glyphs", async () => {
    serve({ cards: [card({ connected: false, paths: [path("mcp", "not_connected"), path("files", "not_connected"), path("chat", "not_connected")] })] });
    render(<Overview />);
    expect(await screen.findByText("Not connected.")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Connect…" })).toBeTruthy();
    expect(screen.queryByRole("img")).toBeNull();
  });

  it("first run shows rows with Connect only: no chat switch, no navigation, no data sources", async () => {
    serve({ cards: [card({ connected: false })] });
    render(<Overview embedded />);
    await screen.findByRole("button", { name: "Connect…" });
    expect(screen.queryByRole("switch")).toBeNull();
    expect(screen.queryByRole("checkbox")).toBeNull();
    expect(screen.queryByText("Data sources")).toBeNull();
    // The only buttons in a first-run row are its action and the toolbar's Refresh.
    expect(screen.getAllByRole("button").map((b) => b.textContent)).toEqual(["Refresh", "Connect…"]);
  });
});

describe("rowSentence", () => {
  it("names the most urgent fact first: broken path over grant over drift", () => {
    const broken = path("mcp", "broken", { reason: { code: "x", text: "The gateway does not answer." } });
    const c = card({ paths: [broken, path("files", "connected"), path("chat", "not_connected")], grant: { code: "grant", text: "g" }, drift: 2 });
    expect(rowSentence(c)).toEqual({ text: "The gateway does not answer.", tone: "red" });
    expect(rowSentence({ ...c, paths: card().paths })).toEqual({ text: "macOS withdrew access to its files.", tone: "amber" });
    expect(rowSentence({ ...c, paths: card().paths, grant: null }).text).toBe("2 settings were changed outside inumaki.");
  });

  it("a failed last check reads red, after a broken path", () => {
    const failed = card({ paths: [path("mcp", "connected"), path("files", "connected", { last_check: "failed" }), path("chat", "not_connected")] });
    expect(rowSentence(failed)).toEqual({ text: "The last check of files failed.", tone: "red" });
    const broken = path("mcp", "broken", { reason: { code: "x", text: "Broken." } });
    expect(rowSentence({ ...failed, paths: [broken, ...failed.paths.slice(1)] }).text).toBe("Broken.");
    // A disconnected harness's stored result does not speak: the disconnected sentence wins.
    expect(rowSentence({ ...failed, disconnected: true }).tone).toBe("red");
    expect(rowSentence({ ...failed, disconnected: true }).text).toMatch(/^Disconnected\./);
  });

  it("unsupported chat is not called off", () => {
    const c = card({ paths: [path("mcp", "connected"), path("files", "connected"), path("chat", "unsupported", { acknowledged: true })] });
    expect(rowSentence(c).text).toBe("MCP tools and files are filtered. Chat is not protected.");
  });

  it("never calls an unverified path filtered", () => {
    const c = card({ paths: [path("mcp", "connected"), path("files", "unverified"), path("chat", "unverified", { reason: { code: "hermes_oauth_no_override", text: "t" } })] });
    expect(rowSentence(c).text).toBe("MCP tools are filtered. Files are on, unverified. Chat needs one line you add.");
  });

  it("a healthy card says what is filtered and that chat is off", () => {
    expect(rowSentence(card()).text).toBe("MCP tools and files are filtered. Chat is off.");
  });
});
