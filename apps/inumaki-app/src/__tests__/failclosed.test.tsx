// Fail-closed UI: a failed action keeps its error through the reload that
// follows it, and a failed Connect never says "Connected.".
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

import { McpServers } from "../views/McpServers";
import { Connection } from "../views/Connection";
import { CLIENT_HEADER_LEFT_TEXT } from "../components/ErrorLine";
import { REVOCATION_PENDING_TEXT } from "../harnessText";
import type { HarnessCard, ServerRow } from "../types";

const count = (cmd: string) => mock.calls.filter((c) => c === cmd).length;
const err = (kind: string, extra: Record<string, unknown> = {}) => Promise.reject({ kind, status: null, kinds: [], ...extra });

const row: ServerRow = {
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
};

const card = (connected: boolean): HarnessCard => ({
  id: "claude-code",
  name: "Claude Code",
  binary_found: true,
  version: "2.0.0",
  tested: true,
  login: "api_key",
  connected,
  disconnected: false,
  paths: [],
  hook: { state: "not_applicable" },
  drift: 0,
  grant: null,
});

beforeEach(() => {
  mock.calls.length = 0;
  mock.handlers = { prefs: () => ({ first_run_done: true, chat_opt_in: {}, chat_effective: {} }) };
});
afterEach(cleanup);

describe("fail-closed", () => {
  it("a rejected protect keeps its alert and snippet after the reload", async () => {
    mock.handlers.mcp_servers = () => [row];
    mock.handlers.protect = () => err("cannot_edit_safely", { snippet: "SNIPPET-LINES" });
    render(<McpServers />);
    fireEvent.click(await screen.findByRole("button", { name: "Protect" }));
    await waitFor(() => expect(count("mcp_servers")).toBe(2));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("SNIPPET-LINES");
  });

  it("a protect shows the connect's fixed harness warning with the note", async () => {
    const text =
      "Codex is set to approval_policy = never and will refuse the inumaki tool calls; to allow them, set default_tools_approval_mode on the inumaki server entry in Codex's config.";
    mock.handlers.mcp_servers = () => [row];
    mock.handlers.protect = () => ({
      dataset: "mcp-files",
      reused: false,
      note: "Takes effect in the harness's next session.",
      warning: null,
      harness_warnings: [{ code: "codex_approval_never", text }],
    });
    render(<McpServers />);
    fireEvent.click(await screen.findByRole("button", { name: "Protect" }));
    await waitFor(() => expect(count("protect")).toBe(1));
    const status = await screen.findByRole("status");
    expect(status.textContent).toContain(`Warning: ${text}`);
  });

  it("a failed connect never shows Connected.", async () => {
    mock.handlers.overview = () => ({ reachable: true, managed_by: "app", cards: [card(false)] });
    mock.handlers.preview_connect = () => [{ path: "/x/settings.json", keys: ["mcpServers"] }];
    mock.handlers.connect = () => err("file_unwritable");
    render(<Connection harness="claude-code" />);
    fireEvent.click(await screen.findByRole("button", { name: "Connect…" }));
    fireEvent.click(await screen.findByRole("button", { name: "Connect" }));
    await waitFor(() => expect(count("overview")).toBeGreaterThanOrEqual(2));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("could not write");
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(screen.queryByText(/Connected\./)).toBeNull();
  });

  it("a refused Connect preview shows its reason in the sheet, and a refused Connect keeps its snippet after the reload", async () => {
    mock.handlers.overview = () => ({ reachable: true, managed_by: "app", cards: [card(false)] });
    mock.handlers.preview_connect = () =>
      err("cannot_edit_safely", { reason: { code: "unsafe", text: "The file has a shape inumaki will not edit." } });
    mock.handlers.connect = () => err("cannot_edit_safely", { snippet: "SNIPPET-LINES" });
    render(<Connection harness="claude-code" />);
    fireEvent.click(await screen.findByRole("button", { name: "Connect…" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(within(dialog).getByText("The file has a shape inumaki will not edit.")).toBeTruthy();
    expect(within(dialog).queryByRole("listitem")).toBeNull();
    expect(count("connect")).toBe(0);
    fireEvent.click(within(dialog).getByRole("button", { name: "Connect" }));
    await waitFor(() => expect(count("connect")).toBe(1));
    await waitFor(() => expect(count("overview")).toBeGreaterThanOrEqual(3));
    expect((await screen.findByRole("alert")).textContent).toContain("SNIPPET-LINES");
    expect(screen.queryByRole("alertdialog")).toBeNull();
  });

  it("shows the manual-setup lines on demand, with the copy button, and never on the card", async () => {
    const hermes: HarnessCard = {
      ...card(true),
      id: "hermes",
      name: "Hermes Agent",
      login: "oauth",
      paths: [
        {
          path: "chat",
          state: "unverified",
          reason: { code: "hermes_oauth_no_override", text: "A fixed sentence." },
          detail: null,
          acknowledged: false,
          last_check: null,
        },
      ],
    };
    mock.handlers.overview = () => ({ reachable: true, managed_by: "app", cards: [hermes] });
    mock.handlers.manual_setup = () => ({
      lines: "HERMES_CODEX_BASE_URL=http://127.0.0.1:8787/codex",
      note: "Hermes OAuth sends no client header, so only session tokens are restored.",
    });
    render(<Connection harness="hermes" />);
    await screen.findByText(/A fixed sentence\./);
    expect(screen.queryByText(/HERMES_CODEX_BASE_URL/)).toBeNull();
    expect(count("manual_setup")).toBe(0);
    fireEvent.click(await screen.findByRole("button", { name: "Show the lines to add" }));
    expect(await screen.findByText(/HERMES_CODEX_BASE_URL=/)).toBeTruthy();
    expect(screen.getByText(/only session tokens are restored/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Copy the lines" })).toBeTruthy();
  });

  it("shows no manual-setup button for a connected OpenClaw Files path that only carries the reason as a note", async () => {
    const openclaw: HarnessCard = {
      ...card(true),
      id: "openclaw",
      name: "OpenClaw",
      paths: [
        {
          path: "files",
          state: "connected",
          reason: { code: "openclaw_docker_binds_only", text: "OpenClaw sees the mirror through its Docker sandbox only." },
          detail: null,
          acknowledged: false,
          last_check: null,
        },
      ],
    };
    mock.handlers.overview = () => ({ reachable: true, managed_by: "app", cards: [openclaw] });
    render(<Connection harness="openclaw" />);
    await screen.findByText(/Docker sandbox only/);
    expect(screen.queryByRole("button", { name: "Show the lines to add" })).toBeNull();
  });

  it("a connect shows the adapter's fixed harness warning with the note", async () => {
    const text =
      "Codex is set to approval_policy = never and will refuse the inumaki tool calls; to allow them, set default_tools_approval_mode on the inumaki server entry in Codex's config.";
    mock.handlers.overview = () => ({ reachable: true, managed_by: "app", cards: [card(false)] });
    mock.handlers.preview_connect = () => [{ path: "/x/config.toml", keys: ["mcp_servers.crm"] }];
    mock.handlers.connect = () => ({
      note: "Takes effect in the harness's next session.",
      warning: null,
      harness_warnings: [{ code: "codex_approval_never", text }],
    });
    render(<Connection harness="claude-code" />);
    fireEvent.click(await screen.findByRole("button", { name: "Connect…" }));
    fireEvent.click(await screen.findByRole("button", { name: "Connect" }));
    await waitFor(() => expect(count("connect")).toBe(1));
    const status = await screen.findByText(/^Connected\./);
    expect(status.textContent).toContain(`Warning: ${text}`);
  });

  it("a connection page without the service says so once, keeps the disconnect and grant notices, and hides its paths", async () => {
    const down: HarnessCard = { ...card(false), disconnected: true, grant: { code: "grant", text: "Allow it in System Settings." } };
    mock.handlers.overview = () => ({ reachable: false, managed_by: null, cards: [down] });
    mock.handlers.prefs = () => err("service_unreachable");
    render(<Connection harness="claude-code" />);
    expect(await screen.findByText("Disconnected.")).toBeTruthy();
    expect(screen.getAllByText(/The inumaki service is not running/)).toHaveLength(1);
    expect(screen.getByText("macOS withdrew access to Claude Code's files.")).toBeTruthy();
    expect(screen.queryByRole("switch")).toBeNull();
    expect(screen.queryByText("Last check")).toBeNull();
  });

  it("a connection page with a broken config shows one alert and no not-running notice", async () => {
    mock.handlers.overview = () => ({
      reachable: false,
      managed_by: null,
      config_error: "config file /d/inumaki.toml: is not valid TOML",
      cards: [card(true)],
    });
    render(<Connection harness="claude-code" />);
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("is not valid TOML");
    expect(screen.queryByText(/service is not running/)).toBeNull();
    expect(screen.queryByRole("switch")).toBeNull();
  });

  it("a revert rejecting client_header_left keeps the warning after the reload", async () => {
    mock.handlers.overview = () => ({ reachable: true, managed_by: "app", cards: [card(true)] });
    mock.handlers.revert = () => err("client_header_left");
    render(<Connection harness="claude-code" />);
    fireEvent.click(await screen.findByRole("button", { name: "Revert…" }));
    fireEvent.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Revert" }));
    await waitFor(() => expect(count("revert")).toBe(1));
    await waitFor(() => expect(count("overview")).toBeGreaterThanOrEqual(2));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("X-Inumaki-Client");
  });

  it("an offline Revert that leaves the client header shows the header warning and the pending note, never 'revoked'", async () => {
    mock.handlers.overview = () => ({ reachable: true, managed_by: "app", cards: [card(true)] });
    mock.handlers.revert = () => err("client_header_left_pending");
    render(<Connection harness="claude-code" />);
    fireEvent.click(await screen.findByRole("button", { name: "Revert…" }));
    fireEvent.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Revert" }));
    await waitFor(() => expect(count("revert")).toBe(1));
    await waitFor(() => expect(count("overview")).toBeGreaterThanOrEqual(2));
    expect(await screen.findByText("One line is left in Claude Code's configuration.")).toBeTruthy();
    expect((await screen.findByRole("alert")).textContent).toContain(CLIENT_HEADER_LEFT_TEXT);
    const note = await screen.findByRole("status");
    expect(note.textContent).toBe(REVOCATION_PENDING_TEXT);
    expect(document.body.textContent).not.toMatch(/was revoked|is revoked/);
  });
});
