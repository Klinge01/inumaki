// The chat switch of every harness, its warnings, and the grey "Chat: off, your choice" section (spec 6.3).
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
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

import {
  CHAT_CONNECT_NOTE,
  CLAUDE_AFTER_NOTE,
  CLAUDE_CHAT_OFF,
  CLAUDE_CHAT_ON,
  CLAUDE_CONNECT_NOTE,
  CODEX_CHAT_ON,
  CODEX_CHAT_SWITCH_LABEL,
  CODEX_OPT_IN_LABEL,
  HERMES_CHAT_OFF,
  HERMES_CHAT_ON,
  HERMES_CHAT_SWITCH_LABEL,
  OPENCLAW_CHAT_ON,
  OPENCLAW_CHAT_SWITCH_LABEL,
} from "../harnessText";
import { Connection } from "../views/Connection";
import type { HarnessCard, HarnessId, PathView } from "../types";

/** What a sheet says: the text of its title, paragraphs, list items, and code blocks, one space apart (R10). */
const sheetText = (dialog: HTMLElement) =>
  Array.from(dialog.querySelectorAll("h2, p, li, pre"))
    .map((e) => e.textContent ?? "")
    .join(" ");

const count = (cmd: string) => mock.calls.filter((c) => c.cmd === cmd).length;

const card = (over: Partial<HarnessCard>): HarnessCard => ({
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
  ...over,
});

const prefs = (over: Record<string, unknown> = {}) => ({
  first_run_done: true,
  chat_opt_in: {},
  chat_effective: {},
  ...over,
});
const effective = (h: HarnessId, on = true) => ({ chat_effective: { [h]: on } });
const setArgs = () => mock.calls.find((c) => c.cmd === "set_chat_opt_in")?.args;

const serve = (cards: HarnessCard[]) => {
  mock.handlers.overview = () => ({ reachable: true, managed_by: "app", cards });
};

beforeEach(() => {
  mock.calls.length = 0;
  mock.handlers = { prefs: () => prefs() };
});
afterEach(cleanup);

describe("Claude Code chat switch", () => {
  it("ticking shows the warning and calls nothing until Yes", async () => {
    serve([card({})]);
    mock.handlers.set_chat_opt_in = () => ({ cleared: [] });
    render(<Connection harness="claude-code" />);
    fireEvent.click(await screen.findByLabelText(/Send Claude Code chat through inumaki/));
    expect(sheetText(await screen.findByRole("alertdialog"))).toContain(CLAUDE_CHAT_ON);
    expect(count("set_chat_opt_in")).toBe(0);
    fireEvent.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Turn on" }));
    await waitFor(() => expect(count("set_chat_opt_in")).toBe(1));
    expect(setArgs()).toEqual({ harness: "claude-code", on: true });
  });

  it("unticking shows the off warning and calls nothing until Yes", async () => {
    serve([card({})]);
    mock.handlers.prefs = () => prefs({ chat_opt_in: { "claude-code": true }, ...effective("claude-code") });
    mock.handlers.set_chat_opt_in = () => ({ reconnect_failures: 0, failed_harnesses: [] });
    render(<Connection harness="claude-code" />);
    const box = () => screen.getByLabelText(/Send Claude Code chat through inumaki/) as HTMLInputElement;
    await waitFor(() => expect(box().checked).toBe(true));
    fireEvent.click(box());
    expect(sheetText(await screen.findByRole("alertdialog"))).toContain(CLAUDE_CHAT_OFF);
    expect(count("set_chat_opt_in")).toBe(0);
    fireEvent.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Turn off" }));
    await waitFor(() => expect(count("set_chat_opt_in")).toBe(1));
    expect(setArgs()).toEqual({ harness: "claude-code", on: false });
  });

  it("the Revert confirm warns that chat goes direct again while it is on", async () => {
    serve([card({})]);
    mock.handlers.prefs = () => prefs(effective("claude-code"));
    render(<Connection harness="claude-code" />);
    const box = () => screen.getByLabelText(/Send Claude Code chat through inumaki/) as HTMLInputElement;
    await waitFor(() => expect(box().checked).toBe(true));
    fireEvent.click(screen.getByRole("button", { name: "Revert…" }));
    expect(sheetText(await screen.findByRole("alertdialog"))).toContain(CLAUDE_CHAT_OFF);
    expect(count("revert")).toBe(0);
  });

  it("a Claude Code Connect ends with its own after note", async () => {
    serve([card({ connected: false })]);
    mock.handlers.preview_connect = () => [{ path: "/x/settings.json", keys: ["hooks"] }];
    mock.handlers.connect = () => ({ note: "Takes effect in the harness's next session.", warning: null, harness_warnings: [] });
    render(<Connection harness="claude-code" />);
    fireEvent.click(await screen.findByRole("button", { name: "Connect…" }));
    fireEvent.click(await screen.findByRole("button", { name: "Connect" }));
    await waitFor(() => expect(count("connect")).toBe(1));
    expect((await screen.findByText(/^Connected\./)).textContent).toBe(`Connected. ${CLAUDE_AFTER_NOTE}`);
  });

  it("a setter failure is shown", async () => {
    serve([card({})]);
    mock.handlers.set_chat_opt_in = () => {
      throw { kind: "state_unwritable", status: null, kinds: [] };
    };
    render(<Connection harness="claude-code" />);
    fireEvent.click(await screen.findByLabelText(/Send Claude Code chat through inumaki/));
    fireEvent.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Turn on" }));
    expect(await screen.findByText(/could not save its own state file/)).toBeTruthy();
  });

  it("a prefs reload that fails is shown, not swallowed", async () => {
    serve([card({})]);
    mock.handlers.prefs = () => {
      throw { kind: "service_unreachable", status: null, kinds: [] };
    };
    render(<Connection harness="claude-code" />);
    expect(await screen.findByText("The inumaki service is not running.")).toBeTruthy();
  });

  it("the switch stays disabled until the prefs reload after a change answered", async () => {
    serve([card({})]);
    let release: () => void = () => undefined;
    let held = false;
    mock.handlers.prefs = () =>
      held ? new Promise((r) => (release = () => r(prefs(effective("claude-code"))))) : prefs();
    mock.handlers.set_chat_opt_in = () => {
      held = true;
      return { reconnect_failures: 0, failed_harnesses: [] };
    };
    render(<Connection harness="claude-code" />);
    const box = () => screen.getByLabelText(/Send Claude Code chat through inumaki/) as HTMLInputElement;
    await waitFor(() => expect(box().disabled).toBe(false));
    fireEvent.click(box());
    fireEvent.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Turn on" }));
    await waitFor(() => expect(count("set_chat_opt_in")).toBe(1));
    await waitFor(() => expect(count("prefs")).toBe(2));
    expect(box().disabled).toBe(true);
    release();
    await waitFor(() => expect(box().disabled).toBe(false));
    expect(box().checked).toBe(true);
  });

  it("is disabled until the card is connected", async () => {
    serve([card({ connected: false })]);
    render(<Connection harness="claude-code" />);
    const box = await screen.findByLabelText(/Send Claude Code chat through inumaki/);
    expect((box as HTMLInputElement).disabled).toBe(true);
    expect(screen.getByText(/Connect first/)).toBeTruthy();
  });

  it("the Connect preview shows the note before the Connect button", async () => {
    serve([card({ connected: false })]);
    mock.handlers.preview_connect = () => [{ path: "/x/settings.json", keys: ["hooks"] }];
    render(<Connection harness="claude-code" />);
    fireEvent.click(await screen.findByRole("button", { name: "Connect…" }));
    const note = await screen.findByText(CLAUDE_CONNECT_NOTE);
    const button = screen.getByRole("button", { name: "Connect" });
    expect(note.compareDocumentPosition(button) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });
});

describe("Chat on", () => {
  const routed: PathView = { path: "chat", state: "connected", reason: null, detail: null, acknowledged: false, last_check: null };

  it("a connected Claude Code with chat routed says Chat: on; disconnected, it makes no protection claim", async () => {
    serve([card({ paths: [routed] })]);
    mock.handlers.prefs = () => prefs(effective("claude-code"));
    render(<Connection harness="claude-code" />);
    expect(await screen.findByText("Chat: on")).toBeTruthy();
    expect(screen.getByText("Chat goes through inumaki.")).toBeTruthy();
    cleanup();

    serve([card({ paths: [routed], disconnected: true })]);
    render(<Connection harness="claude-code" />);
    expect(await screen.findByText("Chat: not filtered now")).toBeTruthy();
    expect(screen.queryByText("Chat: on")).toBeNull();
    expect(screen.queryByText("Chat goes through inumaki.")).toBeNull();
  });
});

describe("Codex chat", () => {
  const chat = (reason: string): PathView => ({
    path: "chat",
    state: "not_connected",
    reason: { code: reason, text: "Codex chat is not routed through inumaki." },
    detail: null,
    acknowledged: false,
    last_check: null,
  });
  const codex = (over: Partial<HarnessCard> = {}) =>
    card({ id: "codex", name: "Codex", login: "oauth", paths: [chat("codex_chatgpt_unverified")], ...over });

  it("an unrouted chat on a connected card is grey and says Off, your choice", async () => {
    serve([codex()]);
    render(<Connection harness="codex" />);
    await screen.findByText("Chat: off, your choice");
    const section = screen.getByRole("region", { name: "Chat: off, your choice" });
    expect(section.querySelector("[data-tone]")?.getAttribute("data-tone")).toBe("off");
    // Not a protection claim: it says where the chat goes, and the fixed reason stays.
    expect(within(section).getByText("Codex with a ChatGPT login talks to ChatGPT directly and isn't filtered.")).toBeTruthy();
    expect(within(section).getByText("Codex chat is not routed through inumaki.")).toBeTruthy();
  });

  it("an unrouted chat on a connected card shows no check result", async () => {
    serve([codex({ paths: [{ ...chat("codex_chatgpt_unverified"), last_check: "passed" }] })]);
    render(<Connection harness="codex" />);
    await screen.findByText("Chat: off, your choice");
    expect(screen.queryByText(/Check passed/)).toBeNull();
  });

  it("an unrouted chat on a card that is not connected stays grey", async () => {
    serve([codex({ connected: false })]);
    render(<Connection harness="codex" />);
    await screen.findByText("Chat: off");
    const section = screen.getByRole("region", { name: "Chat: off" });
    expect(section.querySelector("[data-tone]")?.getAttribute("data-tone")).toBe("off");
  });

  it("the opt-in label says it is refused today", async () => {
    serve([codex()]);
    render(<Connection harness="codex" />);
    const label = await screen.findByText(CODEX_OPT_IN_LABEL);
    expect(label.textContent).toContain("refused today");
  });

  it("a Revert reloads the prefs: the opt-in shows unticked", async () => {
    let optIn = true;
    serve([codex()]);
    mock.handlers.prefs = () => prefs(effective("codex", optIn));
    mock.handlers.revert = () => {
      optIn = false;
      return { reverted: true, exact: true, conflicts: 0, codex_trust_left: false };
    };
    render(<Connection harness="codex" />);
    const box = () => screen.getByLabelText(CODEX_OPT_IN_LABEL) as HTMLInputElement;
    await waitFor(() => expect(box().checked).toBe(true));
    fireEvent.click(screen.getByRole("button", { name: "Revert…" }));
    fireEvent.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Revert" }));
    await waitFor(() => expect(count("revert")).toBe(1));
    await waitFor(() => expect(box().checked).toBe(false));
  });
});

describe("chat switch on the other harnesses", () => {
  const cases: [HarnessId, string, string, string][] = [
    ["codex", "Codex", CODEX_CHAT_SWITCH_LABEL, CODEX_CHAT_ON],
    ["hermes", "Hermes Agent", HERMES_CHAT_SWITCH_LABEL, HERMES_CHAT_ON],
    ["openclaw", "OpenClaw", OPENCLAW_CHAT_SWITCH_LABEL, OPENCLAW_CHAT_ON],
  ];

  it.each(cases)("%s: ticking shows its own warning and calls nothing until Yes", async (id, name, label, on) => {
    serve([card({ id, name })]);
    mock.handlers.set_chat_opt_in = () => ({ reconnect_failures: 0, failed_harnesses: [] });
    render(<Connection harness={id} />);
    fireEvent.click(await screen.findByLabelText(label));
    const text = sheetText(await screen.findByRole("alertdialog"));
    expect(text).toContain(on);
    // Only Claude Code hot-reloads its settings: no other warning claims "at once".
    expect(text).not.toContain("at once");
    expect(text).toContain("next session");
    expect(text).toContain(id === "codex" ? "needs to be restarted" : "not measured");
    expect(text).not.toContain("measured 2026");
    expect(count("set_chat_opt_in")).toBe(0);
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(count("set_chat_opt_in")).toBe(0);
    fireEvent.click(screen.getByLabelText(label));
    fireEvent.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Turn on" }));
    await waitFor(() => expect(count("set_chat_opt_in")).toBe(1));
    expect(setArgs()).toEqual({ harness: id, on: true });
  });

  it("unticking Hermes shows its off warning; the Revert confirm says it too", async () => {
    serve([card({ id: "hermes", name: "Hermes Agent" })]);
    mock.handlers.prefs = () => prefs(effective("hermes"));
    render(<Connection harness="hermes" />);
    const box = () => screen.getByLabelText(HERMES_CHAT_SWITCH_LABEL) as HTMLInputElement;
    await waitFor(() => expect(box().checked).toBe(true));
    fireEvent.click(box());
    expect(sheetText(await screen.findByRole("alertdialog"))).toContain(HERMES_CHAT_OFF);
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    fireEvent.click(screen.getByRole("button", { name: "Revert…" }));
    expect(sheetText(await screen.findByRole("alertdialog"))).toContain(HERMES_CHAT_OFF);
    expect(count("set_chat_opt_in")).toBe(0);
    expect(count("revert")).toBe(0);
  });

  it("one switch per card: Codex shows a single chat control, labelled by its login", async () => {
    serve([card({ id: "codex", name: "Codex", login: "oauth" })]);
    render(<Connection harness="codex" />);
    await screen.findByLabelText(CODEX_OPT_IN_LABEL);
    expect(screen.getAllByRole("switch")).toHaveLength(1);
    cleanup();
    serve([card({ id: "codex", name: "Codex", login: "api_key" })]);
    render(<Connection harness="codex" />);
    await screen.findByLabelText(CODEX_CHAT_SWITCH_LABEL);
    expect(screen.getAllByRole("switch")).toHaveLength(1);
    expect(screen.queryByText(CODEX_OPT_IN_LABEL)).toBeNull();
  });

  it("the Codex ChatGPT-login switch also confirms before the call", async () => {
    serve([card({ id: "codex", name: "Codex", login: "oauth" })]);
    mock.handlers.set_chat_opt_in = () => ({ reconnect_failures: 0, failed_harnesses: [] });
    render(<Connection harness="codex" />);
    fireEvent.click(await screen.findByLabelText(CODEX_OPT_IN_LABEL));
    expect(sheetText(await screen.findByRole("alertdialog"))).toContain(CODEX_CHAT_ON);
    expect(count("set_chat_opt_in")).toBe(0);
    fireEvent.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Turn on" }));
    await waitFor(() => expect(count("set_chat_opt_in")).toBe(1));
    expect(setArgs()).toEqual({ harness: "codex", on: true });
  });

  it.each(["hermes", "openclaw"] as const)("%s with a subscription login has no switch (nothing is written)", async (id) => {
    serve([card({ id, name: id, login: "oauth" })]);
    render(<Connection harness={id} />);
    await screen.findByText("Subscription login");
    expect(screen.queryByRole("switch")).toBeNull();
  });

  it.each(["codex", "hermes", "openclaw"] as const)("%s with an unknown login has no switch (no route is written)", async (id) => {
    serve([card({ id, name: id, login: "unknown" })]);
    render(<Connection harness={id} />);
    await screen.findByText("Login not detected");
    expect(screen.queryByRole("switch")).toBeNull();
  });

  it("Claude Code keeps its switch with any login (its adapter writes the route regardless)", async () => {
    serve([card({ login: "unknown" })]);
    render(<Connection harness="claude-code" />);
    expect(await screen.findByLabelText(/Send Claude Code chat through inumaki/)).toBeTruthy();
  });

  it("the Connect preview says chat is a separate switch", async () => {
    serve([card({ id: "openclaw", name: "OpenClaw", connected: false })]);
    mock.handlers.preview_connect = () => [{ path: "/x/openclaw.json", keys: ["mcp"] }];
    render(<Connection harness="openclaw" />);
    fireEvent.click(await screen.findByRole("button", { name: "Connect…" }));
    expect(await screen.findByText(CHAT_CONNECT_NOTE)).toBeTruthy();
    expect(screen.queryByText(CLAUDE_CONNECT_NOTE)).toBeNull();
  });

  it.each(["claude-code", "codex", "hermes", "openclaw"] as const)(
    "%s: chat not routed on a connected card is grey, Off, your choice",
    async (id) => {
      const notRouted: PathView = {
        path: "chat",
        state: "not_connected",
        reason: { code: "chat_not_protected", text: "Chat is not protected." },
        detail: null,
        acknowledged: false,
        last_check: null,
      };
      serve([card({ id, name: id, paths: [notRouted] })]);
      render(<Connection harness={id} />);
      await screen.findByText("Chat: off, your choice");
      const section = screen.getByRole("region", { name: "Chat: off, your choice" });
      expect(section.querySelector("[data-tone]")?.getAttribute("data-tone")).toBe("off");
      expect(within(section).getByText("Chat is not protected.")).toBeTruthy();
    },
  );
});
