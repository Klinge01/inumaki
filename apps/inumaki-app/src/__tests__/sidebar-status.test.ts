// The sidebar status block never claims a working Easy mode it cannot back.
import { describe, expect, it } from "vitest";
import { sidebarStatus } from "../components/Sidebar";
import { weakestStatus, weakestTone } from "../status";
import type { HarnessCard, OverviewView, PathView } from "../types";

const card = (over: Partial<HarnessCard> = {}): HarnessCard => ({
  id: "codex",
  name: "Codex",
  binary_found: true,
  version: "1.0",
  tested: true,
  login: "api_key",
  connected: true,
  disconnected: false,
  paths: [],
  hook: { state: "installed" },
  drift: 0,
  grant: null,
  ...over,
});
const view = (over: Partial<OverviewView> = {}): OverviewView => ({
  reachable: true,
  managed_by: null,
  cards: [card()],
  ...over,
});

describe("sidebarStatus", () => {
  it("is unknown (no block) until the overview is known", () => {
    expect(sidebarStatus(null)).toBeNull();
  });
  it("is on only with a connected harness and nothing wrong", () => {
    expect(sidebarStatus(view())).toMatchObject({ tone: "on", word: "Connected", line: "Easy mode, 1 harness" });
  });
  it("is not on with nothing connected", () => {
    for (const cards of [[], [card({ connected: false })]]) {
      expect(sidebarStatus(view({ cards }))).toMatchObject({ tone: "off", line: "Nothing is filtered" });
    }
  });
  it("a config error and an unreachable service win over everything", () => {
    const down = card({ disconnected: true });
    expect(sidebarStatus(view({ config_error: "x", cards: [down] }))).toMatchObject({ tone: "bad", word: "Configuration error" });
    expect(sidebarStatus(view({ reachable: false, cards: [down] }))).toMatchObject({ tone: "off", word: "Service not running" });
  });
  it("a failed last check, a disconnected harness, a broken hook, and a withdrawn grant are bad", () => {
    expect(sidebarStatus(view({ last_check: { at: 1, failed: true } }))).toMatchObject({ tone: "bad", line: "Last check failed" });
    expect(sidebarStatus(view({ cards: [card({ disconnected: true })] }))).toMatchObject({
      tone: "bad",
      line: "1 harness disconnected",
    });
    expect(sidebarStatus(view({ cards: [card({ hook: { state: "broken", reason: { code: "h", text: "Hook text." } } })] }))).toMatchObject({
      tone: "bad",
      line: "Hook text.",
    });
    expect(sidebarStatus(view({ cards: [card({ grant: { code: "g", text: "Grant text." } })] }))).toMatchObject({
      tone: "bad",
      line: "Grant text.",
    });
  });
});

const path = (p: PathView["path"], state: PathView["state"], extra: Partial<PathView> = {}): PathView => ({
  path: p,
  state,
  reason: null,
  detail: null,
  acknowledged: false,
  last_check: null,
  ...extra,
});
const on = () => [path("mcp", "connected"), path("chat", "not_connected")];

// The sidebar glyph agrees with the status block and with the Overview row.
describe("weakestTone", () => {
  it("a broken hook is bad", () => {
    expect(weakestTone(card({ paths: on(), hook: { state: "broken", reason: { code: "h", text: "x" } } }))).toBe("bad");
  });
  it("a withdrawn grant is bad", () => {
    expect(weakestTone(card({ paths: on(), grant: { code: "g", text: "x" } }))).toBe("bad");
  });
  it("a connected path whose last check failed is bad", () => {
    expect(weakestTone(card({ paths: [path("mcp", "connected", { last_check: "failed" })] }))).toBe("bad");
  });
  it("a pending hook is unverified", () => {
    expect(weakestTone(card({ paths: on(), hook: { state: "pending", reason: { code: "p", text: "x" } } }))).toBe("unv");
  });
  it("drift is unverified", () => {
    expect(weakestTone(card({ paths: on(), drift: 1 }))).toBe("unv");
  });
  it("a card that is not connected is off, even with an unsupported files path", () => {
    expect(weakestStatus(card({ connected: false, paths: [path("files", "unsupported")] }))).toEqual({
      tone: "off",
      word: "Not connected",
    });
  });
  it("an acknowledged unsupported path is off", () => {
    expect(weakestTone(card({ paths: [path("files", "unsupported", { acknowledged: true })] }))).toBe("off");
  });
  it("MCP on and chat not connected is on", () => {
    expect(weakestStatus(card({ paths: on() }))).toEqual({ tone: "on", word: "On" });
  });
  it("a disconnected card is bad", () => {
    expect(weakestStatus(card({ paths: on(), disconnected: true }))).toEqual({ tone: "bad", word: "Disconnected" });
  });
});
