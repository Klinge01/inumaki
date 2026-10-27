// The Other client page: the gateway token is a text node (never an attribute), is dropped when the
// window hides, and a token that cannot be shown again is renewed by revoke-then-read.
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mock = vi.hoisted(() => ({
  calls: [] as string[],
  handlers: {} as Record<string, (args?: Record<string, unknown>) => unknown>,
  events: {} as Record<string, (() => void)[]>,
}));

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (cmd: string, args?: Record<string, unknown>) => {
    mock.calls.push(cmd);
    const h = mock.handlers[cmd];
    return h ? Promise.resolve().then(() => h(args)) : Promise.reject({ kind: "not_available", status: 404, kinds: [] });
  },
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: (name: string, cb: () => void) => {
    (mock.events[name] ??= []).push(cb);
    return Promise.resolve(() => {
      mock.events[name] = mock.events[name].filter((c) => c !== cb);
    });
  },
}));

import { OtherClient } from "../views/OtherClient";

const TOKEN = "gw-token-SECRET-123";
const info = (token: string | null) => ({
  gateway: [{ name: "files", url: "http://127.0.0.1:7400/mcp/files" }],
  token,
  proxy: [],
  client_header: null,
});

const hideWindow = () => act(() => [...(mock.events["window-hidden"] ?? [])].forEach((cb) => cb()));

/** Every attribute value of every element under the body. */
const attributeValues = () =>
  Array.from(document.body.querySelectorAll("*")).flatMap((el) => Array.from(el.attributes).map((a) => a.value));

beforeEach(() => {
  mock.calls.length = 0;
  mock.handlers = {};
  mock.events = {};
});
afterEach(cleanup);

describe("Other client", () => {
  it("shows the token as text, never in an attribute", async () => {
    mock.handlers.other_client = () => info(TOKEN);
    render(<OtherClient />);
    fireEvent.click(screen.getByRole("button", { name: "Show connection details" }));
    expect(await screen.findByText(TOKEN)).toBeTruthy();
    expect(attributeValues().some((v) => v.includes(TOKEN))).toBe(false);
  });

  it("drops the token when the window hides, and on visibilitychange to hidden", async () => {
    mock.handlers.other_client = () => info(TOKEN);
    render(<OtherClient />);
    await act(async () => Promise.resolve()); // the listeners are registered
    fireEvent.click(screen.getByRole("button", { name: "Show connection details" }));
    await screen.findByText(TOKEN);
    hideWindow();
    expect(screen.queryByText(TOKEN)).toBeNull();
    expect(document.body.textContent).not.toContain(TOKEN);
    expect(screen.getByRole("button", { name: "Show connection details" })).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Show connection details" }));
    await screen.findByText(TOKEN);
    Object.defineProperty(document, "visibilityState", { value: "hidden", configurable: true });
    act(() => void document.dispatchEvent(new Event("visibilitychange")));
    Object.defineProperty(document, "visibilityState", { value: "visible", configurable: true });
    expect(document.body.textContent).not.toContain(TOKEN);
    expect(screen.getByRole("button", { name: "Show connection details" })).toBeTruthy();
  });

  it("a token that cannot be shown again is renewed by revoke, then a new read", async () => {
    let revoked = false;
    mock.handlers.other_client = () => info(revoked ? TOKEN : null);
    mock.handlers.revoke_other_client = () => {
      revoked = true;
    };
    render(<OtherClient />);
    fireEvent.click(screen.getByRole("button", { name: "Show connection details" }));
    fireEvent.click(await screen.findByRole("button", { name: "Revoke it and create a new one" }));
    expect(await screen.findByText(TOKEN)).toBeTruthy();
    const revoke = mock.calls.indexOf("revoke_other_client");
    expect(revoke).toBeGreaterThanOrEqual(0);
    await waitFor(() => expect(mock.calls.lastIndexOf("other_client")).toBeGreaterThan(revoke));
  });
});
