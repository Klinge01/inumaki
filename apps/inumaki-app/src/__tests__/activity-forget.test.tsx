// Known entities and forget (redesign spec sections 7.4 and 12, B8): the chat
// source keeps no entities and asks the service for none, the list is read
// again after every forget (an error too, so a stale row never stays), and a
// forget that matched nothing says "Nothing to forget.".
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
vi.mock("@tauri-apps/api/event", () => ({
  listen: () => Promise.resolve(() => undefined),
}));

import { Activity } from "../views/Activity";

const TOKEN = "<PERSON_a7f2>";
const entity = { token: TOKEN, kind: "PERSON", first_use: 1, last_use: 1, uses: 1, epoch_id: 1, current_epoch: true };
const count = (cmd: string) => mock.calls.filter((c) => c.cmd === cmd).length;

beforeEach(() => {
  mock.calls.length = 0;
  mock.handlers = {
    datasets: () => [
      { id: "inumaki-chat", name: "inumaki-chat", kind: "chat" },
      { id: "kunde", name: "Kunde", kind: "generic" },
    ],
    activity: () => ({ records: [] }),
    journal: () => ({ entries: [] }),
    entities: () => ({ entities: [entity] }),
  };
});
afterEach(cleanup);

async function entitiesOf(name: string) {
  render(<Activity />);
  fireEvent.click(await screen.findByRole("button", { name }));
  fireEvent.click(screen.getByRole("tab", { name: "Known entities" }));
}

/** Forgets the first row through its inline confirm. */
async function forgetFirstRow() {
  fireEvent.click((await screen.findAllByRole("button", { name: "Forget…" }))[0]);
  const row = screen.getByText(/^Forget this PERSON\?/).closest("tr")!;
  fireEvent.click(within(row).getByRole("button", { name: "Forget" }));
}

describe("Known entities", () => {
  it("the Chat source explains that chat keeps no entities and asks the service for none", async () => {
    await entitiesOf("Chat");
    expect(await screen.findByText("Chat keeps no entities")).toBeTruthy();
    expect(screen.queryByLabelText("Forget by value")).toBeNull();
    expect(count("entities")).toBe(0);
    fireEvent.click(screen.getByRole("button", { name: "Show chat records" }));
    expect(screen.getByRole("tab", { name: "Records" }).getAttribute("aria-selected")).toBe("true");
    await screen.findByText("No records yet.");
    expect(count("entities")).toBe(0);
  });

  it("the list is read again after a forget that fails", async () => {
    mock.handlers.forget_token = () => Promise.reject({ kind: "unavailable", status: 503, kinds: [] });
    await entitiesOf("Kunde");
    await screen.findByText(TOKEN);
    expect(count("entities")).toBe(1);
    await forgetFirstRow();
    await screen.findByRole("alert");
    await waitFor(() => expect(count("entities")).toBe(2));
  });

  it("a forget that matched nothing says Nothing to forget.", async () => {
    mock.handlers.forget_value = () => ({ kinds: [], tokens: 0, rows: 0, purge_pending: false });
    await entitiesOf("Kunde");
    await screen.findByText(TOKEN);
    const input = screen.getByLabelText("Forget by value") as HTMLInputElement;
    fireEvent.change(input, { target: { value: "Qwxzvk" } });
    fireEvent.click(screen.getByRole("button", { name: "Forget" }));
    // Cleared on send; the typed value is never echoed.
    expect(input.value).toBe("");
    expect((await screen.findByRole("status")).textContent).toBe("Nothing to forget.");
    expect(screen.getByText(/^No token in Kunde matches\./)).toBeTruthy();
    expect(document.body.textContent).not.toContain("Qwxzvk");
    await waitFor(() => expect(count("entities")).toBe(2));
  });
});
