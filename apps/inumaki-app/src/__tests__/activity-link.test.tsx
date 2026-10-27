// Activity records and the journal (redesign spec sections 7.4 and 9.2): a
// record links to the journal entry with the same `released` digest, and the
// detail pane's payloads go when their reason goes (another record, another
// tab, the window hiding). "As sent" asks for tokens only.
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mock = vi.hoisted(() => ({
  calls: [] as { cmd: string; args?: Record<string, unknown> }[],
  handlers: {} as Record<string, (args?: Record<string, unknown>) => unknown>,
  events: {} as Record<string, (() => void)[]>,
}));

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (cmd: string, args?: Record<string, unknown>) => {
    mock.calls.push({ cmd, args });
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

import { Activity } from "../views/Activity";
import { REVEAL_LABEL } from "../reveal";

const ORIGINAL = "Qwxzvk";
const TOKEN = "<PERSON_a7f2>";
const record = (id: string, at: number, released: string | null, verdict = "released") => ({
  id,
  at,
  dataset: "kunde",
  front_door: "gateway",
  upstream: null,
  direction: "result",
  verdict,
  checks: [],
  kinds: [{ kind: "PERSON", count: 1 }],
  tripwire: false,
  bytes: 10,
  released,
});
// r1 released "d1". The "d0" entry is the closest in time to r1, so only a digest match finds j1.
const R1 = record("r1", 1_000, "d1");
const R0 = record("r0", 500, "d0");
const J0 = { id: "j0", at: 1_000, bytes: 900, released: "d0" };
const J1 = { id: "j1", at: 1_400, bytes: 2_150, released: "d1" };

beforeEach(() => {
  mock.calls.length = 0;
  mock.events = {};
  mock.handlers = {
    datasets: () => [{ id: "kunde", name: "Kunde", kind: "generic" }],
    activity: () => ({ records: [R1, R0] }),
    journal: () => ({ entries: [J1, J0] }),
    journal_record: (a) => ({
      ...(a!.record === "j1" ? J1 : J0),
      unresolved: 0,
      label: "",
      show_values: a!.reveal as boolean,
      payload: a!.reveal ? `{"to":"${ORIGINAL}"}` : `{"to":"${TOKEN}"}`,
    }),
  };
});
afterEach(cleanup);

const hideWindow = () => act(() => [...(mock.events["window-hidden"] ?? [])].forEach((cb) => cb()));
const pick = async (name: string) => fireEvent.click(await screen.findByRole("button", { name }));
const openTab = (name: string) => fireEvent.click(screen.getByRole("tab", { name }));
const when = (at: number) => new Date(at * 1000).toLocaleString();
/** Selects a record (or entry) by its time cell, the row's keyboard handle. */
const selectAt = async (at: number) => fireEvent.click(await screen.findByRole("button", { name: when(at) }));
const selectedRow = () => document.querySelector("tr[aria-current]") as HTMLTableRowElement | null;
const nothingShown = () => {
  expect(screen.queryByText(REVEAL_LABEL)).toBeNull();
  expect(document.body.textContent).not.toContain(ORIGINAL);
  expect(document.body.textContent).not.toContain(TOKEN);
};

describe("Activity records and the journal", () => {
  it("a record links to the journal entry with the same released digest (B8)", async () => {
    render(<Activity />);
    // Under All sources there is no journal and no link.
    await screen.findByRole("button", { name: when(R1.at) });
    expect(mock.calls.some((c) => c.cmd === "journal")).toBe(false);
    expect(screen.queryByRole("button", { name: "2.1 KB" })).toBeNull();

    await pick("Kunde");
    fireEvent.click(await screen.findByRole("button", { name: "2.1 KB" }));
    expect(screen.getByRole("tab", { name: "Journal" }).getAttribute("aria-selected")).toBe("true");
    await waitFor(() => expect(selectedRow()).not.toBeNull());
    const row = selectedRow()!;
    expect(within(row).getByText("2.1 KB")).toBeTruthy();
    expect(within(row).queryByText("900 bytes")).toBeNull();
    // The entry links back to its record, which the Records tab then selects.
    fireEvent.click(within(row).getByRole("button", { name: "Tool result to agent" }));
    expect(screen.getByRole("tab", { name: "Records" }).getAttribute("aria-selected")).toBe("true");
    await waitFor(() => expect(within(selectedRow()!).getByRole("button", { name: when(R1.at) })).toBeTruthy());
  });

  it("revealed originals and the as-sent payload go with another record, a tab switch, and a hidden window (A10)", async () => {
    render(<Activity />);
    await pick("Kunde");
    await screen.findByRole("button", { name: "2.1 KB" });
    await selectAt(R1.at);
    const pane = () => screen.getByRole("complementary", { name: "Record details" });

    // As sent: tokens only, the token as its own element, never originals.
    fireEvent.click(within(pane()).getByRole("button", { name: "As sent" }));
    expect((await within(pane()).findByText(TOKEN)).tagName).toBe("SPAN");
    expect(mock.calls.filter((c) => c.cmd === "journal_record").map((c) => c.args)).toEqual([
      { dataset: "kunde", record: "j1", reveal: false },
    ]);
    expect(document.body.textContent).not.toContain(ORIGINAL);
    // The window hides: the payload goes.
    hideWindow();
    nothingShown();

    // A reveal goes when another record is selected.
    fireEvent.click(within(pane()).getByRole("button", { name: "Reveal originals" }));
    await screen.findByText(REVEAL_LABEL);
    expect(document.body.textContent).toContain(ORIGINAL);
    await selectAt(R0.at);
    nothingShown();

    // So does the as-sent payload.
    await selectAt(R1.at);
    fireEvent.click(within(pane()).getByRole("button", { name: "As sent" }));
    await within(pane()).findByText(TOKEN);
    await selectAt(R0.at);
    nothingShown();

    // And a reveal goes with a tab switch, also when coming back.
    await selectAt(R1.at);
    fireEvent.click(within(pane()).getByRole("button", { name: "Reveal originals" }));
    await screen.findByText(REVEAL_LABEL);
    openTab("Journal");
    await screen.findAllByRole("button", { name: "As sent" });
    nothingShown();
    openTab("Records");
    await screen.findByRole("complementary", { name: "Record details" });
    nothingShown();
  });
});
