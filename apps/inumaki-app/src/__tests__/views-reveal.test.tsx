// Inspect & recover and Activity: a reveal goes when its reason goes (the
// input changes, a file is opened, the window hides), the view slices the NFC
// text the inspect command returned, and a pending purge is not "0 forgotten".
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

import { Inspect } from "../views/Inspect";
import { Activity } from "../views/Activity";
import { REVEAL_LABEL } from "../reveal";

const ORIGINAL = "Qwxzvk";
const inspectBody = (show: boolean) => ({
  label: "local diagnostic output — not approved for transmission",
  outcome: "pass",
  profile: "offline",
  retried: false,
  // "Café " is 6 bytes in NFC.
  spans: [{ start: 6, end: 12, kind: "PERSON", action: "tokenize", source: "Known", ...(show ? { original: ORIGINAL } : {}) }],
  reasons: [],
  replacements: 1,
  limitations: [],
  expiry: { rotation_days: 30, grace_days: 7, epoch_started_at: 1_790_000_000 },
});

beforeEach(() => {
  mock.calls.length = 0;
  mock.events = {};
  mock.handlers = {
    datasets: () => [{ id: "kunde", name: "Kunde", kind: "generic" }],
    inspect_text: (a) => ({ text: (a!.text as string).normalize("NFC"), body: inspectBody(a!.showValues as boolean) }),
  };
});
afterEach(cleanup);

/** The Rust side hid the window: every live listener hears it. */
const hideWindow = () => act(() => [...(mock.events["window-hidden"] ?? [])].forEach((cb) => cb()));

const area = () => screen.getByLabelText("Text to inspect") as HTMLTextAreaElement;

async function inspectAndReveal() {
  render(<Inspect />);
  await screen.findByRole("option", { name: "Kunde" });
  fireEvent.change(area(), { target: { value: `Cafe\u0301 ${ORIGINAL}` } });
  fireEvent.click(screen.getByRole("button", { name: "Inspect" }));
  await screen.findByText(/6 chars at 5/);
  // The textarea now holds the command's NFC text: offsets index into it.
  expect(area().value).toBe(`Café ${ORIGINAL}`);
  fireEvent.click(screen.getByRole("button", { name: "Show values" }));
  await screen.findByText(REVEAL_LABEL);
  expect(screen.getByText(ORIGINAL, { selector: "td" })).toBeTruthy();
}

describe("Inspect & recover", () => {
  it("an edit drops the reveal and the inspection", async () => {
    await inspectAndReveal();
    fireEvent.change(area(), { target: { value: `Café ${ORIGINAL}!` } });
    expect(screen.queryByText(REVEAL_LABEL)).toBeNull();
    expect(screen.queryByText(ORIGINAL, { selector: "td" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Show values" })).toBeNull();
  });

  it("the window hiding drops the reveal", async () => {
    await inspectAndReveal();
    hideWindow();
    expect(screen.queryByText(REVEAL_LABEL)).toBeNull();
    expect(screen.queryByText(ORIGINAL, { selector: "td" })).toBeNull();
  });

  it("Open a file resets the inspection, the marks, and the reveal", async () => {
    mock.handlers.open_text_file = () => "Mu\u0308ller";
    await inspectAndReveal();
    area().setSelectionRange(5, 11);
    fireEvent.click(screen.getByRole("button", { name: "Tokenize selection" }));
    await screen.findByText("1 marked");
    fireEvent.click(screen.getByRole("button", { name: "Open a file…" }));
    await waitFor(() => expect(area().value).toBe("Müller"));
    expect(screen.queryByText(REVEAL_LABEL)).toBeNull();
    expect(screen.queryByText(/marked/)).toBeNull();
    expect(screen.queryByText(/chars at/)).toBeNull();
  });

  it("marks are byte offsets into the returned NFC text", async () => {
    mock.handlers.sanitize_with = () => ({
      outcome: "pass", text: "Café <PERSON_a7f2>", replacements: 1, kinds: ["PERSON"], reasons: [], cached: false, latency_ms: 1,
    });
    await inspectAndReveal();
    area().setSelectionRange(5, 11);
    fireEvent.click(screen.getByRole("button", { name: "Tokenize selection" }));
    fireEvent.click(screen.getByRole("button", { name: "Sanitize with these redactions" }));
    await screen.findByText("Café <PERSON_a7f2>");
    const call = mock.calls.find((c) => c.cmd === "sanitize_with")!;
    expect(call.args!.text).toBe(`Café ${ORIGINAL}`);
    expect(call.args!.spans).toEqual([{ start: 6, end: 12, kind: "PERSON", action: "tokenize" }]);
  });

  const highlighted = () => screen.queryByRole("region", { name: "Inspected text" });

  it("Hide now takes the revealed originals away and puts no original in an attribute", async () => {
    await inspectAndReveal();
    // While revealed, the original is text in the revealed column only, never an attribute value.
    for (const el of Array.from(document.body.querySelectorAll("*"))) {
      for (const attr of Array.from(el.attributes)) expect(attr.value).not.toContain(ORIGINAL);
    }
    fireEvent.click(screen.getByRole("button", { name: "Hide now" }));
    expect(screen.queryByText(REVEAL_LABEL)).toBeNull();
    expect(screen.queryByText(ORIGINAL, { selector: "td" })).toBeNull();
    expect(document.querySelector("td.revealed")).toBeNull();
    // Only the reveal goes: the inspection and its highlighted rendering stay.
    expect(highlighted()).not.toBeNull();
    expect(screen.getByRole("button", { name: "Show values" })).toBeTruthy();
  });

  it("another data source drops the highlighted rendering, the marks, and the reveal", async () => {
    mock.handlers.datasets = () => [
      { id: "kunde", name: "Kunde", kind: "generic" },
      { id: "lief", name: "Lieferant", kind: "generic" },
    ];
    await inspectAndReveal();
    area().setSelectionRange(5, 11);
    fireEvent.click(screen.getByRole("button", { name: "Tokenize selection" }));
    await screen.findByText("1 marked");
    expect(highlighted()!.querySelectorAll("mark").length).toBeGreaterThan(0);
    // Options are valued by index, never by the dataset slug: "1" is Lieferant.
    expect(document.querySelector('option[value="lief"], option[value="kunde"]')).toBeNull();
    fireEvent.change(screen.getByLabelText("Data source"), { target: { value: "1" } });
    expect(highlighted()).toBeNull();
    expect(document.querySelector("mark.hl.found, mark.hl.mine, .hl-text")).toBeNull();
    expect(screen.queryByText(REVEAL_LABEL)).toBeNull();
    expect(screen.queryByText(ORIGINAL, { selector: "td" })).toBeNull();
    expect(screen.queryByText(/marked/)).toBeNull();
    expect(screen.queryByText(/chars at/)).toBeNull();
  });

  it("an edit drops the highlighted rendering", async () => {
    await inspectAndReveal();
    expect(highlighted()).not.toBeNull();
    fireEvent.change(area(), { target: { value: `Café ${ORIGINAL}!` } });
    expect(highlighted()).toBeNull();
  });
});

describe("Activity", () => {
  const entity = (reveal: boolean) => ({
    token: "<PERSON_a7f2>",
    kind: "PERSON",
    first_use: 1,
    last_use: 1,
    uses: 1,
    epoch_id: 1,
    current_epoch: true,
    ...(reveal ? { original: ORIGINAL } : {}),
  });
  beforeEach(() => {
    mock.handlers.datasets = () => [
      { id: "kunde", name: "Kunde", kind: "generic" },
      { id: "lief", name: "Lieferant", kind: "generic" },
    ];
    mock.handlers.activity = () => ({ records: [] });
    mock.handlers.journal = () => ({ entries: [] });
    mock.handlers.entities = (a) => ({ entities: [entity(a!.reveal as boolean)] });
  });
  /** Picks a data source by its chip; the chips come with the dataset list. */
  const pick = async (name: string) => fireEvent.click(await screen.findByRole("button", { name }));
  const openTab = (name: string) => fireEvent.click(screen.getByRole("tab", { name }));
  const noOriginal = () => {
    expect(screen.queryByText(REVEAL_LABEL)).toBeNull();
    expect(screen.queryByText(ORIGINAL, { selector: "td" })).toBeNull();
    expect(document.body.textContent).not.toContain(ORIGINAL);
  };
  /** Opens a source's Known entities tab. */
  async function entitiesOf(name: string) {
    render(<Activity />);
    await pick(name);
    openTab("Known entities");
  }
  async function revealIn(name: string) {
    await entitiesOf(name);
    await screen.findByText("<PERSON_a7f2>");
    fireEvent.click(screen.getByRole("button", { name: "Reveal originals for 60 s" }));
    await screen.findByText(ORIGINAL, { selector: "td" });
    expect(screen.getByText(REVEAL_LABEL)).toBeTruthy();
  }
  const forgetRow = () => screen.getAllByRole("button", { name: "Forget…" })[0];

  it("a reveal does not carry over to another data source or to All", async () => {
    await revealIn("Kunde");
    // The tab stays on Known entities across sources; the panel is a new one.
    await pick("Lieferant");
    expect(screen.getByRole("tab", { name: "Known entities" }).getAttribute("aria-selected")).toBe("true");
    await screen.findByText("<PERSON_a7f2>");
    noOriginal();
    // All sources has only Records.
    await pick("All sources");
    await waitFor(() => expect(screen.queryByText("<PERSON_a7f2>")).toBeNull());
    expect(screen.getByRole("tab", { name: "Records" }).getAttribute("aria-selected")).toBe("true");
    expect((screen.getByRole("tab", { name: "Known entities" }) as HTMLButtonElement).disabled).toBe(true);
    noOriginal();
  });

  it("a reveal on the Journal tab is gone after switching to another tab and back", async () => {
    mock.handlers.journal = () => ({ entries: [{ id: "j1", at: 1, bytes: 12, released: "d1" }] });
    mock.handlers.journal_record = (a) => ({
      id: "j1", at: 1, bytes: 12, released: "d1", unresolved: 0, label: "",
      show_values: a!.reveal as boolean,
      payload: a!.reveal ? `{"to":"${ORIGINAL}"}` : `{"to":"<PERSON_a7f2>"}`,
    });
    render(<Activity />);
    await pick("Kunde");
    openTab("Journal");
    fireEvent.click(await screen.findByRole("button", { name: "Reveal originals" }));
    await screen.findByText(REVEAL_LABEL);
    expect(document.body.textContent).toContain(ORIGINAL);
    openTab("Known entities");
    await screen.findByText("<PERSON_a7f2>");
    openTab("Journal");
    await screen.findByRole("button", { name: "Reveal originals" });
    noOriginal();
  });

  it("Hide now takes the revealed originals off the screen; the pill starts at a full minute", async () => {
    await revealIn("Kunde");
    expect(screen.getByText(/Originals visible, 1:00/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Hide now" }));
    noOriginal();
  });

  it("forgetting an entity takes the revealed originals off the screen", async () => {
    let answer!: (v: unknown) => void;
    mock.handlers.forget_value = () => new Promise((r) => (answer = r));
    await revealIn("Kunde");
    // Row forgets are paused while originals are visible (plan R15); forget by value stays.
    expect((forgetRow() as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Forget by value"), { target: { value: ORIGINAL } });
    fireEvent.click(screen.getByRole("button", { name: "Forget" }));
    await waitFor(() => expect(mock.calls.some((c) => c.cmd === "forget_value")).toBe(true));
    // Gone as soon as the forget starts, and no new reveal while it runs.
    noOriginal();
    expect((screen.getByRole("button", { name: "Reveal originals for 60 s" }) as HTMLButtonElement).disabled).toBe(true);
    await act(async () => answer({ kinds: ["PERSON"], tokens: 1, rows: 1, purge_pending: false }));
    expect((await screen.findByRole("status")).textContent).toBe("Forgot 1 token (PERSON).");
    noOriginal();
  });

  it("a typed forget-by-value is cleared when the window hides", async () => {
    await entitiesOf("Kunde");
    const input = (await screen.findByLabelText("Forget by value")) as HTMLInputElement;
    await act(async () => Promise.resolve()); // the listeners are registered
    fireEvent.change(input, { target: { value: ORIGINAL } });
    expect(input.value).toBe(ORIGINAL);
    // Uncontrolled: React never mirrors the typed original into the DOM attribute.
    expect(input.getAttribute("value")).toBeNull();
    hideWindow();
    expect(input.value).toBe("");
    fireEvent.change(input, { target: { value: ORIGINAL } });
    Object.defineProperty(document, "visibilityState", { value: "hidden", configurable: true });
    act(() => void document.dispatchEvent(new Event("visibilitychange")));
    Object.defineProperty(document, "visibilityState", { value: "visible", configurable: true });
    expect(input.value).toBe("");
  });

  it("a forget with the purge pending says so, not 0 forgotten", async () => {
    mock.handlers.forget_token = () => ({ kinds: [], tokens: 0, rows: 0, purge_pending: true });
    await entitiesOf("Kunde");
    // The row asks inline: its Forget is inside the confirming row.
    await screen.findByText("<PERSON_a7f2>");
    fireEvent.click(forgetRow());
    const row = screen.getByText(/^Forget this PERSON\?/).closest("tr")!;
    fireEvent.click(within(row).getByRole("button", { name: "Forget" }));
    expect((await screen.findByRole("status")).textContent).toBe("Forgotten, cleanup pending.");
  });
});
