// The mailbox app password is held only in the input's state: cleared as soon as it is
// sent (success or failure) and when the window hides.
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { act } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mock = vi.hoisted(() => ({
  sent: [] as Record<string, unknown>[],
  fail: false,
  // When set, add_mailbox and replace_mailbox_password stay pending until it is resolved.
  gate: undefined as undefined | Promise<void>,
  cards: [] as unknown[],
  hidden: undefined as undefined | (() => void),
}));

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (cmd: string, args?: Record<string, unknown>) => {
    if (cmd === "mailboxes") return Promise.resolve(mock.cards);
    if (cmd === "check_mailbox") {
      return Promise.resolve({ folders: 3, drafts_folder_resolved: true, drafts_folder_will_be_created: false, drafts_folder_configured: false });
    }
    if (cmd === "add_mailbox" || cmd === "replace_mailbox_password") {
      mock.sent.push({ cmd, ...args });
      return (mock.gate ?? Promise.resolve()).then(() =>
        mock.fail
          ? Promise.reject({ kind: "mail_auth_failed", status: null, kinds: [] })
          : cmd === "add_mailbox"
            ? { card: {}, reconnect_failures: 0, failed_harnesses: [] }
            : undefined,
      );
    }
    return Promise.reject({ kind: "not_available", status: 404, kinds: [] });
  },
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: (_e: string, cb: () => void) => {
    mock.hidden = cb;
    return Promise.resolve(() => undefined);
  },
}));

import { Email } from "../views/Email";

const pwInput = () => screen.getByLabelText("App password") as HTMLInputElement;

async function fill() {
  render(<Email />);
  await screen.findByText("No mailbox yet.");
  fireEvent.change(screen.getByLabelText("Username"), { target: { value: "me@example.com" } });
  fireEvent.change(pwInput(), { target: { value: "s3cret-app-pw" } });
}

beforeEach(() => {
  mock.sent.length = 0;
  mock.fail = false;
  mock.gate = undefined;
  mock.cards = [];
  mock.hidden = undefined;
});
afterEach(cleanup);

describe("mailbox password", () => {
  it("is a password field and is cleared while the request is still pending", async () => {
    let release!: () => void;
    mock.gate = new Promise<void>((r) => (release = r));
    await fill();
    expect(pwInput().type).toBe("password");
    fireEvent.click(screen.getByRole("button", { name: "Add mailbox" }));
    await waitFor(() => expect(mock.sent).toHaveLength(1));
    expect((mock.sent[0].form as { password: string }).password).toBe("s3cret-app-pw");
    expect(pwInput().value).toBe(""); // empty before the answer arrives
    release();
    await waitFor(() => expect(pwInput().value).toBe(""));
  });

  it("the Replace field is cleared while the request is still pending", async () => {
    let release!: () => void;
    mock.gate = new Promise<void>((r) => (release = r));
    mock.cards = [{ dataset: "mail-1", display_name: "Work", entry_name: "inumaki-mail", mailbox: null }];
    render(<Email />);
    fireEvent.click(await screen.findByRole("button", { name: "Replace app password…" }));
    const field = (await screen.findByLabelText("New app password")) as HTMLInputElement;
    expect(field.type).toBe("password");
    fireEvent.change(field, { target: { value: "new-app-pw" } });
    fireEvent.click(screen.getByRole("button", { name: "Replace password" }));
    await waitFor(() => expect(mock.sent).toHaveLength(1));
    expect(mock.sent[0].password).toBe("new-app-pw");
    expect(field.value).toBe("");
    release();
    await screen.findByText("Password replaced.");
  });

  it("is cleared once sent, on failure, and the error stays", async () => {
    mock.fail = true;
    await fill();
    fireEvent.click(screen.getByRole("button", { name: "Add mailbox" }));
    await screen.findByText(/refused the username or app password/);
    expect(pwInput().value).toBe("");
  });

  it("is cleared when the window hides", async () => {
    await fill();
    expect(pwInput().value).toBe("s3cret-app-pw");
    act(() => mock.hidden?.());
    await waitFor(() => expect(pwInput().value).toBe(""));
  });

  it("a Check shows its result even when the mailbox settings could not be read", async () => {
    mock.cards = [{ dataset: "mail-1", display_name: "Work", entry_name: "inumaki-mail", mailbox: null }];
    render(<Email />);
    fireEvent.click(await screen.findByRole("button", { name: "Check" }));
    expect((await screen.findByRole("status")).textContent).toBe("Last check: 3 folders, drafts folder found");
  });
});
