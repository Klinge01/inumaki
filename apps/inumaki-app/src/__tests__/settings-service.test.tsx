// The login-service row with a config error: Install and start exists but is disabled, and the
// row makes no claim about who manages the service (an unreachable service reports no manager).
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

import { ServiceSection } from "../views/settings/ServiceSection";

beforeEach(() => {
  mock.handlers = {};
});
afterEach(cleanup);

describe("login service row", () => {
  it("a config error shows a disabled Install and no manager claim", async () => {
    mock.handlers.service_info = () => ({
      reachable: false,
      version: null,
      managed_by: null,
      restart_required: false,
      bin_dir: null,
      config_error: "config file /d/inumaki.toml: is not valid TOML",
    });
    render(<ServiceSection />);
    const install = (await screen.findByRole("button", { name: "Install and start" })) as HTMLButtonElement;
    expect(install.disabled).toBe(true);
    expect(screen.getByText("Not reachable")).toBeTruthy();
    expect(document.body.textContent).not.toContain("Manager not reported");
    expect(document.body.textContent).not.toContain("does not say who runs it");
  });
});
