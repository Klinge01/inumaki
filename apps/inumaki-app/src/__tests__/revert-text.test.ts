// An offline Revert must never claim the gateway token was revoked: the service revokes it later.
import { describe, expect, it } from "vitest";
import { CLIENT_HEADER_LEFT_TEXT } from "../components/ErrorLine";
import { REVOCATION_PENDING_TEXT, revertText } from "../harnessText";

describe("offline Revert wording", () => {
  it("a pending revocation never says the token was revoked", () => {
    const base = { exact: true, conflicts: 0, client_header_left: false, codex_trust_left: false };
    const done = revertText({ ...base, reverted: true, revocation_pending: true }, "codex");
    expect(done).toContain(REVOCATION_PENDING_TEXT);
    expect(done).not.toMatch(/was revoked/);
    const none = revertText({ ...base, reverted: false, revocation_pending: true }, "codex");
    expect(none.startsWith(`Nothing to revert. ${REVOCATION_PENDING_TEXT}`)).toBe(true);
    expect(none).not.toMatch(/was revoked/);
    expect(revertText({ ...base, reverted: false, revocation_pending: false }, "codex")).toBe(
      "Nothing to revert; the harness's inumaki token was revoked.",
    );
  });

  it("the client-header warning never claims the token is revoked", () => {
    // R1: it also shows for an offline Revert.
    expect(CLIENT_HEADER_LEFT_TEXT).not.toMatch(/revoked/);
  });
});
