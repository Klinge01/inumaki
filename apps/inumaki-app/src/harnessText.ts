// The fixed texts of the harness cards and their small helpers. Pure: no React, no IO.
import type { ConnectOutcome, HarnessCard, HarnessId, PathView, RevertSummary } from "./types";

/** The display name of each harness. */
export const HARNESS_NAME: Record<HarnessId, string> = {
  "claude-code": "Claude Code",
  codex: "Codex",
  hermes: "Hermes Agent",
  openclaw: "OpenClaw",
};

/** The text monogram of each harness (sidebar and Overview rows); not a vendor logo. */
export const HARNESS_MONOGRAM: Record<HarnessId, string> = { "claude-code": "CC", codex: "Cx", openclaw: "OC", hermes: "H" };

/** Where the per-harness guides live; while null, no guide link is rendered. */
export const GUIDE_BASE_URL: string | null = null;

/** The Easy-mode limit, under a connected harness's header (spec section 6.1). */
export const GOES_AROUND = "An agent that deliberately goes around inumaki can still succeed.";

/**
 * What the login detection knows, in words (plan R5, checked against the adapters). A Claude Code
 * sign-in proves an account, not a plan; Hermes Agent and OpenClaw do not say which provider.
 */
export function loginLabel(card: HarnessCard): string {
  switch (card.login) {
    case "api_key":
      return "API key";
    case "unknown":
      return "Login not detected";
    case "oauth":
      return card.id === "claude-code" ? "Claude account login" : card.id === "codex" ? "ChatGPT login" : "Subscription login";
  }
}

/** Where a harness's chat goes when inumaki does not filter it (plan R26); null: Codex with a ChatGPT login has its own sentence. */
export function chatProvider(card: HarnessCard): string | null {
  if (card.id === "claude-code") return "Anthropic";
  if (card.id === "codex" && card.login === "oauth") return null;
  if (card.id === "codex" && card.login === "api_key") return "OpenAI";
  return "its model provider";
}

/** The program inumaki asks for its version (`<binary> --version`). */
export const HARNESS_BINARY: Record<HarnessId, string> = {
  "claude-code": "claude",
  codex: "codex",
  hermes: "hermes",
  openclaw: "openclaw",
};
// The paths whose lines the user adds by hand (the adapters' `manual_setup`): the state and the
// reason together. A connected OpenClaw Files path can carry the same reason as a note and needs nothing.
export const needsManualSetup = (p: PathView) =>
  (p.state === "unsupported" && p.reason?.code === "openclaw_docker_binds_only") ||
  (p.state === "unverified" && p.reason?.code === "hermes_oauth_no_override");
export const NEXT_SESSION = "Takes effect in the harness's next session.";

// Claude Code reads ~/.claude/settings.json live, so its chat route and hook can change under open windows.
export const CLAUDE_CHAT_REFUSED_NOTE =
  "With the support-email or strict profile, Claude Code's chat requests are refused today (measured 2026-10-11 with Claude Code 2.1.296), so open sessions stop answering until you turn Chat off again.";
export const CLAUDE_CHAT_ON_LEAD = "Every open Claude Code window, in every project, switches to sending chat through inumaki at once.";
export const CLAUDE_CHAT_ON = `${CLAUDE_CHAT_ON_LEAD} ${CLAUDE_CHAT_REFUSED_NOTE}`;
export const CLAUDE_CHAT_OFF =
  "Every open Claude Code window switches back to talking to Anthropic directly at once, and its chat is no longer filtered by inumaki.";
export const CLAUDE_CONNECT_NOTE =
  "Connect does not route Claude Code's chat; that is a separate switch on this card. Open Claude Code windows may pick up the changes to ~/.claude/settings.json (the tool-result hook) at once; MCP servers in ~/.claude.json take effect in the next session.";
export const CLAUDE_AFTER_NOTE =
  "MCP servers take effect in the next Claude Code session; settings.json changes may apply to open windows at once.";
export const CLAUDE_CHAT_SWITCH_LABEL = "Send Claude Code chat through inumaki";

// The other harnesses read their configuration when a session starts (no hot reload is claimed for them).
export const CODEX_CHAT_RESTART_NOTE =
  "Codex needs to be restarted: open sessions keep talking to their provider directly until you quit and reopen Codex.";
export const CODEX_CHAT_ON_LEAD = "Codex sends chat through inumaki from its next session.";
export const CODEX_CHAT_ON = `${CODEX_CHAT_ON_LEAD} ${CODEX_CHAT_RESTART_NOTE}`;
export const CODEX_CHAT_OFF =
  "Codex talks to its provider directly again from its next session, and its chat is no longer filtered by inumaki.";
export const CODEX_CHAT_SWITCH_LABEL = "Send Codex chat through inumaki";
/** The Codex switch's label with a ChatGPT login: the same switch, with what is known about that path. */
export const CODEX_OPT_IN_LABEL =
  "Protect chat with the ChatGPT login (unverified; refused today with privacy_block, so Codex chat stops working while this is on)";
export const HERMES_CHAT_ON_LEAD = "Hermes Agent sends chat through inumaki at the latest from its next session.";
export const HERMES_CHAT_UNMEASURED_NOTE =
  "Whether the support-email or strict profile refuses its chat requests is not measured; if it does, Hermes Agent stops answering until you turn Chat off again.";
export const HERMES_CHAT_ON = `${HERMES_CHAT_ON_LEAD} ${HERMES_CHAT_UNMEASURED_NOTE}`;
export const HERMES_CHAT_OFF =
  "Hermes Agent talks to its provider directly again from its next session, and its chat is no longer filtered by inumaki.";
export const HERMES_CHAT_SWITCH_LABEL = "Send Hermes Agent chat through inumaki";
export const OPENCLAW_CHAT_ON_LEAD = "OpenClaw sends chat through inumaki at the latest from its next session.";
export const OPENCLAW_CHAT_UNMEASURED_NOTE =
  "Whether the support-email or strict profile refuses its chat requests is not measured; if it does, OpenClaw stops answering until you turn Chat off again.";
export const OPENCLAW_CHAT_ON = `${OPENCLAW_CHAT_ON_LEAD} ${OPENCLAW_CHAT_UNMEASURED_NOTE}`;
export const OPENCLAW_CHAT_OFF =
  "OpenClaw talks to its provider directly again from its next session, and its chat is no longer filtered by inumaki.";
export const OPENCLAW_CHAT_SWITCH_LABEL = "Send OpenClaw chat through inumaki";
/** The Connect preview of every harness but Claude Code (which has its own note). */
export const CHAT_CONNECT_NOTE = "Connect does not route chat; that is a separate switch on the harness's page.";

/** What the chat switch of each harness says: its label, and the confirm texts for turning it on and off. */
export const CHAT_TEXT: Record<HarnessId, { label: string; on: string; off: string }> = {
  "claude-code": { label: CLAUDE_CHAT_SWITCH_LABEL, on: CLAUDE_CHAT_ON, off: CLAUDE_CHAT_OFF },
  codex: { label: CODEX_CHAT_SWITCH_LABEL, on: CODEX_CHAT_ON, off: CODEX_CHAT_OFF },
  hermes: { label: HERMES_CHAT_SWITCH_LABEL, on: HERMES_CHAT_ON, off: HERMES_CHAT_OFF },
  openclaw: { label: OPENCLAW_CHAT_SWITCH_LABEL, on: OPENCLAW_CHAT_ON, off: OPENCLAW_CHAT_OFF },
};

/**
 * `CHAT_TEXT[id].on` split into the lead sentence and the note (a restart hint, refused today, or not measured).
 * The chat-on sheet shows the lead as its body and the note in an amber notice; `${lead} ${note}` is `on`.
 */
export const CHAT_ON_PARTS: Record<HarnessId, { lead: string; note: string }> = {
  "claude-code": { lead: CLAUDE_CHAT_ON_LEAD, note: CLAUDE_CHAT_REFUSED_NOTE },
  codex: { lead: CODEX_CHAT_ON_LEAD, note: CODEX_CHAT_RESTART_NOTE },
  hermes: { lead: HERMES_CHAT_ON_LEAD, note: HERMES_CHAT_UNMEASURED_NOTE },
  openclaw: { lead: OPENCLAW_CHAT_ON_LEAD, note: OPENCLAW_CHAT_UNMEASURED_NOTE },
};

/** The switch's label: Codex with a ChatGPT login keeps the label that says what is known about that path. */
export function chatLabel(card: HarnessCard): string {
  return card.id === "codex" && card.login === "oauth" ? CODEX_OPT_IN_LABEL : CHAT_TEXT[card.id].label;
}

/**
 * The logins inumaki writes a chat route for: any login of Claude Code (its adapter routes regardless), an API key
 * elsewhere, and Codex's ChatGPT login. Otherwise the adapters write nothing, and a switch would read "on" over a red card.
 */
export function chatSwitchable(card: HarnessCard): boolean {
  return card.id === "claude-code" || card.login === "api_key" || (card.id === "codex" && card.login === "oauth");
}

/** The MCP section's footer on the connection page (plan A6); Claude Code's is `CLAUDE_AFTER_NOTE`. */
export const serverChangesNote = (name: string) => `Server changes apply in ${name}'s next session.`;

/** The harness's "takes effect in the next session" sentence; Claude Code's differs. */
export const nextSession = (id: HarnessId) => (id === "claude-code" ? CLAUDE_AFTER_NOTE : NEXT_SESSION);


/** The outcome note, plus the fixed warning of a skipped chat route and the adapter's fixed sentences. */
export function withWarnings(note: string, out: ConnectOutcome, id: HarnessId): string {
  const parts = [note.replace(NEXT_SESSION, nextSession(id))];
  if (out.warning) parts.push(`Warning: ${out.warning}.`);
  for (const w of out.harness_warnings ?? []) parts.push(`Warning: ${w.text}`);
  return parts.join(" ");
}

/** Fixed sentence (the CLI prints the same): Codex's trust record for the hook stayed in config.toml. */
export const CODEX_TRUST_LEFT_TEXT = "Codex's trust record for inumaki's hook could not be removed; remove it in Codex's /hooks.";

/** Fixed sentence for an offline Revert: the token is not revoked yet, and the text never says it is. */
export const REVOCATION_PENDING_TEXT =
  "The inumaki service is not reachable. It revokes this harness's gateway token before it serves anything at its next start, or within a minute if it is still running.";

export function revertText(r: RevertSummary, id: HarnessId): string {
  if (!r.reverted) {
    return r.revocation_pending
      ? `Nothing to revert. ${REVOCATION_PENDING_TEXT}`
      : "Nothing to revert; the harness's inumaki token was revoked.";
  }
  const parts = ["Reverted."];
  if (!r.exact) parts.push("The file was restored by editing inumaki's entries out, not byte for byte.");
  if (r.conflicts > 0) {
    parts.push(`${r.conflicts} ${r.conflicts === 1 ? "entry" : "entries"} changed by something else ${r.conflicts === 1 ? "was" : "were"} left alone.`);
  }
  if (r.codex_trust_left) parts.push(CODEX_TRUST_LEFT_TEXT);
  if (r.revocation_pending) parts.push(REVOCATION_PENDING_TEXT);
  parts.push(nextSession(id));
  return parts.join(" ");
}
