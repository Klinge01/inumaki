// The status grammar in one place (spec section 3, plan R4). Pure functions: no React, no IO.
import type { Tone } from "./components/Glyph";
import type { HarnessCard, HarnessId, HookState, PathView, ServerRow } from "./types";

export type PathStatusWord = { tone: Tone; word: string };

/** The tone and word of one path, in the order of the spec's section 3 mapping table. */
export function pathStatus(v: PathView, card: HarnessCard): PathStatusWord {
  if (card.disconnected) return { tone: "off", word: "Not filtered now" };
  switch (v.state) {
    case "broken":
      return { tone: "bad", word: "Needs attention" };
    case "connected":
      return { tone: "on", word: "On" };
    case "unverified":
      return v.path === "chat" && v.reason?.code === "hermes_oauth_no_override"
        ? { tone: "unv", word: "Needs one line you add" }
        : { tone: "unv", word: "On, unverified" };
    case "unsupported":
      return { tone: "na", word: v.acknowledged ? "Not protected, acknowledged" : "Not protected" };
    case "not_connected":
      return v.path === "chat" && card.connected
        ? { tone: "off", word: "Off, your choice" }
        : { tone: "off", word: "Off" };
  }
}

/** "Chat: off, your choice": the word's first letter is lower-cased after the label. */
export function sectionTitle(label: string, word: string): string {
  return `${label}: ${word.charAt(0).toLowerCase()}${word.slice(1)}`;
}

// Weakest first. An acknowledged unsupported path is a decision the user made, so it ranks as off.
const RANK: Record<Tone, number> = { bad: 5, na: 4, unv: 3, on: 2, off: 1, protected: 0 };
const WEAKEST_WORD: Record<Tone, string> = {
  bad: "Needs attention",
  na: "Not protected",
  unv: "On, unverified",
  on: "On",
  off: "Off",
  protected: "Protected",
};

/**
 * The tone and word of a card's weakest point, for the sidebar glyph. A disconnected card, a broken
 * hook and a withdrawn grant are `bad`, as in the status block; a card that is not connected is `off`,
 * as its Overview row says. Otherwise the weakest path wins (bad > na unacknowledged > unv > on > off),
 * where a failed last check counts as bad and a pending hook or drift as at least unverified.
 */
export function weakestStatus(card: HarnessCard): PathStatusWord {
  if (card.disconnected) return { tone: "bad", word: "Disconnected" };
  if (card.grant || card.hook.state === "broken") return { tone: "bad", word: "Needs attention" };
  if (!card.connected) return { tone: "off", word: "Not connected" };
  let weakest: Tone = "off";
  for (const p of card.paths) {
    let t: Tone;
    if (p.last_check === "failed" || p.state === "broken") t = "bad";
    else {
      const { tone } = pathStatus(p, card);
      t = tone === "na" && p.acknowledged ? "off" : tone;
    }
    if (RANK[t] > RANK[weakest]) weakest = t;
  }
  if ((card.hook.state === "pending" || card.drift > 0) && RANK.unv > RANK[weakest]) weakest = "unv";
  return { tone: weakest, word: WEAKEST_WORD[weakest] };
}

/** The tone of {@link weakestStatus}. */
export const weakestTone = (card: HarnessCard): Tone => weakestStatus(card).tone;

/** The harnesses that are disconnected: their protected servers talk to the originals again. */
export const disconnectedIds = (cards: readonly HarnessCard[]): Set<HarnessId> =>
  new Set(cards.filter((c) => c.disconnected).map((c) => c.id));

/**
 * "P of T" for the MCP count: a protected server of a disconnected harness is not counted as
 * protected, because that harness talks to the original server again.
 */
export function protectedCount(rows: readonly ServerRow[], cards: readonly HarnessCard[]): string {
  const down = disconnectedIds(cards);
  return `${rows.filter((r) => r.protected && !down.has(r.harness)).length} of ${rows.length}`;
}

export type HookStatus = { tone: Tone; word: string; reason: string | null };

/** The tool-result hook line (spec section 6.3); `null` when the harness has no hook. */
export function hookStatus(h: HookState): HookStatus | null {
  switch (h.state) {
    case "not_applicable":
      return null;
    case "installed":
      return { tone: "on", word: "installed", reason: null };
    case "not_installed":
      return { tone: "off", word: "not installed", reason: null };
    case "pending":
      return { tone: "unv", word: "waiting for trust", reason: h.reason.text };
    case "broken":
      return { tone: "bad", word: "broken", reason: h.reason.text };
  }
}

export type RowSentence = { text: string; tone: "red" | "amber" | "plain" };

const PATH_NAME = { mcp: "MCP tools", files: "Files", chat: "Chat" } as const;
const PATH_LOWER = { mcp: "MCP tools", files: "files", chat: "chat" } as const;

/**
 * Counts as filtered in the Overview strip: connected, at least one path actually `connected`, and no
 * red row sentence (disconnected, a broken path, a failed check, a broken hook), so the summary and
 * the row can never disagree (L105).
 */
export const isFiltered = (card: HarnessCard): boolean =>
  card.connected && card.paths.some((p) => p.state === "connected") && rowSentence(card).tone !== "red";

const joinNames = (names: string[]): string => {
  const s = names.length === 2 ? `${names[0]} and ${names[1]}` : names.join(", ");
  return s.charAt(0).toUpperCase() + s.slice(1);
};

/** What is filtered on a healthy connected card, in words; unverified paths are never called "filtered". */
function summary(card: HarnessCard): string {
  const state = (k: PathView["path"]) => card.paths.find((p) => p.path === k);
  const lower = { mcp: "MCP tools", files: "files" } as const;
  const filtered = (["mcp", "files"] as const).filter((k) => state(k)?.state === "connected").map((k) => lower[k]);
  const unverified = (["mcp", "files"] as const).filter((k) => state(k)?.state === "unverified").map((k) => lower[k]);
  const parts: string[] = [];
  if (filtered.length > 0) parts.push(`${joinNames(filtered)} are filtered.`);
  if (unverified.length > 0) parts.push(`${joinNames(unverified)} are on, unverified.`);
  const unsupported = (["mcp", "files"] as const).filter((k) => state(k)?.state === "unsupported").map((k) => lower[k]);
  if (unsupported.length > 0) parts.push(`${joinNames(unsupported)} are not protected.`);
  if (parts.length === 0) parts.push("MCP tools and files are not filtered.");
  const chat = state("chat");
  if (chat?.state === "connected") parts.push("Chat is filtered.");
  else if (chat?.state === "unverified") {
    parts.push(
      chat.reason?.code === "hermes_oauth_no_override" ? "Chat needs one line you add." : "Chat is on, unverified.",
    );
  } else if (chat?.state === "unsupported") parts.push("Chat is not protected.");
  else parts.push("Chat is off.");
  return parts.join(" ");
}

/**
 * The one sentence of an Overview row (spec section 5 item 2): the most important fact first. Every
 * sentence is fixed text or a fixed reason from the service; nothing here is a value from a harness file.
 * Red and amber sentences are the ones a user must act on; they never read as "all good".
 */
export function rowSentence(card: HarnessCard): RowSentence {
  if (card.disconnected) {
    return { text: "Disconnected. Its protected servers talk to the originals again, unfiltered.", tone: "red" };
  }
  if (!card.connected) return { text: "Not connected.", tone: "plain" };
  const broken = card.paths.find((p) => p.state === "broken");
  if (broken) return { text: broken.reason?.text ?? "A path needs attention.", tone: "red" };
  const failedCheck = card.paths.find((p) => p.last_check === "failed");
  if (failedCheck) return { text: `The last check of ${PATH_LOWER[failedCheck.path]} failed.`, tone: "red" };
  if (card.hook.state === "broken") return { text: card.hook.reason.text, tone: "red" };
  if (card.grant) return { text: "macOS withdrew access to its files.", tone: "amber" };
  if (card.hook.state === "pending") return { text: card.hook.reason.text, tone: "amber" };
  if (card.drift > 0) {
    return {
      text: `${card.drift} ${card.drift === 1 ? "setting was" : "settings were"} changed outside inumaki.`,
      tone: "amber",
    };
  }
  const unsupported = card.paths.find((p) => p.state === "unsupported" && !p.acknowledged);
  if (unsupported) return { text: `${PATH_NAME[unsupported.path]} can't be protected with this setup.`, tone: "plain" };
  return { text: summary(card), tone: "plain" };
}
