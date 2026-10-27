// Words for an activity record (redesign spec section 7.4) and the link from a
// record to the journal entry of what it released (spec section 9.2). Nothing
// here reads or keeps a payload: records carry kinds, counts, and a digest.
import type { ActivityRecord, JournalEntry } from "../../types";
import type { Tone } from "../../components/Glyph";

const WHAT: Record<string, Record<string, string>> = {
  gateway: { result: "Tool result to agent", arguments: "Tool call from agent" },
  mirror: { result: "Mirrored file", arguments: "Outbox file from agent" },
  proxy: { request: "Chat request to model", response: "Chat answer from model" },
  hook: { result: "Tool result, checked by the hook" },
};

/** What a record was, from its front door and direction; an unknown pair reads as sent. */
export function what(r: ActivityRecord): string {
  if (r.front_door === "control") return "Sanitized on request";
  return WHAT[r.front_door]?.[r.direction] ?? `${r.front_door} ${r.direction}`;
}

const VERDICT: Record<string, { tone: Tone; word: string }> = {
  released: { tone: "on", word: "Passed" },
  blocked: { tone: "bad", word: "Blocked" },
  uncertain: { tone: "unv", word: "Held back" },
  unresolved: { tone: "unv", word: "Unresolved tokens" },
  unsupported: { tone: "off", word: "Unsupported content" },
};

/** The verdict as a word and a tone; an unknown verdict reads as sent, without a tone of its own. */
export function verdict(r: ActivityRecord): { tone: Tone; word: string } {
  return VERDICT[r.verdict] ?? { tone: "na", word: r.verdict };
}

const CHECK: Record<string, string> = {
  Leak: "Leak check",
  Regex: "Pattern re-scan",
  Ner: "Name re-scan",
  Combination: "Combination",
  Policy: "Policy",
  DetectorError: "Detector error",
  ClearValue: "Known value stopped",
};

/** The checks that fired, in words, with "Known value stopped" for a tripwire (once). */
export function checkWords(r: ActivityRecord): string[] {
  const words = r.checks.map((c) => CHECK[c] ?? c);
  if (r.tripwire) words.push(CHECK.ClearValue);
  return [...new Set(words)];
}

/** A byte count for people: "900 bytes", "2.1 KB", "1.4 MB". */
export function size(bytes: number): string {
  if (bytes < 1024) return `${bytes} ${bytes === 1 ? "byte" : "bytes"}`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/**
 * The journal entry that holds what `r` released: the entry with the same `released` digest
 * (spec section 9.2). Identical payloads share a digest; then the entry closest in time at or
 * after the record wins, else the closest one before it.
 */
export function linkFor(r: ActivityRecord, byDigest: Map<string, JournalEntry[]>): JournalEntry | null {
  if (!r.released) return null;
  const same = byDigest.get(r.released);
  if (!same?.length) return null;
  let after: JournalEntry | null = null;
  let before: JournalEntry | null = null;
  for (const e of same) {
    if (e.at >= r.at) {
      if (!after || e.at < after.at) after = e;
    } else if (!before || e.at > before.at) {
      before = e;
    }
  }
  return after ?? before;
}

/** Journal entries indexed by their `released` digest. */
export function byDigest(entries: JournalEntry[]): Map<string, JournalEntry[]> {
  const m = new Map<string, JournalEntry[]>();
  for (const e of entries) {
    const l = m.get(e.released);
    if (l) l.push(e);
    else m.set(e.released, [e]);
  }
  return m;
}

/** Per journal entry id, the record that links to it; of several, the one closest in time. */
export function recordsByEntry(records: ActivityRecord[], entries: JournalEntry[]): Map<string, ActivityRecord> {
  const index = byDigest(entries);
  const m = new Map<string, ActivityRecord>();
  for (const r of records) {
    const e = linkFor(r, index);
    if (!e) continue;
    const had = m.get(e.id);
    if (!had || Math.abs(r.at - e.at) < Math.abs(had.at - e.at)) m.set(e.id, r);
  }
  return m;
}
