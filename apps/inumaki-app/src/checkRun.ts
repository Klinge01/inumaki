import { useSyncExternalStore } from "react";
import { asCmdError, runCheck } from "./ipc";
import type { CheckRun, CmdError } from "./types";

/**
 * The one end-to-end check run (plan R28). A module-level store, so a check survives view switches and
 * the Overview toolbar, the Overview check box, the connection page's side column, and first-run step 5
 * share it. It holds statuses, reason codes, and times only (what `run_check` reports).
 */
export type CheckRunState = {
  running: boolean;
  /** Milliseconds since the epoch when the button was pressed; null while nothing runs. */
  startedAt: number | null;
  /** The service's answer to the last run; cleared when a new run starts. */
  run: CheckRun | null;
  error: CmdError | null;
};

let state: CheckRunState = { running: false, startedAt: null, run: null, error: null };
// Bumped by every start and by clearCheckRun: a run only shows its answer while it is the newest.
let generation = 0;
const listeners = new Set<() => void>();

function set(next: CheckRunState) {
  state = next;
  for (const l of listeners) l();
}

function subscribe(l: () => void) {
  listeners.add(l);
  return () => {
    listeners.delete(l);
  };
}

/** Starts a run. Ignored while one is running. */
export async function startCheckRun(): Promise<void> {
  if (state.running) return;
  const g = ++generation;
  set({ running: true, startedAt: Date.now(), run: null, error: null });
  let next: CheckRunState;
  try {
    next = { running: false, startedAt: null, run: await runCheck(), error: null };
  } catch (e) {
    next = { running: false, startedAt: null, run: null, error: asCmdError(e) };
  }
  // Made stale while it ran (a Connect, Reconnect or Revert): it ends without showing its results.
  set(g === generation ? next : { ...state, running: false, startedAt: null });
}

/** A Connect, Reconnect or Revert makes the last run's results stale; a run in flight ends without showing them. */
export function clearCheckRun() {
  generation += 1;
  set({ ...state, run: null, error: null });
}

/** True when the last run ended in an error or any path of any report failed. */
export function checkFailed(s: Pick<CheckRunState, "run" | "error">): boolean {
  if (s.error) return true;
  return (s.run?.reports ?? []).some((r) => Object.values(r.results).some((p) => p.status === "failed"));
}

export function useCheckRun(): CheckRunState & { start: () => Promise<void> } {
  const s = useSyncExternalStore(subscribe, () => state);
  return { ...s, start: startCheckRun };
}
