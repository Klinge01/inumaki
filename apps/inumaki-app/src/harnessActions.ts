// The actions of one harness (Connect, Reconnect, Revert, chat switch, manual setup, acknowledge) and
// the state they leave behind. Shared by every view that offers them, so a fail-closed rule lives once.
import { useState } from "react";
import * as ipc from "./ipc";
import { clearCheckRun } from "./checkRun";
import type { CmdError, ConnectOutcome, DataChange, FileChange, HarnessCard, ManualSetup, PathKind } from "./types";
import { REVOCATION_PENDING_TEXT, revertText, withWarnings } from "./harnessText";
import { useHeaderLeft } from "./headerLeft";
import { useWindowHidden } from "./useWindowHidden";

/** The outcome carries a warning that `withWarnings` appends to the note. */
const warned = (out: ConnectOutcome) => !!out.warning || (out.harness_warnings?.length ?? 0) > 0;

export function useHarnessActions(card: HarnessCard, onChange: () => Promise<void>) {
  const [headerLefts, setHeaderLefts] = useHeaderLeft();
  const [preview, setPreview] = useState<FileChange[] | null>(null);
  // The preview was refused: Connect then answers with the lines to add by hand.
  const [refused, setRefused] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  // The note carries a Connect/Reconnect warning (plan R12: the page shows it in an amber notice).
  const [noteWarned, setNoteWarned] = useState(false);
  const [error, setError] = useState<CmdError | null>(null);
  const [change, setChange] = useState<DataChange | null>(null);
  const [busy, setBusy] = useState(false);
  // The lines to add by hand, asked for on demand ("none": the service had nothing to offer).
  const [manual, setManual] = useState<ManualSetup | "none" | null>(null);

  // A refused Connect's snippet holds a token and cannot be re-read: not left on a hidden window.
  // The manual-setup lines hold home paths and local URLs: dropped the same way.
  useWindowHidden(() => {
    setError((e) => (e?.snippet ? null : e));
    setManual(null);
  });

  // Runs `f`; reloads either way (a failed Reconnect still changes the card).
  // The controls stay disabled until the reload answered, so a switch never
  // offers the value from before the change.
  const run = async (f: () => Promise<void>) => {
    setError(null);
    setNote(null);
    setNoteWarned(false);
    setBusy(true);
    try {
      await f();
    } catch (e) {
      setError(ipc.asCmdError(e));
    } finally {
      await onChange();
      setBusy(false);
    }
  };

  const setHeaderLeft = (on: boolean) => setHeaderLefts(card.id, on);

  // Not `run`: asking for the lines changes nothing, so it clears no note and reloads nothing.
  const doManualSetup = async () => {
    setError(null);
    try {
      setManual((await ipc.manualSetup(card.id)) ?? "none");
    } catch (e) {
      setError(ipc.asCmdError(e));
    }
  };

  /** Asks what Connect would change: sets `preview`, or `refused` with the reason. */
  const startConnect = () =>
    run(async () => {
      setNote(null);
      setRefused(null);
      try {
        setPreview(await ipc.previewConnect(card.id));
      } catch (e) {
        const err = ipc.asCmdError(e);
        if (err.kind !== "cannot_edit_safely") throw err;
        setPreview(null);
        setRefused(err.reason?.text ?? "inumaki cannot edit this file safely.");
      }
    });

  const cancelConnect = () => {
    setPreview(null);
    setRefused(null);
  };

  // Connect, Reconnect and Revert change the card, answered or failed: the last check run is stale.
  const doConnect = () =>
    run(async () => {
      clearCheckRun();
      // The sheet closes whether Connect answered or failed: a failure's error (and a refused
      // Connect's snippet) shows on the page, not under the sheet's modal layer.
      try {
        const out = await ipc.connect(card.id);
        setHeaderLeft(false);
        setNote(withWarnings(`Connected. ${out.note}`, out, card.id));
        setNoteWarned(warned(out));
      } finally {
        setPreview(null);
        setRefused(null);
      }
    });

  const doReconnect = () =>
    run(async () => {
      clearCheckRun();
      const out = await ipc.reconnect(card.id);
      setHeaderLeft(false);
      setNote(withWarnings(`Reconnected. ${out.note}`, out, card.id));
      setNoteWarned(warned(out));
    });

  const doRevert = () =>
    run(async () => {
      clearCheckRun();
      setNote(null);
      try {
        setNote(revertText(await ipc.revert(card.id), card.id));
        setHeaderLeft(false);
      } catch (e) {
        const err = ipc.asCmdError(e);
        if (err.kind !== "client_header_left" && err.kind !== "client_header_left_pending") throw err;
        // Reverted, but the header is still in the file: a warning that stays (rendered from
        // `headerLeft`), not a one-off error. The pending kind means the service was unreachable:
        // the token is not revoked yet, and the note says so.
        setHeaderLeft(true);
        if (err.kind === "client_header_left_pending") setNote(REVOCATION_PENDING_TEXT);
      }
    });

  const doChat = (on: boolean) =>
    run(async () => {
      setChange(null);
      setChange(await ipc.setChatOptIn(card.id, on));
    });

  const doAcknowledge = (path: PathKind) => run(() => ipc.acknowledge(card.id, path));

  return {
    busy,
    note,
    noteWarned,
    error,
    change,
    manual,
    preview,
    refused,
    /** The client header is still in the harness's file after a Revert (survives reloads). */
    headerLeft: headerLefts.has(card.id),
    setHeaderLeft,
    hideManual: () => setManual(null),
    run,
    doManualSetup,
    startConnect,
    cancelConnect,
    doConnect,
    doReconnect,
    doRevert,
    doChat,
    doAcknowledge,
  };
}

export type HarnessActions = ReturnType<typeof useHarnessActions>;
