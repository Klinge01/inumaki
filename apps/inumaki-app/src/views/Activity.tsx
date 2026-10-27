// Activity (M6 spec §6.4, redesign spec §7.4): records, the record-chain
// check, and per data source the egress journal and the known entities, one
// tab at a time. Originals appear only through useReveal (one item per click,
// 60 s, gone on hide or navigation) inside a RevealPanel, and are never kept
// anywhere else. The tab panel is keyed by source and tab, so changing either
// unmounts it and a reveal never carries over (plan R17).
import { useEffect, useState, type KeyboardEvent } from "react";
import * as ipc from "../ipc";
import type { CmdError, DatasetRow } from "../types";
import { ErrorLine } from "../components/ErrorLine";
import { Toolbar, ViewBody } from "../components/Toolbar";
import { Tick } from "../components/PathSection";
import { CHAT_DATASET, sourceLabel } from "./activity/source";
import { Records } from "./activity/Records";
import { Journal } from "./activity/Journal";
import { ChatEntities, Entities } from "./activity/Entities";

export { CHAT_DATASET, sourceLabel } from "./activity/source";
export { forgetText } from "./activity/Entities";

type Tab = "records" | "journal" | "entities";
const TABS: { id: Tab; label: string }[] = [
  { id: "records", label: "Records" },
  { id: "journal", label: "Journal" },
  { id: "entities", label: "Known entities" },
];

export function Activity() {
  const [sets, setSets] = useState<DatasetRow[]>([]);
  const [dataset, setDataset] = useState<string | null>(null);
  // The chosen tab persists across sources; "All sources" has only Records (plan R17).
  const [tab, setTab] = useState<Tab>("records");
  const [verified, setVerified] = useState<{ ok: boolean; records: number } | null>(null);
  const [error, setError] = useState<CmdError | null>(null);
  // The selected record and journal entry (opaque ids): a record links to its entry and back (spec 9.2).
  const [sel, setSel] = useState<{ record: string | null; entry: string | null }>({ record: null, entry: null });
  useEffect(() => {
    ipc.datasets().then(setSets, (e) => setError(ipc.asCmdError(e)));
  }, []);
  const shown: Tab = dataset ? tab : "records";
  const pick = (id: string | null) => {
    setDataset(id);
    setSel({ record: null, entry: null });
    if (!id) setTab("records");
  };
  const enabled = (t: Tab) => t === "records" || dataset !== null;
  // Arrow keys move between the enabled tabs (WAI-ARIA tabs pattern; selection follows focus).
  const onTabKey = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
    const open = TABS.filter((t) => enabled(t.id));
    const at = open.findIndex((t) => t.id === shown);
    const next = open[(at + (e.key === "ArrowRight" ? 1 : open.length - 1)) % open.length];
    e.preventDefault();
    setTab(next.id);
    document.getElementById(`activity-tab-${next.id}`)?.focus();
  };
  const openEntry = (entry: string) => {
    setSel((s) => ({ ...s, entry }));
    setTab("journal");
  };
  const openRecord = (record: string) => {
    setSel((s) => ({ ...s, record }));
    setTab("records");
  };
  const source = (id: string) => {
    const d = sets.find((x) => x.id === id);
    return sourceLabel(id, d ? d.name || d.id : undefined);
  };
  const chat = sets.some((d) => d.id === CHAT_DATASET);
  const others = sets.filter((d) => d.id !== CHAT_DATASET);
  const chip = (id: string | null, label: string, key: string) => (
    <button key={key} type="button" className="source-chip" aria-pressed={dataset === id} onClick={() => pick(id)}>
      {label}
    </button>
  );
  return (
    <section>
      <Toolbar
        title="Activity"
        actions={
          <>
            {verified &&
              (verified.ok ? (
                <span className="res pass verify-line" role="status">
                  <Tick /> {`Record chain intact, ${verified.records} ${verified.records === 1 ? "record" : "records"}`}
                </span>
              ) : (
                <span className="res fail verify-line" role="status">
                  The record chain is broken.
                </span>
              ))}
            <button
              type="button"
              onClick={() => {
                setVerified(null);
                ipc.verifyActivity().then(
                  (v) => setVerified({ ok: v.ok, records: v.records }),
                  (e) => setError(ipc.asCmdError(e)),
                );
              }}
            >
              Verify records
            </button>
          </>
        }
      />
      <ViewBody>
        <div className="filter-bar">
          <div className="source-chips" role="group" aria-label="Data source">
            {chip(null, "All sources", "all")}
            {chat && chip(CHAT_DATASET, "Chat", "chat")}
            {others.map((d, i) => chip(d.id, d.name || d.id, `set-${i}`))}
          </div>
          <div className="tabs" role="tablist" aria-label="Activity" onKeyDown={onTabKey}>
            {TABS.map((t) => (
              <button
                key={t.id}
                type="button"
                role="tab"
                id={`activity-tab-${t.id}`}
                aria-selected={shown === t.id}
                aria-controls="activity-panel"
                tabIndex={shown === t.id ? 0 : -1}
                disabled={!enabled(t.id)}
                title={enabled(t.id) ? undefined : "Pick a data source"}
                onClick={() => setTab(t.id)}
              >
                {t.label}
              </button>
            ))}
          </div>
        </div>
        {error && <ErrorLine error={error} />}
        {/* key: another source or tab unmounts the panel, so a reveal never carries over (plan R17). */}
        <div
          key={`${dataset ?? ""}:${shown}`}
          role="tabpanel"
          id="activity-panel"
          aria-labelledby={`activity-tab-${shown}`}
        >
          {shown === "records" && (
            <Records
              dataset={dataset}
              source={source}
              selected={sel.record}
              onSelect={(record) => setSel((s) => ({ ...s, record }))}
              onOpenEntry={openEntry}
            />
          )}
          {shown === "journal" && dataset && (
            <Journal
              dataset={dataset}
              selected={sel.entry}
              onSelect={(entry) => setSel((s) => ({ ...s, entry }))}
              onOpenRecord={openRecord}
            />
          )}
          {/* The chat source keeps no entities: its tab explains that and asks the service nothing. */}
          {shown === "entities" && dataset === CHAT_DATASET && <ChatEntities onShowRecords={() => setTab("records")} />}
          {shown === "entities" && dataset && dataset !== CHAT_DATASET && (
            <Entities dataset={dataset} source={source(dataset)} />
          )}
        </div>
      </ViewBody>
    </section>
  );
}
