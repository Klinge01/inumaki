import { useCallback, useEffect, useState } from "react";
import * as ipc from "../ipc";
import type { BackupRow, CmdError, Measured, SettingsView } from "../types";
import { ErrorLine } from "../components/ErrorLine";
import { Toolbar, ViewBody } from "../components/Toolbar";
import { NotAvailable } from "../components/NotAvailable";
import { Confirm } from "../components/Confirm";
import { Notice } from "../components/Notice";
import { Skeleton } from "../components/Skeleton";
import { HARNESS_NAME } from "../harnessText";
import { ServiceSection } from "./settings/ServiceSection";
import { ModelsSection } from "./settings/ModelsSection";
import { Group, Row } from "./settings/Group";

/** Unix seconds (null, 0, or garbage is "unknown"). */
function when(secs: number | null, style: "date" | "datetime"): string {
  if (secs === null || !Number.isFinite(secs) || secs <= 0) return "unknown";
  const d = new Date(secs * 1000);
  if (Number.isNaN(d.getTime())) return "unknown";
  return new Intl.DateTimeFormat(undefined, style === "date" ? { dateStyle: "medium" } : { dateStyle: "medium", timeStyle: "short" }).format(d);
}

const share = (n: number, docs: number) => `${n} of ${docs} (${((100 * n) / Math.max(1, docs)).toFixed(1)} %)`;

function MeasuredTable({ rows }: { rows: Measured[] }) {
  if (rows.length === 0) return <Row label="No measured numbers in this build." />;
  return (
    <table className="grid">
      <thead>
        <tr>
          <th>Profile</th>
          <th>Passed with a leak</th>
          <th>Accepted with a leak</th>
          <th>p50 / p95</th>
          <th>Measured</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((m) => (
          <tr key={m.profile}>
            <td>{m.profile}</td>
            <td>{share(m.leak_docs, m.docs)}</td>
            <td>{share(m.accepted_leak_docs, m.docs)}</td>
            <td>
              {m.p50_ms.toFixed(1)} / {m.p95_ms.toFixed(1)} ms
            </td>
            <td className="muted">
              {when(m.evaluated_at, "date")}, {m.platform}, {m.commit.slice(0, 7)}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/** The backup's date, or "Date unknown" when its id carries no readable time. */
const backupDate = (b: BackupRow) => {
  const d = when(b.backup.created_at, "datetime");
  return d === "unknown" ? "Date unknown" : d;
};

const harnessName = (id: string) => (id in HARNESS_NAME ? HARNESS_NAME[id as keyof typeof HARNESS_NAME] : id);

export function Settings() {
  const [s, setS] = useState<SettingsView | null>(null);
  // A failed load and a failed action are kept apart: a reload never clears the action's error.
  const [loadError, setLoadError] = useState<CmdError | null>(null);
  const [actionError, setActionError] = useState<CmdError | null>(null);
  const [busy, setBusy] = useState(false);
  // The backup the delete sheet asks about.
  const [deleting, setDeleting] = useState<BackupRow | null>(null);
  const load = useCallback(
    () =>
      ipc.settings().then(
        (v) => {
          setLoadError(null);
          setS(v);
        },
        (e) => setLoadError(ipc.asCmdError(e)),
      ),
    [],
  );
  useEffect(() => {
    void load();
  }, [load]);
  // The reload that follows re-reads the truth (the backup list), also after a failure.
  const run = async (f: () => Promise<void>) => {
    setActionError(null);
    setBusy(true);
    try {
      await f();
    } catch (e) {
      setActionError(ipc.asCmdError(e));
    } finally {
      setBusy(false);
      await load();
    }
  };
  // Busy, or the last read failed: the rows show what was read before and must not be acted on.
  const stale = busy || loadError !== null;
  return (
    <section>
      <Toolbar
        title="Settings"
        actions={
          <button
            type="button"
            disabled={busy}
            onClick={() => {
              setActionError(null);
              void load();
            }}
          >
            Refresh
          </button>
        }
      />
      <ViewBody>
        <div className="settings-col">
          <ServiceSection />
          <ModelsSection />
          {loadError && ipc.isNotAvailable(loadError) && <NotAvailable what="The rest of Settings" />}
          {s && loadError && !ipc.isNotAvailable(loadError) && (
            <Notice role="status">
              The last read failed; what is shown below may be out of date and cannot be changed until Refresh succeeds.
            </Notice>
          )}
          {!s && !loadError && (
            <div className="box">
              <Skeleton lines={4} />
            </div>
          )}
          {s && (
            <>
              <Group title="Profiles">
                {s.profiles.length === 0 && <Row label="No profiles reported." />}
                {s.profiles.map((p) => (
                  <Row
                    key={p.name}
                    label={<span className="set-name">{p.name}</span>}
                    sub={p.available ? null : p.reason || null}
                    end={<span className="chip">{p.available ? "Available" : "Unavailable"}</span>}
                  />
                ))}
              </Group>
              <Group
                title="Configuration backups"
                foot={<p>A backup can hold an MCP server&apos;s credentials from before you protected it. Delete the ones you don&apos;t need.</p>}
              >
                {s.backups.length === 0 && <Row label="No backups." />}
                {s.backups.map((b) => (
                  <Row
                    key={`${b.harness}/${b.backup.id}`}
                    label={harnessName(b.harness)}
                    sub={backupDate(b)}
                    end={
                      b.live ? (
                        <span className="chip">Used by Revert</span>
                      ) : (
                        <button type="button" className="danger" disabled={stale} onClick={() => setDeleting(b)}>
                          Delete…
                        </button>
                      )
                    }
                  />
                ))}
              </Group>
              <Group title="About">
                <Row
                  label={`inumaki ${s.version}`}
                  sub="Experimental. Quality and latency are measured on synthetic data, not qualified."
                  end={<span className="chip amber">Experimental</span>}
                />
                <MeasuredTable rows={s.measured} />
                <Row label="App log" sub={<span className="mono">{s.app_log}</span>} />
                <Row label="Updates" sub={s.updates} />
              </Group>
            </>
          )}
          {actionError && <ErrorLine error={actionError} />}
          {loadError && !ipc.isNotAvailable(loadError) && <ErrorLine error={loadError} />}
        </div>
      </ViewBody>
      {deleting && (
        <Confirm
          title="Delete this backup?"
          verb="Delete"
          text={`The ${harnessName(deleting.harness)} configuration backup${backupDate(deleting) !== "Date unknown" ? ` from ${backupDate(deleting)}` : ""} is deleted for good.`}
          onYes={() => {
            const b = deleting;
            setDeleting(null);
            void run(() => ipc.deleteBackup(b.harness, b.backup.id));
          }}
          onNo={() => setDeleting(null)}
        />
      )}
    </section>
  );
}
