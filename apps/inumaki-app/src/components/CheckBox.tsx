import { useEffect, useState, type ReactNode } from "react";
import * as ipc from "../ipc";
import { useCheckRun } from "../checkRun";
import { HARNESS_NAME } from "../harnessText";
import type { CheckReport, HarnessId, PathResult, PathStatus } from "../types";
import { ErrorLine } from "./ErrorLine";
import { Glyph } from "./Glyph";
import { Notice } from "./Notice";
import { Cross, Tick } from "./PathSection";

// Fixed sentences per reason code (inumaki-client PathReason).
const REASON: Record<string, string> = {
  mirror_unavailable: "folders are not available yet",
  proxy_unavailable: "chat protection is not available yet",
  chat_not_routed: "chat text was not checked: this harness did not use the inumaki route",
  canary_in_upstream: "a test value reached the model side in clear",
  no_tokens: "no tokens where tokens were expected",
  not_rehydrated: "the answer did not get the test values back",
  timeout: "a step took too long",
  harness_failed: "the harness run failed",
};

/** "Passed" (tick), "Failed" (x), or "Not checked" (`off` ring). */
export function CheckResult({ status }: { status: PathStatus | null }) {
  if (status === "passed") {
    return (
      <span className="res pass">
        <Tick /> Passed
      </span>
    );
  }
  if (status === "failed") {
    return (
      <span className="res fail">
        <Cross /> Failed
      </span>
    );
  }
  return (
    <span className="res">
      <Glyph tone="off" /> Not checked
    </span>
  );
}

const PATHS: ["gateway" | "mirror" | "proxy", string][] = [
  ["gateway", "MCP tools"],
  ["mirror", "Files"],
  ["proxy", "Chat"],
];

const failed = (r: CheckReport) => Object.values(r.results).some((p) => p.status === "failed");

function Result({ r }: { r: PathResult }) {
  const why = r.reason ? (REASON[r.reason] ?? r.reason) : undefined;
  return (
    <>
      <CheckResult status={r.status} />
      {why && <div className="muted">{why}</div>}
    </>
  );
}

/** "1 min 12 s". */
function elapsed(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000));
  return `${Math.floor(total / 60)} min ${total % 60} s`;
}

/**
 * The connected harnesses' names, for the running lines. The service reports no per-harness progress, so
 * these lines only say what the run covers.
 */
function useRunNames(harness: HarnessId | undefined, running: boolean): string[] | null {
  const [names, setNames] = useState<string[] | null>(null);
  useEffect(() => {
    if (!running || harness) return;
    let cancelled = false;
    ipc.overview().then(
      (v) => {
        if (!cancelled) setNames(v.cards.filter((c) => c.connected && !c.disconnected).map((c) => c.name));
      },
      () => {
        if (!cancelled) setNames([]);
      },
    );
    return () => {
      cancelled = true;
    };
  }, [running, harness]);
  return harness ? [HARNESS_NAME[harness]] : names;
}

function Running({ harness, startedAt }: { harness?: HarnessId; startedAt: number }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  const names = useRunNames(harness, true);
  const lines = names && names.length > 0 ? names : ["inumaki itself"];
  return (
    <>
      <ul className="check-lines">
        {lines.map((n) => (
          <li key={n}>
            <Glyph tone="unv" />
            <span className="check-name">{n}</span>
            <span className="muted">{`Running a session, ${elapsed(now - startedAt)}`}</span>
          </li>
        ))}
      </ul>
      <div className="progress indeterminate" role="progressbar" aria-label="Running the check">
        <span />
      </div>
    </>
  );
}

function Single({ report }: { report: CheckReport | undefined }) {
  if (!report) return <p className="side-line">No result for this harness in this run.</p>;
  return (
    <dl className="dl">
      {PATHS.map(([k, label]) => (
        <div key={k} className="dl-row">
          <dt>{label}</dt>
          <dd>
            <Result r={report.results[k]} />
          </dd>
        </div>
      ))}
    </dl>
  );
}

function Grid({ reports }: { reports: CheckReport[] }) {
  const rows = [...reports].sort((a, b) => Number(failed(b)) - Number(failed(a)));
  return (
    <table className="grid">
      <thead>
        <tr>
          <th>
            <span className="sr-only">Harness</span>
          </th>
          {PATHS.map(([k, label]) => (
            <th key={k}>{label}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.harness ?? "direct"}>
            <th scope="row">{r.harness ? HARNESS_NAME[r.harness] : "inumaki itself"}</th>
            {PATHS.map(([k]) => (
              <td key={k}>
                <Result r={r.results[k]} />
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/**
 * The end-to-end check (spec section 6.7), reading the shared run (plan R28). Nothing shows before a run
 * has started. While it runs, no line says "done": the service reports no per-harness progress. A "Passed"
 * is only ever a result the service reported in this run.
 */
export function CheckBox({ harness }: { harness?: HarnessId }) {
  const { running, startedAt, run, error } = useCheckRun();
  let body: ReactNode = null;
  if (running && startedAt !== null) body = <Running harness={harness} startedAt={startedAt} />;
  else if (error) body = <ErrorLine error={error} />;
  else if (run) {
    const reports = harness ? run.reports.filter((r) => r.harness === harness) : run.reports;
    body = (
      <>
        {run.warning && <Notice>{run.warning}</Notice>}
        {harness ? <Single report={reports[0]} /> : <Grid reports={reports} />}
      </>
    );
  }
  if (body === null) return null;
  return (
    <section className="box check-box" aria-label="End-to-end check">
      <div className="box-head">
        <h3>End-to-end check</h3>
        <span className="muted">Made-up test data only. Nothing goes to a real AI provider.</span>
      </div>
      <div className="check-body">{body}</div>
    </section>
  );
}
