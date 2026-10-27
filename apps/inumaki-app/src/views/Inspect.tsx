// Inspect & recover (redesign spec section 7.5; M6 spec §6.4, M4 spec §9.1):
// nothing is fetched from an upstream and nothing is kept after the view
// unmounts. The inspect command returns the NFC text its span offsets index
// into; once inspected, the view shows, marks, and sanitizes exactly that
// string. Any change to the input (an edit, another data source, an opened
// file) drops the inspection, the marks, the result, and any reveal, and makes
// a late answer for the old input a no-op.
//
// The highlighted rendering and the marks table are derived from the
// inspection (and, while originals are visible, the reveal) at render time and
// held nowhere else, so they go whenever those are reset (plan A11). Revealed
// originals appear only in the table's revealed column inside the reveal panel;
// no original goes into an attribute, a title, or an aria-label.
import { Fragment, useEffect, useRef, useState, type ReactNode } from "react";
import * as ipc from "../ipc";
import type { CmdError, DatasetRow, InspectView, Redaction, SanitizeResponse } from "../types";
import { byteRange, nfc, utf16Index } from "../nfc";
import { useReveal } from "../reveal";
import { ErrorLine } from "../components/ErrorLine";
import { Toolbar } from "../components/Toolbar";
import { CopyButton } from "../components/CopyButton";
import { Notice } from "../components/Notice";
import { RevealPanel } from "../components/RevealPanel";
import { Payload } from "./activity/Payload";

const RECOVERY = [
  "A blocked tool result or mirrored file: paste the text here and inspect it with the same data source.",
  "Mark what must be tokenized or removed, then sanitize with those redactions.",
  "Copy the result and give it to the agent yourself; nothing is fetched or kept here.",
  "A draft with status unknown: check the mailbox's drafts folder before asking the agent to write it again.",
];

const KINDS = ["PERSON", "ORG", "STREET_ADDRESS", "EMAIL", "PHONE", "IBAN", "CUSTOMER_ID", "CONTRACT_ID", "OTHER"];

const OUTCOME: Record<string, string> = { pass: "Passed", pass_uncertain: "Uncertain", blocked: "Blocked" };
/** An outcome in words; an unknown outcome reads as sent. */
const outcomeWord = (o: string) => OUTCOME[o] ?? o;

// Plan R20: the detector that found a span, in words; anything else reads as sent.
const SOURCE: Record<string, string> = {
  Redaction: "Your mark",
  Ner: "Name model",
  Anchor: "Name model",
  RegexValidated: "Pattern",
  RegexSyntax: "Pattern",
  Dictionary: "Known list",
  Domain: "Domain rule",
  Secrets: "Secret scanner",
  Link: "Linked mention",
};

/** A verifier reason in words (kind and check only; a reason never carries text). */
function reasonWords(r: { kind: string; check: string }): string {
  const a = /^[AEIOU]/.test(r.kind) ? "an" : "a";
  switch (r.check) {
    case "Leak":
      return `Leak check found ${a} ${r.kind} value still in the sanitized text.`;
    case "Regex":
      return `Pattern re-scan found ${a} ${r.kind} the first pass missed.`;
    case "Ner":
      return `Name re-scan found ${a} ${r.kind} the first pass missed.`;
    case "Combination":
      return `Combination check found several kept details (${a} ${r.kind} among them) in one sentence that together could identify someone.`;
    case "Policy":
      return `Policy asks for a review of ${a} ${r.kind}.`;
    case "DetectorError":
      return "A detector failed, so the text could not be examined.";
    default:
      return `${r.check} (${r.kind})`;
  }
}

/** One row of the marks table and one highlight: offsets are UTF-16 indexes into the shown text. */
type Row = {
  n: number;
  from: number;
  to: number;
  kind: string;
  action: string;
  source: string;
  /** Index into `marks` for the user's own marks, null for found spans. */
  mark: number | null;
  /** Only while revealed, and only shown in the revealed column. */
  original?: string;
};

/**
 * The inspected text, read-only, with each row's range highlighted and numbered. Text goes in as
 * React text nodes only (never HTML); nothing about the text goes into an attribute.
 */
function Highlighted({ text, rows }: { text: string; rows: Row[] }) {
  const ranges = rows.filter((r) => r.from < r.to);
  const cuts = [...new Set([0, text.length, ...ranges.flatMap((r) => [r.from, r.to])])].sort((x, y) => x - y);
  const out: ReactNode[] = [];
  for (let i = 0; i + 1 < cuts.length; i += 1) {
    const [a, b] = [cuts[i], cuts[i + 1]];
    const cover = ranges.filter((r) => r.from <= a && r.to >= b);
    const seg = text.slice(a, b);
    out.push(
      cover.length === 0 ? (
        <Fragment key={`t${a}`}>{seg}</Fragment>
      ) : (
        <mark key={`t${a}`} className={cover.some((r) => r.mark !== null) ? "hl mine" : "hl found"}>
          {seg}
        </mark>
      ),
    );
    for (const r of ranges.filter((x) => x.to === b)) {
      out.push(
        <sup key={`n${r.n}`} className="hl-n">
          {r.n}
        </sup>,
      );
    }
  }
  return (
    <div className="hl-text" role="region" aria-label="Inspected text">
      {out}
    </div>
  );
}

export function Inspect() {
  const [sets, setSets] = useState<DatasetRow[]>([]);
  const [dataset, setDataset] = useState("");
  const [text, setText] = useState("");
  const [inspected, setInspected] = useState<InspectView | null>(null);
  const [marks, setMarks] = useState<Redaction[]>([]);
  const [kind, setKind] = useState("PERSON");
  const [result, setResult] = useState<SanitizeResponse | null>(null);
  const [error, setError] = useState<CmdError | null>(null);
  const reveal = useReveal<InspectView>();
  const area = useRef<HTMLTextAreaElement>(null);
  // Bumped on every input change; an answer for an older input is dropped.
  const input = useRef(0);

  useEffect(() => {
    ipc.datasets().then(
      (d) => {
        setSets(d);
        if (d[0]) setDataset((cur) => cur || d[0].id);
      },
      (e) => setError(ipc.asCmdError(e)),
    );
  }, []);

  /** The input changed: everything derived from the old one goes. */
  const reset = () => {
    input.current += 1;
    setInspected(null);
    setMarks([]);
    setResult(null);
    setError(null);
    reveal.clear();
  };
  /** Runs `f` for the current input; its answer is applied only if the input is still the same. */
  const run = async (f: (current: () => boolean) => Promise<void>) => {
    setError(null);
    const asked = input.current;
    const current = () => asked === input.current;
    try {
      await f(current);
    } catch (e) {
      if (current()) setError(ipc.asCmdError(e));
    }
  };

  const inspect = () =>
    run(async (current) => {
      const v = await ipc.inspectText(dataset, text, false);
      if (!current()) return;
      reset();
      // Show and slice the daemon's own NFC text from here on.
      setText(v.text);
      setInspected(v);
    });
  const showValues = (v: InspectView) =>
    run(async () => {
      await reveal.request(async () => {
        const r = await ipc.inspectText(dataset, v.text, true);
        if (r.text !== v.text) throw { kind: "bad_response", status: null, kinds: [] };
        return r;
      });
    });
  const mark = (action: "tokenize" | "remove") => {
    const el = area.current;
    if (!el || !inspected || el.value !== inspected.text || el.selectionStart === el.selectionEnd) return;
    const r = byteRange(inspected.text, el.selectionStart, el.selectionEnd);
    setMarks([...marks, { ...r, kind, action }]);
  };
  const sanitize = (v: InspectView) =>
    run(async (current) => {
      const r = await ipc.sanitizeWith(dataset, v.text, marks);
      if (current()) setResult(r);
    });

  const revealed = reveal.value !== null;
  const shown = reveal.value ?? inspected;
  const rows: Row[] = [];
  if (shown) {
    const at = (b: number) => utf16Index(shown.text, b);
    for (const s of shown.body.spans) {
      rows.push({
        n: rows.length + 1,
        from: at(s.start),
        to: at(s.end),
        kind: s.kind,
        action: s.action,
        source: SOURCE[s.source] ?? s.source,
        mark: null,
        original: revealed ? s.original : undefined,
      });
    }
    marks.forEach((m, i) =>
      rows.push({
        n: rows.length + 1,
        from: at(m.start),
        to: at(m.end),
        kind: m.kind,
        action: m.action,
        source: "Your mark",
        mark: i,
      }),
    );
  }

  const table = (
    <table className="grid">
      <thead>
        <tr>
          <th>#</th>
          <th>Kind</th>
          <th>Action</th>
          <th>Source</th>
          {revealed && <th>Original</th>}
          <th>
            <span className="sr-only">Actions</span>
          </th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.n}>
            <td className="num">{r.n}</td>
            <td>{r.kind}</td>
            <td>{r.action}</td>
            <td>
              {r.source}
              <span className="row-sub">{`${r.to - r.from} chars at ${r.from}`}</span>
            </td>
            {revealed && <td className="revealed">{r.original ?? ""}</td>}
            <td className="actions">
              {r.mark !== null && (
                <button
                  type="button"
                  className="sm"
                  onClick={() => {
                    const drop = r.mark;
                    setMarks(marks.filter((_, j) => j !== drop));
                  }}
                >
                  Remove
                </button>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );

  const actions = (
    <>
      {/* Options are keyed and valued by index: the dataset slug never goes into the DOM. */}
      <select
        aria-label="Data source"
        value={String(sets.findIndex((d) => d.id === dataset))}
        onChange={(e) => {
          const id = sets[Number(e.target.value)]?.id;
          if (id === undefined) return;
          reset();
          setDataset(id);
        }}
      >
        {sets.map((d, i) => (
          <option key={i} value={String(i)}>
            {d.name}
          </option>
        ))}
      </select>
      <button
        type="button"
        onClick={() =>
          run(async (current) => {
            const t = await ipc.openTextFile();
            if (t === null || !current()) return;
            reset();
            setText(nfc(t));
          })
        }
      >
        Open a file…
      </button>
    </>
  );

  return (
    <section>
      <Toolbar title="Inspect & recover" actions={actions} />
      <div className="cols">
        <div className="view inspect-main">
          {error && <ErrorLine error={error} />}
          {shown && inspected && (
            <Notice
              kind={shown.body.outcome === "pass" ? undefined : "amber"}
              title={`${outcomeWord(shown.body.outcome)} with ${shown.body.profile}${shown.body.retried ? ", after one retry." : ""}`}
              action={
                <button type="button" className="sm" onClick={() => void showValues(inspected)}>
                  Show values
                </button>
              }
            >
              <>
                {shown.body.reasons.map((r, i) => (
                  <p key={i}>{reasonWords(r)}</p>
                ))}
                {shown.body.limitations.map((l) => (
                  <p key={l}>{l}</p>
                ))}
                <p className="strip-label">{shown.body.label}</p>
              </>
            </Notice>
          )}
          {shown && (
            <>
              <Highlighted text={shown.text} rows={rows} />
              <p className="legend">
                <span>
                  <mark className="hl found">Found</mark>
                </span>
                <span>
                  <mark className="hl mine">Your mark</mark>
                </span>
                <span>Numbers match the rows under Marks.</span>
              </p>
            </>
          )}
          <textarea
            ref={area}
            aria-label="Text to inspect"
            rows={10}
            value={text}
            onChange={(e) => {
              reset();
              setText(e.target.value);
            }}
          />
          <div className="actions">
            <button type="button" disabled={!dataset || !text} onClick={() => void inspect()}>
              Inspect
            </button>
          </div>
          {inspected && (
            <div className="box marks">
              <div className="box-head">
                <h3>Marks</h3>
                <span className="muted">{`${marks.length} marked`}</span>
                <div className="head-end marks-tools">
                  <select aria-label="Kind" value={kind} onChange={(e) => setKind(e.target.value)}>
                    {KINDS.map((k) => (
                      <option key={k} value={k}>
                        {k}
                      </option>
                    ))}
                  </select>
                  <button type="button" className="sm" onClick={() => mark("tokenize")}>
                    Tokenize selection
                  </button>
                  <button type="button" className="sm" onClick={() => mark("remove")}>
                    Remove selection
                  </button>
                </div>
              </div>
              {revealed ? (
                <RevealPanel reveal={reveal}>{rows.length > 0 && table}</RevealPanel>
              ) : rows.length > 0 ? (
                table
              ) : (
                <p className="muted box-pad">Nothing found or marked. Select text in the box above to mark it.</p>
              )}
              <div className="box-foot marks-foot">
                <button type="button" className="primary" onClick={() => void sanitize(inspected)}>
                  Sanitize with these redactions
                </button>
              </div>
            </div>
          )}
          {result && (
            <div className="box result">
              <div className="box-head">
                <h3>{`${outcomeWord(result.outcome)}, ${result.replacements} replacements`}</h3>
                <span className="head-end">
                  <CopyButton text={result.text} />
                </span>
              </div>
              {/* Token chips for the eye; screen readers read the text once, as plain text. */}
              <div className="box-pad" aria-hidden="true">
                <Payload text={result.text} />
              </div>
              <p className="sr-only">{result.text}</p>
            </div>
          )}
        </div>
        <aside className="side">
          <section className="side-section" aria-labelledby="inspect-recovery">
            <h4 id="inspect-recovery">Recovering a blocked read</h4>
            <p className="side-sub">Nothing here goes to an AI provider or is kept after you leave.</p>
            <ol className="recovery">
              {RECOVERY.map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ol>
            {shown && (
              <p className="side-line">
                {`Tokens rotate every ${shown.body.expiry.rotation_days} days, with ${shown.body.expiry.grace_days} days of grace.`}
              </p>
            )}
          </section>
        </aside>
      </div>
    </section>
  );
}
