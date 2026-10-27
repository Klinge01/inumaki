import { useCallback, useEffect, useId, useRef, useState } from "react";
import * as ipc from "../ipc";
import type { CmdError, DataChange, MailboxCard, MailboxCheck, MailboxPreset } from "../types";
import { ErrorLine } from "../components/ErrorLine";
import { Toolbar, ViewBody } from "../components/Toolbar";
import { NotAvailable } from "../components/NotAvailable";
import { Confirm } from "../components/Confirm";
import { DataChangeNote } from "../components/DataChangeNote";
import { Skeleton } from "../components/Skeleton";
import { useWindowHidden } from "../useWindowHidden";

const validPort = (p: string) => /^\d+$/.test(p) && Number(p) >= 1 && Number(p) <= 65535;

type Heading = "h3" | "h4";

const PRESETS: { id: MailboxPreset; label: string }[] = [
  { id: "gmail", label: "Gmail" },
  { id: "outlook", label: "Outlook" },
  { id: "generic", label: "Other IMAP server" },
];
const presetLabel = (p: MailboxPreset) => PRESETS.find((x) => x.id === p)?.label ?? p;

function MailIcon() {
  // Decorative inline SVG: the mailbox name carries the meaning.
  return (
    <svg width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
      <rect x="2" y="4" width="14" height="10" rx="1.5" />
      <path d="m2.5 5 6.5 5 6.5-5" strokeLinejoin="round" />
    </svg>
  );
}

/** The segmented control of the Add form: a radio group of buttons, with arrow-key movement. */
function ProviderChoice({ value, onChange }: { value: MailboxPreset; onChange: (p: MailboxPreset) => void }) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const move = (from: number, step: number) => {
    const i = (from + step + PRESETS.length) % PRESETS.length;
    onChange(PRESETS[i].id);
    refs.current[i]?.focus();
  };
  return (
    <div className="segmented" role="radiogroup" aria-label="Mail provider">
      {PRESETS.map((p, i) => (
        <button
          key={p.id}
          ref={(el) => {
            refs.current[i] = el;
          }}
          type="button"
          role="radio"
          aria-checked={value === p.id}
          tabIndex={value === p.id ? 0 : -1}
          onClick={() => onChange(p.id)}
          onKeyDown={(e) => {
            if (e.key === "ArrowRight" || e.key === "ArrowDown") {
              e.preventDefault();
              move(i, 1);
            } else if (e.key === "ArrowLeft" || e.key === "ArrowUp") {
              e.preventDefault();
              move(i, -1);
            }
          }}
        >
          {p.label}
        </button>
      ))}
    </div>
  );
}

function AddForm({
  H,
  busy,
  onStart,
  onAdded,
  onDone,
}: {
  H: Heading;
  busy: boolean;
  onStart: () => void;
  onAdded: (c: DataChange) => void;
  onDone: () => void;
}) {
  const ids = useId();
  const [preset, setPreset] = useState<MailboxPreset>("gmail");
  const [username, setUsername] = useState("");
  // The app password lives only in the input element (an uncontrolled field, so React never mirrors
  // it into the DOM `value` attribute): the state holds a boolean for the button. It is read once at
  // submit and blanked before the request is awaited, on failure, and when the window hides.
  const pwRef = useRef<HTMLInputElement>(null);
  const [hasValue, setHasValue] = useState(false);
  const [host, setHost] = useState("");
  const [port, setPort] = useState("993");
  const [name, setName] = useState("");
  const [error, setError] = useState<CmdError | null>(null);
  const [helpError, setHelpError] = useState<CmdError | null>(null);
  const clearPassword = () => {
    if (pwRef.current) pwRef.current.value = "";
    setHasValue(false);
  };
  useWindowHidden(clearPassword);
  const generic = preset === "generic";
  const ready = username !== "" && hasValue && (!generic || (host !== "" && validPort(port)));
  const submit = async () => {
    const pw = pwRef.current?.value ?? "";
    if (pw === "") return;
    onStart();
    setError(null);
    clearPassword();
    try {
      const r = await ipc.addMailbox({
        preset,
        username,
        password: pw,
        display_name: name || username,
        ...(generic ? { imap_host: host, imap_port: Number(port) } : {}),
      });
      setUsername("");
      setName("");
      onAdded({ reconnect_failures: r.reconnect_failures, failed_harnesses: r.failed_harnesses });
    } catch (e) {
      clearPassword();
      setError(ipc.asCmdError(e));
    } finally {
      onDone();
    }
  };
  return (
    <section className="card add-mailbox">
      <H>Add a mailbox</H>
      <p className="muted">inumaki reads mail and writes drafts. It never sends mail.</p>
      <ProviderChoice value={preset} onChange={setPreset} />
      <div className="form-grid">
        <div className="field">
          <label htmlFor={`${ids}-user`}>Username</label>
          <input id={`${ids}-user`} autoComplete="off" value={username} onChange={(e) => setUsername(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor={`${ids}-pw`}>App password</label>
          <input
            id={`${ids}-pw`}
            ref={pwRef}
            type="password"
            autoComplete="off"
            onChange={(e) => setHasValue(e.target.value !== "")}
          />
        </div>
        {generic && (
          <>
            <div className="field">
              <label htmlFor={`${ids}-host`}>IMAP host</label>
              <input id={`${ids}-host`} value={host} onChange={(e) => setHost(e.target.value)} />
            </div>
            <div className="field">
              <label htmlFor={`${ids}-port`}>Port</label>
              <input id={`${ids}-port`} inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value)} />
            </div>
          </>
        )}
        <div className="field">
          <label htmlFor={`${ids}-name`}>Name in inumaki (only you see it)</label>
          <input id={`${ids}-name`} value={name} onChange={(e) => setName(e.target.value)} />
        </div>
      </div>
      <div className="form-actions">
        {!generic && (
          <button
            type="button"
            className="text"
            onClick={() => {
              setHelpError(null);
              ipc.openMailHelp(preset).catch((e) => setHelpError(ipc.asCmdError(e)));
            }}
          >
            How do I get an app password?
          </button>
        )}
        <button type="button" className="primary" disabled={!ready || busy} onClick={() => void submit()}>
          Add mailbox
        </button>
      </div>
      {helpError && <ErrorLine error={helpError} />}
      {error && <ErrorLine error={error} />}
    </section>
  );
}

function draftsFolderText(check: MailboxCheck): string {
  const folders = `${check.folders} ${check.folders === 1 ? "folder" : "folders"}`;
  const drafts = check.drafts_folder_resolved ? "found" : check.drafts_folder_will_be_created ? "will be created" : "not found";
  return `${folders}, drafts folder ${drafts}`;
}

function Card({
  c,
  H,
  busy,
  onStart,
  onRemoved,
  onDone,
}: {
  c: MailboxCard;
  H: Heading;
  busy: boolean;
  onStart: () => void;
  onRemoved: (c: DataChange) => void;
  onDone: () => void;
}) {
  const [check, setCheck] = useState<MailboxCheck | null>(null);
  // Uncontrolled, like the Add field: the typed password is never in state or in a DOM attribute.
  const pwRef = useRef<HTMLInputElement>(null);
  const [hasValue, setHasValue] = useState(false);
  const [replacing, setReplacing] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<CmdError | null>(null);
  const clearPassword = () => {
    if (pwRef.current) pwRef.current.value = "";
    setHasValue(false);
  };
  useWindowHidden(clearPassword);
  const run = async (f: () => Promise<void>) => {
    onStart();
    setError(null);
    setNote(null);
    try {
      await f();
    } catch (e) {
      setError(ipc.asCmdError(e));
    } finally {
      onDone();
    }
  };
  const replace = () => {
    const p = pwRef.current?.value ?? "";
    if (p === "") return;
    clearPassword();
    void run(async () => {
      try {
        await ipc.replaceMailboxPassword(c.dataset, p);
      } catch (e) {
        clearPassword();
        throw e;
      }
      setReplacing(false);
      setNote("Password replaced.");
    });
  };
  const m = c.mailbox;
  return (
    <section className="box mailbox">
      <div className="box-head mailbox-head">
        <span className="mailbox-icon">
          <MailIcon />
        </span>
        <div className="mailbox-title">
          <H>{c.display_name}</H>
          <p className="muted">
            Agents see it as <span className="token">{c.entry_name}</span>
          </p>
        </div>
        <span className="chip accent">Reads and drafts, never sends</span>
        <button
          type="button"
          disabled={busy}
          onClick={() =>
            void run(async () => {
              setCheck(null);
              setCheck(await ipc.checkMailbox(c.dataset));
            })
          }
        >
          Check
        </button>
      </div>
      <div className="mailbox-body">
        {m ? (
          <dl className="dl">
            <dt>Provider</dt>
            <dd>{`${presetLabel(m.preset)}, ${m.imap_host}:${m.imap_port}`}</dd>
            <dt>Account</dt>
            <dd>{m.username}</dd>
            <dt>Handles</dt>
            <dd>{`${m.handles.toLocaleString()} ${m.handles === 1 ? "message" : "messages"}`}</dd>
            <dt>Last check</dt>
            {/* "in this session": a check from an earlier session is not remembered. */}
            <dd aria-live="polite">{check ? draftsFolderText(check) : "Not checked in this session"}</dd>
          </dl>
        ) : (
          <>
            <p className="muted">The mailbox settings could not be read.</p>
            {check && <p role="status">{`Last check: ${draftsFolderText(check)}`}</p>}
          </>
        )}
        {replacing && (
          <div className="replace-row">
            <input
              ref={pwRef}
              type="password"
              aria-label="New app password"
              autoComplete="off"
              placeholder="New app password"
              onChange={(e) => setHasValue(e.target.value !== "")}
            />
            <button type="button" className="primary" disabled={!hasValue || busy} onClick={replace}>
              Replace password
            </button>
            <button
              type="button"
              className="text"
              disabled={busy}
              onClick={() => {
                clearPassword();
                setReplacing(false);
              }}
            >
              Cancel
            </button>
          </div>
        )}
        <div className="actions">
          {!replacing && (
            <button type="button" disabled={busy} onClick={() => setReplacing(true)}>
              Replace app password…
            </button>
          )}
          <button type="button" className="danger" disabled={busy} onClick={() => setConfirm(true)}>
            Remove…
          </button>
        </div>
        {note && <p role="status">{note}</p>}
        {error && <ErrorLine error={error} />}
      </div>
      {confirm && (
        <Confirm
          verb="Remove"
          text="Remove this mailbox from inumaki? Your mail is not touched."
          onYes={() => {
            setConfirm(false);
            void run(async () => onRemoved(await ipc.removeMailbox(c.dataset)));
          }}
          onNo={() => setConfirm(false)}
        />
      )}
    </section>
  );
}

export function Email({ embedded = false }: { embedded?: boolean }) {
  const CardH: Heading = embedded ? "h4" : "h3";
  const [cards, setCards] = useState<MailboxCard[] | null>(null);
  // A failed load and a failed action are kept apart: a reload never clears the
  // action's error (the user must see it), and a good reload clears the load's.
  const [loadError, setLoadError] = useState<CmdError | null>(null);
  const [change, setChange] = useState<DataChange | null>(null);
  const [busy, setBusy] = useState(false);
  const load = useCallback(
    () =>
      ipc.mailboxes().then(
        (c) => {
          setLoadError(null);
          setCards(c);
        },
        (e) => setLoadError(ipc.asCmdError(e)),
      ),
    [],
  );
  useEffect(() => {
    void load();
  }, [load]);
  const start = () => {
    setChange(null);
    setBusy(true);
  };
  const done = () => {
    setBusy(false);
    void load();
  };
  if (loadError && ipc.isNotAvailable(loadError)) {
    return (
      <section>
        <Toolbar title="Email" embedded={embedded} />
        <ViewBody embedded={embedded}>
          <NotAvailable what="Email" />
        </ViewBody>
      </section>
    );
  }
  return (
    <section>
      <Toolbar
        title="Email"
        embedded={embedded}
        actions={
          <button type="button" disabled={busy} onClick={() => void load()}>
            Refresh
          </button>
        }
      />
      <ViewBody embedded={embedded}>
        <DataChangeNote change={change} />
        {!cards && !loadError && (
          <div className="box">
            <Skeleton lines={3} />
          </div>
        )}
        {cards?.length === 0 && <p className="muted">No mailbox yet.</p>}
        {cards?.map((c) => (
          <Card key={c.dataset} c={c} H={CardH} busy={busy} onStart={start} onRemoved={setChange} onDone={done} />
        ))}
        <AddForm H={CardH} busy={busy} onStart={start} onAdded={setChange} onDone={done} />
        {loadError && <ErrorLine error={loadError} />}
      </ViewBody>
    </section>
  );
}
