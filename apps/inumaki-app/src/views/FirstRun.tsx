import { useMemo, useRef, useState, type ReactNode } from "react";
import { StepService } from "./firstrun/StepService";
import { StepModels } from "./firstrun/StepModels";
import { StepData } from "./firstrun/StepData";
import { StepAgents } from "./firstrun/StepAgents";
import { CheckBox } from "../components/CheckBox";
import { checkFailed, useCheckRun } from "../checkRun";

/**
 * What lets "Continue" light up:
 * - `reported`: the step's section says it is done (the service runs, the models are in);
 * - `check`: a check run finished and no path failed;
 * - `optional`: nothing reports done (data sources and agents are connected only if wanted).
 */
type Gate = "reported" | "check" | "optional";

/** `done` is the step's own "I am done" signal (see `FirstRun`). */
type Step = { id: string; title: string; intro: string; gate: Gate; body: (done: () => void) => ReactNode };

/** Step 5: made-up test data through every connected path; the run is shared with the Overview. */
function StepCheck() {
  const check = useCheckRun();
  return (
    <>
      <div className="actions">
        <button type="button" className="primary" disabled={check.running} onClick={() => void check.start()}>
          Run the check
        </button>
      </div>
      <CheckBox />
    </>
  );
}

// Spec §6.3, §7.7. Every step can be skipped and reached later from its view.
export const STEPS: Step[] = [
  {
    id: "service",
    title: "Install the service",
    intro:
      "The inumaki service does the detection and keeps the token vault on this computer. Install it to start it at login, or use one you set up another way.",
    gate: "reported",
    body: (done) => <StepService onDone={done} />,
  },
  {
    id: "models",
    title: "Download the models",
    intro:
      "The detection models find names, addresses and identifiers on this computer. The download is about 370 MB and needs the network once.",
    gate: "reported",
    body: (done) => <StepModels onDone={done} />,
  },
  {
    id: "data",
    title: "Connect your data",
    intro:
      "Email, folders and MCP servers reach your agents through inumaki, which swaps identifying details for tokens. Connect what you use; each can also be added later from its own page.",
    gate: "optional",
    body: () => <StepData />,
  },
  {
    id: "agents",
    title: "Connect your agents",
    intro:
      "Choose which agents use inumaki. Connect lists the configuration files it will change before it writes anything, and Revert restores them.",
    gate: "optional",
    body: () => <StepAgents />,
  },
  {
    id: "check",
    title: "Run the check",
    intro:
      "Sends made-up test data through every connected path. Nothing goes to a real AI provider. A run with harnesses can take a few minutes.",
    gate: "check",
    body: () => <StepCheck />,
  },
  {
    id: "later",
    title: "Later: Protected mode",
    intro:
      "Protected mode is not in this version, so it is not active and nothing is protected that way yet. It is planned as a later upgrade that runs inumaki as a separate user, so that an agent cannot go around it.",
    gate: "optional",
    body: () => null,
  },
];

function Tick() {
  return (
    <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="m3 8.5 3.2 3.2L13 4.8" />
    </svg>
  );
}

function Clock() {
  return (
    <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" aria-hidden="true">
      <circle cx="8" cy="8" r="6" />
      <path d="M8 4.8V8l2.2 1.4" />
    </svg>
  );
}

/** The 220 px step list (spec §7.7). A tick means the step reported done (or, for the check, ran clean), never skipped or merely continued past. */
function StepList({ current, completed }: { current: number; completed: ReadonlySet<string> }) {
  return (
    <nav className="fr-steps" aria-label="Setup steps">
      <ol>
        {STEPS.map((s, idx) => {
          const state = idx === current ? "current" : completed.has(s.id) ? "done" : s.id === "later" ? "later" : "todo";
          return (
            <li key={s.id} className="fr-step" data-state={state} aria-current={idx === current ? "step" : undefined}>
              <span className="fr-num" aria-hidden="true">
                {state === "done" ? <Tick /> : s.id === "later" ? <Clock /> : idx + 1}
              </span>
              <span>
                {state === "done" && <span className="sr-only">Done: </span>}
                {s.title}
              </span>
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

/** The first-run window: no app sidebar, a step list beside one step at a time. */
export function FirstRun({ onFinish }: { onFinish: () => void }) {
  const [i, setI] = useState(0);
  const [completed, setCompleted] = useState<ReadonlySet<string>>(new Set());
  const check = useCheckRun();
  // A step's `done` advances only the first time it fires: the service and
  // model sections report "done" again on every mount, and Back must stay
  // on the step the user went back to. Stable callbacks, since the sections
  // re-run their loaders when `onDone` changes.
  const advanced = useRef(new Set<string>());
  const markDone = (id: string) =>
    setCompleted((cur) => (cur.has(id) ? cur : new Set(cur).add(id)));
  const done = useMemo(
    () =>
      STEPS.map((s, idx) => () => {
        markDone(s.id);
        if (advanced.current.has(s.id)) return;
        advanced.current.add(s.id);
        setI((cur) => (cur === idx ? idx + 1 : cur));
      }),
    [],
  );
  // A step left by hand never advances by itself afterwards (its loader
  // may still report "done" after Back, and must not jump forward).
  const leave = (to: number) => {
    advanced.current.add(STEPS[i].id);
    setI(to);
  };
  const step = STEPS[i];
  const last = i === STEPS.length - 1;
  const ready =
    step.gate === "optional" ||
    (step.gate === "reported" && completed.has(step.id)) ||
    (step.gate === "check" && !check.running && check.run !== null && !checkFailed(check));
  return (
    <div className="firstrun">
      <StepList current={i} completed={completed} />
      <main className="main fr-main">
        <div className="scroll fr-scroll">
          <div className="fr-content">
            <h2 className="fr-title">{step.title}</h2>
            <p className="fr-intro">{step.intro}</p>
            {/* key: each step mounts fresh, so its loaders run again when it is revisited. */}
            <div key={step.id}>{step.body(done[i])}</div>
          </div>
        </div>
        <footer className="fr-foot">
          {i > 0 ? (
            <button type="button" className="text" onClick={() => leave(i - 1)}>
              Back
            </button>
          ) : (
            <span />
          )}
          <div className="actions">
            {!last && (
              <button type="button" className="text" onClick={() => leave(i + 1)}>
                Skip this step
              </button>
            )}
            {last ? (
              <button type="button" className="primary" onClick={onFinish}>
                Finish
              </button>
            ) : (
              <button
                type="button"
                className="primary"
                disabled={!ready}
                onClick={() => {
                  // Optional steps report nothing, so Continue must not tick them.
                  if (step.gate !== "optional") markDone(step.id);
                  leave(i + 1);
                }}
              >
                Continue
              </button>
            )}
          </div>
        </footer>
      </main>
    </div>
  );
}
