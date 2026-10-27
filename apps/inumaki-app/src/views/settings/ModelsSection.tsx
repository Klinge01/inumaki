import { useEffect, useRef, useState } from "react";
import { asCmdError, isNotAvailable, modelsPullPoll, modelsPullStart, type CmdError } from "../../ipc";
import type { ModelsJob, ModelsPoll } from "../../types";
import { ErrorLine } from "../../components/ErrorLine";
import { Skeleton } from "../../components/Skeleton";
import { Group, Row } from "./Group";

const JOB_ERROR: Record<NonNullable<ModelsJob["error"]>, string> = {
  network: "the network failed",
  hash_mismatch: "a downloaded file did not match its pinned checksum",
  disk: "the disk is full or not writable",
  manifest: "the model list could not be read",
};

// The app restarts only a service it installed; anything else gets a hint.
const RESTART_HINT: Record<string, string> = {
  homebrew: "Run brew services restart inumaki to load the models.",
  deb: "Run systemctl --user restart inumakid to load the models.",
  manual: "Restart inumakid to load the models.",
};

export function ModelsSection({ onDone }: { onDone?: () => void }) {
  const [poll, setPoll] = useState<ModelsPoll | null>(null);
  const [error, setError] = useState<CmdError | null>(null);
  // Bumped by Download: restarts the poll loop.
  const [round, setRound] = useState(0);
  const onDoneRef = useRef(onDone);
  useEffect(() => {
    onDoneRef.current = onDone;
  }, [onDone]);
  useEffect(() => {
    let stopped = false;
    let timer: number | undefined;
    const tick = async () => {
      try {
        const p = await modelsPullPoll();
        if (stopped) return;
        setPoll(p);
        setError(null);
        if (p.job.state === "running") {
          timer = window.setTimeout(() => void tick(), 1000);
        } else if (p.job.state === "done") {
          onDoneRef.current?.();
        }
      } catch (e) {
        if (!stopped) setError(asCmdError(e));
      }
    };
    void tick();
    return () => {
      stopped = true;
      window.clearTimeout(timer);
    };
  }, [round]);
  const start = async () => {
    setError(null);
    try {
      await modelsPullStart();
      setRound((r) => r + 1);
    } catch (e) {
      setError(asCmdError(e));
    }
  };
  const job = poll?.job;
  const done = job?.files.reduce((a, f) => a + f.bytes_done, 0) ?? 0;
  const total = job?.files.reduce((a, f) => a + f.bytes_total, 0) ?? 0;
  const unavailable = error !== null && isNotAvailable(error);
  const verified = job?.state === "done" && job.files.length > 0 && job.files.every((f) => f.verified);
  const restartHint =
    job?.state === "done" && !poll?.restarted && job.restart_required && poll?.restart_by !== "app"
      ? poll?.restart_by
        ? RESTART_HINT[poll.restart_by]
        : RESTART_HINT.manual
      : null;
  const download = (
    <button type="button" onClick={start}>
      Download models (about 370 MB)
    </button>
  );
  return (
    <>
      <Group title="Detection models">
        {!poll && !error && <Skeleton lines={2} />}
        {!poll && error && !unavailable && <Row label="The state of the models could not be read." end={download} />}
        {unavailable && <Row label="Run inumaki models pull in a terminal to download the models." />}
        {job?.state === "running" && (
          <Row label="Downloading">
            <div
              className="progress"
              role="progressbar"
              aria-label="Model download"
              aria-valuemin={0}
              aria-valuemax={total || 1}
              aria-valuenow={done}
            >
              <span style={{ width: `${total > 0 ? Math.min(100, (100 * done) / total) : 0}%` }} />
            </div>
            <div className="set-sub">
              {Math.round(done / 1e6)} of {Math.round(total / 1e6)} MB
            </div>
          </Row>
        )}
        {job?.state === "failed" && (
          <Row
            label={`The download failed (${job.error ? JOB_ERROR[job.error] : "error"}). You can try again.`}
            end={download}
          />
        )}
        {job?.state === "done" && (
          <Row
            label={verified ? "Downloaded and verified" : "The download finished"}
            sub={poll?.restarted ? "Models downloaded; the service restarted." : restartHint}
            end={download}
          />
        )}
        {job?.state === "idle" && (
          <Row
            label="No download in progress"
            end={download}
          />
        )}
      </Group>
      {error && !unavailable && <ErrorLine error={error} />}
    </>
  );
}
