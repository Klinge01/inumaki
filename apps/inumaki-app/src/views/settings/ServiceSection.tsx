import { useCallback, useEffect, useState } from "react";
import { asCmdError, serviceInfo, serviceInstall, serviceRemove, serviceRestart, type CmdError } from "../../ipc";
import type { ManagedBy, ServiceView } from "../../types";
import { Confirm } from "../../components/Confirm";
import { ErrorLine } from "../../components/ErrorLine";
import { Glyph } from "../../components/Glyph";
import { Skeleton } from "../../components/Skeleton";
import { Group, Row } from "./Group";

// A service the app did not install is never changed from here (M6-3 Review Focus 4).
const MANAGER: Record<string, string> = {
  homebrew: "Homebrew runs this service. Use brew services start, stop, or restart inumaki.",
  deb: "The Debian package runs this service. Use systemctl --user start, stop, or restart inumakid.",
  manual: "This service was started by hand. Stop it the way you started it.",
};
const UNKNOWN_MANAGER = "This service does not say who runs it (an older version). The app leaves it alone.";
const IS_LINUX = typeof navigator !== "undefined" && navigator.userAgent.includes("Linux");

/** Who started the running service, for the secondary line. */
const STARTED_BY: Record<ManagedBy, string> = {
  app: "installed by this app",
  homebrew: "started by Homebrew",
  deb: "started by the Debian package",
  manual: "started by hand",
};
/** The chip of a service the app leaves alone. */
const MANAGED_CHIP: Record<ManagedBy, string> = {
  app: "Managed by this app",
  homebrew: "Managed by Homebrew",
  deb: "Managed by the Debian package",
  manual: "Started by hand",
};

const CONFIG_ERROR_LINE = "Fix the configuration file first. Installing the service again wouldn't help.";

function statusLine(info: ServiceView): string | null {
  const parts: string[] = [];
  if (info.version) parts.push(`Version ${info.version}`);
  if (info.managed_by) parts.push(STARTED_BY[info.managed_by]);
  if (parts.length === 0) return null;
  const line = parts.join(", ");
  // "started by Homebrew" alone starts lower-case; with no version it reads as a sentence start.
  return line.charAt(0).toUpperCase() + line.slice(1);
}

export function ServiceSection({ onDone }: { onDone?: () => void }) {
  const [info, setInfo] = useState<ServiceView | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<CmdError | null>(null);
  const [confirmRemove, setConfirmRemove] = useState(false);
  const refresh = useCallback(
    () =>
      serviceInfo().then(
        (i) => {
          setInfo(i);
          if (i.reachable) onDone?.();
        },
        (e) => setError(asCmdError(e)),
      ),
    [onDone],
  );
  useEffect(() => {
    void refresh();
  }, [refresh]);
  const act = (f: () => Promise<void>) => async () => {
    setBusy(true);
    setError(null);
    try {
      await f();
    } catch (e) {
      setError(asCmdError(e));
    } finally {
      await refresh();
      setBusy(false);
    }
  };
  // A service that answers and was not installed by this app. An unreachable service (including a
  // config error) is never "managed elsewhere": it reports no manager at all.
  const managedElsewhere = !!info?.reachable && info.managed_by !== "app";
  const foot = info && (
    <>
      {managedElsewhere && <p>{info.managed_by ? MANAGER[info.managed_by] : UNKNOWN_MANAGER}</p>}
      <p>Removing the service keeps your vault, models, and backups.</p>
      {IS_LINUX && <p>To keep the service running while you are logged out, run loginctl enable-linger in a terminal.</p>}
    </>
  );
  return (
    <>
      <Group title="Login service" foot={foot}>
        {!info && !error && <Skeleton lines={2} />}
        {!info && error && <Row label="The service status could not be read." />}
        {info && (
          <>
            <Row
              label={
                info.reachable ? (
                  <>
                    <Glyph tone="on" /> Running
                  </>
                ) : info.config_error ? (
                  <>
                    <Glyph tone="bad" /> Not reachable
                  </>
                ) : (
                  <>
                    <Glyph tone="off" /> Not running
                  </>
                )
              }
              sub={info.config_error ? CONFIG_ERROR_LINE : info.reachable ? statusLine(info) : null}
              end={
                !info.reachable ? (
                  <button type="button" disabled={busy || !!info.config_error} onClick={act(serviceInstall)}>
                    Install and start
                  </button>
                ) : managedElsewhere ? (
                  info.managed_by ? (
                    <span className="chip">{MANAGED_CHIP[info.managed_by]}</span>
                  ) : (
                    <span className="chip">Manager not reported</span>
                  )
                ) : (
                  <>
                    <button type="button" disabled={busy} onClick={act(serviceRestart)}>
                      Restart
                    </button>
                    <button type="button" className="danger" disabled={busy} onClick={() => setConfirmRemove(true)}>
                      Remove…
                    </button>
                  </>
                )
              }
            >
              {info.config_error && (
                <pre className="card" role="alert">
                  {info.config_error}
                </pre>
              )}
            </Row>
            {info.restart_required && (
              <Row
                label="A restart is needed to load the new models."
                end={<span className="chip amber">Restart needed</span>}
              />
            )}
            {info.bin_dir && (
              <Row label="Helper programs" sub={<span className="mono">{info.bin_dir}</span>} />
            )}
          </>
        )}
      </Group>
      {error && <ErrorLine error={error} />}
      {confirmRemove && (
        <Confirm
          title="Remove the login service?"
          verb="Remove"
          text="inumaki stops running until you install the service again. Your vault, models, and backups are kept."
          onYes={() => {
            setConfirmRemove(false);
            void act(serviceRemove)();
          }}
          onNo={() => setConfirmRemove(false)}
        />
      )}
    </>
  );
}
