import { useState } from "react";
import * as ipc from "../ipc";
import type { CmdError, HarnessId, OverviewView } from "../types";
import { useNavigate } from "../nav";
import { CopyButton } from "./CopyButton";
import { ErrorLine } from "./ErrorLine";
import { NoticeIcon } from "./Notice";

const IS_LINUX = typeof navigator !== "undefined" && navigator.userAgent.includes("Linux");

/** True while `ServiceState` shows something: a config error, or a service that does not answer. */
export const serviceDown = (view: OverviewView | null): boolean => !!view && (!!view.config_error || !view.reachable);

/**
 * One red line per disconnected harness. Its servers talk to the originals again whether or not the
 * service runs, so the words stay while the harness list is hidden.
 */
function DisconnectedLines({ view, except }: { view: OverviewView; except?: HarnessId }) {
  return (
    <>
      {view.cards
        .filter((c) => c.disconnected && c.id !== except)
        .map((c) => (
          <div key={c.id} className="notice notice-grid red">
            <span className="notice-icon">
              <NoticeIcon kind="red" />
            </span>
            <div className="notice-body">
              <p>{`${c.name} is disconnected: its protected servers talk to the originals again, unfiltered.`}</p>
            </div>
          </div>
        ))}
    </>
  );
}

/**
 * The global notices of a service that cannot be used (spec section 5): a config error, or a service
 * that is not running. Renders nothing while the service is reachable without a config error.
 * Shared by the Overview and the connection pages, which hide their harness status while this shows:
 * with no service, nothing is filtered and the page must not look as if it were.
 */
export function ServiceState({
  view,
  onRefresh,
  embedded = false,
  except,
}: {
  view: OverviewView | null;
  onRefresh: () => void;
  /** First run has no other view to open. */
  embedded?: boolean;
  /** A connection page: its own harness's disconnect is the page's own notice, not a second line here. */
  except?: HarnessId;
}) {
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<CmdError | null>(null);
  if (!view || !serviceDown(view)) return null;

  if (view.config_error) {
    return (
      <>
        <div className="notice notice-grid red">
          <span className="notice-icon">
            <NoticeIcon kind="red" />
          </span>
          <div className="notice-body" role="alert">
            <p className="notice-title">Configuration error</p>
            <p>The config file that names the service socket can&apos;t be used, so the app doesn&apos;t talk to any service.</p>
            <pre className="card">{view.config_error}</pre>
            <p>Fix or remove the file, then refresh. inumaki won&apos;t guess another service.</p>
            <p>Harness status is hidden until the service can be reached.</p>
          </div>
          <div className="notice-action">
            <button type="button" onClick={onRefresh}>
              Refresh
            </button>
            <CopyButton text={view.config_error} label="Copy the message" />
          </div>
        </div>
        <DisconnectedLines view={view} except={except} />
      </>
    );
  }

  // The same rule as the Settings service section: the app starts only a service it manages itself.
  const canStart = view.managed_by === null || view.managed_by === "app";
  const start = async () => {
    setBusy(true);
    setError(null);
    try {
      await ipc.serviceInstall();
    } catch (e) {
      setError(ipc.asCmdError(e));
    } finally {
      setBusy(false);
      onRefresh();
    }
  };
  return (
    <>
      <div className="empty-state" role="status">
        <span className="empty-ring" aria-hidden="true" />
        <h3>The inumaki service is not running</h3>
        <p>
          Nothing is filtered while it&apos;s stopped. Harnesses connected to inumaki can&apos;t use their protected servers,
          the mirror or filtered chat until it runs again.
        </p>
        <div className="actions">
          {canStart && (
            <button type="button" className="primary" disabled={busy} onClick={() => void start()}>
              Start the service
            </button>
          )}
          {!embedded && (
            <button type="button" onClick={() => navigate("settings")}>
              Open Settings
            </button>
          )}
        </div>
        <p className="muted">
          {IS_LINUX ? (
            <>
              Started by the Debian package? Run <code>systemctl --user start inumakid</code> instead.
            </>
          ) : (
            <>
              Started by Homebrew? Run <code>brew services start inumaki</code> instead.
            </>
          )}
        </p>
        {error && <ErrorLine error={error} />}
      </div>
      <DisconnectedLines view={view} except={except} />
    </>
  );
}
