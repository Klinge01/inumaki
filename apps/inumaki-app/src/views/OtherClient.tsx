import { useState } from "react";
import * as ipc from "../ipc";
import type { CmdError, OtherClient as OtherClientInfo } from "../types";
import { CopyButton } from "../components/CopyButton";
import { ErrorLine } from "../components/ErrorLine";
import { Notice } from "../components/Notice";
import { Toolbar, ViewBody } from "../components/Toolbar";
import { useWindowHidden } from "../useWindowHidden";

/**
 * The "Other client" page (spec section 6.6). The gateway token is a secret: it lives in this
 * component's state only, is dropped when the window hides and when the view unmounts, and is
 * shown as a text node with a fixed label (never in an attribute). Nothing else stores or logs it.
 */
export function OtherClient() {
  const [info, setInfo] = useState<OtherClientInfo | null>(null);
  const [error, setError] = useState<CmdError | null>(null);
  // The token cannot be shown again: when the window hides it is dropped, and
  // "Revoke it and create a new one" is the way back.
  useWindowHidden(() => {
    setInfo(null);
    setError(null);
  });
  const show = () => {
    setError(null);
    ipc.otherClient().then(setInfo, (e) => setError(ipc.asCmdError(e)));
  };
  const renew = () => {
    setError(null);
    ipc.revokeOtherClient().then(
      () => ipc.otherClient().then(setInfo, (e) => setError(ipc.asCmdError(e))),
      (e) => setError(ipc.asCmdError(e)),
    );
  };
  return (
    <section>
      <Toolbar title="Other client" />
      <ViewBody>
        <p className="muted">For any client that takes an MCP server URL or a model base URL.</p>
        {!info && (
          <div className="actions">
            <button type="button" onClick={show}>
              Show connection details
            </button>
          </div>
        )}
        {info && (
          <>
            <div className="box">
              <div className="sec-pad other-token">
                {info.token ? (
                  <>
                    <div className="token-row">
                      {/* A text node, not an input: a field's value would be mirrored into a DOM attribute. */}
                      <code className="mono token-value" aria-label="Token">
                        {info.token}
                      </code>
                      <CopyButton text={info.token} />
                    </div>
                    <p className="muted">
                      Cleared when you leave this view or hide the window. Lost it? Revoke it and create a new one.
                    </p>
                  </>
                ) : (
                  <p className="muted">
                    A token for other clients exists already and cannot be shown again.{" "}
                    <button type="button" onClick={renew}>
                      Revoke it and create a new one
                    </button>
                  </p>
                )}
              </div>
              <table className="grid">
                <tbody>
                  {info.gateway.map((g) => (
                    <tr key={g.url}>
                      <td>{g.name}</td>
                      <td className="mono">{g.url}</td>
                    </tr>
                  ))}
                  {info.proxy.map(([p, u]) => (
                    <tr key={u}>
                      <td>chat {p}</td>
                      <td className="mono">{u}</td>
                    </tr>
                  ))}
                  {info.client_header && (
                    <tr>
                      <td>Header for chat base URLs</td>
                      <td className="mono">
                        {info.client_header} <CopyButton text={info.client_header} />
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            {info.proxy_warning && (
              <Notice kind="amber" role="status">{`Warning: ${info.proxy_warning}.`}</Notice>
            )}
          </>
        )}
        {error && <ErrorLine error={error} />}
      </ViewBody>
    </section>
  );
}
