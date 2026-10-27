import { useEffect, useState } from "react";
import * as ipc from "./ipc";
import { FirstRun } from "./views/FirstRun";
import { Overview } from "./views/Overview";
import { McpServers } from "./views/McpServers";
import { Email } from "./views/Email";
import { Folders } from "./views/Folders";
import { Activity } from "./views/Activity";
import { Inspect } from "./views/Inspect";
import { Settings } from "./views/Settings";
import { Connection } from "./views/Connection";
import { OtherClient } from "./views/OtherClient";
import { Sidebar } from "./components/Sidebar";
import { NavContext, type ViewId } from "./nav";
import type { HarnessId } from "./types";

/** The view for an id. `connection:<harness>` and `connection:other` resolve to the connection pages. */
function ViewFor({ id }: { id: ViewId }) {
  switch (id) {
    case "overview":
      return <Overview />;
    case "mcp":
      return <McpServers />;
    case "email":
      return <Email />;
    case "folders":
      return <Folders />;
    case "activity":
      return <Activity />;
    case "inspect":
      return <Inspect />;
    case "settings":
      return <Settings />;
    case "connection:other":
      return <OtherClient />;
    default:
      return <Connection harness={id.slice("connection:".length) as HarnessId} />;
  }
}

export function App() {
  const [view, setView] = useState<ViewId>("overview");
  const [firstRun, setFirstRun] = useState<boolean | null>(null);
  useEffect(() => {
    ipc.prefs().then(
      (p) => setFirstRun(!p.first_run_done),
      // Preferences unreadable: do not trap the user in the first-run flow.
      () => setFirstRun(false),
    );
  }, []);
  if (firstRun === null) return null;
  if (firstRun) {
    return (
      <FirstRun
        onFinish={() => {
          // Leave the flow either way; a failed save only shows it again next launch.
          void ipc.setFirstRunDone().then(
            () => setFirstRun(false),
            () => setFirstRun(false),
          );
        }}
      />
    );
  }
  return (
    <NavContext.Provider value={setView}>
      <div className="app">
        <Sidebar view={view} onSelect={setView} />
        {/* key: a view switch unmounts the previous view, clearing any reveal (spec §6.5). */}
        <main className="main" key={view}>
          <div className="scroll">
            <ViewFor id={view} />
          </div>
        </main>
      </div>
    </NavContext.Provider>
  );
}
