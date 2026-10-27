import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { listen } from "@tauri-apps/api/event";
import * as ipc from "../ipc";
import type { OverviewView, ServerRow, ServiceView } from "../types";
import type { ViewId } from "../nav";
import { HARNESS_MONOGRAM } from "../harnessText";
import { protectedCount, weakestStatus } from "../status";
import { Glyph, type Tone } from "./Glyph";


export type SidebarStatus = { tone: Tone; word: string; line: string };

/**
 * The status block (spec section 4, item 1), variants chosen in this order: a config error, a
 * service that is not reachable, a harness that needs attention (A1: also a failed last check, as
 * the tray), otherwise on. `null` while the overview is unknown: the block never claims "on" then.
 */
export function sidebarStatus(ov: OverviewView | null): SidebarStatus | null {
  if (!ov) return null;
  if (ov.config_error) return { tone: "bad", word: "Configuration error", line: "Config file can't be read" };
  if (!ov.reachable) return { tone: "off", word: "Service not running", line: "Nothing is filtered" };
  const down = ov.cards.filter((c) => c.disconnected).length;
  const broken = ov.cards.flatMap((c) => c.paths).find((p) => p.state === "broken");
  const hook = ov.cards.find((c) => c.hook.state === "broken")?.hook;
  const grant = ov.cards.find((c) => c.grant)?.grant;
  if (down > 0 || broken || hook || grant || ov.last_check?.failed) {
    // The first reason, in the order a user would fix them; every line is a fixed sentence.
    const line =
      down > 0
        ? `${down} ${down === 1 ? "harness" : "harnesses"} disconnected`
        : broken
          ? (broken.reason?.text ?? "A path needs attention")
          : hook?.state === "broken"
            ? hook.reason.text
            : grant
              ? grant.text
              : "Last check failed";
    return { tone: "bad", word: "Needs attention", line };
  }
  const n = ov.cards.filter((c) => c.connected).length;
  // Nothing connected is not a working Easy mode (L5-29).
  if (n === 0) return { tone: "off", word: "Not connected", line: "Nothing is filtered" };
  return { tone: "on", word: "Connected", line: `Easy mode, ${n} ${n === 1 ? "harness" : "harnesses"}` };
}

function Item({
  id,
  view,
  onSelect,
  children,
}: {
  id: ViewId;
  view: ViewId;
  onSelect: (id: ViewId) => void;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      className="nav-item"
      aria-current={id === view ? "page" : undefined}
      onClick={() => onSelect(id)}
    >
      {children}
    </button>
  );
}

function Group({ label, children }: { label: string; children: ReactNode }) {
  const id = `nav-group-${label.toLowerCase().replace(/\s+/g, "-")}`;
  return (
    <div role="group" aria-labelledby={id} className="nav-group">
      <div id={id} className="nav-heading">
        {label}
      </div>
      {children}
    </div>
  );
}

const LinkIcon = () => (
  <svg className="nav-icon" width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" aria-hidden="true">
    <path d="M6.5 9.5a3 3 0 0 0 4.2 0l2-2a3 3 0 0 0-4.2-4.2l-.7.7" />
    <path d="M9.5 6.5a3 3 0 0 0-4.2 0l-2 2a3 3 0 0 0 4.2 4.2l.7-.7" />
  </svg>
);

// The MCP rows stay as rows: the "P of T" count needs the overview's disconnected harnesses, and
// shows nothing while the overview is unknown or failed.
type Counts = { mcp: ServerRow[] | null; email: string | null; folders: string | null };
// `info: null`: the service answer failed (shown as unreachable). The whole value is null until the first answer.
type Info = { info: ServiceView | null };

export function Sidebar({ view, onSelect }: { view: ViewId; onSelect: (id: ViewId) => void }) {
  const [overview, setOverview] = useState<OverviewView | null>(null);
  const [counts, setCounts] = useState<Counts | null>(null);
  const [service, setService] = useState<Info | null>(null);

  // Each load is numbered; an answer from a load that a newer one overtook is dropped. A failed
  // load clears the view: a stale "Connected" must not stay on screen.
  const loads = useRef(0);
  const loadOverview = useCallback(async () => {
    const n = ++loads.current;
    try {
      const v = await ipc.overview();
      if (n === loads.current) setOverview(v);
    } catch {
      if (n === loads.current) setOverview(null);
    }
  }, []);
  // The footer follows the snapshots too, so it never disagrees with the status block.
  const infoLoads = useRef(0);
  const loadInfo = useCallback(async () => {
    const n = ++infoLoads.current;
    let info: ServiceView | null = null;
    try {
      info = await ipc.serviceInfo();
    } catch {
      info = null;
    }
    if (n === infoLoads.current) setService({ info });
  }, []);
  useEffect(() => {
    void loadOverview();
    let cancelled = false;
    let un: (() => void) | undefined;
    listen("snapshot", () => {
      void loadOverview();
      void loadInfo();
    }).then(
      (u) => {
        if (cancelled) u();
        else un = u;
      },
      () => undefined,
    );
    return () => {
      cancelled = true;
      un?.();
    };
  }, [loadOverview, loadInfo]);

  // Counts and the service line load on mount and whenever the user switches view (a data change
  // in a view shows when the user leaves it). A count whose command fails is hidden.
  useEffect(() => {
    let cancelled = false;
    void Promise.allSettled([ipc.mcpServers(), ipc.mailboxes(), ipc.folders()]).then(([m, e, f]) => {
      if (cancelled) return;
      setCounts({
        mcp: m.status === "fulfilled" ? m.value : null,
        email: e.status === "fulfilled" ? String(e.value.length) : null,
        folders: f.status === "fulfilled" ? String(f.value.folders.length) : null,
      });
    });
    void loadInfo();
    return () => {
      cancelled = true;
    };
  }, [view, loadInfo]);

  const status = sidebarStatus(overview);
  const count = (c: string | null | undefined) => (c ? <span className="count num">{c}</span> : null);
  // Fails closed: without a known overview the disconnected harnesses are unknown, and "P of T"
  // could read high, so no count shows.
  const mcpCount = counts?.mcp && overview ? protectedCount(counts.mcp, overview.cards) : null;
  return (
    <nav className="sidebar" aria-label="Views">
      {status && (
        <div className="status-block">
          <div className="status-word">
            <Glyph tone={status.tone} />
            <b>{status.word}</b>
          </div>
          <div className="status-line">{status.line}</div>
        </div>
      )}
      <Item id="overview" view={view} onSelect={onSelect}>
        Overview
      </Item>
      <Group label="Connections">
        {overview?.cards.map((c) => {
          const s = weakestStatus(c);
          return (
            <Item key={c.id} id={`connection:${c.id}`} view={view} onSelect={onSelect}>
              <span className="monogram sm" aria-hidden="true">
                {HARNESS_MONOGRAM[c.id]}
              </span>
              {c.name}
              <span className="nav-end">
                <Glyph tone={s.tone} />
                <span className="sr-only">{s.word}</span>
              </span>
            </Item>
          );
        })}
        <Item id="connection:other" view={view} onSelect={onSelect}>
          <LinkIcon />
          Other client
        </Item>
      </Group>
      <Group label="Data sources">
        <Item id="mcp" view={view} onSelect={onSelect}>
          MCP servers
          {count(mcpCount)}
        </Item>
        <Item id="email" view={view} onSelect={onSelect}>
          Email
          {count(counts?.email)}
        </Item>
        <Item id="folders" view={view} onSelect={onSelect}>
          Folders
          {count(counts?.folders)}
        </Item>
      </Group>
      <Group label="Records">
        <Item id="activity" view={view} onSelect={onSelect}>
          Activity
        </Item>
        <Item id="inspect" view={view} onSelect={onSelect}>
          Inspect &amp; recover
        </Item>
      </Group>
      <div className="nav-spacer" />
      <Item id="settings" view={view} onSelect={onSelect}>
        Settings
      </Item>
      {service && (
        <div className="nav-footer">
          {service.info?.reachable
            ? `Service ${service.info.version ? `${service.info.version} ` : ""}running`
            : "Service unreachable"}
        </div>
      )}
    </nav>
  );
}
