import { useCallback, useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import * as ipc from "../ipc";
import type { OverviewView, ServerRow } from "../types";
import { ErrorLine } from "../components/ErrorLine";
import { Toolbar, ViewBody } from "../components/Toolbar";
import { OrphanNotice, ServerTable, useServerActions } from "../components/ServerTable";
import { Skeleton } from "../components/Skeleton";
import { useNavigate } from "../nav";
import { disconnectedIds } from "../status";

function ServerIcon() {
  // Decorative inline SVG: the heading carries the meaning.
  return (
    <svg
      width="20"
      height="20"
      viewBox="0 0 20 20"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      aria-hidden="true"
    >
      <rect x="3" y="3.5" width="14" height="5" rx="1.5" />
      <rect x="3" y="11.5" width="14" height="5" rx="1.5" />
      <path d="M6 6h.01M6 14h.01" strokeLinecap="round" />
    </svg>
  );
}

export function McpServers({ embedded = false }: { embedded?: boolean }) {
  const navigate = useNavigate();
  const [rows, setRows] = useState<ServerRow[] | null>(null);
  // The harness states, only to tell which harnesses are disconnected. Each load is numbered; an
  // answer that a newer load overtook is dropped. A failed read keeps the rows' own words.
  const [view, setView] = useState<OverviewView | null>(null);
  const ovLoads = useRef(0);
  const loadOverview = useCallback(async () => {
    const n = ++ovLoads.current;
    try {
      const v = await ipc.overview();
      if (n === ovLoads.current) setView(v);
    } catch {
      if (n === ovLoads.current) setView(null);
    }
  }, []);
  // The rows and the harness states load together (on mount, on Refresh, after each action), so a
  // disconnected harness's server never shows as protected while the states are still loading.
  const load = useCallback(async () => {
    const [r] = await Promise.all([ipc.mcpServers(), loadOverview()]);
    setRows(r);
  }, [loadOverview]);
  const actions = useServerActions(load);
  const { error, busy, note, reload } = actions;
  useEffect(() => {
    void reload();
  }, [reload]);
  useEffect(() => {
    let cancelled = false;
    let un: (() => void) | undefined;
    listen("snapshot", () => void loadOverview()).then(
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
  }, [loadOverview]);
  const disconnected = disconnectedIds(view?.cards ?? []);
  return (
    <section>
      <Toolbar
        title="MCP servers"
        embedded={embedded}
        actions={
          rows && (
            <button type="button" disabled={busy} onClick={actions.refresh}>
              Refresh
            </button>
          )
        }
      />
      <ViewBody embedded={embedded}>
        <p className="muted">
          Protect moves a server behind inumaki. Its credentials go into the local vault, and the agent keeps the same
          tool names. Servers that come from plugins aren&apos;t listed and aren&apos;t protected.
        </p>
        {!rows && !error && (
          <div className="box">
            <Skeleton lines={4} />
          </div>
        )}
        {rows && rows.length === 0 && (
          <div className="empty-state">
            <span className="empty-tile" aria-hidden="true">
              <ServerIcon />
            </span>
            <h3>No MCP servers in connected harnesses</h3>
            <p>
              Servers you add to Claude Code, Codex, Hermes Agent or OpenClaw show up here once the harness is
              connected. Plugin servers aren&apos;t listed.
            </p>
            {!embedded && (
              <div className="actions">
                <button type="button" onClick={() => navigate("overview")}>
                  Go to Overview
                </button>
              </div>
            )}
          </div>
        )}
        {rows && rows.length > 0 && (
          <div className="box">
            <ServerTable rows={rows} actions={actions} disconnected={disconnected} />
          </div>
        )}
        <OrphanNotice actions={actions} />
        {note && <p role="status">{note}</p>}
        {error && <ErrorLine error={error} />}
      </ViewBody>
    </section>
  );
}
