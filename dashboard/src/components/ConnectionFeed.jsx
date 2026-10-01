import { useEffect, useRef, useState } from "react";
import ThreatBadge from "./ThreatBadge";
import { formatRelative, shortId } from "../lib/format";

const FLASH_MS = 900;

/** Re-renders once a second so relative timestamps stay current. */
function useNow(intervalMs = 1000) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(id);
  }, [intervalMs]);
  return now;
}

/**
 * Table of captured attacker sessions (one row per session_id).
 * Props:
 *   sessions  [{ id, ip, username, count, lastId, lastTimestamp, threat, tactic }]
 *   activeId  session currently shown in the terminal
 *   onSelect  (sessionId) => void   (selecting the active row again releases the pin)
 */
export default function ConnectionFeed({ sessions, activeId, onSelect }) {
  const now = useNow();
  const [fresh, setFresh] = useState(() => new Set());
  const prevLast = useRef(new Map());
  const initialized = useRef(false);

  // Flash rows whose session received a new command since the last poll.
  useEffect(() => {
    const changed = new Set();
    for (const s of sessions) {
      const before = prevLast.current.get(s.id);
      if (initialized.current && (before === undefined || s.lastId > before)) {
        changed.add(s.id);
      }
      prevLast.current.set(s.id, s.lastId);
    }
    initialized.current = true;
    if (changed.size === 0) return undefined;
    setFresh(changed);
    const timer = setTimeout(() => setFresh(new Set()), FLASH_MS);
    return () => clearTimeout(timer);
  }, [sessions]);

  return (
    <section className="flex min-h-0 flex-1 flex-col" aria-label="Captured sessions">
      <header className="flex h-9 shrink-0 items-center justify-between border-b border-zinc-800 px-4 text-xs">
        <h2 className="font-medium text-zinc-200">Captured sessions</h2>
        <span className="font-mono tabular-nums text-zinc-500">{sessions.length}</span>
      </header>

      {sessions.length === 0 ? (
        <div className="flex flex-1 items-center justify-center px-6 text-center">
          <p className="font-mono text-xs text-zinc-500">
            Waiting for incoming connection on port 2222...
            <span className="caret" aria-hidden="true" />
          </p>
        </div>
      ) : (
        <div className="min-h-0 flex-1 overflow-auto">
          <table className="w-full min-w-[640px] border-collapse text-left font-mono text-xs">
            <thead className="sticky top-0 z-10 bg-zinc-950 text-zinc-500">
              <tr className="border-b border-zinc-800">
                <th className="px-4 py-2 font-normal">Source IP</th>
                <th className="px-2 py-2 font-normal">Session</th>
                <th className="px-2 py-2 font-normal">User</th>
                <th className="px-2 py-2 text-right font-normal">Cmds</th>
                <th className="px-2 py-2 font-normal">Threat</th>
                <th className="px-2 py-2 font-normal">MITRE tactic</th>
                <th className="px-4 py-2 text-right font-normal">Last seen</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((s) => {
                const active = s.id === activeId;
                return (
                  <tr
                    key={s.id}
                    tabIndex={0}
                    aria-current={active ? "true" : undefined}
                    onClick={() => onSelect(s.id)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        onSelect(s.id);
                      }
                    }}
                    className={`cursor-pointer border-b border-zinc-800/70 outline-none focus-visible:outline focus-visible:outline-1 focus-visible:-outline-offset-1 focus-visible:outline-zinc-400 ${
                      active
                        ? "bg-zinc-900 shadow-[inset_2px_0_0_0_#e4e4e7]"
                        : "hover:bg-zinc-900/60"
                    } ${fresh.has(s.id) ? "row-flash" : ""}`}
                  >
                    <td className="whitespace-nowrap px-4 py-2 text-zinc-100">{s.ip ?? "unknown"}</td>
                    <td className="whitespace-nowrap px-2 py-2 text-zinc-500">{shortId(s.id)}</td>
                    <td className="max-w-[8rem] truncate px-2 py-2 text-zinc-300">{s.username ?? "-"}</td>
                    <td className="px-2 py-2 text-right tabular-nums text-zinc-300">{s.count}</td>
                    <td className="px-2 py-2">
                      <ThreatBadge level={s.threat} />
                    </td>
                    <td className="max-w-[10rem] truncate px-2 py-2 text-zinc-400" title={s.tactic ?? ""}>
                      {s.tactic || "-"}
                    </td>
                    <td className="whitespace-nowrap px-4 py-2 text-right tabular-nums text-zinc-500">
                      {formatRelative(s.lastTimestamp, now)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}