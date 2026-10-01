import { useCallback, useEffect, useRef, useState } from "react";
import { THREAT_STYLE, formatClock, normalizeThreat, shortId } from "../lib/format";

const HOSTNAME = "srv-prod-01";
const TICK_MS = 16;
const MAX_TYPING_TICKS = 60; // caps typing at roughly one second, however long the output is

const prefersReducedMotion = () =>
  typeof window !== "undefined" &&
  Boolean(window.matchMedia?.("(prefers-reduced-motion: reduce)").matches);

/** Prints text progressively when `animate` is true, otherwise renders it whole. */
function TypedOutput({ text, animate, onGrow }) {
  const [shown, setShown] = useState(() => (animate ? 0 : text.length));
  const typing = shown < text.length;

  useEffect(() => {
    if (!typing) return undefined;
    const step = Math.max(2, Math.ceil(text.length / MAX_TYPING_TICKS));
    const timer = setTimeout(() => setShown((n) => Math.min(text.length, n + step)), TICK_MS);
    return () => clearTimeout(timer);
  }, [typing, shown, text]);

  useEffect(() => {
    onGrow?.();
  }, [shown, onGrow]);

  if (text === "") return null;
  return (
    <pre className="m-0 whitespace-pre-wrap break-words font-mono text-zinc-300">
      {text.slice(0, shown)}
      {typing && <span className="caret" aria-hidden="true" />}
    </pre>
  );
}

/**
 * One session's transcript. Mounted per session (keyed by session id) so that
 * commands already present when you open a session render instantly, and only
 * commands that arrive afterwards are typed out.
 */
function SessionView({ entries, username }) {
  const scrollerRef = useRef(null);
  const stickToBottom = useRef(true);
  const [baseline] = useState(() => new Set(entries.map((e) => e.id)));
  const [reduced] = useState(prefersReducedMotion);

  const scrollToEnd = useCallback(() => {
    const el = scrollerRef.current;
    if (el && stickToBottom.current) el.scrollTop = el.scrollHeight;
  }, []);

  useEffect(() => {
    scrollToEnd();
  }, [entries.length, scrollToEnd]);

  const handleScroll = () => {
    const el = scrollerRef.current;
    if (el) stickToBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
  };

  return (
    <div
      ref={scrollerRef}
      onScroll={handleScroll}
      className="min-h-0 flex-1 overflow-y-auto px-4 py-3 font-mono text-[13px] leading-5"
    >
      {entries.map((entry) => {
        const threat = normalizeThreat(entry.threat_level);
        const output = String(entry.output ?? entry.output_snippet ?? "").replace(/\s+$/, "");
        return (
          <div key={entry.id} className="mb-3">
            <div className="flex items-baseline gap-3">
              <p className="m-0 min-w-0 flex-1 break-all">
                <span className="text-zinc-500">
                  {entry.username ?? username}@{HOSTNAME}:{entry.cwd ?? "~"}${" "}
                </span>
                <span className="text-zinc-100">{entry.command}</span>
              </p>
              {threat !== "INFO" && entry.mitre_tactic && (
                <span className={`shrink-0 text-xs ${THREAT_STYLE[threat].text}`}>{entry.mitre_tactic}</span>
              )}
              <time className="shrink-0 text-xs tabular-nums text-zinc-600">{formatClock(entry.timestamp)}</time>
            </div>
            <TypedOutput text={output} animate={!reduced && !baseline.has(entry.id)} onGrow={scrollToEnd} />
          </div>
        );
      })}
      <p className="m-0 text-zinc-500">
        {username}@{HOSTNAME}:~$ <span className="caret" aria-hidden="true" />
      </p>
    </div>
  );
}

/**
 * Props:
 *   session  the session being viewed (or null)
 *   entries  that session's log rows, oldest first
 *   pinned   true when the viewer clicked a session; false while following the latest
 */
export default function LiveTerminal({ session, entries, pinned }) {
  return (
    <section className="flex min-h-0 flex-1 flex-col" aria-label="Live terminal">
      <header className="flex h-9 shrink-0 items-center justify-between gap-3 border-b border-zinc-800 px-4 text-xs">
        {session ? (
          <p className="m-0 flex min-w-0 items-baseline gap-3">
            <span className="font-mono text-zinc-100">{session.ip ?? "unknown"}</span>
            <span className="truncate font-mono text-zinc-500">session {shortId(session.id)}</span>
          </p>
        ) : (
          <h2 className="font-medium text-zinc-200">Live terminal</h2>
        )}
        {session && (
          <span className="shrink-0 text-zinc-500">{pinned ? "Pinned to this session" : "Following latest"}</span>
        )}
      </header>

      <div className="crt flex min-h-0 flex-1 flex-col bg-zinc-950" aria-live="polite">
        {session ? (
          <SessionView key={session.id} entries={entries} username={session.username ?? "root"} />
        ) : (
          <div className="flex flex-1 items-center justify-center px-6 text-center">
            <p className="font-mono text-xs text-zinc-500">
              Waiting for incoming connection on port 2222...
              <span className="caret" aria-hidden="true" />
            </p>
          </div>
        )}
      </div>
    </section>
  );
}