import { useEffect, useMemo, useState } from "react";
import ConnectionFeed from "./components/ConnectionFeed";
import LiveTerminal from "./components/LiveTerminal";
import { THREAT_RANK, normalizeThreat } from "./lib/format";

const API_BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";
const POLL_MS = 1500;
const LOG_LIMIT = 500;

const EMPTY_STATS = {
  total_sessions: 0,
  total_commands: 0,
  threat_counts: { INFO: 0, WARNING: 0, CRITICAL: 0 },
  tactic_counts: {},
};

const STATUS_TEXT = {
  connecting: "Connecting to API",
  online: "API connected",
  offline: `API unreachable at ${API_BASE}`,
};
const STATUS_DOT = {
  connecting: "bg-zinc-500",
  online: "bg-emerald-400",
  offline: "bg-rose-400",
};

/** Oldest first, so the terminal reads top to bottom. */
function normalizeLogs(data) {
  return Array.isArray(data) ? [...data].sort((a, b) => a.id - b.id) : [];
}

function sameLogs(a, b) {
  return a.length === b.length && a[a.length - 1]?.id === b[b.length - 1]?.id;
}

/** Group flat command rows into per-session summaries plus per-session transcripts. */
function buildSessions(logs) {
  const sessions = new Map();
  const entries = new Map();

  for (const log of logs) {
    const threat = normalizeThreat(log.threat_level);
    let s = sessions.get(log.session_id);
    if (!s) {
      s = {
        id: log.session_id,
        ip: log.ip,
        username: log.username,
        count: 0,
        lastId: log.id,
        lastTimestamp: log.timestamp,
        threat: "INFO",
        tactic: null,
      };
      sessions.set(log.session_id, s);
      entries.set(log.session_id, []);
    }
    s.count += 1;
    s.lastId = Math.max(s.lastId, log.id);
    s.lastTimestamp = log.timestamp;
    // Session threat = highest severity seen; tactic follows that severity.
    if (THREAT_RANK[threat] >= THREAT_RANK[s.threat]) {
      s.threat = threat;
      if (log.mitre_tactic) s.tactic = log.mitre_tactic;
    }
    entries.get(log.session_id).push(log);
  }

  return {
    sessions: [...sessions.values()].sort((a, b) => b.lastId - a.lastId),
    entries,
  };
}

function Metric({ label, value, tone = "text-zinc-100" }) {
  return (
    <div className="flex flex-col gap-1.5 px-4 py-3">
      <span className="text-xs text-zinc-500">{label}</span>
      <span className={`font-mono text-2xl font-medium leading-none tabular-nums ${tone}`}>
        {(Number(value) || 0).toLocaleString()}
      </span>
    </div>
  );
}

function TopTactics({ counts }) {
  const top = Object.entries(counts ?? {})
    .filter(([tactic]) => tactic && tactic !== "null")
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3);

  return (
    <div className="flex min-w-0 flex-col gap-1.5 px-4 py-3">
      <span className="text-xs text-zinc-500">Top MITRE tactics</span>
      {top.length === 0 ? (
        <span className="font-mono text-xs leading-5 text-zinc-600">No tactics observed yet</span>
      ) : (
        <ul className="m-0 list-none p-0 font-mono text-xs leading-5 text-zinc-300">
          {top.map(([tactic, n]) => (
            <li key={tactic} className="flex justify-between gap-3">
              <span className="truncate" title={tactic}>
                {tactic}
              </span>
              <span className="tabular-nums text-zinc-500">{n}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default function App() {
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState(EMPTY_STATS);
  const [status, setStatus] = useState("connecting");
  const [pinnedId, setPinnedId] = useState(null);

  // Poll logs + stats. The next request is scheduled only after the previous one
  // settles, so slow responses from the LLM-backed API never stack up.
  useEffect(() => {
    let stopped = false;
    let timer;
    const controller = new AbortController();

    const tick = async () => {
      try {
        const [logsRes, statsRes] = await Promise.all([
          fetch(`${API_BASE}/api/logs?limit=${LOG_LIMIT}`, { signal: controller.signal }),
          fetch(`${API_BASE}/api/stats`, { signal: controller.signal }),
        ]);
        if (!logsRes.ok || !statsRes.ok) throw new Error("API returned an error status");
        const [logsData, statsData] = await Promise.all([logsRes.json(), statsRes.json()]);
        if (stopped) return;
        const next = normalizeLogs(logsData);
        setLogs((prev) => (sameLogs(prev, next) ? prev : next));
        setStats({ ...EMPTY_STATS, ...statsData });
        setStatus("online");
      } catch (err) {
        if (err.name !== "AbortError" && !stopped) setStatus("offline");
      } finally {
        if (!stopped) timer = setTimeout(tick, POLL_MS);
      }
    };

    tick();
    return () => {
      stopped = true;
      clearTimeout(timer);
      controller.abort();
    };
  }, []);

  const { sessions, entries } = useMemo(() => buildSessions(logs), [logs]);

  // A pinned session wins; otherwise follow whichever session was active most recently.
  const pinnedSession = sessions.find((s) => s.id === pinnedId) ?? null;
  const activeSession = pinnedSession ?? sessions[0] ?? null;
  const activeEntries = activeSession ? entries.get(activeSession.id) ?? [] : [];

  const handleSelect = (id) => setPinnedId((current) => (current === id ? null : id));

  const critical = Number(stats.threat_counts?.CRITICAL) || 0;

  return (
    <div className="flex min-h-screen flex-col bg-zinc-950 text-zinc-200 lg:h-screen">
      <header className="flex h-11 shrink-0 items-center justify-between border-b border-zinc-800 px-4">
        <div className="flex items-baseline gap-3">
          <h1 className="m-0 font-mono text-sm font-bold text-zinc-100">Decepti-Node</h1>
          <span className="hidden text-xs text-zinc-500 sm:inline">LLM honeypot console</span>
        </div>
        <p className="m-0 flex items-center gap-2 text-xs text-zinc-400" role="status">
          <span className={`h-1.5 w-1.5 rounded-full ${STATUS_DOT[status]}`} aria-hidden="true" />
          {STATUS_TEXT[status]}
        </p>
      </header>

      <section
        aria-label="Summary"
        className="grid shrink-0 grid-cols-2 divide-x divide-zinc-800 border-b border-zinc-800 lg:grid-cols-4"
      >
        <Metric label="Sessions captured" value={stats.total_sessions} />
        <Metric label="Total interceptions" value={stats.total_commands} />
        <Metric label="Critical exploits" value={critical} tone={critical > 0 ? "text-rose-400" : "text-zinc-100"} />
        <TopTactics counts={stats.tactic_counts} />
      </section>

      <main className="grid min-h-0 flex-1 grid-cols-1 divide-y divide-zinc-800 lg:grid-cols-[minmax(0,5fr)_minmax(0,6fr)] lg:divide-x lg:divide-y-0">
        <div className="flex min-h-[280px] min-w-0 flex-col">
          <ConnectionFeed sessions={sessions} activeId={activeSession?.id ?? null} onSelect={handleSelect} />
        </div>
        <div className="flex min-h-[360px] min-w-0 flex-col">
          <LiveTerminal session={activeSession} entries={activeEntries} pinned={Boolean(pinnedSession)} />
        </div>
      </main>
    </div>
  );
}