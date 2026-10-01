"""SQLite persistence layer for Decepti-Node (sessions + command logs)."""
import os
import sqlite3
import threading
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "honeypot.db")

# check_same_thread=False lets FastAPI's worker threads share one connection;
# the lock serialises access so writes never interleave.
_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
_conn.row_factory = sqlite3.Row
_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db() -> None:
    """Create tables if they don't exist."""
    with _lock:
        _conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                ip         TEXT,
                username   TEXT,
                started_at TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS command_logs (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id   TEXT,
                command      TEXT,
                output       TEXT,
                threat_level TEXT,
                mitre_tactic TEXT,
                timestamp    TIMESTAMP
            );
            """
        )
        _conn.commit()


def log_session(session_id: str, ip: str, username: str) -> bool:
    """Insert a session if new. Returns True if it was newly created."""
    with _lock:
        cur = _conn.execute(
            "INSERT OR IGNORE INTO sessions (session_id, ip, username, started_at) "
            "VALUES (?, ?, ?, ?)",
            (session_id, ip, username, _now()),
        )
        _conn.commit()
        return cur.rowcount > 0


def log_command(session_id: str, command: str, output: str,
                threat_level: str, mitre_tactic: str) -> None:
    with _lock:
        _conn.execute(
            "INSERT INTO command_logs "
            "(session_id, command, output, threat_level, mitre_tactic, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (session_id, command, output, threat_level, mitre_tactic, _now()),
        )
        _conn.commit()


def get_recent_logs(limit: int = 50) -> list[dict]:
    """Newest-first command logs, joined with session ip/username for the dashboard."""
    with _lock:
        rows = _conn.execute(
            """
            SELECT c.id, c.session_id, s.ip, s.username, c.command, c.output,
                   c.threat_level, c.mitre_tactic, c.timestamp
            FROM command_logs c
            LEFT JOIN sessions s ON s.session_id = c.session_id
            ORDER BY c.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_stats() -> dict:
    with _lock:
        total_sessions = _conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        total_commands = _conn.execute("SELECT COUNT(*) FROM command_logs").fetchone()[0]
        level_rows = _conn.execute(
            "SELECT threat_level, COUNT(*) AS n FROM command_logs GROUP BY threat_level"
        ).fetchall()
        tactic_rows = _conn.execute(
            "SELECT mitre_tactic, COUNT(*) AS n FROM command_logs "
            "GROUP BY mitre_tactic ORDER BY n DESC"
        ).fetchall()

    threat_counts = {"INFO": 0, "WARNING": 0, "CRITICAL": 0}
    for r in level_rows:
        threat_counts[r["threat_level"]] = r["n"]

    return {
        "total_sessions": total_sessions,
        "total_commands": total_commands,
        "threat_counts": threat_counts,
        "tactic_counts": {r["mitre_tactic"]: r["n"] for r in tactic_rows},
    }


init_db()