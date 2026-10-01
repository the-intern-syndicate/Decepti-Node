"""In-memory per-session state (cwd + rolling history) and fast-path commands."""
import posixpath
import threading
from typing import Optional

DEFAULT_CWD = "/root"
HISTORY_LIMIT = 5
CLEAR_SEQUENCE = "\033[H\033[2J"


class SessionManager:
    def __init__(self) -> None:
        self._sessions: dict[str, dict] = {}
        self._lock = threading.Lock()

    def get_state(self, session_id: str) -> dict:
        """Return (creating if needed) the state dict for a session."""
        with self._lock:
            return self._sessions.setdefault(
                session_id, {"cwd": DEFAULT_CWD, "history": []}
            )

    def get_cwd(self, session_id: str) -> str:
        return self.get_state(session_id)["cwd"]

    def get_history(self, session_id: str) -> list[dict]:
        return list(self.get_state(session_id)["history"])

    def add_history(self, session_id: str, cmd: str, out: str) -> None:
        state = self.get_state(session_id)
        with self._lock:
            state["history"].append({"cmd": cmd, "out": out})
            state["history"] = state["history"][-HISTORY_LIMIT:]

    def intercept(self, session_id: str, command: str) -> Optional[str]:
        """Handle commands that don't need the LLM.

        Returns the output string if handled, or None to defer to the LLM.
        """
        state = self.get_state(session_id)
        cmd = command.strip()

        if cmd == "clear":
            return CLEAR_SEQUENCE

        if cmd == "pwd":  # keeps cwd perfectly consistent with state
            return state["cwd"]

        if cmd == "cd" or cmd.startswith("cd "):
            target = cmd[2:].strip().strip("'\"")
            if target in ("", "~"):
                new_cwd = DEFAULT_CWD
            elif target.startswith("~/"):
                new_cwd = posixpath.normpath(posixpath.join(DEFAULT_CWD, target[2:]))
            elif target.startswith("/"):
                new_cwd = posixpath.normpath(target)
            else:
                new_cwd = posixpath.normpath(posixpath.join(state["cwd"], target))
            with self._lock:
                state["cwd"] = new_cwd
            return ""

        return None