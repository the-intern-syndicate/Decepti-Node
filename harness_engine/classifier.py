"""Lightweight heuristic threat classifier mapping commands to MITRE ATT&CK tactics."""
import re

# Checked in order; first match wins (most severe first).
_RULES = [
    ("CRITICAL", "Credential Access",
     [r"shadow", r"passwd", r"\.env", r"id_rsa"]),
    ("CRITICAL", "Defense Evasion",
     [r"\bchmod\b", r"\bufw\b", r"\biptables\b"]),
    ("WARNING", "Exfiltration",
     [r"\bcurl\b", r"\bwget\b", r"\bnc\b", r"\bscp\b"]),
]

_COMPILED = [
    (level, tactic, [re.compile(p, re.IGNORECASE) for p in patterns])
    for level, tactic, patterns in _RULES
]


def analyze_command(command: str) -> dict:
    """Return {"level": ..., "tactic": ...} for a raw command string."""
    for level, tactic, patterns in _COMPILED:
        if any(p.search(command) for p in patterns):
            return {"level": level, "tactic": tactic}
    return {"level": "INFO", "tactic": "Reconnaissance"}