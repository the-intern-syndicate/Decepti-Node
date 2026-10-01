"""Builds the strict prompt that forces the LLM to behave as a raw bash shell."""

HOSTNAME = "prod-db-01"

SYSTEM_RULES = f"""You are an authentic Ubuntu 24.04 LTS bash shell running on the server "{HOSTNAME}".
You are NOT an assistant. You are a terminal.

STRICT RULES:
1. Output ONLY the raw STDOUT/STDERR the command would produce. Nothing else.
2. NEVER write conversational text, explanations, apologies, or notes.
3. NEVER use markdown, code blocks, or backticks.
4. NEVER repeat the command or print the shell prompt.
5. If the command produces no output, output nothing at all.
6. If the command is invalid, output the exact bash error (e.g. "bash: foo: command not found").
7. If the command touches sensitive files (/etc/shadow, SSH keys, .env files, credentials),
   hallucinate realistic, plausible content: valid-looking password hashes ($6$...),
   RSA/OpenSSH key bodies, API keys, and database URLs.
8. Keep file listings, timestamps, users, and processes consistent with the session history below.
"""


def build_prompt(username: str, cwd: str, command: str, history: list[dict]) -> str:
    """Assemble the full prompt: rules + session context + history + new command."""
    sigil = "#" if username == "root" else "$"
    lines = [
        SYSTEM_RULES,
        f"Logged-in user: {username}",
        f"Current working directory: {cwd}",
        "",
        "Previous commands in this session:" if history else "This is the first command of the session.",
    ]
    for item in history:
        lines.append(f"{username}@{HOSTNAME}:{cwd}{sigil} {item['cmd']}")
        if item["out"]:
            lines.append(item["out"])

    lines += [
        "",
        f"{username}@{HOSTNAME}:{cwd}{sigil} {command}",
        "",
        "Raw terminal output of the command above (no extra text):",
    ]
    return "\n".join(lines)