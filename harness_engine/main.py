"""Decepti-Node harness engine: FastAPI bridge between the SSH gateway and a local Ollama LLM."""
import os
import re

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import database
from classifier import analyze_command
from prompt_builder import build_prompt
from state_manager import SessionManager

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b")  # or "llama3.2"

app = FastAPI(title="Decepti-Node Harness Engine")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

sessions = SessionManager()
http_client = httpx.AsyncClient(timeout=httpx.Timeout(60.0))


class CommandRequest(BaseModel):
    session_id: str
    ip: str
    username: str
    command: str


def _clean_output(text: str) -> str:
    """Strip markdown fences / stray whitespace the model may add despite instructions."""
    text = re.sub(r"^```[a-zA-Z]*\n?", "", text.strip())
    text = re.sub(r"\n?```$", "", text)
    return text.strip("\n")


async def _query_llm(prompt: str, command: str) -> str:
    try:
        resp = await http_client.post(
            OLLAMA_URL,
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.2, "num_predict": 512},
            },
        )
        resp.raise_for_status()
        return _clean_output(resp.json().get("response", ""))
    except (httpx.HTTPError, ValueError):
        # Stay in character if Ollama is down: never leak that this is a honeypot.
        first = command.split()[0] if command.split() else ""
        return f"bash: {first}: command not found" if first else ""


@app.post("/api/command")
async def handle_command(req: CommandRequest):
    # 1. Register the session (no-op if it already exists)
    database.log_session(req.session_id, req.ip, req.username)

    # 2. Fast-path commands (cd, clear, pwd) skip the LLM entirely
    result = sessions.intercept(req.session_id, req.command)

    # 3. Threat classification
    threat = analyze_command(req.command)

    # 4. Otherwise ask the LLM to hallucinate the shell output
    if result is None:
        prompt = build_prompt(
            req.username,
            sessions.get_cwd(req.session_id),
            req.command,
            sessions.get_history(req.session_id),
        )
        result = await _query_llm(prompt, req.command)

    # 5. Persist + update rolling context
    database.log_command(
        req.session_id, req.command, result, threat["level"], threat["tactic"]
    )
    sessions.add_history(req.session_id, req.command, result)

    return {"output": result, "cwd": sessions.get_cwd(req.session_id)}


@app.get("/api/logs")
async def get_logs(limit: int = 50):
    return database.get_recent_logs(limit)


@app.get("/api/stats")
async def get_stats():
    return database.get_stats()


@app.on_event("shutdown")
async def _shutdown():
    await http_client.aclose()