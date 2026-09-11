"""JSONL session logger. One line per event.

Events:
  {"t": "meta",       "objective": "...", "config": {...}}   session start
  {"t": "llm_reply",  "content": "...", "tool_calls": [...]}  each model turn
  {"t": "tool_call",  "name": "...", "args": {...}}           before dispatch
  {"t": "tool_result","name": "...", "result": "..."}         after dispatch
  {"t": "kill",       "reason": "..."}                        kill switch fired
  {"t": "sigint"}                                             Ctrl+C
  {"t": "finish",     "summary": "..."}                       finish() called
  {"t": "end",        "iterations": N, "elapsed_sec": F}      session end
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class Session:
    def __init__(self, sessions_dir: str | Path,
                 objective: str, config_snapshot: dict[str, Any]):
        self.dir = Path(sessions_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.path = self.dir / f"{stamp}.jsonl"
        self.start_ts = datetime.now(timezone.utc)
        self._fp = open(self.path, "w", encoding="utf-8", buffering=1)
        self.write("meta", objective=objective, config=config_snapshot)

    def write(self, event_type: str, **fields: Any) -> None:
        row = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "t": event_type, **fields}
        self._fp.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")

    def close(self, iterations: int) -> None:
        elapsed = (datetime.now(timezone.utc) - self.start_ts).total_seconds()
        self.write("end", iterations=iterations, elapsed_sec=round(elapsed, 2))
        try:
            self._fp.close()
        except Exception:
            pass
