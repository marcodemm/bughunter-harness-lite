"""Session JSONL → REPORT.md.

Consumes the JSONL log written by session.py and produces a human-readable
Markdown report next to it (same base name, `.md` extension). One report
per one-shot session — in REPL mode where each accepted line spawns a
fresh session, each objective produces its own JSONL + its own REPORT.md.

The report is best-effort: any failure while reading or rendering the
log falls through to a stub with the error message. Never raises to the
caller.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_report(session_jsonl: Path | str) -> Path:
    """Read a session JSONL and write its Markdown counterpart alongside.
    Returns the path to the report file."""
    path = Path(session_jsonl)
    report_path = path.with_suffix(".md")
    try:
        events = _load(path)
        md = _render(events, session_name=path.name)
    except Exception as e:
        md = (f"# Bughunter Harness Lite — Session Report\n\n"
              f"Failed to build the report from `{path.name}`: "
              f"{type(e).__name__}: {e}\n")
    report_path.write_text(md, encoding="utf-8")
    return report_path


# ── internals ────────────────────────────────────────────────────────
def _load(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except Exception:
                # Malformed line — skip. Better half a report than none.
                continue
    return events


def _last(events: list[dict], event_type: str) -> dict | None:
    match = None
    for e in events:
        if e.get("t") == event_type:
            match = e
    return match


def _short(s: str, n: int) -> str:
    s = (s or "").replace("\r", " ").replace("\n", " ").strip()
    return s if len(s) <= n else s[:n] + "…"


def _md_cell(s: str) -> str:
    """Escape a string for use inside a Markdown table cell."""
    return s.replace("|", "\\|")


def _render(events: list[dict], session_name: str) -> str:
    meta = _last(events, "meta") or {}
    end = _last(events, "end") or {}
    finish = _last(events, "finish") or {}
    kill = _last(events, "kill") or {}
    sigint = _last(events, "sigint")

    cfg = meta.get("config") or {}
    scope = cfg.get("scope") or {}

    objective = meta.get("objective") or "(none)"
    started = meta.get("ts") or ""
    ended = end.get("ts") or ""
    iters = end.get("iterations", 0)
    elapsed = end.get("elapsed_sec", 0)

    tool_calls = [e for e in events if e.get("t") == "tool_call"]
    tool_results = [e for e in events if e.get("t") == "tool_result"]
    llm_replies = [e for e in events if e.get("t") == "llm_reply"]

    if finish:
        outcome = "finish"
        outcome_note = finish.get("summary") or "(empty summary)"
    elif sigint:
        outcome = "sigint"
        outcome_note = "user interrupted with Ctrl+C"
    elif kill:
        outcome = "kill"
        outcome_note = kill.get("reason") or "(unknown reason)"
    else:
        outcome = "incomplete"
        outcome_note = "(session ended without finish/kill/sigint marker)"

    lines: list[str] = []
    lines.append("# Bughunter Harness Lite — Session Report")
    lines.append("")

    # Header block
    lines.append(f"- **Session log**: `{session_name}`")
    lines.append(f"- **Objective**: {_short(objective, 400)}")
    lines.append(f"- **Backend**: {cfg.get('backend', '?')} · "
                 f"model `{cfg.get('model', '?')}`")
    if cfg.get("base_url"):
        lines.append(f"- **Base URL**: `{cfg['base_url']}`")
    lines.append(
        f"- **Scope**: "
        f"hosts={scope.get('hosts', [])} · "
        f"wildcards={scope.get('wildcards', [])} · "
        f"networks={scope.get('networks', [])}"
    )
    if cfg.get("oob_host"):
        lines.append(f"- **OOB**: {cfg['oob_host']} · "
                     f"prefix `{cfg.get('oob_token_prefix', 'lite')}`")
    lines.append(f"- **Started**: {started}")
    lines.append(f"- **Ended**: {ended} · "
                 f"{elapsed}s elapsed · {iters} iterations · "
                 f"{len(tool_calls)} tool calls")
    lines.append(f"- **Outcome**: `{outcome}` — {_short(outcome_note, 400)}")
    lines.append("")

    # Tool call timeline
    lines.append("## Tool calls (timeline)")
    lines.append("")
    if not tool_calls:
        lines.append("_(none)_")
    else:
        lines.append("| # | Tool | Args | Result (first 120 chars) |")
        lines.append("|---|------|------|--------------------------|")
        for i, tc in enumerate(tool_calls, 1):
            args_short = _short(json.dumps(tc.get("args") or {},
                                          ensure_ascii=False), 60)
            res = (tool_results[i - 1].get("result", "")
                   if i - 1 < len(tool_results) else "")
            res_short = _short(res, 120)
            lines.append(
                f"| {i} | `{_md_cell(tc.get('name', '?'))}` | "
                f"`{_md_cell(args_short)}` | "
                f"`{_md_cell(res_short)}` |"
            )
    lines.append("")

    # Assistant narrative — the free-text content of any LLM reply that
    # also carried words (models often speak only through tool_calls, in
    # which case this section is empty).
    narratives = [(i + 1, r.get("content", "")) for i, r in enumerate(llm_replies)
                  if (r.get("content") or "").strip()]
    lines.append("## Assistant narrative")
    lines.append("")
    if not narratives:
        lines.append("_(model spoke only through tool calls — no free text)_")
    else:
        for turn, txt in narratives:
            lines.append(f"### Turn {turn}")
            lines.append("")
            lines.append(txt.rstrip())
            lines.append("")

    # Findings — parsed from the finish() summary (or the kill reason if
    # the session did not finish cleanly).
    lines.append("## Findings")
    lines.append("")
    if finish and finish.get("summary"):
        lines.append(finish["summary"])
    elif kill:
        lines.append(f"_Session killed before finish(): {_short(outcome_note, 400)}_")
    elif sigint:
        lines.append("_Session interrupted with Ctrl+C._")
    else:
        lines.append("_Session ended without finish() — no findings recorded._")
    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(f"Full event log: `{session_name}` "
                 f"({len(events)} events, JSONL format).")
    lines.append("")
    return "\n".join(lines)
