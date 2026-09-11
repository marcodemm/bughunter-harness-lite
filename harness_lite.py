#!/usr/bin/env python3
"""bughunter-harness-lite — mobile-first LLM pentest agent.

UX kept intentionally identical to the desktop `bughunter-harness`:
    - Same red ASCII banner at startup (from banner.py).
    - Same HELP_TEXT sections (USAGE, REPL COMMANDS, SCOPE, OBJECTIVES,
      SESSIONS).
    - Same REPL flow: each line is a fresh one-shot objective; sticky
      flags (--scope, --header, etc.) persist across sessions; slash
      commands (/quit /bye /exit /help) leave.

What actually differs under the hood: no multi-agent orchestrator, no
multi-host loop, no adversarial-review gate, and the shell toolbox is
capped to what runs cleanly in a Termux+Kali chroot on ARM (no katana,
no gowitness, no sqlmap, no dalfox, no nikto, no masscan/nmap -sS).
`nuclei` is only accepted with `-id <template>` — no bulk `-tags cve`.

Two entry modes:
  one-shot:  `python harness_lite.py --objective "..." --scope example.com`
  repl:      `python harness_lite.py`
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import signal
import sys
import time
from pathlib import Path
from typing import Any

import requests
import yaml

# Local modules
from llm import LLMClient, resolve_backend
from redact import redact
from scope import ScopeChecker
from session import Session
from throttle import RateLimiter
from tools import Tools, openai_schemas

ROOT = Path(__file__).resolve().parent
DEFAULT_CFG = ROOT / "config.yaml"
DEFAULT_SCOPE = ROOT / "scope.txt"
SESSIONS_DIR = ROOT / "sessions"

QUIT_COMMANDS = {"/quit", "/bye", "/exit", "/q",
                 "quit", "bye", "exit"}
HELP_COMMANDS = {"/help", "/?", "/h", "help", "?"}

REPL_COMMANDS_HINT = (
    "REPL commands:  /quit | /bye | /exit    /help\n"
    "Sticky flags:   --scope PAT (repeatable)  --header \"N: V\" (repeatable)\n"
    "                --skip-preflight  --strict-preflight\n"
    "                --max-iterations N  --max-wall-time-sec N\n"
    "                --servertype S  --model M  --base-url URL\n"
    "Objective:      any other text = start a new one-shot with that goal."
)

HELP_TEXT = r"""
════════════════════════════════════════════════════════════════════
 BUGHUNTER HARNESS · LITE  ·  mobile / single-process REPL
 A minimal, mobile-first sibling of `bughunter-harness`
════════════════════════════════════════════════════════════════════

USAGE
  python harness_lite.py                          → REPL (prompt for objective)
  python harness_lite.py --objective "..."        → one-shot from CLI
  python harness_lite.py --scope "*.example.com"  → inline scope (repeatable)
  python harness_lite.py --header "N: V"          → custom HTTP header (repeatable)
  python harness_lite.py --scope-file scope.txt   → override scope.txt path
  python harness_lite.py --config file.yaml       → override config path
  python harness_lite.py --servertype ollama      → LLM backend
                                                    (auto|lmstudio|ollama|
                                                     llamacpp|openai|
                                                     anthropic|nvidia|gemini)
  python harness_lite.py --model bughunter-v9     → LLM model id
  python harness_lite.py --base-url URL           → OpenAI-compat endpoint
  python harness_lite.py --skip-preflight         → do not probe target
  python harness_lite.py --strict-preflight       → abort on preflight failure
  python harness_lite.py --max-iterations N       → override cap (default 20)
  python harness_lite.py --max-wall-time-sec N    → override cap (default 900)
  python harness_lite.py --help                   → show this help

  Flags can combine, e.g.
    python harness_lite.py --scope "*.example.com" --scope "10.0.0.0/24" \
                           --header "X-HackerOne-Researcher: yourhandle" \
                           --objective "Fingerprint https://www.example.com"

REPL COMMANDS
  After each session the harness prompts for a new objective:
    <free text>         → start a new session with that objective
    <bare URL>          → equivalent to "Recon <URL>"
    /quit /bye /exit    → leave the harness (also: quit / bye / exit)
    /help               → show this help again
    Ctrl+C              → cancel current session and exit

  Sticky inline flags accepted in the prompt (persist across sessions):
    --scope PAT (repeatable)         in-scope allowlist
    --header "NAME: VALUE" (repeat)  custom HTTP header
    --skip-preflight                 skip probe for this run
    --strict-preflight               abort on probe failure
    --max-iterations N               override iter cap
    --max-wall-time-sec N            override wall-time cap
    --servertype {auto,lmstudio,ollama,llamacpp,openai,anthropic,nvidia,gemini}
    --model MODEL_ID                 LLM model id
    --base-url URL                   OpenAI-compat endpoint override
  Pass an empty value to clear a sticky:  --scope ""   --header ""

SCOPE (in-scope allowlist)
  Two ways to define what hosts the agent is allowed to touch:

  1) File on disk (default): scope.txt in the harness folder, one entry per
     line. Path overridable via --scope-file / config.yaml → scope_file.
  2) Inline via CLI/REPL: --scope PATTERN (repeatable). Overrides scope.txt
     for that session.

  Entry formats (both file and --scope):
    example.com          exact host (apex only)
    *.example.com        wildcard subdomain (a.example.com, a.b.example.com…)
    10.0.0.0/24          CIDR range
    10.0.0.1             exact IP
    127.0.0.1            loopback
    # ... a comment      lines starting with # are ignored (file only)

  Enforcement is HARD: every http_get / http_post request and every run_shell
  URL/host argument is checked against scope. Out-of-scope → ERROR to the
  model, no request goes out.

OBJECTIVE EXAMPLES  (copy-paste one)

  Fingerprint tech stack of https://www.example.com — headers, favicon,
  common paths. Stop after 8 tool calls.

  Recon https://www.example.com : subs (subfinder), live hosts (httpx),
  exposed .git/.env/backup.zip on the apex. Stop after 12 tool calls.

  Check if https://www.example.com/wp-login.php exists and if wpscan
  fingerprints any plugin. Non-destructive.

  Given the OOB catcher token XYZ, verify the payload landed at
  https://oob.example.net/oob/XYZ and summarise the hit.

LITE — WHAT'S DIFFERENT vs bughunter-harness (desktop)
  The lite is a single-process REPL/one-shot agent loop, NOT a pipeline.
  There is no orchestrator, no multi-host mode, no adversarial-review gate,
  no email/telegram report. Under the hood you have ONE loop:
    LLM → tool_call → gates → execute → redact → back to LLM
  ...until the model calls finish() or a kill switch fires.

  Toolbox — everything below runs. Nothing else:
    http_get, http_post, oob_generate_token, finish
    run_shell — allowlist:
        curl, dig, host, whois, httpx, subfinder,
        gau, waybackurls, nuclei (-id <template> only),
        ffuf, wpscan
  Excluded by design: katana (JS crawl too heavy on ARM chroot),
  gowitness (Chrome headless), sqlmap (long runs), dalfox, nikto,
  masscan / nmap -sS (raw sockets, no root in chroot).

  For the full 13-stage pipeline (recon → sub_prioritizer → fingerprint →
  content_discovery → screenshot → login_probe → web_vuln → wordpress →
  api_fuzzer → auth → report → adversarial_review), use the desktop
  bughunter-harness — same author, same security gates.

SECURITY GATES  (enforced in code — model cannot bypass them)
  1) Scope allowlist  — every host is checked against scope.
  2) Rate limit       — blocking, global, min interval per config.
  3) Shell allowlist  — 11 binaries only; nuclei needs -id <template>.
  4) Shell denylist   — no pipes/redirects, no sudo/rm/chmod, no destructive
                        HTTP verbs (DELETE / PUT / PATCH from run_shell).
  5) Redact           — every tool output is scrubbed for secrets before
                        the model or the log see it (JWT / AWS / GitHub /
                        Stripe / PEM / cookies / emails).
  6) Kill switches    — max_iterations, max_wall_time_sec, shell_timeout_sec,
                        http_timeout_sec.  Ctrl+C is always honored.

SESSIONS
  Every run writes a JSONL log of the whole conversation:
    - objective + config snapshot
    - LLM responses (content + tool_calls)
    - redacted result of each tool call
    - kill switch / sigint / finish, if any

  Location:  <harness-dir>/sessions/YYYYMMDDTHHMMSSZ.jsonl
  (dir auto-created; one file per one-shot / per REPL objective)

  Review after every engagement to audit what the agent tried.
════════════════════════════════════════════════════════════════════
"""

# Small system prompt: on a 3B model with num_ctx=4096 we spend the budget
# on tool results, not on scaffolding.
SYSTEM_PROMPT = """You are a bug-bounty assistant running on the operator's mobile device.
You have a small toolbox: http_get, http_post, run_shell, oob_generate_token, finish.

Rules that are enforced in code (you cannot bypass them):
- Every URL host must be in the operator's scope allowlist.
- A minimum interval between tool calls is enforced (rate limit).
- run_shell only accepts: curl, dig, host, whois, httpx, subfinder, gau,
  waybackurls, nuclei (only with -id <template>), ffuf, wpscan.
- No pipes, redirects, sudo, rm, or destructive HTTP verbs.
- Tool output is redacted for secrets before you see it.

Practical guidance:
- Prefer http_get + a single nuclei -id when you already suspect a CVE.
- Prefer subfinder + httpx over katana (crawlers are excluded here).
- One request per turn is fine — the operator is on a phone, not a server.
- Call finish(summary) as soon as you have a result. Do not keep looping.
"""


# ────────────────────────────────────────────────────────────────────────
# config load
# ────────────────────────────────────────────────────────────────────────
def load_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        example = path.with_name("config.example.yaml")
        if example.exists():
            sys.stderr.write(
                f"[!] {path.name} not found. Copy {example.name} → "
                f"{path.name} and edit before running.\n"
            )
        else:
            sys.stderr.write(f"[!] {path} not found and no example nearby.\n")
        sys.exit(2)
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


# ────────────────────────────────────────────────────────────────────────
# pre-flight probe (same shape as desktop harness)
# ────────────────────────────────────────────────────────────────────────
FATAL_INPUT_MARKERS = (
    "InvalidURL", "No host supplied", "MissingSchema",
    "InvalidSchema", "empty target",
)
FATAL_NETWORK_MARKERS = (
    # DNS
    "NXDOMAIN", "Name or service not known",
    "nodename nor servname provided", "getaddrinfo failed",
    "Temporary failure in name resolution",
    # Transport
    "Connection refused",
    "No route to host", "Network is unreachable",
    "Network unreachable",
)


def preflight_reachable(target: str, timeout_sec: int = 10,
                        attribution_headers: dict | None = None
                        ) -> tuple[bool, str]:
    """Best-effort probe. Any HTTP status counts as ALIVE.
    Only network-level failures count as DEAD."""
    t = (target or "").strip()
    if not t:
        return False, "empty target"
    urls: list[str] = []
    if t.startswith("http://") or t.startswith("https://"):
        urls.append(t)
    else:
        urls.append(f"https://{t}")
        urls.append(f"http://{t}")
    headers = dict(attribution_headers or {})
    last_err = "no error"
    for url in urls:
        try:
            r = requests.get(url, headers=headers, timeout=timeout_sec,
                             allow_redirects=False, verify=False)
            return True, f"HTTP {r.status_code} from {url}"
        except requests.exceptions.SSLError as e:
            return True, f"SSL error from {url} (server is up): {str(e)[:120]}"
        except requests.exceptions.ConnectTimeout:
            last_err = f"connect timeout ({timeout_sec}s) to {url}"
        except requests.exceptions.ReadTimeout:
            return True, f"slow response from {url} (server is up)"
        except requests.exceptions.ConnectionError as e:
            last_err = (f"connection error to {url}: "
                        f"{type(e).__name__}: {str(e)[:120]}")
        except Exception as e:
            last_err = f"{type(e).__name__}: {str(e)[:120]}"
    return False, last_err


def preflight_verdict(alive: bool, reason: str,
                      strict: bool) -> tuple[bool, str]:
    """Return (abort, why). abort=True means stop before the agent loop."""
    if alive:
        return False, ""
    is_input = any(m in reason for m in FATAL_INPUT_MARKERS)
    is_net = any(m in reason for m in FATAL_NETWORK_MARKERS)
    if strict or is_input or is_net:
        if is_input:
            why = "invalid target URL"
        elif is_net:
            why = "network unreachable (DNS/connect-refused/no-route)"
        else:
            why = "preflight.strict"
        return True, why
    return False, "soft-continue (probe failed but not fatal)"


def target_from_objective(objective: str) -> str:
    """Return the first http(s):// URL or bare host mentioned in the
    objective, or empty string. Used only to steer the pre-flight probe."""
    for tok in (objective or "").split():
        if tok.startswith("http://") or tok.startswith("https://"):
            return tok.rstrip(".,;:")
    return ""


# ────────────────────────────────────────────────────────────────────────
# agent loop  (LLM ↔ tools)
# ────────────────────────────────────────────────────────────────────────
def run_agent_loop(client: LLMClient, tools: Tools, sess: Session,
                   messages: list[dict], max_iterations: int,
                   max_wall_time_sec: int,
                   temperature: float, max_tokens: int) -> int:
    """Run the LLM<->tools loop mutating `messages` in-place.
    Return the number of iterations executed."""
    t0 = time.monotonic()
    iters = 0
    while iters < max_iterations:
        elapsed = time.monotonic() - t0
        if elapsed >= max_wall_time_sec:
            sess.write("kill", reason=f"max_wall_time_sec {max_wall_time_sec}s")
            print(f"\n[kill] wall time cap {max_wall_time_sec}s hit "
                  f"after {iters} iterations.")
            break
        iters += 1
        try:
            reply = client.chat(messages, tools=openai_schemas(),
                                temperature=temperature,
                                max_tokens=max_tokens)
        except Exception as e:
            sess.write("kill", reason=f"llm error: {type(e).__name__}: {e}")
            print(f"\n[error] LLM call failed: {e}")
            break
        content = reply.get("content") or ""
        tool_calls = reply.get("tool_calls") or []
        sess.write("llm_reply", content=content, tool_calls=tool_calls)

        if content:
            print(f"\n[assistant]\n{redact(content).rstrip()}")
        if not tool_calls and not content:
            sess.write("kill", reason="empty reply")
            break
        messages.append({"role": "assistant",
                         "content": content,
                         "tool_calls": tool_calls})
        for tc in tool_calls:
            fn = (tc.get("function") or {})
            name = fn.get("name", "")
            raw_args = fn.get("arguments") or "{}"
            try:
                args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
            except Exception:
                args = {}
            sess.write("tool_call", name=name, args=args)
            print(f"[tool] {name}({_short_args(args)})")
            result = tools.dispatch(name, args)
            sess.write("tool_result", name=name, result=result)
            print(f"[result] {result[:400]}"
                  + (" [...trunc]" if len(result) > 400 else ""))
            messages.append({"role": "tool",
                             "tool_call_id": tc.get("id", ""),
                             "name": name,
                             "content": result})
        if tools.finished:
            sess.write("finish", summary=tools.finish_summary)
            print(f"\n[finish] {tools.finish_summary}")
            break
    return iters


def _short_args(args: dict, max_len: int = 120) -> str:
    try:
        s = json.dumps(args, ensure_ascii=False)
    except Exception:
        s = str(args)
    return s if len(s) <= max_len else s[:max_len] + "…"


# ────────────────────────────────────────────────────────────────────────
# REPL sticky-flag parser
# ────────────────────────────────────────────────────────────────────────
_STICKY_FLAGS = {
    "--scope", "--header",
    "--skip-preflight", "--strict-preflight",
    "--max-iterations", "--max-wall-time-sec",
    "--servertype", "--model", "--base-url",
    "--config", "--scope-file",
}


def parse_repl_line(line: str) -> tuple[str, dict[str, Any]]:
    """Split a REPL line into (leftover_text, parsed_flags).
    Sticky flags are pulled out; anything else is joined back as the
    objective text."""
    try:
        parts = shlex.split(line)
    except ValueError:
        return line, {}
    remaining: list[str] = []
    flags: dict[str, Any] = {}
    i = 0
    while i < len(parts):
        t = parts[i]
        if t == "--scope" and i + 1 < len(parts):
            flags.setdefault("scope", []).append(parts[i + 1])
            i += 2; continue
        if t == "--header" and i + 1 < len(parts):
            flags.setdefault("header", []).append(parts[i + 1])
            i += 2; continue
        if t in ("--skip-preflight",):
            flags["skip_preflight"] = True
            i += 1; continue
        if t in ("--strict-preflight",):
            flags["strict_preflight"] = True
            i += 1; continue
        if t == "--max-iterations" and i + 1 < len(parts):
            try:
                flags["max_iterations"] = int(parts[i + 1])
            except ValueError:
                pass
            i += 2; continue
        if t == "--max-wall-time-sec" and i + 1 < len(parts):
            try:
                flags["max_wall_time_sec"] = int(parts[i + 1])
            except ValueError:
                pass
            i += 2; continue
        if t in ("--servertype", "--model", "--base-url",
                 "--config", "--scope-file") and i + 1 < len(parts):
            key = t.lstrip("-").replace("-", "_")
            flags[key] = parts[i + 1]
            i += 2; continue
        remaining.append(t)
        i += 1
    return " ".join(remaining), flags


def _looks_like_target(text: str) -> bool:
    """Heuristic: URL / bare host with TLD / IP / CIDR / wildcard sub,
    OR a natural-language objective (≥4 words)."""
    t = (text or "").strip()
    if not t:
        return False
    if t.startswith("http://") or t.startswith("https://"):
        return True
    if "/" in t and any(c.isdigit() for c in t):
        return True  # CIDR-ish
    if t.startswith("*.") and "." in t[2:]:
        return True
    if "." in t and all(c.isalnum() or c in ".-:_*" for c in t):
        return True  # bare host
    return len(t.split()) >= 4  # NL objective


def _did_you_mean_quit(line: str) -> str | None:
    """1-edit-distance typos of quit/bye/exit → suggest the /form."""
    low = line.lower().strip()
    for target in ("quit", "bye", "exit", "q"):
        if low == target:
            return f"/{target}"
        if abs(len(low) - len(target)) <= 1 and _levenshtein(low, target) == 1:
            return f"/{target}"
    return None


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(curr[-1] + 1, prev[j] + 1,
                            prev[j - 1] + (ca != cb)))
        prev = curr
    return prev[-1]


# ────────────────────────────────────────────────────────────────────────
# REPL
# ────────────────────────────────────────────────────────────────────────
def _prompt_reader():
    """Return a callable `() -> str` that reads one line with history if
    prompt_toolkit is available, otherwise falls back to input()."""
    try:
        from prompt_toolkit import PromptSession
        from prompt_toolkit.history import FileHistory
        hist_path = str(Path.home() / ".harness_lite_history")
        pt = PromptSession(history=FileHistory(hist_path))
        return lambda: pt.prompt("> ")
    except Exception:
        return lambda: input("> ")


def prompt_for_objective(is_first: bool, reader) -> str | None:
    """Ask stdin for a new objective. Returns text, or None on quit/EOF."""
    try:
        if is_first:
            print("\nObjective (one-line goal for the agent). "
                  "Type /quit or /bye to exit.")
            print("Inline flags (sticky): --scope PAT (repeat)  "
                  "--header \"N: V\" (repeat)  --skip-preflight  "
                  "--strict-preflight")
            print("Target: bare URL, or full sentence describing the goal")
            print('Example:  --scope "*.example.com" '
                  '--header "X-HackerOne-Researcher: yourhandle" '
                  'Fingerprint https://www.example.com')
        else:
            print("\n─── Previous session ended ───")
            print("New objective (or /quit / /bye to exit).")
        line = reader().strip()
    except (EOFError, KeyboardInterrupt):
        print("\n[!] Cancelled.")
        return None
    if not line:
        print("[!] Empty objective — enter some text, or /quit to exit.")
        return prompt_for_objective(is_first=is_first, reader=reader)
    if line.lower() in QUIT_COMMANDS:
        return None
    if line.lower() in HELP_COMMANDS:
        print(HELP_TEXT)
        return prompt_for_objective(is_first=False, reader=reader)

    dym = _did_you_mean_quit(line)
    if dym is not None:
        print(f"[!] Unknown input '{line}'. Did you mean '{dym}' (exit) ?")
        print(f"    If you meant a target, add a TLD (e.g. '{line}.com') "
              f"or paste the full URL.")
        return prompt_for_objective(is_first=is_first, reader=reader)

    if line.startswith("/") and line.lower() not in QUIT_COMMANDS \
            and line.lower() not in HELP_COMMANDS:
        print(f"[!] Unknown REPL command '{line}'.")
        print(REPL_COMMANDS_HINT)
        return prompt_for_objective(is_first=is_first, reader=reader)

    stripped, flags = parse_repl_line(line)
    if not stripped:
        # Line was only sticky flags → valid "update settings" line.
        if flags:
            return line
        print("[!] No target provided (only flags parsed).")
        print(REPL_COMMANDS_HINT)
        return prompt_for_objective(is_first=is_first, reader=reader)
    if not _looks_like_target(stripped):
        print(f"[!] '{stripped}' doesn't look like a target (URL / host "
              f"with TLD / IP / CIDR / wildcard) or a natural-language "
              f"objective (≥4 words).")
        print(REPL_COMMANDS_HINT)
        return prompt_for_objective(is_first=is_first, reader=reader)
    return line


def apply_sticky(state: dict, flags: dict) -> None:
    """Fold parsed REPL flags into the running state dict."""
    if "scope" in flags:
        # Empty first entry clears; else replace-and-append this run
        if flags["scope"] == [""]:
            state["scope"] = []
            print("[+] scope cleared (sticky).")
        else:
            state["scope"] = list(flags["scope"])
            print(f"[+] scope set (sticky): {state['scope']}")
    if "header" in flags:
        if flags["header"] == [""]:
            state["headers"] = {}
            print("[+] headers cleared (sticky).")
        else:
            for h in flags["header"]:
                if ":" in h:
                    k, v = h.split(":", 1)
                    state.setdefault("headers", {})[k.strip()] = v.strip()
                    print(f"[+] header set (sticky): {k.strip()}: {v.strip()}")
    if "skip_preflight" in flags:
        state["skip_preflight"] = True
        print("[+] skip_preflight = True (sticky).")
    if "strict_preflight" in flags:
        state["strict_preflight"] = True
        print("[+] strict_preflight = True (sticky).")
    for k in ("max_iterations", "max_wall_time_sec"):
        if k in flags:
            state[k] = flags[k]
            print(f"[+] {k} = {flags[k]} (sticky).")
    for k in ("servertype", "model", "base_url"):
        if k in flags:
            state[k] = flags[k]
            print(f"[+] llm.{k} = {flags[k]} (sticky).")


def run_repl(cfg: dict, cli_args: argparse.Namespace) -> int:
    """REPL loop: each accepted line = fresh one-shot with that objective."""
    reader = _prompt_reader()
    is_first = True
    # Sticky state carried across sessions in this REPL
    state: dict[str, Any] = {
        "scope": list(cli_args.scope) if cli_args.scope else [],
        "headers": {},
        "skip_preflight": cli_args.skip_preflight,
        "strict_preflight": cli_args.strict_preflight,
        "max_iterations": cli_args.max_iterations,
        "max_wall_time_sec": cli_args.max_wall_time_sec,
    }
    while True:
        line = prompt_for_objective(is_first=is_first, reader=reader)
        if line is None:
            print("Goodbye!")
            return 0
        objective, flags = parse_repl_line(line)
        if flags:
            apply_sticky(state, flags)
        if not objective:
            # Only-flags line: refresh state, no session
            is_first = False
            continue
        # Bare URL → treat as recon objective for readability in the log
        if _looks_like_target(objective) and " " not in objective.strip():
            objective = f"Recon {objective.strip()} — fingerprint tech and note anything obvious."
        rc = run_one_shot(cfg, cli_args, state, objective)
        if rc == 130:
            return 130  # Ctrl+C mid-session → exit REPL too
        is_first = False


# ────────────────────────────────────────────────────────────────────────
# one-shot session runner
# ────────────────────────────────────────────────────────────────────────
def run_one_shot(cfg: dict, cli_args: argparse.Namespace,
                 state: dict, objective: str) -> int:
    """Run ONE agent loop for `objective`. Uses state (sticky REPL flags)
    where set, falling back to cli_args / config."""
    # Scope
    scope_patterns = state.get("scope") or (list(cli_args.scope) if cli_args.scope else None)
    scope = ScopeChecker(
        scope_file=cli_args.scope_file if not scope_patterns else None,
        patterns=scope_patterns if scope_patterns else None,
    )
    if not (scope.hosts or scope.wildcards or scope.networks):
        sys.stderr.write("[!] Empty scope. Add hosts to scope.txt or pass "
                         "--scope example.com. Refusing to run.\n")
        return 2

    # Backend (state overrides win over config)
    llm_cfg = dict(cfg.get("llm") or {})
    for k in ("servertype", "base_url", "model"):
        if state.get(k):
            llm_cfg[k] = state[k]
    stype, base_url, api_key = resolve_backend({"llm": llm_cfg})
    model = str(llm_cfg.get("model") or "").strip()
    if not model:
        sys.stderr.write("[!] llm.model missing in config.yaml. "
                         "Set it to the exact id LM Studio/Ollama serves "
                         "(e.g. 'bughunter-v9').\n")
        return 2
    client = LLMClient(stype, base_url, api_key, model,
                       timeout_sec=int(llm_cfg.get("timeout_sec", 300)))

    # Tools
    lim_cfg = cfg.get("limits") or {}
    throttle_cfg = cfg.get("throttle") or {}
    rate = RateLimiter(float(throttle_cfg.get("min_interval_sec", 1.0)))
    attribution = dict(cfg.get("attribution_headers") or {})
    attribution.update(state.get("headers") or {})
    oob_cfg = cfg.get("oob") or {}
    oob_host = str(oob_cfg.get("host") or "").strip()
    oob_token_prefix = str(oob_cfg.get("token_prefix") or "lite").strip()
    tools = Tools(scope=scope, rate=rate,
                  attribution_headers=attribution,
                  oob_host=oob_host, oob_token_prefix=oob_token_prefix,
                  shell_timeout_sec=int(lim_cfg.get("shell_timeout_sec", 60)),
                  http_timeout_sec=int(lim_cfg.get("http_timeout_sec", 20)))

    # Session
    sess = Session(SESSIONS_DIR, objective=objective, config_snapshot={
        "backend": stype, "base_url": base_url, "model": model,
        "scope": {"hosts": sorted(scope.hosts), "wildcards": scope.wildcards,
                  "networks": [str(n) for n in scope.networks]},
        "limits": lim_cfg, "throttle": throttle_cfg,
        "oob_host": oob_host, "oob_token_prefix": oob_token_prefix,
        "sticky": {k: v for k, v in state.items() if k != "headers"},
    })

    # Pre-flight
    skip = bool(state.get("skip_preflight") or cli_args.skip_preflight)
    strict = bool(state.get("strict_preflight")
                  or cli_args.strict_preflight
                  or (cfg.get("preflight") or {}).get("strict", False))
    if not skip:
        target = target_from_objective(objective)
        if target:
            alive, reason = preflight_reachable(
                target,
                timeout_sec=int((cfg.get("preflight") or {}).get("timeout_sec", 10)),
                attribution_headers=attribution,
            )
            abort, why = preflight_verdict(alive, reason, strict)
            print(f"[+] Pre-flight: {'ALIVE' if alive else 'UNREACHABLE'} · {reason}")
            if abort:
                print(f"[!] TARGET UNREACHABLE — aborting ({why}).")
                sess.write("kill", reason=f"preflight {why}: {reason}")
                sess.close(iterations=0)
                return 1

    max_iter = state.get("max_iterations") or int(lim_cfg.get("max_iterations", 20))
    max_wall = state.get("max_wall_time_sec") or int(lim_cfg.get("max_wall_time_sec", 900))

    base_messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Objective: {objective}"},
    ]

    def _on_sigint(_signum, _frame):
        sess.write("sigint")
        print("\n^C — closing session.")
        try:
            sess.close(iterations=0)
        finally:
            os._exit(130)
    prev = signal.signal(signal.SIGINT, _on_sigint)
    try:
        iters = run_agent_loop(
            client, tools, sess, base_messages,
            max_iterations=max_iter,
            max_wall_time_sec=max_wall,
            temperature=float(llm_cfg.get("temperature", 0.1)),
            max_tokens=int(llm_cfg.get("max_tokens", 1024)),
        )
        sess.close(iterations=iters)
        return 0
    except Exception as e:
        sess.write("kill", reason=f"unhandled: {type(e).__name__}: {e}")
        sess.close(iterations=0)
        raise
    finally:
        signal.signal(signal.SIGINT, prev)


# ────────────────────────────────────────────────────────────────────────
# CLI
# ────────────────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="harness-lite",
        description="Mobile-first LLM bug-bounty agent. Runs a small "
                    "OpenAI-compatible loop with a hard-coded toolbox and "
                    "strict scope/rate/redact gates. Same UX as the desktop "
                    "bughunter-harness — smaller toolbox and no orchestrator.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="For the full flag reference and REPL commands, run without "
               "--objective and read the printed HELP_TEXT.",
    )
    p.add_argument("--objective", default="",
                   help="One-shot goal. If empty, drops into REPL.")
    p.add_argument("--scope", action="append", default=[],
                   help="Add a host/wildcard/CIDR to in-scope. Repeatable. "
                        "Overrides scope.txt when given.")
    p.add_argument("--header", action="append", default=[],
                   help='Extra HTTP header "N: V" added to every request. '
                        'Repeatable.')
    p.add_argument("--scope-file", default=str(DEFAULT_SCOPE),
                   help="Path to scope.txt (default: scope.txt in cwd).")
    p.add_argument("--config", default=str(DEFAULT_CFG),
                   help="Path to config.yaml (default: config.yaml in cwd).")
    p.add_argument("--servertype", default="",
                   help="LLM backend override "
                        "(auto|lmstudio|ollama|llamacpp|openai|anthropic|"
                        "nvidia|gemini).")
    p.add_argument("--model", default="",
                   help="LLM model id override.")
    p.add_argument("--base-url", default="",
                   help="OpenAI-compatible endpoint override.")
    p.add_argument("--skip-preflight", action="store_true",
                   help="Skip the reachability probe (VPN/allowlist targets).")
    p.add_argument("--strict-preflight", action="store_true",
                   help="Abort if the reachability probe fails "
                        "(overrides config.preflight.strict).")
    p.add_argument("--max-iterations", type=int, default=0,
                   help="Override config.limits.max_iterations.")
    p.add_argument("--max-wall-time-sec", type=int, default=0,
                   help="Override config.limits.max_wall_time_sec.")
    return p.parse_args()


def _print_banner_safe() -> None:
    """Print banner to stderr. Auto-disables when stderr isn't a TTY
    (piped, --help, NO_COLOR). Never raises."""
    try:
        from banner import print_banner
        print_banner()
    except Exception:
        pass


def main() -> int:
    args = parse_args()

    cfg = load_config(Path(args.config))

    # CLI overrides for llm.* into the loaded config
    llm_cfg = cfg.setdefault("llm", {})
    if args.servertype:
        llm_cfg["servertype"] = args.servertype
    if args.model:
        llm_cfg["model"] = args.model
    if args.base_url:
        llm_cfg["base_url"] = args.base_url

    # Header CLI → attribution_headers
    if args.header:
        attribution = dict(cfg.setdefault("attribution_headers", {}))
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                attribution[k.strip()] = v.strip()
        cfg["attribution_headers"] = attribution

    if args.objective:
        # One-shot mode: banner at the top (no prompt to stick it to),
        # then straight to the run. No HELP_TEXT dump.
        _print_banner_safe()
        state: dict[str, Any] = {
            "scope": list(args.scope) if args.scope else [],
            "headers": {},
            "skip_preflight": args.skip_preflight,
            "strict_preflight": args.strict_preflight,
            "max_iterations": args.max_iterations,
            "max_wall_time_sec": args.max_wall_time_sec,
        }
        return run_one_shot(cfg, args, state, args.objective)

    # REPL mode: HELP first, then banner right before the prompt.
    # Order requested by the operator (2026-09-11): banner should sit
    # flush against the '>' so it's the last thing you see before typing.
    print(HELP_TEXT)
    _print_banner_safe()
    return run_repl(cfg, args)


if __name__ == "__main__":
    sys.exit(main())
