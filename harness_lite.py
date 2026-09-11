#!/usr/bin/env python3
"""bughunter-harness-lite — mobile-first LLM pentest agent.

Two entry modes:
  one-shot:   `python harness_lite.py --objective "..." --scope example.com`
  repl:       `python harness_lite.py` (with or without --scope)

One-shot exits when the model calls finish(), hits max_iterations, or wall
time. REPL keeps the same LLM context between turns and adds a few slash
commands (/help /tools /scope /save /exit).

Design goals: fit in an Android chroot + Ollama + 3B model, keep the same
security gates as the desktop harness, session-log everything to JSONL,
never talk to a host outside scope, never bypass rate limit.
"""
from __future__ import annotations

import argparse
import json
import os
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

# System prompt kept small on purpose — a 3B model with num_ctx=4096 has to
# spend most of the budget on tool results, not on scaffolding.
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


# ────────────────────────────────────────────────────────────────────────
# agent loop
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

        # Print the assistant text (redacted just in case)
        if content:
            print(f"\n[assistant]\n{redact(content).rstrip()}")
        # If model didn't call any tool AND has no content, break to avoid
        # infinite empty turns (rare on Ollama with a 3B model but seen).
        if not tool_calls and not content:
            sess.write("kill", reason="empty reply")
            break
        # Append the assistant message to history
        messages.append({"role": "assistant",
                         "content": content,
                         "tool_calls": tool_calls})
        # Dispatch each tool call, append result
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
        # If the model produced text but no tool_calls, one more turn to let
        # it either call a tool or finish() — but that's counted in iters.
    return iters


def _short_args(args: dict, max_len: int = 120) -> str:
    """Compact repr of tool args for the printout."""
    try:
        s = json.dumps(args, ensure_ascii=False)
    except Exception:
        s = str(args)
    return s if len(s) <= max_len else s[:max_len] + "…"


# ────────────────────────────────────────────────────────────────────────
# REPL
# ────────────────────────────────────────────────────────────────────────
REPL_HELP = """REPL commands:
  /help                     show this
  /tools                    list available tools
  /scope [list|add HOST]    inspect or add to in-memory scope
  /save NAME                save current messages to sessions/NAME.json
  /clear                    reset conversation (keeps scope, tools, session)
  /exit                     leave

Anything not starting with '/' is sent to the model as a user turn.
"""


def repl_loop(client: LLMClient, tools: Tools, sess: Session, scope: ScopeChecker,
              base_messages: list[dict], cfg: dict) -> None:
    print("REPL ready. '/help' for commands, '/exit' to quit.")
    messages = list(base_messages)
    try:
        from prompt_toolkit import PromptSession
        from prompt_toolkit.history import FileHistory
        hist_path = str(Path.home() / ".harness_lite_history")
        pt = PromptSession(history=FileHistory(hist_path))
        prompt_fn = lambda: pt.prompt("> ")
    except Exception:
        prompt_fn = lambda: input("> ")

    while True:
        try:
            line = prompt_fn()
        except (EOFError, KeyboardInterrupt):
            print("\nbye.")
            return
        s = (line or "").strip()
        if not s:
            continue
        if s.startswith("/"):
            parts = s.split(None, 2)
            cmd = parts[0].lower()
            if cmd in ("/exit", "/quit"):
                return
            if cmd == "/help":
                print(REPL_HELP)
                continue
            if cmd == "/tools":
                for t in openai_schemas():
                    fn = t["function"]
                    print(f"  {fn['name']:22} {fn['description']}")
                continue
            if cmd == "/scope":
                sub = parts[1].lower() if len(parts) > 1 else "list"
                if sub == "list":
                    print("hosts:", sorted(scope.hosts))
                    print("wildcards:", scope.wildcards)
                    print("networks:", [str(n) for n in scope.networks])
                elif sub == "add" and len(parts) > 2:
                    scope._ingest_lines([parts[2]])
                    print(f"added: {parts[2]}")
                else:
                    print("usage: /scope [list|add HOST]")
                continue
            if cmd == "/clear":
                messages = list(base_messages)
                print("conversation cleared (scope + tools preserved).")
                continue
            if cmd == "/save" and len(parts) > 1:
                name = parts[1].strip()
                out = SESSIONS_DIR / f"{name}.json"
                out.write_text(json.dumps(messages, ensure_ascii=False, indent=2),
                               encoding="utf-8")
                print(f"saved: {out}")
                continue
            print(f"unknown command: {cmd} (see /help)")
            continue
        # Regular user turn
        messages.append({"role": "user", "content": s})
        max_iter_per_turn = int((cfg.get("limits") or {}).get(
            "max_iterations_per_repl_turn", 4))
        run_agent_loop(client, tools, sess, messages,
                       max_iterations=max_iter_per_turn,
                       max_wall_time_sec=int((cfg.get("limits") or {})
                                              .get("max_wall_time_sec", 900)),
                       temperature=float((cfg.get("llm") or {})
                                          .get("temperature", 0.1)),
                       max_tokens=int((cfg.get("llm") or {})
                                       .get("max_tokens", 1024)))
        # Reset finish flag so the REPL can keep going after the model called
        # finish() on the previous turn.
        tools.finished = False


# ────────────────────────────────────────────────────────────────────────
# main
# ────────────────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="harness-lite",
        description="Mobile-first LLM bug-bounty agent. Runs a small "
                    "OpenAI-compatible loop with a hard-coded toolbox and "
                    "strict scope/rate/redact gates.",
    )
    p.add_argument("--objective", default="",
                   help="One-shot goal. If empty, drops into REPL.")
    p.add_argument("--scope", action="append", default=[],
                   help="Add a host/wildcard/CIDR to in-scope. Repeatable. "
                        "Overrides scope.txt when given.")
    p.add_argument("--scope-file", default=str(DEFAULT_SCOPE),
                   help="Path to scope.txt (default: scope.txt in cwd).")
    p.add_argument("--config", default=str(DEFAULT_CFG),
                   help="Path to config.yaml (default: config.yaml in cwd).")
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


def main() -> int:
    args = parse_args()
    cfg = load_config(Path(args.config))

    # Scope
    scope = ScopeChecker(
        scope_file=args.scope_file if not args.scope else None,
        patterns=args.scope if args.scope else None,
    )
    if not (scope.hosts or scope.wildcards or scope.networks):
        sys.stderr.write("[!] Empty scope. Add hosts to scope.txt or pass "
                         "--scope example.com. Refusing to run.\n")
        return 2

    # Backend
    stype, base_url, api_key = resolve_backend(cfg)
    llm_cfg = cfg.get("llm") or {}
    model = str(llm_cfg.get("model") or "").strip()
    if not model:
        sys.stderr.write("[!] llm.model missing in config.yaml. "
                         "Set it to the exact id LM Studio/Ollama serves "
                         "(e.g. 'bughunter-v9').\n")
        return 2
    client = LLMClient(stype, base_url, api_key, model,
                       timeout_sec=int(llm_cfg.get("timeout_sec", 300)))

    # Rate limit + tools
    lim_cfg = cfg.get("limits") or {}
    throttle_cfg = cfg.get("throttle") or {}
    rate = RateLimiter(float(throttle_cfg.get("min_interval_sec", 1.0)))
    attribution = dict(cfg.get("attribution_headers") or {})
    oob_cfg = cfg.get("oob") or {}
    oob_host = str(oob_cfg.get("host") or "").strip()
    oob_token_prefix = str(oob_cfg.get("token_prefix") or "lite").strip()
    tools = Tools(scope=scope, rate=rate,
                  attribution_headers=attribution,
                  oob_host=oob_host, oob_token_prefix=oob_token_prefix,
                  shell_timeout_sec=int(lim_cfg.get("shell_timeout_sec", 60)),
                  http_timeout_sec=int(lim_cfg.get("http_timeout_sec", 20)))

    # Session
    sess = Session(SESSIONS_DIR, objective=args.objective, config_snapshot={
        "backend": stype, "base_url": base_url, "model": model,
        "scope": {"hosts": sorted(scope.hosts), "wildcards": scope.wildcards,
                  "networks": [str(n) for n in scope.networks]},
        "limits": lim_cfg, "throttle": throttle_cfg,
        "oob_host": oob_host,
    })

    # Pre-flight (only if we have an objective with a target-looking URL)
    if args.objective and not args.skip_preflight:
        target = _target_from_objective(args.objective)
        if target:
            alive, reason = preflight_reachable(
                target,
                timeout_sec=int((cfg.get("preflight") or {}).get("timeout_sec", 10)),
                attribution_headers=attribution,
            )
            pf_strict = bool(args.strict_preflight
                             or (cfg.get("preflight") or {}).get("strict", False))
            abort, why = preflight_verdict(alive, reason, pf_strict)
            print(f"[+] Pre-flight: {'ALIVE' if alive else 'UNREACHABLE'} · {reason}")
            if abort:
                print(f"[!] TARGET UNREACHABLE — aborting ({why}).")
                sess.write("kill", reason=f"preflight {why}: {reason}")
                sess.close(iterations=0)
                return 1

    # SIGINT clean-up
    def _on_sigint(_signum, _frame):
        sess.write("sigint")
        print("\n^C — closing session.")
        try:
            sess.close(iterations=0)
        finally:
            os._exit(130)
    signal.signal(signal.SIGINT, _on_sigint)

    base_messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
    ]
    if args.objective:
        base_messages.append({"role": "user",
                              "content": f"Objective: {args.objective}"})

    max_iter = args.max_iterations or int(lim_cfg.get("max_iterations", 20))
    max_wall = args.max_wall_time_sec or int(lim_cfg.get("max_wall_time_sec", 900))

    try:
        if args.objective:
            iters = run_agent_loop(
                client, tools, sess, base_messages,
                max_iterations=max_iter,
                max_wall_time_sec=max_wall,
                temperature=float(llm_cfg.get("temperature", 0.1)),
                max_tokens=int(llm_cfg.get("max_tokens", 1024)),
            )
            sess.close(iterations=iters)
            return 0
        # REPL mode
        repl_loop(client, tools, sess, scope, base_messages, cfg)
        sess.close(iterations=0)
        return 0
    except Exception as e:
        sess.write("kill", reason=f"unhandled: {type(e).__name__}: {e}")
        sess.close(iterations=0)
        raise


def _target_from_objective(objective: str) -> str:
    """Return the first http(s):// URL or bare host mentioned in the
    objective, or empty string. Used only to steer the pre-flight probe."""
    for tok in objective.split():
        if tok.startswith("http://") or tok.startswith("https://"):
            return tok.rstrip(".,;:")
    return ""


if __name__ == "__main__":
    sys.exit(main())
