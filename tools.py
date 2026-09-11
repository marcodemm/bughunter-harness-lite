"""Tools exposed to the LLM. Mobile-friendly subset — every heavy scanner
that either needs raw sockets, a headless browser, or long-running crawls
is excluded on purpose.

Included:
  http_get(url)           HTTP GET with attribution headers
  http_post(url, body)    HTTP POST (JSON or urlencoded)
  run_shell(command)      allowlisted CLI runner
  oob_generate_token()    fresh OOB catcher URL under the configured host
  finish(summary)         end the run cleanly

Excluded (see README): katana (JS crawl too heavy on ARM chroot), gowitness
(Chrome headless), sqlmap (multi-minute runs), dalfox, nikto, masscan/nmap
(need raw sockets).

Every call goes through: scope check → rate limit → shell allowlist/denylist
→ execute → redact output → return. None of these gates live in the prompt.
"""
from __future__ import annotations

import json
import re
import shlex
import subprocess
import time
from typing import Any
from urllib.parse import urlparse

import requests

from redact import redact
from scope import ScopeChecker
from throttle import RateLimiter

# Strip ANSI escape sequences (colors, cursor moves, etc.) from tool
# output. Tools like nuclei/httpx/subfinder colorize their stdout with
# escapes like `\x1b[92mfoo\x1b[0m`; the LLM sees those as noise and
# they inflate the context budget. This regex matches the CSI (Control
# Sequence Introducer) family plus OSC (Operating System Command) — enough
# to cover 100% of what these CLIs actually emit.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|\x1b\][^\x07]*\x07")


def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s or "")


# Allowed first-token of any shell command. Kept short on purpose — every
# addition is an audit item.
SHELL_ALLOWLIST = {
    "curl", "dig", "host", "whois",
    "httpx", "subfinder", "gau", "waybackurls",
    "nuclei", "ffuf", "wpscan",
}

# Flags/patterns that abort the command regardless of the allowed binary.
# Keeps a run destructive-safe even if the model tries something creative.
SHELL_DENYLIST_PATTERNS = [
    # Destructive verbs on the target
    "-X DELETE", "-X PUT", "-X PATCH",
    # Heavy scans / evasion / OS-facing
    "-T4", "-T5", "-sS", "-sU", "-A ",
    # Shell metachars that let you chain arbitrary commands
    "|", ";", "&&", "||", "`", "$(",
    # Redirects out
    ">", "<",
    # Privilege / persistence
    "sudo", "chmod", "chown", "rm ", "mv ", "cp ",
    # Backticks in flags
    "--data-binary @/",   # can exfil local files
]

# Nuclei is allowed only with `-id <template>` (single template) — never
# with `-tags cve` or `-w wordlist` which scans thousands. Enforced below.
NUCLEI_REQUIRE_ID_FLAG = True


def _is_scope_host(scope: ScopeChecker, url_or_host: str) -> tuple[bool, str]:
    """Return (in_scope, host_resolved). host_resolved is what we checked."""
    if not url_or_host:
        return False, ""
    if "://" in url_or_host:
        host = urlparse(url_or_host).hostname or ""
    else:
        # Bare host — strip any :port
        host = url_or_host.split("/", 1)[0].split(":", 1)[0]
    return scope.is_in_scope(host), host


def openai_schemas() -> list[dict]:
    """Tool schemas advertised to the model. Keep names + descriptions
    STABLE across releases — the model was fine-tuned on these."""
    return [
        {"type": "function", "function": {
            "name": "http_get",
            "description": "HTTP GET a URL. Automatically adds attribution "
                           "headers. URL host must be in scope.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Full URL."},
                    "headers": {"type": "object", "description":
                                "Optional extra headers as name:value."},
                },
                "required": ["url"],
            },
        }},
        {"type": "function", "function": {
            "name": "http_post",
            "description": "HTTP POST. Body is either a raw string or a JSON "
                           "object (auto-serialized). URL must be in scope.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "body": {"type": "string",
                             "description": "Request body (string)."},
                    "content_type": {"type": "string",
                                     "description": "Default application/json."},
                    "headers": {"type": "object"},
                },
                "required": ["url", "body"],
            },
        }},
        {"type": "function", "function": {
            "name": "run_shell",
            "description": "Run an allowlisted CLI. First token must be one "
                           "of: curl, dig, host, whois, httpx, subfinder, "
                           "gau, waybackurls, nuclei (only with -id <id>), "
                           "ffuf, wpscan. No pipes, redirects, sudo, rm.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                },
                "required": ["command"],
            },
        }},
        {"type": "function", "function": {
            "name": "oob_generate_token",
            "description": "Return a fresh OOB catcher URL to embed in a "
                           "payload. Hits are visible in the operator's own "
                           "catcher panel.",
            "parameters": {
                "type": "object",
                "properties": {
                    "purpose": {"type": "string",
                                "description": "Short tag (ssrf/xxe/blind-xss/etc.)"},
                },
                "required": ["purpose"],
            },
        }},
        {"type": "function", "function": {
            "name": "finish",
            "description": "End the run cleanly with a short summary of what "
                           "you found (or that you found nothing).",
            "parameters": {
                "type": "object",
                "properties": {
                    "summary": {"type": "string"},
                },
                "required": ["summary"],
            },
        }},
    ]


class Tools:
    """Dispatcher. Feed it the LLM's tool_call payload; get back a string
    result (already redacted) that the harness sends back as tool role."""

    def __init__(self, scope: ScopeChecker, rate: RateLimiter,
                 attribution_headers: dict[str, str],
                 oob_host: str = "", oob_token_prefix: str = "lite",
                 shell_timeout_sec: int = 60,
                 http_timeout_sec: int = 20,
                 scope_mode: str = "strict"):
        self.scope = scope
        self.rate = rate
        self.attribution_headers = dict(attribution_headers)
        self.oob_host = oob_host.rstrip("/")
        # Prefix stamped on every OOB token so multiple harnesses hitting the
        # same catcher panel stay distinguishable (e.g. `harness-*` for the
        # desktop pipeline vs `lite-*` for this one).
        _pref = (oob_token_prefix or "lite").strip().lower()
        self.oob_token_prefix = "".join(
            c for c in _pref if c.isalnum() or c in "-_"
        )[:20] or "lite"
        self.shell_timeout_sec = shell_timeout_sec
        self.http_timeout_sec = http_timeout_sec
        # scope_enforcement: how strict is the scope gate?
        #   strict → out-of-scope host = ERROR, tool refuses.
        #   warn   → out-of-scope host = [WARN] prefixed, tool RUNS anyway.
        #   off    → no gate at all.
        # Same three modes as the desktop bughunter-harness so an operator
        # switching between them gets identical behaviour.
        self.scope_mode = (scope_mode or "strict").lower()
        if self.scope_mode not in ("strict", "warn", "off"):
            self.scope_mode = "strict"
        self.finished: bool = False
        self.finish_summary: str = ""
        self._oob_counter = 0

    def _scope_gate(self, host: str) -> tuple[bool, str]:
        """Decide whether `host` passes the scope gate.
        Returns (allowed, prefix_to_prepend_to_output)."""
        if not host:
            return (True, "")
        if self.scope_mode == "off":
            return (True, "")
        if self.scope.is_in_scope(host):
            return (True, "")
        if self.scope_mode == "warn":
            return (True, f"[WARN] host '{host}' not in scope "
                          f"(scope_enforcement=warn — allowed, audit "
                          f"manually).\n")
        # strict
        return (False, f"ERROR: host '{host}' not in scope. "
                       f"Add to scope.txt or --scope, or relax "
                       f"config.scope_enforcement to 'warn'.")

    # ── entry point ───────────────────────────────────────────────────
    def dispatch(self, name: str, args: dict[str, Any]) -> str:
        """Route by tool name. Errors come back as strings starting with
        'ERROR:' — the model can then adapt on the next turn."""
        args = args or {}
        try:
            if name == "http_get":
                return self._http_get(args)
            if name == "http_post":
                return self._http_post(args)
            if name == "run_shell":
                return self._run_shell(args)
            if name == "oob_generate_token":
                return self._oob_generate(args)
            if name == "finish":
                return self._finish(args)
            return f"ERROR: unknown tool '{name}'"
        except Exception as e:
            return f"ERROR: {type(e).__name__}: {str(e)[:400]}"

    # ── tools ─────────────────────────────────────────────────────────
    def _http_get(self, args: dict) -> str:
        url = str(args.get("url", "")).strip()
        headers = dict(args.get("headers") or {})
        _, host = _is_scope_host(self.scope, url)
        allowed, prefix = self._scope_gate(host)
        if not allowed:
            return prefix
        self.rate.wait()
        merged = {**self.attribution_headers, **headers}
        r = requests.get(url, headers=merged,
                         timeout=self.http_timeout_sec,
                         allow_redirects=False, verify=False)
        return prefix + self._format_http(r)

    def _http_post(self, args: dict) -> str:
        url = str(args.get("url", "")).strip()
        body = args.get("body", "")
        content_type = str(args.get("content_type") or "application/json")
        headers = dict(args.get("headers") or {})
        _, host = _is_scope_host(self.scope, url)
        allowed, prefix = self._scope_gate(host)
        if not allowed:
            return prefix
        self.rate.wait()
        merged = {"Content-Type": content_type,
                  **self.attribution_headers, **headers}
        r = requests.post(url, headers=merged, data=body,
                          timeout=self.http_timeout_sec,
                          allow_redirects=False, verify=False)
        return prefix + self._format_http(r)

    def _run_shell(self, args: dict) -> str:
        cmd = str(args.get("command", "")).strip()
        if not cmd:
            return "ERROR: empty command"
        # Denylist first — any hit kills the call outright
        low = cmd.lower()
        for pat in SHELL_DENYLIST_PATTERNS:
            if pat.lower() in low:
                return f"ERROR: shell denylist match '{pat}'"
        try:
            parts = shlex.split(cmd)
        except ValueError as e:
            return f"ERROR: shell parse failed: {e}"
        if not parts:
            return "ERROR: empty command"
        binary = parts[0].split("/")[-1]  # strip path if fully-qualified
        if binary not in SHELL_ALLOWLIST:
            return (f"ERROR: '{binary}' not in shell allowlist. "
                    f"Allowed: {sorted(SHELL_ALLOWLIST)}")
        if binary == "nuclei" and NUCLEI_REQUIRE_ID_FLAG:
            if "-id" not in parts and "--template-id" not in parts:
                return ("ERROR: nuclei must be called with -id <template> "
                        "on lite (bulk template runs are excluded).")
        # Best-effort scope check for tools that take a URL/host as first arg
        prefix = ""
        for i, tok in enumerate(parts[1:], start=1):
            if tok.startswith("http://") or tok.startswith("https://"):
                _, host = _is_scope_host(self.scope, tok)
                allowed, p = self._scope_gate(host)
                if not allowed:
                    return f"ERROR: shell arg host '{host}' not in scope"
                prefix = p
                break
            if tok.startswith("-"):
                continue
            # Bare host as positional (subfinder -d example.com etc.)
            if "." in tok and "/" not in tok and self._looks_like_host(tok):
                _, host = _is_scope_host(self.scope, tok)
                allowed, p = self._scope_gate(host)
                if not allowed:
                    return f"ERROR: shell arg host '{host}' not in scope"
                prefix = p
                break
        self.rate.wait()
        t0 = time.monotonic()
        try:
            proc = subprocess.run(parts, capture_output=True, text=True,
                                  timeout=self.shell_timeout_sec)
        except subprocess.TimeoutExpired:
            elapsed = time.monotonic() - t0
            return (f"ERROR: shell timeout after {elapsed:.1f}s "
                    f"(cap {self.shell_timeout_sec}s)")
        # Strip ANSI colors from both streams — projectdiscovery tools
        # (nuclei/httpx/subfinder), rich-formatted CLIs and any Ruby gem
        # that respects TTY emit color codes that only add noise for an
        # LLM consumer.
        stdout_clean = _strip_ansi(proc.stdout or "")
        stderr_clean = _strip_ansi(proc.stderr or "")
        out = stdout_clean + (
            f"\n[stderr]\n{stderr_clean}" if stderr_clean else "")
        # Cap output to keep the LLM context tight
        MAX = 4000
        if len(out) > MAX:
            out = out[:MAX] + f"\n[...truncated {len(out) - MAX} chars]"
        return prefix + redact(f"[exit={proc.returncode}]\n{out}")

    def _oob_generate(self, args: dict) -> str:
        purpose = str(args.get("purpose") or "hit").strip().lower()
        purpose = "".join(c for c in purpose if c.isalnum() or c in "-_")[:20]
        if not self.oob_host:
            return ("ERROR: no oob_host configured. Set oob.host in "
                    "config.yaml.")
        self._oob_counter += 1
        token = (f"{self.oob_token_prefix}-{purpose or 'hit'}-"
                 f"{int(time.time())}-{self._oob_counter:03d}")
        return f"{self.oob_host}/oob/{token}"

    def _finish(self, args: dict) -> str:
        self.finished = True
        self.finish_summary = str(args.get("summary") or "").strip()
        return "OK — session finished."

    # ── helpers ───────────────────────────────────────────────────────
    # HTTP headers worth keeping on a 404 short-circuit — they're the only
    # ones a fingerprint can lean on, and they're usually identical to what
    # the root already exposed, so keeping just these three is enough.
    _404_FINGERPRINT_HEADERS = ("Server", "X-Powered-By", "Content-Type")

    def _format_http(self, r: requests.Response) -> str:
        # Short-circuit 404 responses: small models tend to read every
        # non-200 as "exists", which then bloats the finish() summary
        # with false positives ("Robot files, security.txt, phpinfo.php,
        # git config, .env, phpinfo.php all exist"). A 404 body is
        # almost always the generic error page of the stack (WP theme
        # 404, Apache default), never useful signal — dropping it also
        # saves 500-2000 tokens of context per probe, which matters on
        # a 3B model with num_ctx=4096.
        if r.status_code == 404:
            kept = "\n".join(
                f"{k}: {v}" for k, v in r.headers.items()
                if k in self._404_FINGERPRINT_HEADERS
            )
            rendered = (
                f"HTTP 404 Not Found\n"
                f"URL: {r.url}\n"
                f"--- headers (fingerprint only) ---\n{kept}\n"
                f"--- note ---\n"
                f"Path does not exist on this server. "
                f"DO NOT list it in the finish() summary as an existing "
                f"path or finding. Move on to the next probe."
            )
            return redact(rendered)
        MAX_BODY = 3000
        body = r.text or ""
        if len(body) > MAX_BODY:
            body = body[:MAX_BODY] + f"\n[...truncated {len(body) - MAX_BODY} chars]"
        headers_str = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        rendered = (f"HTTP {r.status_code} {r.reason}\n"
                    f"URL: {r.url}\n"
                    f"--- headers ---\n{headers_str}\n"
                    f"--- body ---\n{body}")
        return redact(rendered)

    @staticmethod
    def _looks_like_host(tok: str) -> bool:
        # Cheap heuristic — a bare domain or IPv4-like string
        if tok.count(".") == 0:
            return False
        return all(c.isalnum() or c in ".-:" for c in tok)
