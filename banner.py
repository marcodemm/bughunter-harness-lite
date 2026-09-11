"""Startup banner — compact 3-row ASCII art of BUGHUNTER / HARNESS /
LITE / MANU + a small beetle, rendered in red à la Hexstrike. Printed
once at the top of `main()` before any REPL output.

The block letters are the "mini" figlet font: 3 rows per word, ≤26 cols
wide for the widest word (BUGHUNTER). Everything fits inside a portrait-
mode mobile terminal (~40 cols) as well as a normal desktop terminal —
no adaptive-width logic needed, one banner works everywhere. The old
6-row block glyphs looked great on Mac but wrapped illegibly on a Kali
NetHunter chroot on Android; this compact version was chosen after a
real screenshot showed only LITE (the smallest 6-row word) rendered
correctly on the phone.

Colors are ANSI escapes; auto-disabled when stderr is not a TTY (piped
runs, `--help`, `NO_COLOR` env, etc.) so log files stay clean.
"""
from __future__ import annotations

import os
import sys


_RED = "\033[38;5;196m"       # bright red (xterm-256)
_RED_BOLD = "\033[1;91m"      # bold bright red — reserved for the beetle
_DIM = "\033[2m"
_RESET = "\033[0m"


# ─── ASCII text: BUGHUNTER (3 rows, ~26 cols — mini figlet) ────────────
_BUGHUNTER = r"""
 _     __         ____ _
|_)| |/__|_|| ||\ |||_|_)
|_)|_|\_|| ||_|| \|||_| \
"""

# ─── ASCII text: HARNESS (3 rows, ~23 cols — mini figlet) ──────────────
_HARNESS = r"""
        _      _ __ __
|_| /\ |_)|\ ||_(_ (_
| |/--\| \| \||___)__)
"""

# ─── ASCII text: LITE (3 rows, ~10 cols — mini figlet) ─────────────────
_LITE = r"""
  _______
|  |  ||_
|__|_ ||_
"""

# ─── MANU + beetle side by side (3 rows, ~28 cols total) ───────────────
# The beetle sits to the right of MANU on the same 3 lines so the block
# keeps the same vertical strip as the others.
_MANU_BEETLE = r"""
                 .--.
|\/| /\ |\ || | ((oo))
|  |/--\| \||_|  `--'
"""


# Two-line compact tagline (fits ~40 cols on portrait mobile).
_TAGLINE_1 = "autonomous local-LLM pentest agent"
_TAGLINE_2 = "rate · scope · redact"


def _colors_ok() -> bool:
    """Return True when ANSI colors should be emitted to stderr.
    Disabled when: NO_COLOR set, TERM=dumb, or stderr isn't a TTY."""
    if os.environ.get("NO_COLOR"):
        return False
    if (os.environ.get("TERM") or "").lower() == "dumb":
        return False
    try:
        return bool(sys.stderr.isatty())
    except Exception:
        return False


def render_banner(color: bool | None = None) -> str:
    """Return the full banner as a string. Color pass optional — defaults
    to auto-detection via _colors_ok()."""
    if color is None:
        color = _colors_ok()
    parts = [_BUGHUNTER, _HARNESS, _LITE, _MANU_BEETLE]
    body = "\n".join(p.rstrip() for p in parts)
    tagline = f"  {_TAGLINE_1}\n  {_TAGLINE_2}"
    if color:
        return (f"{_RED}{body}{_RESET}\n"
                f"{_DIM}{tagline}{_RESET}\n")
    return f"{body}\n{tagline}\n"


def print_banner() -> None:
    """Print the banner to stderr (so it doesn't mix with tool JSON on
    stdout). No-op if it can't render for any reason — the banner is
    decorative, never critical."""
    try:
        sys.stderr.write(render_banner())
        sys.stderr.flush()
    except Exception:
        # Never let a decorative banner break a run
        pass
