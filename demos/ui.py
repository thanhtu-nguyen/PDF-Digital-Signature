"""ui.py - small console helpers so the live demo is easy to follow."""

import os
import sys

if os.name == "nt":
    os.system("")  # enable ANSI escape codes in the Windows console
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

_USE_COLOR = (sys.stdout.isatty() or bool(os.environ.get("FORCE_COLOR"))) and not os.environ.get("NO_COLOR")


def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text


def banner(title):
    line = "=" * 72
    print("\n" + _c("1;36", line))
    print(_c("1;36", f"  {title}"))
    print(_c("1;36", line))


def step(text):
    print("\n" + _c("1;33", f">> {text}"))


def info(label, value=""):
    print(f"   {label:<28}{value}")


def ok(text):
    print(_c("1;32", f"   [OK]   {text}"))


def fail(text):
    print(_c("1;31", f"   [FAIL] {text}"))


def alert(text):
    print(_c("1;35", f"   [!!]   {text}"))


def short_hex(x, width=24):
    h = f"{x:064x}" if isinstance(x, int) else x.hex()
    return h if len(h) <= width * 2 else f"{h[:width]}...{h[-8:]}"


def pause(enabled):
    if enabled:
        input("\n   (press Enter to continue)")
