"""Process-wide runtime state shared by the web modules.

Read these as ``state.app_token`` (not ``from .state import app_token``) so
changes made after import are visible.
"""
from __future__ import annotations

# Set by the desktop launcher; None means server mode (login-based auth).
app_token: str | None = None
bound_port: int | None = None


def desktop_mode() -> bool:
    return app_token is not None
