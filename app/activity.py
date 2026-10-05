"""The activity log: what was done, when and by whom, for the admin to read in the app.

Every INFO or WARNING line the app logs while handling a request is also kept in the
database (the per-request access line and background jobs are not). The log lines are
written for this page too, so they name things rather than ids and never carry secrets.
"""
from __future__ import annotations

import logging

from flask import g, has_request_context, request, session

from . import db

_SKIPPED_FORMATS = (
    "%s %s %s %.0fms",       # the access line: one per request
    "Re-authenticated: %s",  # follows every key download; the download itself is logged
)


def _message(record: logging.LogRecord) -> str:
    """The line as logged, except a failed sign-in: what was typed as the user name is kept only
    when it is a real account, since people type passwords into that field by mistake."""
    if record.msg == "Failed login for %r from %s" and isinstance(record.args, tuple) and record.args:
        typed = str(record.args[0])
        return f"Failed sign-in for {typed}" if db.get_user(typed) else "Failed sign-in for an unknown user name"
    return record.getMessage()


class ActivityHandler(logging.Handler):
    """Copies request-time log lines into the activity log. It never raises: a log line that
    can't be stored must not fail the request that wrote it."""

    def emit(self, record: logging.LogRecord) -> None:
        if not has_request_context() or record.msg in _SKIPPED_FORMATS or str(record.msg).startswith("Relay envelope"):
            return
        try:
            user = g.get("user")
            if user:
                actor = user["username"]
            elif request.path.startswith("/api/pal/v1/"):
                actor = "a PC"  # signed by its device key; the line names it
            elif session.get("user"):
                actor = session["user"]  # signing in: the session is set, the request's user isn't yet
            else:
                actor = "not signed in"
            level = "warning" if record.levelno >= logging.WARNING else "info"
            db.add_activity(actor, request.remote_addr or "", level, _message(record))
        except Exception:  # noqa: BLE001 - see the class docstring
            self.handleError(record)


def install(logger: logging.Logger) -> None:
    if not any(isinstance(h, ActivityHandler) for h in logger.handlers):
        logger.addHandler(ActivityHandler(level=logging.INFO))
    if logger.getEffectiveLevel() > logging.INFO:
        logger.setLevel(logging.INFO)  # the log page records INFO lines whatever the console shows
