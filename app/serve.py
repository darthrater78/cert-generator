"""Production server entry point for Docker / standalone deployment."""
from __future__ import annotations

import logging
import os
import signal
import sys

from waitress import serve

from .legacy_exports import find_legacy_exports, legacy_export_dir

from .db import (
    bump_session_version,
    delete_trusted_devices,
    get_user,
    password_too_long,
    reset_user_password,
    update_user_require_password,
    update_user_totp,
)
from .server import app, set_bound_port

log = logging.getLogger("cert-generator")


def _run_admin_resets() -> None:
    reset_mfa = os.environ.get("RESET_MFA")
    if reset_mfa:
        user = get_user(reset_mfa)
        if user is None:
            log.error("RESET_MFA: user '%s' not found", reset_mfa)
        else:
            update_user_totp(user["id"], None, False)
            update_user_require_password(user["id"], False)
            delete_trusted_devices(user["id"])
            bump_session_version(user["id"])
            log.warning("RESET_MFA: disabled MFA, cleared trusted devices, and ended sessions for '%s'. "
                        "Remove RESET_MFA from the environment now.", reset_mfa)

    reset_pw = os.environ.get("RESET_PASSWORD")
    if reset_pw:
        if ":" not in reset_pw:
            log.error("RESET_PASSWORD: expected 'username:newpassword'")
        else:
            username, new_password = reset_pw.split(":", 1)
            if len(new_password) < 8 or password_too_long(new_password):
                log.error("RESET_PASSWORD: new password must be 8 characters to 72 bytes")
            elif reset_user_password(username, new_password):
                log.warning("RESET_PASSWORD: password reset, trusted devices cleared, and sessions ended for '%s'. "
                            "Remove RESET_PASSWORD from the environment now.", username)
            else:
                log.error("RESET_PASSWORD: user '%s' not found", username)


def _warn_about_configuration() -> None:
    if not os.environ.get("SECRET_KEY"):
        log.warning("SECRET_KEY is not set: a random key is in use and everyone must sign in again after a restart")
    legacy = find_legacy_exports()
    if legacy:
        log.warning("%s contains %d export files written by versions before 2.0.0, which may include "
                    "unencrypted private keys. Delete them from Encryption Settings in the web UI.",
                    legacy_export_dir(), len(legacy))


def _exit_on_sigterm(signum: int, _frame) -> None:
    # A container's PID 1 has no default SIGTERM handler, so `docker stop` would
    # otherwise wait out its timeout and kill the process.
    log.info("Received signal %d, shutting down", signum)
    sys.exit(0)


def main() -> None:
    logging.basicConfig(
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO),
    )
    # The database is initialised when app.server is imported.
    _run_admin_resets()
    _warn_about_configuration()
    # 0.0.0.0 is needed inside a container; set HOST=127.0.0.1 behind a local reverse proxy.
    host = os.environ.get("HOST", "0.0.0.0")  # nosec B104
    port = int(os.environ.get("PORT", "5000"))
    set_bound_port(port)
    signal.signal(signal.SIGTERM, _exit_on_sigterm)
    log.info("Listening on http://%s:%d", host, port)
    serve(app, host=host, port=port, threads=4)
    log.info("Server stopped")


if __name__ == "__main__":
    main()
