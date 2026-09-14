"""Production server entry point for Docker / standalone deployment."""
from __future__ import annotations

import logging
import os
from pathlib import Path

from waitress import serve

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
    export_dir = os.environ.get("EXPORT_DIR")
    if export_dir and Path(export_dir).is_dir() and any(Path(export_dir).iterdir()):
        log.warning("%s contains files written by earlier versions. Exports are no longer stored "
                    "on the server, and these files may include unencrypted private keys: review and delete them.",
                    export_dir)


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
    log.info("Listening on http://%s:%d", host, port)
    serve(app, host=host, port=port, threads=4)


if __name__ == "__main__":
    main()
