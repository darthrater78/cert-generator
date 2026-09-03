"""Production server entry point for Docker / standalone deployment."""
from __future__ import annotations

import logging
import os
import secrets

from waitress import serve

from .db import (
    delete_trusted_devices,
    get_user,
    init_db,
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
            log.warning("RESET_MFA: disabled MFA and cleared trusted devices for '%s'", reset_mfa)

    reset_pw = os.environ.get("RESET_PASSWORD")
    if reset_pw:
        if ":" not in reset_pw:
            log.error("RESET_PASSWORD: expected 'username:newpassword'")
        else:
            username, new_password = reset_pw.split(":", 1)
            if reset_user_password(username, new_password):
                log.warning("RESET_PASSWORD: password reset for '%s'", username)
            else:
                log.error("RESET_PASSWORD: user '%s' not found", username)


def main() -> None:
    logging.basicConfig(
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO),
    )
    init_db()
    _run_admin_resets()
    app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "5000"))
    set_bound_port(port)
    logging.getLogger("cert-generator").info("Listening on http://%s:%d", host, port)
    serve(app, host=host, port=port, threads=4)


if __name__ == "__main__":
    main()
