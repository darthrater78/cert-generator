"""Production server entry point for Docker / standalone deployment."""
from __future__ import annotations

import logging
import os
import secrets

from waitress import serve

from .db import init_db
from .server import app, set_bound_port


def main() -> None:
    logging.basicConfig(
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO),
    )
    init_db()
    app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "5000"))
    set_bound_port(port)
    logging.getLogger("cert-generator").info("Listening on http://%s:%d", host, port)
    serve(app, host=host, port=port, threads=4)


if __name__ == "__main__":
    main()
