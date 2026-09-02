"""Production server entry point for Docker / standalone deployment."""
from __future__ import annotations

import os
import secrets

from waitress import serve

from .db import init_db
from .server import app, set_bound_port


def main() -> None:
    init_db()
    app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "5000"))
    set_bound_port(port)
    print(f"Cert Generator listening on http://{host}:{port}")
    serve(app, host=host, port=port, threads=4)


if __name__ == "__main__":
    main()
