from __future__ import annotations

import threading

import webview

from .db import init_db
from .server import app


def main() -> None:
    init_db()

    server_thread = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=5174, use_reloader=False),
        daemon=True,
    )
    server_thread.start()

    webview.create_window(
        "Cert Generator",
        "http://127.0.0.1:5174",
        width=1100,
        height=720,
        min_size=(800, 500),
    )
    webview.start()


if __name__ == "__main__":
    main()
