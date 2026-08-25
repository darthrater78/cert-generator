from __future__ import annotations

import os
import socket
import threading

import webview
from werkzeug.serving import make_server

from .db import init_db
from .server import app, set_bound_port


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main() -> None:
    init_db()

    port = _find_free_port()
    set_bound_port(port)

    server = make_server("127.0.0.1", port, app, threaded=True)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    def on_closing() -> None:
        server.shutdown()

    window = webview.create_window(
        "Cert Generator",
        f"http://127.0.0.1:{port}",
        width=1100,
        height=720,
        min_size=(800, 500),
    )
    window.events.closing += on_closing
    webview.start()

    os._exit(0)


if __name__ == "__main__":
    main()
