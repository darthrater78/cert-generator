from __future__ import annotations

import socket
import sys
import threading
import webbrowser

import webview
from werkzeug.serving import make_server

from .db import init_db
from .server import app, set_bound_port

ALLOWED_EXTERNAL_HOSTS = {"github.com"}


class Api:
    def open_external(self, url: str) -> None:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.hostname not in ALLOWED_EXTERNAL_HOSTS:
            return
        webbrowser.open(url)


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
        js_api=Api(),
    )
    window.events.closing += on_closing
    webview.start()

    sys.exit(0)


if __name__ == "__main__":
    main()
