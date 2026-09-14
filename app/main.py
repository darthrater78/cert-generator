"""Desktop entry point: runs the server on loopback inside a pywebview window."""
from __future__ import annotations

import secrets
import socket
import sys
import threading
import webbrowser
from urllib.parse import urlparse

ALLOWED_EXTERNAL_HOSTS = {"github.com"}

WINDOW_OPTIONS = {"width": 1100, "height": 720, "min_size": (800, 500)}


class Api:
    def open_external(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.hostname not in ALLOWED_EXTERNAL_HOSTS:
            return
        webbrowser.open(url)


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_desktop_server():
    """Start the app on a random loopback port with a fresh token; returns (server, url)."""
    # Imported here so --self-test can point the database at a temp dir first.
    from werkzeug.serving import make_server

    from .server import app, set_app_token, set_bound_port

    port = _find_free_port()
    token = secrets.token_urlsafe(32)
    set_bound_port(port)
    set_app_token(token)

    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{port}/_auth?token={token}"


def main() -> None:
    if len(sys.argv) >= 2 and sys.argv[1] in ("--self-test", "--self-test-gui"):
        from .selftest import run

        sys.exit(run(gui=sys.argv[1] == "--self-test-gui", output=sys.argv[2] if len(sys.argv) > 2 else None))

    import webview

    server, url = start_desktop_server()
    window = webview.create_window("Cert Generator", url, js_api=Api(), **WINDOW_OPTIONS)
    window.events.closing += server.shutdown
    webview.start()
    sys.exit(0)


if __name__ == "__main__":
    main()
