# dashboard/server.py
"""HTTP server that queues commands from the web UI."""
from __future__ import annotations

import json
import queue
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from commands.base import drain_log_lines, wait_for_log

_STATIC_HTML: str | None = None


def _load_html() -> str:
    global _STATIC_HTML
    if _STATIC_HTML is None:
        _STATIC_HTML = (Path(__file__).resolve().parent / "index.html").read_text(encoding="utf-8")
    return _STATIC_HTML


class CommandHttpServer(ThreadingHTTPServer):
    """HTTP server that holds a shared command queue."""

    def __init__(self, addr: tuple[str, int], cmd_queue: queue.Queue[str]):
        super().__init__(addr, _Handler)
        self.command_queue = cmd_queue


class _Handler(BaseHTTPRequestHandler):
    server_version = "BotConsole/1.0"

    def log_message(self, _fmt: str, *_args) -> None:
        return

    def _json(self, status: HTTPStatus, data: dict) -> None:
        body = json.dumps(data, ensure_ascii=True).encode()
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, status: HTTPStatus, html: str) -> None:
        body = html.encode()
        self.send_response(int(status))
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _enqueue(self, cmd: str) -> None:
        assert isinstance(self.server, CommandHttpServer)
        self.server.command_queue.put(cmd)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path in ("/", "/dashboard"):
            self._html(HTTPStatus.OK, _load_html())
            return

        if parsed.path == "/health":
            self._json(HTTPStatus.OK, {"ok": True})
            return

        if parsed.path == "/logs":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            try:
                while True:
                    wait_for_log(timeout=5.0)
                    for line in drain_log_lines():
                        self.wfile.write(f"data: {json.dumps(line)}\n\n".encode())
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                return

        if parsed.path == "/cmd":
            qs = parse_qs(parsed.query)
            cmd = qs.get("q", qs.get("cmd", [""]))[0].strip()
            if not cmd:
                self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "missing q"})
                return
            self._enqueue(cmd)
            self._json(HTTPStatus.ACCEPTED, {"ok": True, "queued": cmd})
            return

        self._json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/cmd":
            self._json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not found"})
            return

        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length).decode("utf-8", errors="replace").strip() if length else ""
        ct = (self.headers.get("Content-Type") or "").lower()

        cmd = ""
        if "application/json" in ct:
            try:
                obj = json.loads(raw or "{}")
            except json.JSONDecodeError:
                self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "invalid json"})
                return
            if isinstance(obj, dict):
                cmd = str(obj.get("cmd", "")).strip()
        else:
            cmd = raw

        if not cmd:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "empty command"})
            return

        self._enqueue(cmd)
        self._json(HTTPStatus.ACCEPTED, {"ok": True, "queued": cmd})


def start_server(cmd_queue: queue.Queue[str], host: str, port: int) -> CommandHttpServer:
    """Create, start (daemon thread), and return the dashboard HTTP server."""
    srv = CommandHttpServer((host, port), cmd_queue)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"[INFO] Dashboard: http://{host}:{port}")
    return srv