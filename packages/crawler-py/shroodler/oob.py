"""Local HTTP out-of-band (OOB) collaborator for SSRF / XXE / blind SQLi.

Stdlib only. The target fetches a minted callback URL; probes wait briefly
and upgrade confidence when a hit is logged. Not persisted to state.json.
"""

from __future__ import annotations

import secrets
import threading
import time
import weakref
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

_DEFAULT_WAIT = 3.0
_HEADER_CAP = 20
_HEADER_VALUE_CAP = 200
_active_ref: Any = None


class OOBError(Exception):
    """Collaborator configuration or bind failure."""


class OOBBindError(OOBError):
    """Raised when the HTTP listener cannot bind."""


@dataclass
class OOBHit:
    token: str
    method: str
    path: str
    remote: str
    headers: dict[str, str]
    at: str  # ISO-8601


@dataclass
class OOBToken:
    token: str
    url: str


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _cap_headers(raw: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    if raw is None:
        return out
    items = raw.items() if hasattr(raw, "items") else []
    for i, (key, value) in enumerate(items):
        if i >= _HEADER_CAP:
            break
        out[str(key)] = str(value)[:_HEADER_VALUE_CAP]
    return out


def parse_listen(spec: str) -> tuple[str, int]:
    """Parse HOST:PORT. Raises OOBError on invalid input."""
    text = (spec or "").strip() or "127.0.0.1:8765"
    host, sep, port_s = text.rpartition(":")
    if not sep or not host.strip() or not port_s.strip():
        raise OOBError(
            f"invalid OOB listen address {spec!r}; expected HOST:PORT"
        )
    try:
        port = int(port_s)
    except ValueError as exc:
        raise OOBError(
            f"invalid OOB listen port in {spec!r}; expected HOST:PORT"
        ) from exc
    if port < 0 or port > 65535:
        raise OOBError(f"invalid OOB listen port {port} in {spec!r}")
    return host.strip(), port


def confirm_oob(
    collab: OOBCollaborator | None,
    token: str,
    timeout: float = _DEFAULT_WAIT,
) -> OOBHit | None:
    """Wait briefly for a callback hit. None if collaborator is inactive."""
    if collab is None or not token:
        return None
    return collab.wait_for_hit(token, timeout=timeout)


def collaborator_of(
    oob: Any | None = None,
    state: Any | None = None,
) -> OOBCollaborator | None:
    if oob is not None:
        return oob
    found = getattr(state, "oob", None)
    if found is not None:
        return found
    return active()


def set_active(collab: OOBCollaborator | None) -> None:
    global _active_ref
    _active_ref = weakref.ref(collab) if collab is not None else None


def active() -> OOBCollaborator | None:
    if _active_ref is None:
        return None
    return _active_ref()


class _Handler(BaseHTTPRequestHandler):
    collaborator: OOBCollaborator

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return

    def _read_body(self) -> None:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            length = 0
        if length > 0:
            try:
                self.rfile.read(length)
            except OSError:
                pass

    def _record(self, *, write_body: bool = True) -> None:
        collab = getattr(self, "collaborator", None)
        if collab is not None:
            collab._record_request(self)
        try:
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if write_body:
                self.wfile.write(body)
        except OSError:
            pass

    def do_GET(self) -> None:  # noqa: N802
        self._record()

    def do_HEAD(self) -> None:  # noqa: N802
        self._record(write_body=False)

    def do_POST(self) -> None:  # noqa: N802
        self._read_body()
        self._record()


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


@dataclass
class OOBCollaborator:
    listen_host: str
    listen_port: int
    public_base: str | None = None
    _server: _Server | None = field(default=None, init=False, repr=False)
    _thread: threading.Thread | None = field(default=None, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    _log: dict[str, list[OOBHit]] = field(default_factory=dict, init=False, repr=False)
    _public_base_arg: str | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self.listen_host = str(self.listen_host or "127.0.0.1").strip() or "127.0.0.1"
        self.listen_port = int(self.listen_port)
        raw = (self.public_base or "").strip() or None
        self._public_base_arg = raw.rstrip("/") if raw else None
        self.public_base = self._public_base_arg

    @property
    def server_address(self) -> tuple[str, int]:
        if self._server is not None:
            host, port = self._server.server_address[:2]
            return str(host), int(port)
        return self.listen_host, int(self.listen_port)

    def _callback_base(self) -> str:
        if self._public_base_arg:
            return self._public_base_arg
        host, port = self.server_address
        if host in {"0.0.0.0", "::", ""}:
            host = "127.0.0.1"
        return f"http://{host}:{port}"

    def start(self) -> None:
        if self._server is not None:
            return
        handler = type(
            "OOBHandler",
            (_Handler,),
            {"collaborator": self},
        )
        try:
            server = _Server((self.listen_host, int(self.listen_port)), handler)
        except OSError as exc:
            raise OOBBindError(
                f"OOB collaborator failed to bind {self.listen_host}:{self.listen_port}: {exc}"
            ) from exc
        except OverflowError as exc:
            raise OOBBindError(
                f"OOB collaborator failed to bind {self.listen_host}:{self.listen_port}: {exc}"
            ) from exc
        self._server = server
        bound_host, bound_port = server.server_address[:2]
        self.listen_host = str(bound_host)
        self.listen_port = int(bound_port)
        self.public_base = self._callback_base()
        thread = threading.Thread(
            target=server.serve_forever,
            name="shroodler-oob",
            daemon=True,
        )
        self._thread = thread
        thread.start()

    def stop(self) -> None:
        server = self._server
        thread = self._thread
        self._server = None
        self._thread = None
        if server is not None:
            try:
                server.shutdown()
            except Exception:  # noqa: BLE001
                pass
            try:
                server.server_close()
            except Exception:  # noqa: BLE001
                pass
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)

    def mint(self, prefix: str = "") -> OOBToken:
        raw = secrets.token_urlsafe(16)
        label = "".join(ch for ch in (prefix or "") if ch.isalnum() or ch in "-_")
        token = f"{label}-{raw}" if label else raw
        with self._lock:
            self._log.setdefault(token, [])
        url = f"{self._callback_base()}/{token}"
        return OOBToken(token=token, url=url)

    def hits(self, token: str) -> list[OOBHit]:
        with self._lock:
            return list(self._log.get(token) or [])

    def wait_for_hit(self, token: str, timeout: float = _DEFAULT_WAIT) -> OOBHit | None:
        deadline = time.monotonic() + max(0.0, float(timeout))
        while True:
            found = self.hits(token)
            if found:
                return found[0]
            if time.monotonic() >= deadline:
                return None
            time.sleep(0.05)

    def summary(self) -> str:
        with self._lock:
            n_hits = sum(len(rows) for rows in self._log.values())
            n_tok = len(self._log)
        return f"oob {self._callback_base()} tokens={n_tok} hits={n_hits}"

    def _known_tokens(self) -> set[str]:
        with self._lock:
            return set(self._log)

    def _token_from_path(self, raw_path: str) -> str | None:
        parsed = urlparse(raw_path or "")
        known = self._known_tokens()
        qs = parse_qs(parsed.query, keep_blank_values=True)
        for value in qs.get("oob") or []:
            if value in known:
                return value
        parts = [seg for seg in (parsed.path or "/").strip("/").split("/") if seg]
        for seg in parts:
            if seg in known:
                return seg
        return None

    def _record_request(self, handler: BaseHTTPRequestHandler) -> None:
        token = self._token_from_path(getattr(handler, "path", "") or "")
        if not token:
            return
        remote = ""
        addr = getattr(handler, "client_address", None)
        if addr:
            remote = str(addr[0])
        hit = OOBHit(
            token=token,
            method=str(getattr(handler, "command", "") or "GET"),
            path=str(getattr(handler, "path", "") or ""),
            remote=remote,
            headers=_cap_headers(getattr(handler, "headers", None)),
            at=_now_iso(),
        )
        with self._lock:
            self._log.setdefault(token, []).append(hit)

    def record_hit_for_tests(self, token: str, **kwargs: Any) -> OOBHit:
        """Pre-seed a hit (unit tests)."""
        hit = OOBHit(
            token=token,
            method=str(kwargs.get("method") or "GET"),
            path=str(kwargs.get("path") or f"/{token}"),
            remote=str(kwargs.get("remote") or "127.0.0.1"),
            headers=dict(kwargs.get("headers") or {}),
            at=str(kwargs.get("at") or _now_iso()),
        )
        with self._lock:
            self._log.setdefault(token, []).append(hit)
        return hit


def start_from_config(config: Any) -> OOBCollaborator:
    """Bind a collaborator from AgentConfig. Raises OOBError on failure."""
    host, port = parse_listen(str(getattr(config, "oob_listen", None) or "127.0.0.1:8765"))
    public = str(getattr(config, "oob_public_url", "") or "").strip() or None
    collab = OOBCollaborator(host, port, public)
    collab.start()
    return collab
