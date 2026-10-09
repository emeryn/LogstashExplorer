"""Forwarding of application and audit logs to a remote syslog server (configured from the admin UI).

Logging calls never wait on the network: records go through a bounded in-memory queue drained by a
background thread. When the server is unreachable, records are dropped and counted instead of piling
up in memory, and reconnection is attempted at most every RETRY_S seconds. Nothing here logs through
the `logging` module itself (that would loop back into the queue).
"""

import json
import logging
import logging.handlers
import os
import queue
import socket
import ssl
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from app.core.security import tls_context

FACILITIES = {"kern": 0, "user": 1, "daemon": 3, "auth": 4, **{f"local{i}": 16 + i for i in range(8)}}
QUEUE_SIZE = 10_000
RETRY_S = 30.0
TIMEOUT_S = 5.0


@dataclass(frozen=True)
class SyslogTarget:
    host: str
    port: int
    protocol: Literal["udp", "tcp", "tls"]
    framing: Literal["octet_counting", "lf"] = "octet_counting"  # TCP/TLS only (RFC 6587 / RFC 5425)
    facility: str = "local0"
    client_cert: str | None = None  # PEM, TLS client authentication (mTLS)
    client_key: str | None = None


def build_tls_context(target: SyslogTarget) -> ssl.SSLContext:
    """System trust store + PKI-injected CAs, hostname verification, optional client certificate."""
    ctx = tls_context()
    ctx.check_hostname = True
    if target.client_cert and target.client_key:
        # load_cert_chain only reads files: write them briefly to the private tmpfs, then delete.
        with tempfile.TemporaryDirectory() as tmp:
            cert, key = Path(tmp) / "cert.pem", Path(tmp) / "key.pem"
            cert.write_text(target.client_cert)
            key.touch(mode=0o600)
            key.write_text(target.client_key)
            ctx.load_cert_chain(cert, key)
    return ctx


class SyslogSender:
    """One connection to the server. Not thread-safe: used by the single forwarding thread (or a test)."""

    def __init__(self, target: SyslogTarget):
        self.target = target
        self._tls = build_tls_context(target) if target.protocol == "tls" else None
        self._sock: socket.socket | None = None

    def _connect(self) -> socket.socket:
        t = self.target
        if t.protocol == "udp":
            family, _, _, _, addr = socket.getaddrinfo(t.host, t.port, type=socket.SOCK_DGRAM)[0]
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.connect(addr)
            return sock
        sock = socket.create_connection((t.host, t.port), timeout=TIMEOUT_S)
        if self._tls is not None:
            sock = self._tls.wrap_socket(sock, server_hostname=t.host)
        return sock

    def frame(self, message: str) -> bytes:
        data = message.encode("utf-8", errors="replace")
        if self.target.protocol == "udp":
            return data
        if self.target.framing == "lf":
            return data.replace(b"\n", b" ") + b"\n"
        return f"{len(data)} ".encode() + data

    def send(self, message: str) -> None:
        if self._sock is None:
            self._sock = self._connect()
        self._sock.sendall(self.frame(message))

    def close(self) -> None:
        """Graceful close: an abrupt one (RST) can make the server discard data it already received."""
        sock, self._sock = self._sock, None
        if sock is None:
            return
        try:
            sock.settimeout(1.0)
            if isinstance(sock, ssl.SSLSocket):
                sock = sock.unwrap()  # close_notify; also consumes pending TLS 1.3 session tickets
            elif sock.type == socket.SOCK_STREAM:
                sock.shutdown(socket.SHUT_WR)
        except OSError, ValueError:
            pass
        finally:
            sock.close()


class Rfc5424Formatter(logging.Formatter):
    """RFC 5424 message with the record context as structured data (framing is added by the sender)."""

    _SEVERITY = {"DEBUG": 7, "INFO": 6, "WARNING": 4, "ERROR": 3, "CRITICAL": 2}
    SD_ID = "lsx@32473"

    def __init__(self, facility: str = "local0", app_name: str = "logstash-explorer"):
        super().__init__()
        self.facility = FACILITIES[facility]
        self.app_name = app_name
        self.hostname = socket.gethostname()

    @staticmethod
    def _sd_escape(value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")

    def format(self, record: logging.LogRecord) -> str:
        pri = self.facility * 8 + self._SEVERITY.get(record.levelname, 6)
        ts = datetime.fromtimestamp(record.created, UTC).isoformat()
        params = {"logger": record.name}
        ctx = getattr(record, "ctx", None) or {}
        params.update({k: v if isinstance(v, str) else json.dumps(v, default=str) for k, v in ctx.items()})
        sd = (
            f"[{self.SD_ID}"
            + "".join(f' {k[:32]}="{self._sd_escape(str(v))}"' for k, v in params.items() if k.isidentifier())
            + "]"
        )
        msgid = "AUDIT" if record.name == "audit" else "-"
        return f"<{pri}>1 {ts} {self.hostname} {self.app_name} {os.getpid()} {msgid} {sd} {record.getMessage()}"


class RemoteSyslogHandler(logging.Handler):
    """Runs in the forwarding thread. Reconnects once per record, then backs off for RETRY_S."""

    def __init__(self, sender: SyslogSender):
        super().__init__()
        self.sender = sender
        self.sent = 0
        self.dropped = 0
        self.last_error: str | None = None
        self._down_until = 0.0

    def emit(self, record: logging.LogRecord) -> None:
        if time.monotonic() < self._down_until:
            self.dropped += 1
            return
        try:
            message = self.format(record)
        except Exception:  # noqa: BLE001 - a broken record must not kill the forwarding thread
            self.dropped += 1
            return
        for attempt in (1, 2):
            try:
                self.sender.send(message)
                self.sent += 1
                self.last_error = None
                return
            except (OSError, ssl.SSLError) as exc:
                self.sender.close()
                if attempt == 2:
                    self.last_error = f"{exc.__class__.__name__}: {exc}"[:300]
                    self._down_until = time.monotonic() + RETRY_S
                    self.dropped += 1

    def close(self) -> None:
        self.sender.close()
        super().close()


class _DroppingQueueHandler(logging.handlers.QueueHandler):
    """Never blocks the caller: a full queue (server too slow or down) drops the record."""

    def __init__(self, q: queue.Queue, target: RemoteSyslogHandler):
        super().__init__(q)
        self.target = target

    def enqueue(self, record: logging.LogRecord) -> None:
        try:
            self.queue.put_nowait(record)
        except queue.Full:
            self.target.dropped += 1


class _Forwarder:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.entry: _DroppingQueueHandler | None = None
        self.listener: logging.handlers.QueueListener | None = None
        self.handler: RemoteSyslogHandler | None = None
        self.target: SyslogTarget | None = None


_fwd = _Forwarder()


def configure(target: SyslogTarget | None, filters: list[logging.Filter] | None = None) -> None:
    """(Re)start forwarding to `target`, or stop it when None. Raises on an invalid TLS client certificate."""
    sender = SyslogSender(target) if target else None  # build first: a bad certificate keeps the old setup
    with _fwd.lock:
        root = logging.getLogger()
        if _fwd.entry is not None:
            root.removeHandler(_fwd.entry)
        if _fwd.listener is not None:
            _fwd.listener.stop()  # drains what is already queued
        if _fwd.handler is not None:
            _fwd.handler.close()
        _fwd.entry = _fwd.listener = _fwd.handler = None
        _fwd.target = target
        if target is None or sender is None:
            return
        handler = RemoteSyslogHandler(sender)
        handler.setFormatter(Rfc5424Formatter(target.facility))
        q: queue.Queue = queue.Queue(QUEUE_SIZE)
        entry = _DroppingQueueHandler(q, handler)
        for f in filters or []:
            entry.addFilter(f)
        listener = logging.handlers.QueueListener(q, handler)
        listener.start()
        root.addHandler(entry)
        _fwd.entry, _fwd.listener, _fwd.handler = entry, listener, handler


def status() -> dict:
    h = _fwd.handler
    if h is None:
        return {"active": False}
    return {"active": True, "sent": h.sent, "dropped": h.dropped, "last_error": h.last_error}


def send_test(target: SyslogTarget) -> None:
    """Synchronous one-off message (admin "test" button). Raises OSError / ssl.SSLError on failure."""
    sender = SyslogSender(target)
    record = logging.makeLogRecord(
        {"name": "audit", "levelname": "INFO", "msg": "Logstash Explorer: remote syslog test message"}
    )
    try:
        sender.send(Rfc5424Formatter(target.facility).format(record))
    finally:
        sender.close()
