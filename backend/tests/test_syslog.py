import datetime as dt
import logging
import socket
import ssl
import tempfile
import threading
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import HTTPException

from app.core import syslog
from app.core.logging import PiiMaskingFilter
from app.core.syslog import Rfc5424Formatter, SyslogSender, SyslogTarget


def _pem_pair(cn: str, issuer=None, san: str | None = None, ca: bool = False):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer_name, issuer_key = (issuer[0].subject, issuer[1]) if issuer else (name, key)
    now = dt.datetime.now(dt.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
    cert = builder.sign(issuer_key, hashes.SHA256())
    return cert, key


def _pem(cert, key) -> tuple[str, str]:
    return (
        cert.public_bytes(serialization.Encoding.PEM).decode(),
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode(),
    )


class _Server:
    """Local TCP (optionally TLS) syslog server collecting raw bytes."""

    def __init__(self, tls: ssl.SSLContext | None = None):
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.tls = tls
        self.data = b""
        self.peer_cert = None
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        conn, _ = self.sock.accept()
        if self.tls:
            conn = self.tls.wrap_socket(conn, server_side=True)
            self.peer_cert = conn.getpeercert()
        conn.settimeout(3)
        try:
            while chunk := conn.recv(65536):
                self.data += chunk
        except OSError:
            pass

    def wait_for(self, needle: bytes, timeout: float = 3.0) -> bytes:
        end = time.monotonic() + timeout
        while needle not in self.data and time.monotonic() < end:
            time.sleep(0.02)
        return self.data


def test_framing():
    tls = SyslogSender(SyslogTarget("h", 1, "tcp"))
    assert tls.frame("<14>1 é") == b"8 <14>1 \xc3\xa9"  # octet count is in bytes, not characters
    lf = SyslogSender(SyslogTarget("h", 1, "tcp", framing="lf"))
    assert lf.frame("a\nb") == b"a b\n"
    assert SyslogSender(SyslogTarget("h", 1, "udp")).frame("x") == b"x"


def test_rfc5424_format_uses_facility_and_structured_data():
    record = logging.makeLogRecord({"name": "audit", "levelname": "WARNING", "msg": "login failed"})
    record.ctx = {"actor": 'bob"]', "details": {"n": 1}}
    line = Rfc5424Formatter("local3").format(record)
    assert line.startswith(f"<{19 * 8 + 4}>1 ")
    assert ' AUDIT [lsx@32473 logger="audit" actor="bob\\"\\]" details="{\\"n\\": 1}"] login failed' in line


def test_forwarding_over_tcp_is_asynchronous_and_masked():
    server = _Server()
    syslog.configure(SyslogTarget("127.0.0.1", server.port, "tcp"), [PiiMaskingFilter()])
    try:
        logging.getLogger("audit").warning("contact jane@example.org")
        data = server.wait_for(b"[EMAIL]")
        assert b"[EMAIL]" in data and b"jane@example.org" not in data
        assert syslog.status()["sent"] >= 1
    finally:
        syslog.configure(None)
    assert syslog.status() == {"active": False}


def test_unreachable_server_drops_without_blocking():
    port = socket.create_server(("127.0.0.1", 0))
    closed = port.getsockname()[1]
    port.close()
    syslog.configure(SyslogTarget("127.0.0.1", closed, "tcp"))
    try:
        started = time.monotonic()
        for _ in range(50):
            logging.getLogger("x").warning("lost")
        assert time.monotonic() - started < 0.5  # callers never wait on the network
        deadline = time.monotonic() + 20  # Windows retries refused SYNs for ~2 s per attempt
        while syslog.status()["dropped"] < 50 and time.monotonic() < deadline:
            time.sleep(0.02)
        st = syslog.status()
        assert st["dropped"] == 50 and st["sent"] == 0 and "ConnectionRefused" in st["last_error"]
    finally:
        syslog.configure(None)


def test_mutual_tls(monkeypatch):
    ca = _pem_pair("Test CA", ca=True)
    server_cert = _pem_pair("localhost", issuer=ca, san="localhost")
    client_cert = _pem_pair("lsx-backend", issuer=ca)
    ca_pem = ca[0].public_bytes(serialization.Encoding.PEM).decode()

    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.verify_mode = ssl.CERT_REQUIRED
    server_ctx.load_verify_locations(cadata=ca_pem)
    with tempfile.TemporaryDirectory() as tmp:
        c, k = _pem(*server_cert)
        Path(tmp, "c.pem").write_text(c)
        Path(tmp, "k.pem").write_text(k)
        server_ctx.load_cert_chain(Path(tmp, "c.pem"), Path(tmp, "k.pem"))

    def trusting_ctx():
        ctx = ssl.create_default_context(cadata=ca_pem)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx

    monkeypatch.setattr(syslog, "tls_context", trusting_ctx)  # stands for a CA imported in Admin → PKI
    server = _Server(server_ctx)
    cert_pem, key_pem = _pem(*client_cert)
    syslog.send_test(SyslogTarget("localhost", server.port, "tls", client_cert=cert_pem, client_key=key_pem))
    assert b"remote syslog test message" in server.wait_for(b"test message")
    assert dict(x[0] for x in server.peer_cert["subject"])["commonName"] == "lsx-backend"


def test_tls_rejects_unknown_server_certificate():
    server = _Server(None)
    with pytest.raises(OSError):  # plain TCP server or untrusted cert: the handshake fails
        syslog.send_test(SyslogTarget("127.0.0.1", server.port, "tls"))


def test_admin_rejects_mismatched_client_key():
    from app.api.admin import _check_client_pair

    cert, _ = _pem_pair("a")
    _, other_key = _pem_pair("b")
    cert_pem, other_pem = _pem(cert, other_key)
    with pytest.raises(HTTPException) as exc:
        _check_client_pair(cert_pem, other_pem)
    assert exc.value.status_code == 422
    with pytest.raises(HTTPException):
        _check_client_pair("not a pem", other_pem)
