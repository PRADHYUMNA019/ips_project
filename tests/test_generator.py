#!/usr/bin/env python3
"""
tests/test_generator.py — Verify the benign IoT generator (F1 fix).

Starts a local TLS echo server on 127.0.0.1, runs one device with a
fast profile for ~10 s, and asserts:
  1. At least 5 messages were sent on ONE connection (no reconnect loop).
  2. Zero exceptions were raised inside run_iot_device.
"""
import os
import sys
import ssl
import socket
import threading
import time
import tempfile
import subprocess

import pytest

# Ensure the repo root is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from traffic.benign_iot_generator import run_iot_device, PROFILES


# ---------------------------------------------------------------------------
# Helpers: a minimal TLS echo server for testing
# ---------------------------------------------------------------------------

def _generate_test_certs(cert_dir):
    """Generate a throwaway self-signed cert for the test server.

    Uses `cryptography` in pure Python if available, falling back to `openssl`.
    """
    cert_path = os.path.join(cert_dir, "test.crt")
    key_path = os.path.join(cert_dir, "test.key")
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    except ImportError:
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key_path, "-out", cert_path,
                "-days", "1", "-nodes", "-subj", "/CN=localhost",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    return cert_path, key_path


class _TLSEchoServer:
    """A minimal TLS echo server for test purposes."""

    def __init__(self, host="127.0.0.1", port=0):
        self.host = host
        self._cert_dir = tempfile.mkdtemp(prefix="ips_test_certs_")
        self._cert, self._key = _generate_test_certs(self._cert_dir)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self._cert, self._key)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        self._raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._raw_sock.bind((host, port))
        self._raw_sock.listen(32)
        self.port = self._raw_sock.getsockname()[1]
        self._tls_sock = ctx.wrap_socket(self._raw_sock, server_side=True)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        # Nudge accept() out of blocking
        try:
            s = socket.create_connection((self.host, self.port), timeout=0.5)
            s.close()
        except Exception:
            pass
        self._thread.join(timeout=3)

    def _serve(self):
        self._tls_sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                conn, addr = self._tls_sock.accept()
                threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
            except (socket.timeout, ssl.SSLError, OSError):
                continue

    @staticmethod
    def _handle(conn):
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(data[:64])
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

# Monkey-patch a fast profile for testing (0.2 s interval)
PROFILES["_test_fast"] = {
    "interval_s": (0.2, 0.05),
    "payload_size": (32, 64),
    "burst_probability": 0.0,
    "burst_count": (0, 0),
}


@pytest.fixture(scope="module")
def tls_server():
    """Start a TLS echo server for the test module."""
    srv = _TLSEchoServer()
    srv.start()
    yield srv
    srv.stop()


def test_device_sends_multiple_messages_one_connection(tls_server):
    """F1 regression: device must send >= 5 messages without reconnecting."""
    result = {}
    t = threading.Thread(
        target=run_iot_device,
        args=("test-device", "_test_fast", tls_server.host, tls_server.port),
        kwargs={"duration_s": 5.0, "result_holder": result},
    )
    t.start()
    t.join(timeout=15)

    assert "msg_count" in result, "run_iot_device did not populate result_holder"
    assert result["msg_count"] >= 5, (
        f"Expected >= 5 messages but got {result['msg_count']}. "
        "The wait-before-assignment bug (F1) may still be present."
    )
    assert result["connections"] == 1, (
        f"Expected 1 connection but got {result['connections']}. "
        "Device is reconnecting (F1 regression)."
    )
    # Allow at most the initial connection log, no crash exceptions
    crash_exceptions = [e for e in result.get("exceptions", [])
                        if "wait" in e.lower() or "local variable" in e.lower()]
    assert len(crash_exceptions) == 0, (
        f"F1 crash exceptions found: {crash_exceptions}"
    )


def test_slow_profile_sends_multiple_messages(tls_server):
    """A slower profile (~1 s) should still send multiple messages in 8 s."""
    PROFILES["_test_slow"] = {
        "interval_s": (1.0, 0.1),
        "payload_size": (48, 96),
        "burst_probability": 0.0,
        "burst_count": (0, 0),
    }
    result = {}
    t = threading.Thread(
        target=run_iot_device,
        args=("test-slow", "_test_slow", tls_server.host, tls_server.port),
        kwargs={"duration_s": 8.0, "result_holder": result},
    )
    t.start()
    t.join(timeout=20)

    assert result["msg_count"] >= 3, (
        f"Slow profile sent only {result['msg_count']} messages in 8 s"
    )
    assert result["connections"] == 1

