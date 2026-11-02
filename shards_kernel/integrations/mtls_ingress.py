"""Pinned-certificate mTLS ingress for the existing loopback-only operator.

Only POST /submit is forwarded. Client identity requires BOTH an mTLS client
certificate pinned by an independently signed ingress policy and a distinct
agent bearer verified by the signed operator. No administrator endpoints,
arbitrary destinations, shell tools, agent signing keys or MCP protocol
framing exist at this boundary. This is an HTTPS transport increment, NOT a
native remote MCP endpoint and NOT a production deployment certificate.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import os
import ssl
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from shards_kernel.cli.service import _reject_constant, _unique_pairs
from shards_kernel.common.time import SystemClock

_DOMAIN = b"SHARDS-MTLS-INGRESS-V1\x00"
_MAX_CONFIG_BYTES = 96 * 1024
_MAX_BODY_BYTES = 64 * 1024
_MAX_RESPONSE_BYTES = 64 * 1024
_MAX_POLICY_MS = 24 * 60 * 60 * 1000


@dataclass(frozen=True)
class SignedIngressConfig:
    listen_host: str
    listen_port: int
    operator_port: int
    tls_cert_file: Path
    tls_key_file: Path
    client_ca_file: Path
    cert_actors: dict[str, str]
    expires_at_ms: int


def _fields(value: Any, expected: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("Ingress policy contains unexpected or missing fields")
    return value


def _path(value: Any) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("TLS files must be existing absolute regular files")
    path = Path(value)
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise ValueError("TLS files must be existing absolute regular files")
    return path


def _port(value: Any) -> int:
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError("Ingress ports must be valid integers")
    return value


def _actor(value: Any) -> str:
    if (
        not isinstance(value, str) or not 1 <= len(value) <= 128
        or not value.isascii()
        or not all(ch.isalnum() or ch in "-_" for ch in value)
    ):
        raise ValueError("Certificate identities must be restricted agent names")
    return value


def canonical_ingress_policy(envelope: dict[str, Any]) -> bytes:
    """Domain-separated, deterministic bytes signed by an OFFLINE operator."""
    fields = {
        key: envelope[key]
        for key in ("schema", "issued_at_ms", "expires_at_ms", "config")
    }
    return _DOMAIN + json.dumps(
        fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def verify_ingress_policy(
    envelope: Any, *, pinned_public_key_hex: str, now_ms: int
) -> SignedIngressConfig:
    """Reject unsigned, expired, untrusted or ambiguous ingress configuration."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    record = _fields(envelope, {
        "schema", "issued_at_ms", "expires_at_ms", "config", "signature_hex",
    })
    if record["schema"] != "shards.mtls-ingress.v1":
        raise ValueError("Unrecognised ingress protocol")
    for key in ("issued_at_ms", "expires_at_ms"):
        if type(record[key]) is not int or record[key] < 0:
            raise ValueError("Ingress validity timestamps must be nonnegative integers")
    if (
        not 0 < record["expires_at_ms"] - record["issued_at_ms"] <= _MAX_POLICY_MS
        or type(now_ms) is not int
        or not record["issued_at_ms"] <= now_ms <= record["expires_at_ms"]
    ):
        raise ValueError("Ingress policy expired, future-dated or too long")
    if (
        not isinstance(pinned_public_key_hex, str)
        or len(pinned_public_key_hex) != 64
        or any(ch not in "0123456789abcdef" for ch in pinned_public_key_hex)
    ):
        raise ValueError("An independently pinned Ed25519 trust root is required")
    signature = record["signature_hex"]
    if (
        not isinstance(signature, str) or len(signature) != 128
        or any(ch not in "0123456789abcdef" for ch in signature)
    ):
        raise ValueError("Malformed ingress policy signature")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pinned_public_key_hex)).verify(
            bytes.fromhex(signature), canonical_ingress_policy(record)
        )
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ValueError("Ingress policy signature invalid") from exc

    raw = _fields(record["config"], {
        "listen_host", "listen_port", "operator_port", "tls_cert_file",
        "tls_key_file", "client_ca_file", "agents",
    })
    host = raw["listen_host"]
    if not isinstance(host, str) or not host:
        raise ValueError("Ingress host must be an IP address")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("Ingress host must be a literal IPv4 address") from exc
    if ip.version != 4 or ip.is_multicast or ip.is_unspecified and host != "0.0.0.0":
        raise ValueError("Unsupported ingress network bind")
    entries = raw["agents"]
    if not isinstance(entries, list) or not 2 <= len(entries) <= 16:
        raise ValueError("Ingress policy requires two to sixteen pinned agent certificates")
    fingerprints: dict[str, str] = {}
    actors: set[str] = set()
    for entry in entries:
        agent = _fields(entry, {"actor", "client_cert_sha256"})
        actor = _actor(agent["actor"])
        digest = agent["client_cert_sha256"]
        if (
            not isinstance(digest, str) or len(digest) != 64
            or any(ch not in "0123456789abcdef" for ch in digest)
        ):
            raise ValueError("Client certificate fingerprint must be 64 lowercase hex characters")
        if actor in actors or digest in fingerprints:
            raise ValueError("Duplicated client certificate identity")
        fingerprints[digest] = actor
        actors.add(actor)

    return SignedIngressConfig(
        listen_host=host, listen_port=_port(raw["listen_port"]),
        operator_port=_port(raw["operator_port"]),
        tls_cert_file=_path(raw["tls_cert_file"]),
        tls_key_file=_path(raw["tls_key_file"]),
        client_ca_file=_path(raw["client_ca_file"]),
        cert_actors=fingerprints, expires_at_ms=record["expires_at_ms"],
    )


def load_ingress_policy(
    path: str, *, pinned_public_key_hex: str, now_ms: int
) -> SignedIngressConfig:
    file = Path(path)
    if not file.is_file() or file.is_symlink() or file.stat().st_size > _MAX_CONFIG_BYTES:
        raise ValueError("Ingress policy file invalid or too large")
    with file.open("rb") as stream:
        data = stream.read(_MAX_CONFIG_BYTES + 1)
    if len(data) > _MAX_CONFIG_BYTES:
        raise ValueError("Ingress policy file too large")
    try:
        parsed = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
            parse_float=_reject_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid ingress policy JSON") from exc
    return verify_ingress_policy(
        parsed, pinned_public_key_hex=pinned_public_key_hex, now_ms=now_ms
    )


def _reject_float(_unused: str) -> None:
    raise ValueError("Floating point policy values are not supported")


def _tls_context(config: SignedIngressConfig) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(str(config.tls_cert_file), str(config.tls_key_file))
    context.load_verify_locations(cafile=str(config.client_ca_file))
    return context


def _make_handler(config: SignedIngressConfig, clock: SystemClock):
    """Only signed-cert-mapped, authenticated agent submissions are forwarded."""

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _reply(self, code: int, data: dict[str, Any]) -> None:
            body = json.dumps(data, separators=(",", ":")).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def do_GET(self) -> None:
            self._reply(404, {"error": "Not found"})

        def do_OPTIONS(self) -> None:
            self._reply(405, {"error": "Method not allowed"})

        def do_POST(self) -> None:
            if self.path != "/submit":
                self._reply(404, {"error": "Not found"})
                return
            try:
                if clock.now_ms() > config.expires_at_ms:
                    self._reply(503, {"error": "Signed ingress policy expired"})
                    return
            except Exception:
                self._reply(503, {"error": "Ingress clock unavailable"})
                return
            peer_cert = self.connection.getpeercert(binary_form=True)
            if not peer_cert:
                self._reply(403, {"error": "Missing authenticated client certificate"})
                return
            digest = hashlib.sha256(peer_cert).hexdigest()
            actor = config.cert_actors.get(digest)
            if actor is None:
                self._reply(403, {"error": "Client certificate not enrolled"})
                return
            headers = self.headers.get_all("Authorization", [])
            if len(headers) != 1 or not headers[0].startswith("Bearer "):
                self._reply(401, {"error": "Missing agent credential"})
                return
            bearer = headers[0]
            if not bearer.startswith("Bearer " + actor + "."):
                self._reply(403, {"error": "Certificate and bearer principal mismatch"})
                return
            try:
                length_raw = self.headers.get_all("Content-Length", [])
                if len(length_raw) != 1:
                    raise ValueError("Request length missing")
                length = int(length_raw[0])
                if length <= 0 or length > _MAX_BODY_BYTES:
                    raise ValueError("Invalid request size")
                data = self.rfile.read(length)
                if len(data) != length:
                    raise ValueError("Truncated body")
                payload = json.loads(
                    data.decode("utf-8"),
                    object_pairs_hook=_unique_pairs,
                    parse_constant=_reject_constant,
                    parse_float=_reject_float,
                )
                if not isinstance(payload, dict) or payload.get("actor") != actor:
                    self._reply(403, {"error": "Certificate and request principal mismatch"})
                    return
                call = payload.get("tool_call")
                if (
                    not isinstance(call, dict)
                    or call.get("name") not in {"echo", "add"}
                ):
                    self._reply(403, {"error": "Tool not available at ingress"})
                    return
            except (ValueError, TypeError, UnicodeError, json.JSONDecodeError):
                self._reply(400, {"error": "Invalid governed request"})
                return

            conn = http.client.HTTPConnection(
                "127.0.0.1", config.operator_port, timeout=3
            )
            try:
                conn.request(
                    "POST", "/submit", body=data,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": bearer,
                    },
                )
                response = conn.getresponse()
                result = response.read(_MAX_RESPONSE_BYTES + 1)
                if len(result) > _MAX_RESPONSE_BYTES:
                    raise ValueError("Oversized operator response")
                if response.status not in {200, 401, 403, 400, 413, 503}:
                    raise ValueError("Unexpected operator response")
                response_json = json.loads(result.decode("utf-8"))
                if not isinstance(response_json, dict):
                    raise ValueError("Invalid operator response")
                if response.status == 200 and response_json.get("request_id") != payload.get("request_id"):
                    raise ValueError("Uncorrelated operator receipt")
                self._reply(response.status, response_json)
            except (OSError, ValueError, http.client.HTTPException, UnicodeError):
                self._reply(502, {"error": "Local operator unavailable"})
            finally:
                conn.close()

        def log_message(self, _format: str, *_args: Any) -> None:
            """Never log request paths, bearer material or payloads."""
            return

    return Handler


class MTLSIngressServer:
    """Isolated HTTPS/mTLS ingress. Never launches or signs for the kernel."""

    def __init__(
        self, config: SignedIngressConfig, *, allow_remote_listen: bool = False
    ) -> None:
        if config.listen_host != "127.0.0.1" and not allow_remote_listen:
            raise ValueError("Remote interface requires explicit operator opt-in")
        self.config = config
        self._clock = SystemClock()
        self._context = _tls_context(config)
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self, *, blocking: bool = True) -> None:
        server = ThreadingHTTPServer(
            (self.config.listen_host, self.config.listen_port),
            _make_handler(self.config, self._clock),
        )
        server.daemon_threads = True
        server.socket = self._context.wrap_socket(server.socket, server_side=True)
        self._server = server
        if blocking:
            server.serve_forever()
        else:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            self._thread = thread
            thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None


def run_mtls_ingress(config_path: str, *, allow_remote_listen: bool = False) -> int:
    """Start only after checking the out-of-band signed ingress policy."""
    try:
        pinned = os.environ.get("SHARDS_KERNEL_INGRESS_PUBLIC_KEY_HEX", "")
        config = load_ingress_policy(
            config_path, pinned_public_key_hex=pinned,
            now_ms=SystemClock().now_ms(),
        )
        ingress = MTLSIngressServer(config, allow_remote_listen=allow_remote_listen)
        try:
            ingress.start(blocking=True)
        except KeyboardInterrupt:
            pass
        finally:
            ingress.stop()
        return 0
    except Exception:
        print("mTLS ingress refused startup or failed; verify trusted operator configuration")
        return 2
