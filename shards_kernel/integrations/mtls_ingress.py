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
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from shards_kernel.cli.service import _reject_constant, _unique_pairs
from shards_kernel.common.time import SystemClock
from shards_kernel.integrations.mtls_checkpoint import (
    checkpoint_ingress_revision, verify_ingress_checkpoint,
)

_DOMAIN = b"SHARDS-MTLS-INGRESS-V1\x00"
_MAX_CONFIG_BYTES = 96 * 1024
_MAX_BODY_BYTES = 64 * 1024
_MAX_RESPONSE_BYTES = 64 * 1024
_MAX_POLICY_MS = 24 * 60 * 60 * 1000
_MAX_CONCURRENT_CONNECTIONS = 32
_HANDSHAKE_TIMEOUT_SECONDS = 3.0
_REQUEST_TIMEOUT_SECONDS = 3.0
_HEADER_DEADLINE_SECONDS = 8.0
_BODY_DEADLINE_SECONDS = 8.0


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
    ingress_id: str | None = None
    revision: int = 0
    policy_digest: str | None = None
    checkpoint_db_file: Path | None = None


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
    schema = envelope["schema"]
    if schema == "shards.mtls-ingress.v2":
        names = ("schema", "revision", "issued_at_ms", "expires_at_ms", "config")
    elif schema == "shards.mtls-ingress.v1":
        names = ("schema", "issued_at_ms", "expires_at_ms", "config")
    else:
        raise ValueError("Unrecognised ingress protocol")
    fields = {key: envelope[key] for key in names}
    return _DOMAIN + json.dumps(
        fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _validate_envelope(record: Any, public_key_hex: str, now_ms: int) -> dict[str, Any]:
    """Authenticate the envelope before reading any referenced TLS files."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if not isinstance(record, dict):
        raise ValueError("Ingress policy must be a JSON object")
    schema = record.get("schema")
    if schema == "shards.mtls-ingress.v2":
        obj = _fields(record, {
            "schema", "revision", "issued_at_ms", "expires_at_ms",
            "config", "signature_hex",
        })
        if type(obj["revision"]) is not int or obj["revision"] < 1:
            raise ValueError("Signed ingress revision must be positive")
    elif schema == "shards.mtls-ingress.v1":
        obj = _fields(record, {
            "schema", "issued_at_ms", "expires_at_ms", "config", "signature_hex",
        })
    else:
        raise ValueError("Unrecognised ingress protocol")
    issued, expires = obj["issued_at_ms"], obj["expires_at_ms"]
    if (
        type(issued) is not int or type(expires) is not int
        or issued < 0 or not 0 < expires - issued <= _MAX_POLICY_MS
        or type(now_ms) is not int or not issued <= now_ms <= expires
    ):
        raise ValueError("Ingress policy expired, future-dated or too long")
    if (
        not isinstance(public_key_hex, str) or len(public_key_hex) != 64
        or any(ch not in "0123456789abcdef" for ch in public_key_hex)
    ):
        raise ValueError("An independently pinned Ed25519 trust root is required")
    signature = obj["signature_hex"]
    if (
        not isinstance(signature, str) or len(signature) != 128
        or any(ch not in "0123456789abcdef" for ch in signature)
    ):
        raise ValueError("Malformed ingress policy signature")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex)).verify(
            bytes.fromhex(signature), canonical_ingress_policy(obj)
        )
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ValueError("Ingress policy signature invalid") from exc
    return obj


def _pinned_cert_actors(value: Any) -> dict[str, str]:
    if not isinstance(value, list) or not 2 <= len(value) <= 16:
        raise ValueError("Ingress policy requires two to sixteen pinned agent certificates")
    fingerprints: dict[str, str] = {}
    actors: set[str] = set()
    for entry in value:
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
    return fingerprints


def _listen_ip(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("Ingress listener must be an explicit IPv4 address")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("Ingress listener must be an explicit IPv4 address") from exc
    if address.version != 4 or address.is_multicast or address.is_unspecified:
        raise ValueError("Wildcard, multicast and IPv6 listeners are not supported")
    return value


def verify_ingress_policy(
    envelope: Any, *, pinned_public_key_hex: str, now_ms: int
) -> SignedIngressConfig:
    """Verify signature and exact TLS identity policy before network binding."""
    obj = _validate_envelope(envelope, pinned_public_key_hex, now_ms)
    versioned = obj["schema"] == "shards.mtls-ingress.v2"
    fields = {
        "listen_host", "listen_port", "operator_port", "tls_cert_file",
        "tls_key_file", "client_ca_file", "agents",
    }
    if versioned:
        fields |= {"ingress_id", "checkpoint_db_file"}
    raw = _fields(obj["config"], fields)
    return SignedIngressConfig(
        listen_host=_listen_ip(raw["listen_host"]),
        listen_port=_port(raw["listen_port"]),
        operator_port=_port(raw["operator_port"]),
        tls_cert_file=_path(raw["tls_cert_file"]),
        tls_key_file=_path(raw["tls_key_file"]),
        client_ca_file=_path(raw["client_ca_file"]),
        cert_actors=_pinned_cert_actors(raw["agents"]),
        expires_at_ms=obj["expires_at_ms"],
        ingress_id=_actor(raw["ingress_id"]) if versioned else None,
        revision=obj["revision"] if versioned else 0,
        policy_digest=hashlib.sha256(canonical_ingress_policy(obj)).hexdigest()
        if versioned else None,
        checkpoint_db_file=_path(raw["checkpoint_db_file"]) if versioned else None,
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


class _DeadlineHeaderStream:
    """Constrain all request-line/header byte reads to one monotonic deadline.

    A socket idle timeout is insufficient against a client sending one byte
    just before each timeout. Avoid BufferedReader.readline(), which may
    perform multiple blocking reads inside one call.
    """

    def __init__(self, stream: Any, connection: ssl.SSLSocket, deadline: float):
        self._stream = stream
        self._connection = connection
        self._deadline = deadline

    def readline(self, limit: int = -1) -> bytes:
        limit = 65537 if limit < 0 else min(limit, 65537)
        data = bytearray()
        while len(data) < limit:
            remaining = self._deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("HTTP header deadline exceeded")
            self._connection.settimeout(min(_REQUEST_TIMEOUT_SECONDS, remaining))
            char = self._stream.read1(1)
            if not char:
                break
            data.extend(char)
            if char == b"\\n":
                break
        return bytes(data)


class _IngressHandler(BaseHTTPRequestHandler):
    """Per-connection client certificate and token binding before forwarding."""

    protocol_version = "HTTP/1.1"
    config: SignedIngressConfig
    clock: SystemClock
    policy_guard: Any

    def handle_one_request(self) -> None:
        """Apply an absolute deadline before parsing any HTTP bytes."""
        self._unwrapped_rfile = self.rfile
        self.rfile = _DeadlineHeaderStream(
            self._unwrapped_rfile, self.connection,
            time.monotonic() + _HEADER_DEADLINE_SECONDS,
        )
        try:
            super().handle_one_request()
        finally:
            self.rfile = self._unwrapped_rfile
            self.connection.settimeout(_REQUEST_TIMEOUT_SECONDS)

    def parse_request(self) -> bool:
        """Restore the normal reader only once all headers have been parsed."""
        try:
            return super().parse_request()
        finally:
            self.rfile = self._unwrapped_rfile
            self.connection.settimeout(_REQUEST_TIMEOUT_SECONDS)

    def _reply(self, status: int, data: dict[str, Any]) -> None:
        body = json.dumps(data, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
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

    def _policy_safe(self) -> bool:
        try:
            self.policy_guard()
            if self.clock.now_ms() > self.config.expires_at_ms:
                self._reply(503, {"error": "Signed ingress policy expired"})
                return False
        except Exception:
            self._reply(503, {"error": "Ingress policy checkpoint or clock unavailable"})
            return False
        return True

    def _authenticated_principal(self) -> tuple[str, str] | None:
        leaf = self.connection.getpeercert(binary_form=True)
        if not leaf:
            self._reply(403, {"error": "Missing authenticated client certificate"})
            return None
        actor = self.config.cert_actors.get(hashlib.sha256(leaf).hexdigest())
        if actor is None:
            self._reply(403, {"error": "Client certificate not enrolled"})
            return None
        headers = self.headers.get_all("Authorization", [])
        if len(headers) != 1 or not headers[0].startswith("Bearer "):
            self._reply(401, {"error": "Missing agent credential"})
            return None
        bearer = headers[0]
        if not bearer.startswith("Bearer " + actor + "."):
            self._reply(403, {"error": "Certificate and bearer principal mismatch"})
            return None
        return actor, bearer

    def _governed_body(self, actor: str) -> tuple[bytes, dict[str, Any]] | None:
        try:
            if self.headers.get_all("Transfer-Encoding", []):
                raise ValueError("Transfer encoding not accepted")
            length_headers = self.headers.get_all("Content-Length", [])
            if len(length_headers) != 1:
                raise ValueError("Request length missing")
            length = int(length_headers[0])
            if length <= 0 or length > _MAX_BODY_BYTES:
                raise ValueError("Invalid request size")
            if self.headers.get("Content-Type") != "application/json":
                raise ValueError("JSON content type required")
            # Socket read timeouts alone do not stop a slow client that sends
            # one byte just before each timeout. Bound the whole body transfer.
            deadline = time.monotonic() + _BODY_DEADLINE_SECONDS
            chunks: list[bytes] = []
            received = 0
            previous_timeout = self.connection.gettimeout()
            try:
                while received < length:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ValueError("Request body deadline exceeded")
                    # Every blocking read is limited by the *remaining*
                    # total deadline, not merely the idle socket timeout.
                    self.connection.settimeout(
                        min(_REQUEST_TIMEOUT_SECONDS, remaining)
                    )
                    chunk = self.rfile.read1(min(8192, length - received))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    received += len(chunk)
            finally:
                self.connection.settimeout(previous_timeout)
            if received != length or time.monotonic() >= deadline:
                raise ValueError("Truncated or timed-out request")
            body = b"".join(chunks)
            payload = json.loads(
                body.decode("utf-8"),
                object_pairs_hook=_unique_pairs,
                parse_constant=_reject_constant,
                parse_float=_reject_float,
            )
        except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError):
            self._reply(400, {"error": "Invalid governed request"})
            return None
        if not isinstance(payload, dict) or payload.get("actor") != actor:
            self._reply(403, {"error": "Certificate and request principal mismatch"})
            return None
        call = payload.get("tool_call")
        if not isinstance(call, dict) or call.get("name") not in {"echo", "add"}:
            self._reply(403, {"error": "Tool not available at ingress"})
            return None
        return body, payload

    def _submit_to_operator(
        self, body: bytes, payload: dict[str, Any], bearer: str
    ) -> None:
        conn = http.client.HTTPConnection(
            "127.0.0.1", self.config.operator_port, timeout=3
        )
        try:
            conn.request(
                "POST", "/submit", body=body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": bearer,
                },
            )
            response = conn.getresponse()
            data = response.read(_MAX_RESPONSE_BYTES + 1)
            if len(data) > _MAX_RESPONSE_BYTES:
                raise ValueError("Oversized operator response")
            if response.status not in {200, 400, 401, 403, 413, 503}:
                raise ValueError("Unexpected operator response")
            receipt = json.loads(data.decode("utf-8"))
            if not isinstance(receipt, dict):
                raise ValueError("Invalid operator response")
            if response.status == 200 and receipt.get("request_id") != payload.get("request_id"):
                raise ValueError("Uncorrelated operator receipt")
            self._reply(response.status, receipt)
        except (OSError, ValueError, http.client.HTTPException, UnicodeError):
            self._reply(502, {"error": "Local operator unavailable"})
        finally:
            conn.close()

    def do_POST(self) -> None:
        if self.path != "/submit":
            self._reply(404, {"error": "Not found"})
            return
        if not self._policy_safe():
            return
        principal = self._authenticated_principal()
        if principal is None:
            return
        actor, bearer = principal
        result = self._governed_body(actor)
        if result is None:
            return
        body, payload = result
        # A policy can expire during a slow (but bounded) body upload.
        # Do not forward under authority that expired after admission.
        if not self._policy_safe():
            return
        self._submit_to_operator(body, payload, bearer)

    # BaseHTTPRequestHandler requires the parameter name 'format' in its API.
    def log_message(self, format: str, *args: Any) -> None:  # pylint: disable=redefined-builtin
        """Never log request paths, bearer material or payloads."""
        return


def _make_handler(config: SignedIngressConfig, clock: SystemClock, policy_guard: Any):
    class BoundHandler(_IngressHandler):
        pass

    BoundHandler.config = config
    BoundHandler.clock = clock
    BoundHandler.policy_guard = staticmethod(policy_guard)
    return BoundHandler


class _BoundedTLSServer(ThreadingHTTPServer):
    """Bound slow client handshakes without blocking the accept loop.

    TLS must be negotiated in a worker, *not* by wrapping the listening
    socket: an unauthenticated TCP client can otherwise stall accept().
    Admission is deliberately bounded. Rejected connections receive no
    HTTP response because they have not authenticated with TLS.
    """

    daemon_threads = True
    request_queue_size = 16

    def __init__(self, address: tuple[str, int], handler: type, context: ssl.SSLContext):
        self._tls_context = context
        self._slots = threading.BoundedSemaphore(_MAX_CONCURRENT_CONNECTIONS)
        super().__init__(address, handler)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            self.shutdown_request(request)
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            try:
                request.settimeout(_HANDSHAKE_TIMEOUT_SECONDS)
                authenticated = self._tls_context.wrap_socket(request, server_side=True)
            except OSError:
                # Invalid, incomplete and timed-out handshakes are not HTTP requests.
                self.shutdown_request(request)
                return
            authenticated.settimeout(_REQUEST_TIMEOUT_SECONDS)
            super().process_request_thread(authenticated, client_address)
        finally:
            self._slots.release()


class MTLSIngressServer:
    """Isolated HTTPS/mTLS ingress. Never launches or signs for the kernel."""

    def __init__(
        self, config: SignedIngressConfig, *, allow_remote_listen: bool = False
    ) -> None:
        if config.listen_host != "127.0.0.1":
            if not allow_remote_listen:
                raise ValueError("Remote interface requires explicit operator opt-in")
            if not config.revision:
                raise ValueError("Remote interface requires signed versioned ingress policy")
        self.config = config
        self._checkpoint_identity: tuple[int, int] | None = None
        if config.revision:
            if not (config.checkpoint_db_file and config.ingress_id and config.policy_digest):
                raise ValueError("Versioned ingress policy missing checkpoint identity")
            self._checkpoint_identity = checkpoint_ingress_revision(
                config.checkpoint_db_file,
                ingress_id=config.ingress_id,
                revision=config.revision,
                digest=config.policy_digest,
            )
        self._clock = SystemClock()
        self._context = _tls_context(config)
        self._server: _BoundedTLSServer | None = None
        self._thread: threading.Thread | None = None

    def _verify_policy_checkpoint(self) -> None:
        if self.config.revision:
            # Never use asserts for runtime trust checks. Python -O removes
            # assertions and would silently bypass these authority guards.
            checkpoint = self.config.checkpoint_db_file
            ingress_id = self.config.ingress_id
            digest = self.config.policy_digest
            identity = self._checkpoint_identity
            if (
                checkpoint is None
                or ingress_id is None
                or digest is None
                or identity is None
            ):
                raise ValueError("Missing signed ingress checkpoint authority")
            verify_ingress_checkpoint(
                checkpoint,
                ingress_id=ingress_id,
                revision=self.config.revision,
                digest=digest,
                identity=identity,
            )

    def start(self, *, blocking: bool = True) -> None:
        server = _BoundedTLSServer(
            (self.config.listen_host, self.config.listen_port),
            _make_handler(self.config, self._clock, self._verify_policy_checkpoint),
            self._context,
        )
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
