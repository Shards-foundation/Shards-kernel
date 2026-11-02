"""Live TLS v1.3 mutual-auth boundary: two pinned agent certs, one operator."""

from __future__ import annotations

import copy
import datetime as dt
import http.client
import json
import secrets
import socket
import ssl
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from shards_kernel.cli.service import (
    build_operator_server, exclusive_local_audit_lock, parse_operator_config,
)
from shards_kernel.cli.signed_policy import verify_signed_policy
from shards_kernel.integrations.auth import agent_token_kdf
from shards_kernel.integrations.mtls_ingress import (
    MTLSIngressServer, load_ingress_policy, run_mtls_ingress, verify_ingress_policy,
)
from shards_kernel.integrations.wire import permit_to_mapping
from shards_kernel.issuer import sign_mtls_ingress_policy, sign_operator_policy, sign_v2_permit
from shards_kernel.permits import PermitBuilder


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _key_files(folder, prefix, private_key, certificate):
    key = folder / (prefix + "-key.pem")
    cert = folder / (prefix + ".pem")
    key.write_bytes(private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return cert, key


def _make_certificates(folder):
    """Real short-lived CA, server leaf and three distinct client leaves."""
    import ipaddress

    now = dt.datetime.now(dt.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Shards test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = folder / "ca.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))

    def leaf(label, *, server=False):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)]))
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.SERVER_AUTH if server
                    else ExtendedKeyUsageOID.CLIENT_AUTH
                ]), critical=False,
            )
        )
        if server:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(
                    ipaddress.ip_address("127.0.0.1")
                )]), critical=False,
            )
        cert = builder.sign(ca_key, hashes.SHA256())
        cert_file, key_file = _key_files(folder, label, key, cert)
        return cert_file, key_file, cert.fingerprint(hashes.SHA256()).hex()

    return {
        "ca": ca_path,
        "server": leaf("server", server=True),
        "alpha": leaf("alpha"),
        "beta": leaf("beta"),
        "unlisted": leaf("unlisted"),
    }


def _https(port, ca_path, client_pair=None, *, method="POST", path="/submit",
           bearer=None, payload=None):
    context = ssl.create_default_context(cafile=str(ca_path))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    if client_pair is not None:
        context.load_cert_chain(str(client_pair[0]), str(client_pair[1]))
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if bearer is not None:
        headers["Authorization"] = "Bearer " + bearer
    conn = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=3)
    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        return response.status, json.loads(response.read().decode())
    finally:
        conn.close()


def _permit(issuer, actor, tool, params):
    now = int(time.time() * 1000)
    return permit_to_mapping(sign_v2_permit(
        (
            PermitBuilder().issuer("operator").subject(actor)
            .jurisdiction("default").action(tool).params(params)
            .max_executions(1).valid_from_ms(now - 30_000)
            .valid_until_ms(now + 120_000).proposal_hash("offline-reviewed")
            .build_unsigned_v2(key_id="issuer", audience="mtls-operator")
        ), issuer,
    ))


def _body(actor, request_id, name, params, permit=None):
    result = {
        "request_id": request_id, "actor": actor, "intent": "TLS authenticated tool",
        "tool_call": {"name": name, "params": params}, "params": params,
    }
    if permit is not None:
        result["permit"] = permit
    return result


def _setup(tmp_path):
    files = _make_certificates(tmp_path)
    operator_key = ed25519.Ed25519PrivateKey.generate()
    issuer = ed25519.Ed25519PrivateKey.generate()
    ingress_key = ed25519.Ed25519PrivateKey.generate()
    pepper = secrets.token_urlsafe(48)
    alpha = "agent-alpha." + secrets.token_urlsafe(48)
    beta = "agent-beta." + secrets.token_urlsafe(48)
    operator_port = _free_port()
    ingress_port = _free_port()
    now = int(time.time() * 1000)
    raw_operator = {
        "version": 2,
        "kernel_id": "mtls-operator",
        "tools": ["echo", "add"],
        "agents": [
            {"actor": "agent-alpha", "token_scrypt": agent_token_kdf(
                alpha, pepper.encode()
            ), "allowed_tools": ["echo"]},
            {"actor": "agent-beta", "token_scrypt": agent_token_kdf(
                beta, pepper.encode()
            ), "allowed_tools": ["add"]},
        ],
        "issuer_keys": [{
            "key_id": "issuer", "issuer": "operator",
            "public_key_hex": issuer.public_key().public_bytes_raw().hex(),
            "revoked": False,
        }],
        "audit_db": str(tmp_path / "audit.sqlite3"), "port": operator_port,
    }
    signed_operator = sign_operator_policy(
        raw_operator, operator_key, revision=1,
        issued_at_ms=now - 30_000, expires_at_ms=now + 600_000,
    )
    verified_operator = verify_signed_policy(
        signed_operator,
        trusted_public_key_hex=operator_key.public_key().public_bytes_raw().hex(),
        current_time_ms=now,
    )
    raw_ingress = {
        "listen_host": "127.0.0.1", "listen_port": ingress_port,
        "operator_port": operator_port,
        "tls_cert_file": str(files["server"][0]),
        "tls_key_file": str(files["server"][1]),
        "client_ca_file": str(files["ca"]),
        "agents": [
            {"actor": "agent-alpha", "client_cert_sha256": files["alpha"][2]},
            {"actor": "agent-beta", "client_cert_sha256": files["beta"][2]},
        ],
    }
    signed_ingress = sign_mtls_ingress_policy(
        raw_ingress, ingress_key, issued_at_ms=now - 30_000,
        expires_at_ms=now + 600_000,
    )
    pinned = ingress_key.public_key().public_bytes_raw().hex()
    config = verify_ingress_policy(
        signed_ingress, pinned_public_key_hex=pinned, now_ms=now,
    )
    return {
        "files": files, "issuer": issuer, "pepper": pepper,
        "alpha": alpha, "beta": beta, "operator": verified_operator,
        "config": config, "policy": signed_ingress, "ingress_key": ingress_key,
        "pinned": pinned, "operator_port": operator_port, "ingress_port": ingress_port,
    }


def test_real_mutual_tls_agent_cert_and_bearer_and_permit_separation(tmp_path):
    setup = _setup(tmp_path)
    files = setup["files"]
    operator = setup["operator"]
    with exclusive_local_audit_lock(operator.config.audit_db):
        server = build_operator_server(
            operator.config, api_key=secrets.token_urlsafe(48),
            agent_pepper=setup["pepper"],
            policy_expires_at_ms=operator.expires_at_ms,
        )
        ingress = MTLSIngressServer(setup["config"])
        server.start(blocking=False)
        ingress.start(blocking=False)
        try:
            port, ca = setup["ingress_port"], files["ca"]
            alpha_pair = files["alpha"]
            beta_pair = files["beta"]
            unlisted_pair = files["unlisted"]
            alpha_permit = _permit(
                setup["issuer"], "agent-alpha", "echo", {"text": "scoped"}
            )
            beta_permit = _permit(
                setup["issuer"], "agent-beta", "add", {"a": 4, "b": 5}
            )
            alpha_body = _body(
                "agent-alpha", "mTLS-alpha", "echo", {"text": "scoped"}, alpha_permit
            )
            with pytest.raises((ssl.SSLError, OSError, http.client.HTTPException)):
                _https(port, ca, None, payload=alpha_body, bearer=setup["alpha"])

            assert _https(
                port, ca, unlisted_pair, payload=alpha_body,
                bearer=setup["alpha"],
            )[0] == 403
            assert _https(
                port, ca, alpha_pair, payload=alpha_body,
                bearer=setup["beta"],
            )[0] == 403
            assert _https(
                port, ca, beta_pair, payload=alpha_body,
                bearer=setup["alpha"],
            )[0] == 403
            assert _https(
                port, ca, alpha_pair, payload=alpha_body,
                bearer="agent-alpha." + secrets.token_urlsafe(48),
            )[0] == 401
            assert _https(
                port, ca, alpha_pair,
                payload=_body("agent-alpha", "no-permit", "echo", {"text": "x"}),
                bearer=setup["alpha"],
            )[1]["decision"] == "DENY"

            status, allowed = _https(
                port, ca, alpha_pair, payload=alpha_body, bearer=setup["alpha"]
            )
            assert status == 200 and allowed["decision"] == "ALLOW"
            assert allowed["result"] == "scoped"
            status, bob = _https(
                port, ca, beta_pair,
                payload=_body(
                    "agent-beta", "mTLS-beta", "add", {"a": 4, "b": 5}, beta_permit
                ), bearer=setup["beta"],
            )
            assert status == 200 and bob["decision"] == "ALLOW"
            assert bob["result"] == 9

            status, replay = _https(
                port, ca, alpha_pair,
                payload=_body(
                    "agent-alpha", "mTLS-alpha-replay", "echo",
                    {"text": "scoped"}, alpha_permit,
                ), bearer=setup["alpha"],
            )
            assert status == 200 and replay["decision"] == "DENY"
            assert "REPLAY_DETECTED" in replay["error"]
            for method, path in (("GET", "/evidence"), ("POST", "/halt"),
                                 ("POST", "/policy")):
                assert _https(
                    port, ca, alpha_pair, method=method,
                    path=path, bearer=setup["alpha"], payload={}
                )[0] == 404
        finally:
            ingress.stop()
            server.stop()


def test_unsigned_modified_and_expired_ingress_policy_fails_closed(tmp_path):
    data = _setup(tmp_path)
    signed, pinned = data["policy"], data["pinned"]
    now = int(time.time() * 1000)
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(signed))
    assert load_ingress_policy(
        str(path), pinned_public_key_hex=pinned, now_ms=now
    ) == data["config"]
    assert run_mtls_ingress(str(path)) == 2  # Trust root missing by default.
    assert verify_ingress_policy(
        signed, pinned_public_key_hex=pinned, now_ms=now,
    ).listen_host == "127.0.0.1"
    for field, value in (
        ("listen_host", "0.0.0.0"),
        ("operator_port", 9999),
        ("tls_cert_file", str(tmp_path / "missing.pem")),
        ("agents", []),
    ):
        changed = copy.deepcopy(signed)
        changed["config"][field] = value
        with pytest.raises(ValueError):
            verify_ingress_policy(
                changed, pinned_public_key_hex=pinned, now_ms=now,
            )
    other = ed25519.Ed25519PrivateKey.generate()
    with pytest.raises(ValueError, match="signature"):
        verify_ingress_policy(
            signed,
            pinned_public_key_hex=other.public_key().public_bytes_raw().hex(),
            now_ms=now,
        )
    with pytest.raises(ValueError, match="expired"):
        verify_ingress_policy(
            signed, pinned_public_key_hex=pinned, now_ms=now + 720_000,
        )
    changed = copy.deepcopy(signed)
    changed["config"]["listen_host"] = "0.0.0.0"
    resig = sign_mtls_ingress_policy(
        changed["config"], data["ingress_key"],
        issued_at_ms=now - 10_000, expires_at_ms=now + 60_000,
    )
    remote = verify_ingress_policy(
        resig, pinned_public_key_hex=pinned, now_ms=now,
    )
    with pytest.raises(ValueError, match="explicit"):
        MTLSIngressServer(remote)


def test_untrusted_json_and_symlinks_are_rejected(tmp_path):
    data = _setup(tmp_path)
    path = tmp_path / "policy.json"
    for text, pattern in (
        ('{"schema":"x","schema":"y"}', "Duplicate"),
        ('{"schema":NaN}', "Non-finite"),
        ('{"schema":1.5}', "Floating"),
    ):
        path.write_text(text)
        with pytest.raises(ValueError, match=pattern):
            load_ingress_policy(
                str(path), pinned_public_key_hex=data["pinned"],
                now_ms=int(time.time() * 1000),
            )
    path.write_text(json.dumps(data["policy"]))
    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(path)
    with pytest.raises(ValueError, match="invalid"):
        load_ingress_policy(
            str(symlink), pinned_public_key_hex=data["pinned"],
            now_ms=int(time.time() * 1000),
        )
