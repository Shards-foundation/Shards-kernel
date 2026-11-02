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
    build_operator_server, exclusive_local_audit_lock,
)
from shards_kernel.cli.signed_policy import verify_signed_policy
from shards_kernel.integrations.auth import agent_token_kdf
from shards_kernel.integrations import mtls_ingress as ingress_module
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
    config = ingress_module.verify_ingress_policy(
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
        ingress = ingress_module.MTLSIngressServer(setup["config"])
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
    assert ingress_module.load_ingress_policy(
        str(path), pinned_public_key_hex=pinned, now_ms=now
    ) == data["config"]
    assert ingress_module.run_mtls_ingress(str(path)) == 2  # Trust root missing by default.
    assert ingress_module.verify_ingress_policy(
        signed, pinned_public_key_hex=pinned, now_ms=now,
    ).listen_host == "127.0.0.1"
    for field, value in (
        ("listen_host", "192.0.2.44"),
        ("operator_port", 9999),
        ("tls_cert_file", str(tmp_path / "missing.pem")),
        ("agents", []),
    ):
        changed = copy.deepcopy(signed)
        changed["config"][field] = value
        with pytest.raises(ValueError):
            ingress_module.verify_ingress_policy(
                changed, pinned_public_key_hex=pinned, now_ms=now,
            )
    other = ed25519.Ed25519PrivateKey.generate()
    with pytest.raises(ValueError, match="signature"):
        ingress_module.verify_ingress_policy(
            signed,
            pinned_public_key_hex=other.public_key().public_bytes_raw().hex(),
            now_ms=now,
        )
    with pytest.raises(ValueError, match="expired"):
        ingress_module.verify_ingress_policy(
            signed, pinned_public_key_hex=pinned, now_ms=now + 720_000,
        )
    changed = copy.deepcopy(signed)
    changed["config"]["listen_host"] = "192.0.2.44"
    resig = sign_mtls_ingress_policy(
        changed["config"], data["ingress_key"],
        issued_at_ms=now - 10_000, expires_at_ms=now + 60_000,
    )
    remote = ingress_module.verify_ingress_policy(
        resig, pinned_public_key_hex=pinned, now_ms=now,
    )
    with pytest.raises(ValueError, match="explicit"):
        ingress_module.MTLSIngressServer(remote)


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
            ingress_module.load_ingress_policy(
                str(path), pinned_public_key_hex=data["pinned"],
                now_ms=int(time.time() * 1000),
            )
    path.write_text(json.dumps(data["policy"]))
    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(path)
    with pytest.raises(ValueError, match="invalid"):
        ingress_module.load_ingress_policy(
            str(symlink), pinned_public_key_hex=data["pinned"],
            now_ms=int(time.time() * 1000),
        )


def test_signed_ingress_policy_validation_rejects_ambiguous_network_and_identity(tmp_path):
    """Exercise independently signed but operationally dangerous configurations."""
    setup = _setup(tmp_path)
    now = int(time.time() * 1000)
    original = setup["policy"]["config"]
    key = setup["ingress_key"]

    def rejected(mutator):
        changed = copy.deepcopy(original)
        mutator(changed)
        signed = sign_mtls_ingress_policy(
            changed, key,
            issued_at_ms=now - 1_000, expires_at_ms=now + 60_000,
        )
        with pytest.raises(ValueError):
            ingress_module.verify_ingress_policy(
                signed, pinned_public_key_hex=setup["pinned"], now_ms=now
            )

    rejected(lambda x: x.update(listen_host="not-a-host"))
    rejected(lambda x: x.update(listen_host="::1"))
    rejected(lambda x: x.update(listen_host="239.1.1.1"))
    rejected(lambda x: x.update(listen_port=0))
    rejected(lambda x: x.update(operator_port=True))
    rejected(lambda x: x.update(tls_key_file=None))
    rejected(lambda x: x.update(tls_key_file="relative.pem"))
    rejected(lambda x: x.update(client_ca_file=str(tmp_path / "absent-ca.pem")))
    rejected(lambda x: x.update(agents=[]))
    rejected(lambda x: x["agents"].append(dict(x["agents"][0])))
    rejected(lambda x: x["agents"][0].update(actor="*"))
    rejected(lambda x: x["agents"][0].update(client_cert_sha256="bad-digest"))
    rejected(lambda x: x["agents"][1].update(client_cert_sha256=x["agents"][0]["client_cert_sha256"]))
    rejected(lambda x: x.update(private_key=secrets.token_urlsafe(48)))
    rejected(lambda x: x.update(listen_port="9443"))


def test_ingress_envelope_schema_clock_and_signature_fail_closed(tmp_path):
    setup = _setup(tmp_path)
    now = int(time.time() * 1000)
    signed = setup["policy"]
    pinned = setup["pinned"]
    key = setup["ingress_key"]
    for change in (
        {"schema": "other-protocol"},
        {"issued_at_ms": True},
        {"issued_at_ms": -1},
        {"expires_at_ms": 0},
        {"signature_hex": "bad"},
        {"unexpected": "extra"},
    ):
        forged = dict(signed, **change)
        with pytest.raises(ValueError):
            ingress_module.verify_ingress_policy(forged, pinned_public_key_hex=pinned, now_ms=now)
    for root in ("", "0", "g" * 64):
        with pytest.raises(ValueError):
            ingress_module.verify_ingress_policy(
                signed, pinned_public_key_hex=root, now_ms=now
            )
    with pytest.raises(ValueError, match="expired"):
        ingress_module.verify_ingress_policy(signed, pinned_public_key_hex=pinned, now_ms=now - 120_000)
    for start, end in (
        (now, now + 25 * 60 * 60 * 1000),
        (-1, now + 10_000),
        (now, now),
    ):
        with pytest.raises(ValueError):
            sign_mtls_ingress_policy(
                signed["config"], key, issued_at_ms=start, expires_at_ms=end
            )
    with pytest.raises(TypeError):
        sign_mtls_ingress_policy(
            signed["config"], object(),
            issued_at_ms=now, expires_at_ms=now + 120_000,
        )


def test_runtime_expiry_invalid_body_privileged_path_and_downstream_outage(tmp_path, monkeypatch):
    """TLS handshake and policy are valid, but unauthorised payloads never run."""
    setup = _setup(tmp_path)
    ingress = ingress_module.MTLSIngressServer(setup["config"])
    ingress.start(blocking=False)
    try:
        port, ca = setup["ingress_port"], setup["files"]["ca"]
        alpha = setup["files"]["alpha"]
        token = setup["alpha"]
        request = _body(
            "agent-alpha", "no-backend", "echo", {"text": "no"}, None
        )
        assert _https(port, ca, alpha, bearer=token, payload=request)[0] == 502
        assert _https(
            port, ca, alpha, method="GET", path="/evidence", bearer=token
        )[0] == 404
        assert _https(
            port, ca, alpha, method="POST", path="/halt", bearer=token, payload={}
        )[0] == 404
        assert _https(
            port, ca, alpha, bearer=token,
            payload=_body("agent-beta", "spoofed", "echo", {"text": "wrong"}),
        )[0] == 403
        assert _https(
            port, ca, alpha, bearer=token,
            payload=_body("agent-alpha", "unknown-tool", "not-allowlisted", {}),
        )[0] == 403
        assert _https(port, ca, alpha, bearer=None, payload=request)[0] == 401

        def raw_request(body, content_type="application/json", extra_headers=None):
            context = ssl.create_default_context(cafile=str(ca))
            context.load_cert_chain(str(alpha[0]), str(alpha[1]))
            conn = http.client.HTTPSConnection(
                "127.0.0.1", port, context=context, timeout=3
            )
            try:
                headers = {
                    "Content-Type": content_type,
                    "Authorization": "Bearer " + token,
                }
                if extra_headers:
                    headers.update(extra_headers)
                conn.request("POST", "/submit", body=body, headers=headers)
                result = conn.getresponse()
                return result.status
            finally:
                conn.close()

        assert raw_request(b"{}", content_type="text/plain") == 400
        assert raw_request(b"{}") == 403
        assert raw_request(
            b'{"actor":"agent-alpha","actor":"agent-beta"}'
        ) == 400
        assert raw_request(b"x" * (64 * 1024 + 1)) == 400
        assert raw_request(
            b"{}", extra_headers={"Transfer-Encoding": "chunked"}
        ) == 400

        # Enforce short lived signed ingress policy *after* socket startup.
        monkeypatch.setattr(
            ingress._clock, "now_ms", lambda: setup["config"].expires_at_ms + 1
        )
        assert _https(port, ca, alpha, bearer=token, payload=request)[0] == 503
        def failed_clock():
            raise RuntimeError("host time invalid")
        monkeypatch.setattr(ingress._clock, "now_ms", failed_clock)
        assert _https(port, ca, alpha, bearer=token, payload=request)[0] == 503
    finally:
        ingress.stop()


def test_cli_ingress_valid_signed_policy_runs_and_stops_without_leaking(tmp_path, monkeypatch):
    setup = _setup(tmp_path)
    signed_path = tmp_path / "signed-ingress.json"
    signed_path.write_text(json.dumps(setup["policy"]))
    monkeypatch.setenv("SHARDS_KERNEL_INGRESS_PUBLIC_KEY_HEX", setup["pinned"])
    calls = []

    class FakeIngress:
        def __init__(self, config, *, allow_remote_listen=False):
            assert config == setup["config"]
            assert not allow_remote_listen
        def start(self, *, blocking=True):
            assert blocking
            calls.append("start")
        def stop(self):
            calls.append("stop")

    monkeypatch.setattr(ingress_module, "MTLSIngressServer", FakeIngress)
    assert ingress_module.run_mtls_ingress(str(signed_path)) == 0
    assert calls == ["start", "stop"]


def test_tls_policy_file_limit_and_crypto_file_symlink_rejected(tmp_path):
    setup = _setup(tmp_path)
    now = int(time.time() * 1000)
    path = tmp_path / "big-policy.json"
    path.write_bytes(b" " * (96 * 1024 + 1))
    with pytest.raises(ValueError, match="too large"):
        ingress_module.load_ingress_policy(
            str(path), pinned_public_key_hex=setup["pinned"], now_ms=now
        )
    signed_config = copy.deepcopy(setup["policy"]["config"])
    symlink = tmp_path / "server-cert-alias.pem"
    symlink.symlink_to(setup["files"]["server"][0])
    signed_config["tls_cert_file"] = str(symlink)
    signed = sign_mtls_ingress_policy(
        signed_config, setup["ingress_key"],
        issued_at_ms=now - 1_000, expires_at_ms=now + 60_000,
    )
    with pytest.raises(ValueError, match="regular"):
        ingress_module.verify_ingress_policy(
            signed, pinned_public_key_hex=setup["pinned"], now_ms=now
        )


def test_low_level_ingress_validators_reject_unsafe_transport_and_metadata(tmp_path):
    """Direct negative paths also run on Python 3.9 without the optional MCP SDK."""
    import ipaddress

    from shards_kernel.integrations.mtls_ingress import (
        _actor, _listen_ip, _path, _port,
    )

    with pytest.raises(ValueError, match="Wildcard"):
        _listen_ip(str(ipaddress.IPv4Address(0)))
    for host in (None, "", "localhost", "::1", "239.0.0.1"):
        with pytest.raises(ValueError):
            _listen_ip(host)
    assert _listen_ip("127.0.0.1") == "127.0.0.1"
    for actor in (None, "*", "two words", "agent.dot", "", "x" * 129):
        with pytest.raises(ValueError):
            _actor(actor)
    assert _actor("agent-alpha") == "agent-alpha"
    for port in (0, 65536, True, False, "9443", None):
        with pytest.raises(ValueError):
            _port(port)
    assert _port(9443) == 9443
    for candidate in (None, "", "relative", str(tmp_path / "absent.pem")):
        with pytest.raises(ValueError):
            _path(candidate)


def test_explicit_remote_ip_flag_and_keyboard_interrupt_cleanup(tmp_path, monkeypatch):
    """Operator must explicitly allow a signed, specific remote bind."""
    setup = _setup(tmp_path)
    now = int(time.time() * 1000)
    raw = copy.deepcopy(setup["policy"]["config"])
    raw["listen_host"] = "192.0.2.99"  # Documentation-only, never actually bound.
    signed = sign_mtls_ingress_policy(
        raw, setup["ingress_key"],
        issued_at_ms=now - 1_000, expires_at_ms=now + 60_000,
    )
    config = ingress_module.verify_ingress_policy(
        signed, pinned_public_key_hex=setup["pinned"], now_ms=now,
    )
    with pytest.raises(ValueError, match="explicit"):
        ingress_module.MTLSIngressServer(config)
    ingress = ingress_module.MTLSIngressServer(config, allow_remote_listen=True)
    assert ingress.config.listen_host == "192.0.2.99"

    monkeypatch.setenv("SHARDS_KERNEL_INGRESS_PUBLIC_KEY_HEX", setup["pinned"])
    path = tmp_path / "signed-policy.json"
    path.write_text(json.dumps(setup["policy"]))
    calls = []

    class Interrupted:
        def __init__(self, _config, *, allow_remote_listen=False):
            assert not allow_remote_listen
        def start(self, *, blocking=True):
            calls.append("start")
            raise KeyboardInterrupt()
        def stop(self):
            calls.append("stop")

    monkeypatch.setattr(ingress_module, "MTLSIngressServer", Interrupted)
    assert ingress_module.run_mtls_ingress(str(path)) == 0
    assert calls == ["start", "stop"]


def test_corrupt_ingress_json_is_rejected_before_tls_or_operator_start(tmp_path):
    """Malformed UTF-8 and JSON exercise the loader's fail-closed error path."""
    setup = _setup(tmp_path)
    path = tmp_path / "bad-ingress.json"
    now = int(time.time() * 1000)
    for bytes_ in (b"{invalid-json", b"\xff\xfe\x00"):
        path.write_bytes(bytes_)
        with pytest.raises(ValueError, match="Invalid ingress policy JSON"):
            ingress_module.load_ingress_policy(
                str(path), pinned_public_key_hex=setup["pinned"], now_ms=now,
            )


def test_unfinished_tls_handshake_cannot_block_valid_client(tmp_path):
    """A raw TCP peer must not block accept() before an enrolled TLS agent."""
    setup = _setup(tmp_path)
    ingress = ingress_module.MTLSIngressServer(setup["config"])
    ingress.start(blocking=False)
    stalled = None
    try:
        stalled = socket.create_connection(
            ("127.0.0.1", setup["ingress_port"]), timeout=2,
        )
        # Keep the unauthenticated connection open without a TLS ClientHello.
        started = time.monotonic()
        status, response = _https(
            setup["ingress_port"], setup["files"]["ca"],
            setup["files"]["alpha"], bearer=setup["alpha"],
            payload=_body("agent-alpha", "live-while-stalled", "echo", {"text": "x"}),
        )
        # The backend is intentionally absent: a prompt gateway 502 proves
        # TLS and forwarding proceeded despite the stalled connection.
        assert status == 502 and response["error"] == "Local operator unavailable"
        assert time.monotonic() - started < 2.9
    finally:
        if stalled is not None:
            stalled.close()
        ingress.stop()


def test_exhausted_tls_worker_capacity_rejects_and_recovers(tmp_path, monkeypatch):
    """An adversary cannot create unbounded threads with incomplete handshakes."""

    monkeypatch.setattr(ingress_module, "_MAX_CONCURRENT_CONNECTIONS", 2)
    setup = _setup(tmp_path)
    ingress = ingress_module.MTLSIngressServer(setup["config"])
    ingress.start(blocking=False)
    stalled = []
    try:
        for _ in range(2):
            stalled.append(socket.create_connection(
                ("127.0.0.1", setup["ingress_port"]), timeout=2,
            ))
        # The two accepted sockets are occupying the only handshake slots.
        deadline = time.monotonic() + 2
        while ingress._server._slots._value != 0 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert ingress._server._slots._value == 0

        # At capacity, a new connection must fail closed rather than spawn
        # a third worker or become a privileged unauthenticated request.
        with pytest.raises((OSError, ssl.SSLError, http.client.HTTPException)):
            _https(
                setup["ingress_port"], setup["files"]["ca"],
                setup["files"]["alpha"], bearer=setup["alpha"],
                payload=_body("agent-alpha", "over-capacity", "echo", {"text": "x"}),
            )
        # Recovery is part of the admission contract, not just rejection.
        for connection in stalled:
            connection.close()
        stalled.clear()
        deadline = time.monotonic() + 3
        while ingress._server._slots._value != 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert ingress._server._slots._value == 2
        status, _ = _https(
            setup["ingress_port"], setup["files"]["ca"],
            setup["files"]["alpha"], bearer=setup["alpha"],
            payload=_body("agent-alpha", "recovered-capacity", "echo", {"text": "x"}),
        )
        assert status == 502  # Missing backend; TLS admission recovered.
    finally:
        for connection in stalled:
            connection.close()
        ingress.stop()


def test_policy_expiring_during_body_parse_denies_forward(tmp_path, monkeypatch):
    """Authority must still be live at execution, not just at admission."""
    setup = _setup(tmp_path)
    ingress = ingress_module.MTLSIngressServer(setup["config"])
    ingress.start(blocking=False)
    try:
        expiry = setup["config"].expires_at_ms
        samples = iter((expiry - 1, expiry + 1))
        monkeypatch.setattr(ingress._clock, "now_ms", lambda: next(samples))
        status, response = _https(
            setup["ingress_port"], setup["files"]["ca"], setup["files"]["alpha"],
            bearer=setup["alpha"],
            payload=_body("agent-alpha", "expiry-race", "echo", {"text": "x"}),
        )
        assert status == 503
        assert response["error"] == "Signed ingress policy expired"
    finally:
        ingress.stop()


def test_slow_body_has_total_deadline_not_just_socket_timeout(tmp_path, monkeypatch):
    """A client trickling bytes must not occupy a worker indefinitely."""
    import threading

    monkeypatch.setattr(ingress_module, "_BODY_DEADLINE_SECONDS", 0.05)
    monkeypatch.setattr(ingress_module, "_REQUEST_TIMEOUT_SECONDS", 1.0)
    started = threading.Event()
    original = ingress_module._IngressHandler._governed_body

    def signal_body_read(self, actor):
        started.set()
        return original(self, actor)

    monkeypatch.setattr(ingress_module._IngressHandler, "_governed_body", signal_body_read)
    setup = _setup(tmp_path)
    ingress = ingress_module.MTLSIngressServer(setup["config"])
    ingress.start(blocking=False)
    connection = None
    try:
        context = ssl.create_default_context(cafile=str(setup["files"]["ca"]))
        context.load_cert_chain(
            str(setup["files"]["alpha"][0]), str(setup["files"]["alpha"][1])
        )
        connection = http.client.HTTPSConnection(
            "127.0.0.1", setup["ingress_port"], context=context, timeout=3,
        )
        body = json.dumps(
            _body("agent-alpha", "body-deadline", "echo", {"text": "x"})
        ).encode()
        connection.putrequest("POST", "/submit")
        connection.putheader("Authorization", "Bearer " + setup["alpha"])
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", str(len(body)))
        connection.endheaders()
        connection.send(body[:1])
        assert started.wait(timeout=2)
        # No more bytes arrive. A strictly bounded read must terminate
        # promptly without waiting for the longer socket idle timeout.
        started_at = time.monotonic()
        response = connection.getresponse()
        elapsed = time.monotonic() - started_at
        assert response.status == 400
        assert json.loads(response.read())["error"] == "Invalid governed request"
        assert elapsed < 0.8
    finally:
        if connection is not None:
            connection.close()
        ingress.stop()


def test_tls_handshake_times_out_and_releases_capacity(tmp_path, monkeypatch):
    """Half-open pre-authentication TLS sockets cannot hold slots indefinitely."""
    from shards_kernel.integrations import mtls_ingress as module

    monkeypatch.setattr(ingress_module, "_HANDSHAKE_TIMEOUT_SECONDS", 0.15)
    setup = _setup(tmp_path)
    ingress = ingress_module.MTLSIngressServer(setup["config"])
    ingress.start(blocking=False)
    stalled = None
    try:
        assert ingress._server.request_queue_size == 16
        stalled = socket.create_connection(
            ("127.0.0.1", setup["ingress_port"]), timeout=2,
        )
        stalled.settimeout(2)
        assert stalled.recv(1) == b""  # Server drops incomplete handshake.
        deadline = time.monotonic() + 2
        while ingress._server._slots._value != module._MAX_CONCURRENT_CONNECTIONS and time.monotonic() < deadline:
            time.sleep(0.01)
        assert ingress._server._slots._value == module._MAX_CONCURRENT_CONNECTIONS
        status, _ = _https(
            setup["ingress_port"], setup["files"]["ca"],
            setup["files"]["alpha"], bearer=setup["alpha"],
            payload=_body("agent-alpha", "handshake-timeout-recovery", "echo", {"text": "x"}),
        )
        assert status == 502  # Valid TLS accepted; backend remains absent.
    finally:
        if stalled is not None:
            stalled.close()
        ingress.stop()


def test_authenticated_socket_idle_timeout_releases_worker(tmp_path, monkeypatch):
    """An authenticated TLS peer cannot stall HTTP header parsing indefinitely."""
    from shards_kernel.integrations import mtls_ingress as module

    monkeypatch.setattr(ingress_module, "_REQUEST_TIMEOUT_SECONDS", 0.15)
    setup = _setup(tmp_path)
    ingress = ingress_module.MTLSIngressServer(setup["config"])
    ingress.start(blocking=False)
    tls_sock = None
    try:
        context = ssl.create_default_context(cafile=str(setup["files"]["ca"]))
        context.load_cert_chain(
            str(setup["files"]["alpha"][0]), str(setup["files"]["alpha"][1])
        )
        raw = socket.create_connection(("127.0.0.1", setup["ingress_port"]), timeout=2)
        tls_sock = context.wrap_socket(raw, server_hostname="127.0.0.1")
        tls_sock.settimeout(2)
        tls_sock.sendall(b"POST /submit HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\n")
        # No HTTP header terminator: server must release worker on idle timeout.
        assert tls_sock.recv(1) == b""
        deadline = time.monotonic() + 2
        while ingress._server._slots._value != module._MAX_CONCURRENT_CONNECTIONS and time.monotonic() < deadline:
            time.sleep(0.01)
        assert ingress._server._slots._value == module._MAX_CONCURRENT_CONNECTIONS
    finally:
        if tls_sock is not None:
            tls_sock.close()
        ingress.stop()


@pytest.mark.parametrize("unfinished", [
    b"POST /sub",
    b"POST /submit HTTP/1.1\\r\\nHost: local\\r\\nX-Slow: ",
])
def test_aggregate_http_header_deadline_releases_tls_slot(
    tmp_path, monkeypatch, unfinished,
):
    """Slow request-line/header bytes cannot extend the absolute admission slot."""
    monkeypatch.setattr(ingress_module, "_MAX_CONCURRENT_CONNECTIONS", 1)
    monkeypatch.setattr(ingress_module, "_HEADER_DEADLINE_SECONDS", 0.35)
    monkeypatch.setattr(ingress_module, "_REQUEST_TIMEOUT_SECONDS", 1.5)
    setup = _setup(tmp_path)
    ingress = ingress_module.MTLSIngressServer(setup["config"])
    ingress.start(blocking=False)
    peer = None
    try:
        context = ssl.create_default_context(cafile=str(setup["files"]["ca"]))
        context.load_cert_chain(
            str(setup["files"]["unlisted"][0]),
            str(setup["files"]["unlisted"][1]),
        )
        raw = socket.create_connection(
            ("127.0.0.1", setup["ingress_port"]), timeout=2,
        )
        peer = context.wrap_socket(raw, server_hostname="127.0.0.1")
        peer.settimeout(2)
        started = time.monotonic()
        peer.sendall(unfinished)
        # The peer has a CA-valid but *unpinned* certificate. Request-header
        # parsing must end before actor pin and bearer checks are reached.
        for _ in range(2):
            time.sleep(0.08)
            try:
                peer.sendall(b"x")
            except OSError:
                break
        try:
            remaining = peer.recv(1)
        except (OSError, ssl.SSLError):
            remaining = b""
        elapsed = time.monotonic() - started
        assert remaining == b""
        assert elapsed < 1.2

        deadline = time.monotonic() + 2
        while ingress._server._slots._value != 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert ingress._server._slots._value == 1
        status, _ = _https(
            setup["ingress_port"], setup["files"]["ca"],
            setup["files"]["alpha"], bearer=setup["alpha"],
            payload=_body("agent-alpha", "header-deadline-recovery", "echo", {"text": "ok"}),
        )
        assert status == 502  # TLS accepted again; backend is intentionally absent.
    finally:
        if peer is not None:
            peer.close()
        ingress.stop()
