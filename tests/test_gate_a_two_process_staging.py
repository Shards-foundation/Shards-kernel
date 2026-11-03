"""Bidirectional multi-process mTLS staging simulation, not real two-host certification.

Synthetic keys only; two distinct service processes, TLS roots and SQLite
databases. An enrolled certificate, key and bearer are copied to the CALLING
process's own private directory before the request. No runtime code changes.
"""
from __future__ import annotations

import multiprocessing
import os
from pathlib import Path
import sys
import time

import pytest


def _install_client_identity(client_root, target_info, target_label):
    """Simulate human provisioning of a target-enrolled agent on the peer host."""
    directory = Path(client_root) / "client-identities" / target_label
    directory.mkdir(parents=True, mode=0o700)
    for name, data in (
        ("agent.pem", Path(target_info["cert"]).read_bytes()),
        ("agent-key.pem", Path(target_info["key"]).read_bytes()),
        ("ca.pem", Path(target_info["ca"]).read_bytes()),
        ("token", target_info["bearer"].encode("ascii")),
    ):
        dest = directory / name
        fd = os.open(str(dest), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
    return directory


def _node(root: str, channel) -> None:
    from tests.test_mtls_agent_ingress import _body, _https, _permit, _setup
    from shards_kernel.cli.service import build_operator_server, exclusive_local_audit_lock
    from shards_kernel.integrations.mtls_ingress import MTLSIngressServer

    server = ingress = None
    try:
        config = _setup(Path(root))
        with exclusive_local_audit_lock(config["operator"].config.audit_db):
            server = build_operator_server(
                config["operator"].config,
                api_key="synthetic-operator-only-" + os.urandom(16).hex(),
                agent_pepper=config["pepper"],
                policy_expires_at_ms=config["operator"].expires_at_ms,
            )
            ingress = MTLSIngressServer(config["config"])
            server.start(blocking=False)
            ingress.start(blocking=False)
            channel.send({
                "ready": True,
                "pid": os.getpid(),
                "port": config["ingress_port"],
                "ca": str(config["files"]["ca"]),
                "cert": str(config["files"]["alpha"][0]),
                "key": str(config["files"]["alpha"][1]),
                "bearer": config["alpha"],
                "database": str(config["operator"].config.audit_db),
            })
            while True:
                request = channel.recv()
                op = request["op"]
                if op == "stop":
                    channel.send({"stopped": True})
                    break
                if op == "mint":
                    channel.send({"permit": _permit(
                        config["issuer"], "agent-alpha", "echo", request["params"]
                    )})
                    continue
                if op == "call":
                    # All client credentials are read from the CALLER'S local
                    # root. We never load the destination's private-key path.
                    target_label = request["target_label"]
                    identity_dir = Path(root) / "client-identities" / target_label
                    client_pair = (
                        identity_dir / "agent.pem",
                        identity_dir / "agent-key.pem",
                    )
                    if request.get("foreign_cert"):
                        # This process's *own* CA-issued cert is deliberately
                        # foreign to the target ingress.
                        client_pair = config["files"]["alpha"][:2]
                    ca = identity_dir / "ca.pem"
                    bearer = (identity_dir / "token").read_text("ascii")
                    params = request["params"]
                    payload = _body(
                        "agent-alpha", request["request_id"], "echo",
                        params, request.get("permit"),
                    )
                    for attempt in range(15):
                        try:
                            status, response = _https(
                                request["port"], ca, client_pair,
                                bearer=bearer, payload=payload,
                                method=request.get("method", "POST"),
                                path=request.get("path", "/submit"),
                            )
                            channel.send({
                                "status": status, "body": response,
                                "client_cert_path": str(client_pair[0]),
                                "caller_pid": os.getpid(),
                            })
                            break
                        except ConnectionRefusedError:
                            if attempt == 14:
                                channel.send({"error": "ingress never became reachable"})
                            else:
                                time.sleep(0.15)
                        except Exception as exc:
                            channel.send({"transport_error": type(exc).__name__})
                            break
                    continue
                channel.send({"error": "unknown command"})
    except Exception as exc:
        # Report a failure, not a silent pass. Never print synthetic secrets.
        print("two-process staging worker failed: %s" % type(exc).__name__, file=sys.stderr)
        try:
            channel.send({"fatal": type(exc).__name__})
        except (BrokenPipeError, EOFError, OSError) as report_error:
            print("could not report worker failure: %s" % type(report_error).__name__, file=sys.stderr)
    finally:
        if ingress is not None:
            ingress.stop()
        if server is not None:
            server.stop()
        channel.close()


def _rpc(channel, command, timeout=30):
    channel.send(command)
    assert channel.poll(timeout), "worker timed out"
    response = channel.recv()
    assert "error" not in response and "fatal" not in response, response
    return response


def _start_node(ctx, root):
    root.mkdir(mode=0o700)
    parent, child = ctx.Pipe()
    process = ctx.Process(target=_node, args=(str(root), child), daemon=True)
    process.start()
    child.close()
    assert parent.poll(40), "service did not start"
    info = parent.recv()
    assert info.get("ready"), info
    return process, parent, info


def _stop_node(process, channel):
    try:
        if process.is_alive():
            channel.send({"op": "stop"})
            if channel.poll(5):
                assert channel.recv().get("stopped") is True
        process.join(timeout=6)
        if process.is_alive():
            process.terminate()
            process.join(timeout=3)
        assert not process.is_alive(), "worker not cleaned up"
    finally:
        channel.close()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux staging simulation")
def test_two_independent_processes_bidirectional_mtls_and_replay(tmp_path):
    ctx = multiprocessing.get_context("spawn")
    nodes = []
    try:
        for label in ("a", "b"):
            process, channel, info = _start_node(ctx, tmp_path / label)
            nodes.append((process, channel, info))

        (proc_a, chan_a, info_a), (proc_b, chan_b, info_b) = nodes
        assert info_a["pid"] != info_b["pid"]
        assert info_a["database"] != info_b["database"]
        assert Path(info_a["ca"]).read_bytes() != Path(info_b["ca"]).read_bytes()

        # Certificate/key/token for ingress A live in B's directory.
        a_on_b = _install_client_identity(tmp_path / "b", info_a, "a")
        b_on_a = _install_client_identity(tmp_path / "a", info_b, "b")
        assert a_on_b != b_on_a
        for folder in (a_on_b, b_on_a):
            assert (folder / "agent-key.pem").stat().st_mode & 0o777 == 0o600
            assert (folder / "token").stat().st_mode & 0o777 == 0o600

        params_a = {"text": "B-to-A"}
        permit_a = _rpc(chan_a, {"op": "mint", "params": params_a})["permit"]
        d1 = _rpc(chan_b, {
            "op": "call", "target_label": "a", "port": info_a["port"],
            "request_id": "d1-first", "params": params_a, "permit": permit_a,
        })
        assert d1["status"] == 200 and d1["body"]["decision"] == "ALLOW", d1
        assert d1["body"]["result"] == "B-to-A"
        assert d1["caller_pid"] == info_b["pid"]
        assert d1["client_cert_path"] == str(a_on_b / "agent.pem")
        assert d1["client_cert_path"] != info_a["cert"]

        replay = _rpc(chan_b, {
            "op": "call", "target_label": "a", "port": info_a["port"],
            "request_id": "d1-replay", "params": params_a, "permit": permit_a,
        })
        assert replay["status"] == 200 and replay["body"]["decision"] == "DENY", replay
        assert "REPLAY_DETECTED" in replay["body"].get("error", "")

        params_b = {"text": "A-to-B"}
        permit_b = _rpc(chan_b, {"op": "mint", "params": params_b})["permit"]
        d2 = _rpc(chan_a, {
            "op": "call", "target_label": "b", "port": info_b["port"],
            "request_id": "d2-first", "params": params_b, "permit": permit_b,
        })
        assert d2["status"] == 200 and d2["body"]["decision"] == "ALLOW", d2
        assert d2["body"]["result"] == "A-to-B"
        assert d2["caller_pid"] == info_a["pid"]
        assert d2["client_cert_path"] == str(b_on_a / "agent.pem")
        assert d2["client_cert_path"] != info_b["cert"]

        foreign = _rpc(chan_b, {
            "op": "call", "target_label": "a", "port": info_a["port"],
            "request_id": "d1-foreign-ca", "params": params_a,
            "permit": permit_a, "foreign_cert": True,
        })
        assert foreign.get("transport_error") in (
            "SSLError", "SSLEOFError", "SSLCertVerificationError",
            "ConnectionResetError", "BrokenPipeError",
        ), foreign

        admin = _rpc(chan_b, {
            "op": "call", "target_label": "a", "port": info_a["port"],
            "request_id": "d1-admin", "params": params_a,
            "method": "GET", "path": "/evidence",
        })
        assert admin["status"] == 404, admin
    finally:
        for process, channel, _ in reversed(nodes):
            _stop_node(process, channel)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux staging simulation")
def test_worker_startup_failure_is_reported(tmp_path):
    ctx = multiprocessing.get_context("spawn")
    parent, child = ctx.Pipe()
    process = ctx.Process(target=_node, args=(str(tmp_path / "missing"), child))
    process.start()
    child.close()
    try:
        assert parent.poll(25), "startup failure was silent"
        message = parent.recv()
        assert message.get("fatal") == "FileNotFoundError", message
    finally:
        process.join(timeout=5)
        if process.is_alive():
            process.terminate()
            process.join(timeout=3)
        parent.close()
    assert not process.is_alive()


def test_rpc_timeout_does_not_report_success():
    parent, child = multiprocessing.Pipe()
    try:
        with pytest.raises(AssertionError, match="worker timed out"):
            _rpc(parent, {"op": "unknown"}, timeout=0.01)
    finally:
        parent.close()
        child.close()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux staging simulation")
def test_unknown_rpc_is_rejected_and_worker_stops(tmp_path):
    ctx = multiprocessing.get_context("spawn")
    process, channel, _ = _start_node(ctx, tmp_path / "single")
    try:
        with pytest.raises(AssertionError, match="unknown command"):
            _rpc(channel, {"op": "unknown"})
    finally:
        _stop_node(process, channel)
