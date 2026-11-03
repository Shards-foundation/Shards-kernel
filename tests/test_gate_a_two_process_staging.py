"""Two-process, bidirectional staging simulation for real Shards-Kernel mTLS ingress.

This is not a two-host certification. Both independent service processes run on
one GitHub Actions runner and share its filesystem. Every key is synthetic;
two operators, two ingress listeners, distinct CAs and audit DBs are used.
No production infrastructure, credentials, wallets or external effects.
"""
from __future__ import annotations

import multiprocessing
import os
from pathlib import Path
import sys
import time

import pytest


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
                "ready": True, "pid": os.getpid(),
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
                    target = request["target"]
                    credential = request.get("credential", target)
                    payload = _body(
                        "agent-alpha", request["request_id"], "echo",
                        request["params"], request.get("permit"),
                    )
                    for attempt in range(15):
                        try:
                            status, response = _https(
                                target["port"], Path(target["ca"]),
                                (Path(credential["cert"]), Path(credential["key"])),
                                bearer=target["bearer"], payload=payload,
                                method=request.get("method", "POST"),
                                path=request.get("path", "/submit"),
                            )
                            channel.send({"status": status, "body": response})
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
    except BaseException as exc:
        try:
            channel.send({"fatal": type(exc).__name__, "message": str(exc)[:150]})
        except Exception:
            pass
    finally:
        if ingress is not None:
            ingress.stop()
        if server is not None:
            server.stop()
        channel.close()


def _rpc(channel, command):
    channel.send(command)
    assert channel.poll(30), "worker timed out"
    response = channel.recv()
    assert "error" not in response and "fatal" not in response, response
    return response


@pytest.mark.skipif(sys.platform != "linux", reason="Linux staging simulation")
def test_two_independent_processes_bidirectional_mtls_and_replay(tmp_path):
    ctx = multiprocessing.get_context("spawn")
    nodes = []
    for label in ("a", "b"):
        root = tmp_path / label
        root.mkdir(mode=0o700)
        parent, child = ctx.Pipe()
        proc = ctx.Process(target=_node, args=(str(root), child), daemon=True)
        proc.start()
        nodes.append((proc, parent))
    try:
        (proc_a, chan_a), (proc_b, chan_b) = nodes
        assert chan_a.poll(40) and chan_b.poll(40), "services did not start"
        info_a, info_b = chan_a.recv(), chan_b.recv()
        assert info_a.get("ready") and info_b.get("ready"), (info_a, info_b)
        assert info_a["pid"] != info_b["pid"]
        assert info_a["database"] != info_b["database"]
        assert Path(info_a["ca"]).read_bytes() != Path(info_b["ca"]).read_bytes()

        # D1: client in process B calls A's real mTLS ingress.
        params_a = {"text": "B-to-A"}
        permit_a = _rpc(chan_a, {"op": "mint", "params": params_a})["permit"]
        allowed_a = _rpc(chan_b, {
            "op": "call", "target": info_a, "request_id": "d1-first",
            "params": params_a, "permit": permit_a,
        })
        assert allowed_a["status"] == 200 and allowed_a["body"]["decision"] == "ALLOW", allowed_a
        assert allowed_a["body"]["result"] == "B-to-A"

        replay_a = _rpc(chan_b, {
            "op": "call", "target": info_a, "request_id": "d1-replay",
            "params": params_a, "permit": permit_a,
        })
        assert replay_a["status"] == 200 and replay_a["body"]["decision"] == "DENY", replay_a
        assert "REPLAY_DETECTED" in replay_a["body"].get("error", "")

        # D2: client in process A calls B with B's independent CA.
        params_b = {"text": "A-to-B"}
        permit_b = _rpc(chan_b, {"op": "mint", "params": params_b})["permit"]
        allowed_b = _rpc(chan_a, {
            "op": "call", "target": info_b, "request_id": "d2-first",
            "params": params_b, "permit": permit_b,
        })
        assert allowed_b["status"] == 200 and allowed_b["body"]["decision"] == "ALLOW", allowed_b
        assert allowed_b["body"]["result"] == "A-to-B"

        foreign_cert = _rpc(chan_b, {
            "op": "call", "target": info_a, "credential": info_b,
            "request_id": "d1-foreign-ca", "params": params_a, "permit": permit_a,
        })
        assert foreign_cert.get("transport_error") in (
            "SSLError", "SSLEOFError", "SSLCertVerificationError",
            "ConnectionResetError", "BrokenPipeError",
        ), foreign_cert

        private_path = _rpc(chan_b, {
            "op": "call", "target": info_a, "request_id": "d1-admin",
            "params": params_a, "method": "GET", "path": "/evidence",
        })
        assert private_path["status"] == 404, private_path
    finally:
        for proc, chan in nodes:
            if proc.is_alive():
                try:
                    chan.send({"op": "stop"})
                    if chan.poll(5):
                        chan.recv()
                except (OSError, EOFError, BrokenPipeError):
                    pass
            proc.join(timeout=6)
            if proc.is_alive():
                proc.terminate()
                proc.join(timeout=3)
            chan.close()
