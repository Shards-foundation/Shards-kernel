#!/usr/bin/env python3
"""Independent, strictly scoped runtime probes. Imports installed PyPI distribution only."""
import concurrent.futures
import dataclasses
import hashlib
import importlib.metadata as metadata
import json
import os
import pathlib
import platform
import subprocess
import sys
import tempfile
import time
import traceback
from enum import Enum

OUT = pathlib.Path(os.environ.get("ACCEPTANCE_OUT", "evidence")).resolve()
OUT.mkdir(parents=True, exist_ok=True)
(OUT / "failure-evidence").mkdir(exist_ok=True)
EXPECTED_WHEEL_SHA256 = "08dc0df1ade8769a3c9cd7560fd22362e1a313aa78de5d1063c67d64a59fa057"
GATES = {
  0: "Supply chain and installation", 1: "Cryptographic authorisation",
  2: "Concurrency and replay", 3: "Crash consistency and recovery",
  4: "Audit integrity", 5: "HTTP service security",
  6: "Mutual TLS and network identity", 7: "MCP end-to-end integration",
  8: "All kernel variants", 9: "Resource exhaustion and reliability",
  10: "Operational deployment"
}
tests = []
def check(gate, name, procedure, *, mandatory=True):
    started = time.perf_counter()
    try:
        evidence = procedure()
        result = {"gate":gate, "id":name, "status":"PASS", "mandatory":mandatory,
                  "elapsed_ms":round((time.perf_counter()-started)*1000,2),
                  "evidence":evidence if evidence is not None else {}}
    except Exception as exc:
        result = {"gate":gate, "id":name, "status":"FAIL", "mandatory":mandatory,
                  "elapsed_ms":round((time.perf_counter()-started)*1000,2),
                  "error_type":type(exc).__name__, "error":str(exc)[:700]}
        (OUT/"failure-evidence"/(name.replace("/","_")+".json")).write_text(
            json.dumps({"case":name,"error_type":type(exc).__name__,
                        "error":str(exc)[:700],"traceback":traceback.format_exc()[-3500:]},indent=2))
    tests.append(result)
    print(json.dumps({"case":name,"gate":gate,"status":result["status"],"elapsed_ms":result["elapsed_ms"]}),flush=True)

def require(cond, message):
    if not cond:
        raise AssertionError(message)

def run_cli(args):
    cp = subprocess.run([str(pathlib.Path(sys.executable).parent/"shards-kernel"),*args],capture_output=True,text=True,timeout=30)
    require(cp.returncode == 0, f"CLI {args} exit={cp.returncode} stderr={cp.stderr[-450:]}")
    return cp.stdout

def cli_version():
    from shards_kernel import __version__
    require(__version__=="0.1.2","wrong import version")
    require(metadata.version("shards-kernel")=="0.1.2","wrong installed dist")
    path = pathlib.Path(__import__("shards_kernel").__file__).resolve()
    require(str(path).startswith(sys.prefix),f"import not from isolated venv: {path}")
    require("0.1.2" in run_cli(["--version"]),"CLI incorrect")
    require("Strict Kernel" in run_cli(["info","--variant","strict"]),"CLI info wrong")
    return {"import_path":str(path),"version":"0.1.2"}

def wheel_integrity():
    wheels=list(pathlib.Path(os.environ.get("ACCEPTANCE_WHEELHOUSE","wheelhouse")).glob("shards_kernel-0.1.2-*.whl"))
    require(len(wheels)==1,f"expected one wheel, found {len(wheels)}")
    h=hashlib.sha256(wheels[0].read_bytes()).hexdigest()
    require(h==EXPECTED_WHEEL_SHA256, f"wheel sha256 mismatch: {h}")
    return {"wheel":wheels[0].name,"sha256":h,"bytes":wheels[0].stat().st_size}

def demo():
    v=json.loads(run_cli(["demo","--json"]))
    require(v["passed"] is True,"published demo failed")
    require(v["production_ready"] is False, "demo must not claim certification")
    require(all(c["passed"] for c in v["checks"]),"demo subtasks failed")
    return {"checks":v["checks"],"audited_entries":v["audited_entries"]}

check(0,"published_wheel_sha256",wheel_integrity)
check(0,"installed_distribution_cli",cli_version)
check(0,"offline_signed_permit_demo",demo)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from shards_kernel import (StrictKernel, PermissiveKernel, EvidenceFirstKernel,
    DualChannelKernel, KernelConfig, KernelRequest, ToolCall, VirtualClock, Decision,
    JurisdictionPolicy, PermitBuilder)
from shards_kernel.issuer import sign_v2_permit
from shards_kernel.permits import PublicVerificationKey
from shards_kernel.audit.replay import replay_and_verify
from shards_kernel.common.types import KernelState

ACTOR="agent-acceptance"
KID="acceptance-kernel"
KEY_ID="independent-issuer"
ISSUER="acceptance-issuer"
SECRET=Ed25519PrivateKey.generate()
PUBLIC=PublicVerificationKey(issuer=ISSUER,audience=KID,
                             public_key=SECRET.public_key().public_bytes_raw())
def new_kernel(variant=StrictKernel, verifier=PUBLIC, *, effects=None):
    k=variant()
    k.boot(KernelConfig(kernel_id=KID,variant={
      StrictKernel:"strict",PermissiveKernel:"permissive",
      EvidenceFirstKernel:"evidence-first",DualChannelKernel:"dual-channel"}[variant],
      clock=VirtualClock(1000)))
    k.set_policy(JurisdictionPolicy(allowed_actors=frozenset({ACTOR}),
                                    allowed_tools=frozenset({"effect"})))
    k.set_public_verifiers({KEY_ID:verifier})
    if effects is not None:
        def effect(payload):
            effects.append(payload)
            return {"done":True}
        k._dispatcher.registry.register("effect",effect)
    return k
def new_permit(params=None,max_uses=1,**kw):
    p=(PermitBuilder().issuer(ISSUER).subject(ACTOR)
       .jurisdiction("default").action("effect")
       .params(params if params is not None else {"payload":{"amount":1}})
       .max_executions(max_uses)
       .valid_from_ms(kw.get("from_ms",0))
       .valid_until_ms(kw.get("until_ms",2000))
       .proposal_hash("independent-runtime-probe")
       .build_unsigned_v2(key_id=KEY_ID,audience=KID))
    return sign_v2_permit(p,SECRET)
def request(ident,params=None,actor=ACTOR,tool="effect",tool_params=None):
    p=params if params is not None else {"payload":{"amount":1}}
    return KernelRequest(request_id=ident,ts_ms=1000,actor=actor,
       intent="independent-governed-side-effect",
       tool_call=ToolCall(name=tool,params=p if tool_params is None else tool_params),
       params=p)
def case(name, mutator=None, *, allowed=False):
    effects=[]
    k=new_kernel(effects=effects)
    permit=new_permit()
    req=request(name)
    if mutator:
        req,permit,k=mutator(req,permit,k)
    receipt=k.submit(req,permit_token=permit)
    require((receipt.decision==Decision.ALLOW)==allowed,
            f"wrong decision {receipt.decision} / {receipt.error}")
    require(len(effects)==int(allowed),
            f"unexpected effect count {len(effects)}")
    return {"decision":receipt.decision.value,
            "error":(receipt.error or "")[:220],"effect_count":len(effects)}

def missing(req,p,k): return req,None,k
def wrong_actor(req,p,k): return dataclasses.replace(req,actor="impostor"),p,k
def wrong_tool(req,p,k): return request("wrongtool",tool="echo"),p,k
def wrong_value(req,p,k): return request("wrongvalue",{"payload":{"amount":2}}),p,k
def bool_int(req,p,k): return request("boolint",{"payload":{"amount":True}}),p,k
def nested(req,p,k): return request("nested",{"payload":{"amount":1,"extra":"x"}}),p,k
def missing_param(req,p,k): return request("missing",{}),p,k
def extra_param(req,p,k): return request("extra",{"payload":{"amount":1},"other":1}),p,k
def mismatched(req,p,k): return request("mismatch",tool_params={"payload":{"amount":999}}),p,k
def tamper(req,p,k): return req,dataclasses.replace(p,params={"payload":{"amount":999}}),k
def wrong_sig(req,p,k): return req,dataclasses.replace(p,signature="00"*64),k
def future(req,p,k): return req,new_permit(from_ms=1001),k
def expired(req,p,k): return req,new_permit(until_ms=999),k
def revoked(req,p,k):
    k.set_public_verifiers({KEY_ID:dataclasses.replace(PUBLIC,revoked=True)})
    return req,p,k
def unknown_issuer(req,p,k):
    k.set_public_verifiers({})
    return req,p,k

for name, mutator in [
    ("valid_real_tool_effect",None),("missing_permit",missing),
    ("wrong_actor",wrong_actor),("wrong_tool",wrong_tool),
    ("wrong_params",wrong_value),("bool_int_ambiguity",bool_int),
    ("nested_payload_change",nested),("missing_param",missing_param),
    ("extra_param",extra_param),("tool_request_parameter_mismatch",mismatched),
    ("tampered_permit",tamper),("invalid_signature",wrong_sig),
    ("not_yet_valid",future),("expired_permit",expired),
    ("revoked_issuer",revoked),("unknown_issuer",unknown_issuer)]:
    check(1,name,lambda n=name,m=mutator:case(n,m,allowed=(m is None)))

def replay_and_restart():
    effects=[];k=new_kernel(effects=effects);permit=new_permit()
    r=k.submit(request("original"),permit_token=permit)
    require(r.decision==Decision.ALLOW and len(effects)==1,"initial not allowed")
    r2=k.submit(request("same-permit"),permit_token=permit)
    require(r2.decision==Decision.DENY and len(effects)==1,"replay allowed")
    export=k.export_evidence()
    restored=new_kernel(effects=effects)
    restored.load_ledger(export)
    r3=restored.submit(request("recovered-replay"),permit_token=permit)
    require(r3.decision==Decision.DENY and len(effects)==1,"restart replay allowed")
    return {"original":"ALLOW","replay":"DENY","recovered":"DENY","effects":1,
            "root":export.root_hash,"entries":len(export.ledger_entries)}
check(3,"verified_ledger_restart_replay",replay_and_restart)

def thread_race():
    effects=[];k=new_kernel(effects=effects);p=new_permit()
    def work(i):
        try:return k.submit(request("race-"+str(i)),permit_token=p).decision.value
        except Exception as e:return "exception:"+type(e).__name__
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as pool:
        results=list(pool.map(work,range(100)))
    admitted=results.count("ALLOW")
    require(admitted<=1 and len(effects)<=1,
           f"permit overconsumption: admitted={admitted}, effects={len(effects)}")
    return {"attempts":100,"admitted":admitted,"effects":len(effects),
            "exceptions":sum(r.startswith("exception") for r in results),
            "note":"Direct multi-thread kernel calls may be unsupported topology"}
check(2,"100_competing_single_use_calls",thread_race)

def verify_ledger():
    k=new_kernel(effects=[])
    p=new_permit()
    k.submit(request("audit-allow"),permit_token=p)
    k.submit(request("audit-replay"),permit_token=p)
    e=k.export_evidence()
    def conv(v):
        if isinstance(v,Enum):return v.value
        if isinstance(v,dict):return {a:conv(b) for a,b in v.items()}
        if isinstance(v,(list,tuple)):return [conv(x) for x in v]
        return v
    entries=[conv(dataclasses.asdict(x)) for x in e.ledger_entries]
    ok, errors=replay_and_verify(entries,e.root_hash)
    require(ok,f"clean ledger replay failed: {errors}")
    changed=json.loads(json.dumps(entries))
    if changed:
        changed[0]["actor"]="forged-actor"
        ok2,_=replay_and_verify(changed,e.root_hash)
        require(not ok2,"tampered ledger accepted")
        ok3,_=replay_and_verify(entries[:-1],e.root_hash)
        require(not ok3,"tail deletion undetected against trusted witness")
    return {"entries":len(entries),"root":e.root_hash,
            "tamper_rejected":True,"tail_truncation_with_witness_rejected":True}
check(4,"audit_replay_tamper_and_witness",verify_ledger)

def variants_reject_missing_permit():
    output={}
    for variant in [StrictKernel,PermissiveKernel,EvidenceFirstKernel,DualChannelKernel]:
        effects=[]
        k=new_kernel(variant,effects=effects)
        decision=k.submit(request("missing-"+variant.__name__)).decision
        require(decision!=Decision.ALLOW and not effects,
                f"{variant.__name__} allowed unauthorised effect")
        output[variant.__name__]=decision.value
    return output
check(8,"all_variants_missing_permit",variants_reject_missing_permit)


# Deliberate high-severity adversarial regression: a permit demanding a field
# must not authorise an effect if the caller omits that field entirely.
def omitted_signed_constraint():
    seen=[]
    k=new_kernel()
    def effect(**kwargs):
        seen.append(dict(kwargs))
        return "external-side-effect"
    k._dispatcher.registry.register("effect",effect)
    p=new_permit(params={"marker":"approved"})
    req=KernelRequest(request_id="omitted-signed-marker",ts_ms=1000,
        actor=ACTOR,intent="intent",
        tool_call=ToolCall(name="effect",params={}),params={})
    receipt=k.submit(req,permit_token=p)
    require(receipt.decision!=Decision.ALLOW and len(seen)==0,
        "P1: signed required marker omitted; DECISION="+receipt.decision.value+
        "; effects="+repr(seen))
    return {"decision":receipt.decision.value,"side_effects":len(seen)}
check(1,"required_signed_field_omission",omitted_signed_constraint)

def omitted_signed_null_constraint():
    seen=[]
    k=new_kernel()
    def effect(**kwargs):
        seen.append(dict(kwargs))
        return "external-side-effect"
    k._dispatcher.registry.register("effect",effect)
    p=new_permit(params={"x":None})
    req=KernelRequest(request_id="omitted-signed-null",ts_ms=1000,actor=ACTOR,
        intent="intent",tool_call=ToolCall(name="effect",params={}),params={})
    receipt=k.submit(req,permit_token=p)
    require(receipt.decision!=Decision.ALLOW and len(seen)==0,
        "P1: signed null constraint omitted; DECISION="+receipt.decision.value+
        "; effects="+repr(seen))
    return {"decision":receipt.decision.value,"side_effects":len(seen)}
check(1,"required_signed_null_omission",omitted_signed_null_constraint)

def durable_crash_replay():
    """Real SQLite audit + independent effect DB + SIGKILL mid-tool.
    Verifies one supported durable-storage recovery scenario, not exactly once.
    """
    import sqlite3
    import signal
    with tempfile.TemporaryDirectory(prefix="shards-acceptance-crash-") as tmp:
        work=pathlib.Path(tmp)
        ledger=str(work/"audit.sqlite")
        effectdb=str(work/"effects.sqlite")
        permit=new_permit()
        (work/"permit.json").write_text(json.dumps(dataclasses.asdict(permit)))
        child=work/"worker.py"
        child.write_text(r'''
import dataclasses,json,sqlite3,sys,time
from implementations.storage import SQLiteAuditStorage
from shards_kernel import StrictKernel,KernelConfig,KernelRequest,ToolCall,VirtualClock,JurisdictionPolicy
from shards_kernel.permits import PublicVerificationKey,PermitToken
db,effects,pfile,pub,mode=sys.argv[1:]
p=PermitToken(**json.load(open(pfile)))
k=StrictKernel(audit_storage=SQLiteAuditStorage(db))
k.boot(KernelConfig(kernel_id="acceptance-kernel",variant="strict",clock=VirtualClock(1000)))
k.set_policy(JurisdictionPolicy(allowed_actors=frozenset({"agent-acceptance"}),
                               allowed_tools=frozenset({"effect"})))
k.set_public_verifiers({"independent-issuer":PublicVerificationKey(
    issuer="acceptance-issuer",audience="acceptance-kernel",public_key=bytes.fromhex(pub))})
def effect(payload):
    with sqlite3.connect(effects) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS effects(id INTEGER PRIMARY KEY,value TEXT)")
        conn.execute("INSERT INTO effects(value) VALUES (?)",(str(payload),))
        conn.commit()
    print("EFFECT_COMMITTED",flush=True)
    if mode=="kill-me":time.sleep(20)
    return "effect-done"
k._dispatcher.registry.register("effect",effect)
req=KernelRequest(request_id="request-"+mode,ts_ms=1000,actor="agent-acceptance",
    intent="external-effect",tool_call=ToolCall(name="effect",params={"payload":{"amount":1}}),
    params={"payload":{"amount":1}})
result=k.submit(req,permit_token=p)
print("DECISION="+result.decision.value,flush=True)
''')
        pub=SECRET.public_key().public_bytes_raw().hex()
        args=[sys.executable,"-I",str(child),ledger,effectdb,str(work/"permit.json"),pub]
        first=subprocess.Popen(args+["kill-me"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            # The first line is emitted only AFTER an independent SQLite commit.
            line=first.stdout.readline().strip()
            require(line=="EFFECT_COMMITTED",
                    "child did not durably execute: "+line+" "+first.stderr.read()[:300] if first.poll() is not None else "child emitted: "+line)
            first.kill()
            first.wait(timeout=10)
        finally:
            if first.poll() is None: first.kill();first.wait(timeout=10)
        with sqlite3.connect(effectdb) as db:
            n1=db.execute("SELECT COUNT(*) FROM effects").fetchone()[0]
        require(n1==1,"external side effect was not committed before kill")
        again=subprocess.run(args+["restart"],capture_output=True,text=True,timeout=20)
        require(again.returncode==0,"recovery worker failed: "+again.stderr[-600:])
        with sqlite3.connect(effectdb) as db:
            n2=db.execute("SELECT COUNT(*) FROM effects").fetchone()[0]
        require("DECISION=DENY" in again.stdout and n2==1,
                "P1: replay after SIGKILL created duplicate effects; before="+str(n1)+
                " after="+str(n2)+" restarted="+again.stdout[-250:])
        return {"sigkill":"after separate effects DB commit",
                "external_effects_before":n1,"external_effects_after_restart":n2,
                "restart_decision":"DENY","durable_audit":True}
check(3,"sigkill_after_external_effect_with_durable_audit",durable_crash_replay)

def sequential_10000():
    k=new_kernel(effects=[])
    start=time.perf_counter()
    for n in range(10000):
        receipt=k.submit(request("bulk-denied-"+str(n)))
        require(receipt.decision==Decision.DENY,"missing permit accepted in sequential stress")
    seconds=time.perf_counter()-start
    evidence=k.export_evidence()
    require(len(evidence.ledger_entries)>=10000,"missing audit records")
    return {"attempts":10000,"unapproved":0,"audit_entries":len(evidence.ledger_entries),
            "elapsed_seconds":round(seconds,3),
            "decisions_per_second":round(10000/seconds,1)}
check(9,"ten_thousand_real_denied_decisions",sequential_10000)


def http_service_signed_end_to_end():
    """Real signed-policy subprocess bound to 127.0.0.1 only; real HTTP requests."""
    import urllib.request
    import urllib.error
    import socket
    import secrets
    from shards_kernel.issuer import sign_operator_policy
    from shards_kernel.sdk.client import KernelClient
    from shards_kernel.integrations.wire import permit_to_mapping
    import shutil

    with tempfile.TemporaryDirectory(prefix="shards-http-acceptance-") as folder:
        root=pathlib.Path(folder)
        issuer_pub=SECRET.public_key().public_bytes_raw().hex()
        policy_private=Ed25519PrivateKey.generate()
        policy_public=policy_private.public_key().public_bytes_raw().hex()
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1",0))
            port=sock.getsockname()[1]
        now=int(time.time()*1000)
        config={
            "version":1,"kernel_id":KID,"actor":ACTOR,
            "tools":["echo"],
            "issuer_keys":[{"key_id":KEY_ID,"issuer":ISSUER,
                            "public_key_hex":issuer_pub,"revoked":False}],
            "audit_db":str(root/"operator.db"),"port":port
        }
        signed=sign_operator_policy(config,policy_private,revision=1,
                                   issued_at_ms=now-1000,expires_at_ms=now+3600000)
        policy_file=root/"signed.json"
        policy_file.write_text(json.dumps(signed,sort_keys=True))
        api_key=secrets.token_urlsafe(50)
        env={**os.environ,"SHARDS_KERNEL_POLICY_PUBLIC_KEY_HEX":policy_public,
             "SHARDS_KERNEL_API_KEY":api_key}
        cli=str(pathlib.Path(sys.executable).parent/"shards-kernel")
        process=subprocess.Popen([cli,"serve","--config",str(policy_file)],
             stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=env)
        base=f"http://127.0.0.1:{port}"
        def request_http(method,path,data=None,token=None,raw=False):
            headers={"Content-Type":"application/json"}
            if token is not None: headers["Authorization"]="Bearer "+token
            body=(data if raw else json.dumps(data).encode()) if data is not None else None
            req=urllib.request.Request(base+path,data=body,headers=headers,method=method)
            try:
                with urllib.request.urlopen(req,timeout=3) as resp:
                    return resp.status,json.loads(resp.read().decode())
            except urllib.error.HTTPError as err:
                return err.code,json.loads(err.read().decode())
        try:
            started=False
            for i in range(60):
                if process.poll() is not None:break
                try:
                    code,body=request_http("GET","/health")
                    if code==200 and body.get("status")=="healthy":
                        started=True;break
                except (OSError,ValueError):
                    pass
                time.sleep(.1)
            require(started,"signed operator failed to reach healthy state; exit="+str(process.poll()))
            unauth_status,_=request_http("GET","/status")
            invalid_auth,_=request_http("GET","/status",token="invalid")
            auth_status,auth_body=request_http("GET","/status",token=api_key)
            require((unauth_status,invalid_auth,auth_status)==(401,401,200),
                    f"operator bearer enforcement failed: {(unauth_status,invalid_auth,auth_status)}")
            require(auth_body.get("state")=="IDLE","operator not idle")
            from_ms=now-5000
            until_ms=now+60000
            signed_permit=sign_v2_permit(
                PermitBuilder().issuer(ISSUER).subject(ACTOR)
                  .jurisdiction("default").action("echo")
                  .params({"text":"accepted"}).max_executions(1)
                  .valid_from_ms(from_ms).valid_until_ms(until_ms)
                  .proposal_hash("http-acceptance")
                  .build_unsigned_v2(key_id=KEY_ID,audience=KID),SECRET)
            data={"request_id":"http-allowed","actor":ACTOR,"intent":"signed HTTP",
                  "tool_call":{"name":"echo","params":{"text":"accepted"}},
                  "params":{"text":"accepted"},"permit":permit_to_mapping(signed_permit)}
            notok,_=request_http("POST","/submit",data)
            require(notok==401,"unauthenticated submission accepted")
            allowed,first=request_http("POST","/submit",data,token=api_key)
            require(allowed==200 and first["decision"]=="ALLOW" and first["result"]=="accepted",
                    "valid signed HTTP permit did not execute: "+repr(first))
            replay_data={**data,"request_id":"http-replayed"}
            replay_status,replay=request_http("POST","/submit",replay_data,token=api_key)
            require(replay_status==200 and replay["decision"]=="DENY" and replay["result"] is None,
                    "HTTP replay incorrectly executed: "+repr(replay))
            sdk=KernelClient(base,api_key=api_key,timeout=3)
            sdk_receipt=sdk.submit(KernelRequest(
                request_id="http-sdk-replay",ts_ms=now,actor=ACTOR,intent="SDK replay",
                tool_call=ToolCall(name="echo",params={"text":"accepted"}),
                params={"text":"accepted"}),permit_token=signed_permit)
            require(sdk_receipt.decision==Decision.DENY and sdk_receipt.tool_result is None,
                    "SDK treats denied receipt as an executed tool")
            bad_actor={**data,"request_id":"http-impostor","actor":"other-agent"}
            wrong_status,_=request_http("POST","/submit",bad_actor,token=api_key)
            require(wrong_status==403,"HTTP actor mismatch accepted")
            badjson,_=request_http("POST","/submit",b"{malformed",token=api_key,raw=True)
            require(badjson==400,"malformed JSON accepted")
            evidence_status,evidence=request_http("GET","/evidence",token=api_key)
            require(evidence_status==200 and len(evidence.get("ledger_entries",[]))>=3,
                    "missing operator audit export")
            valid,_=replay_and_verify(evidence["ledger_entries"],evidence["root_hash"])
            require(valid,"operator evidence replay invalid")
            haltcode,halt=request_http("POST","/halt",{},token=api_key)
            require(haltcode==200 and halt.get("kernel_state")=="HALTED","operator halt failed")
            health_after,_=request_http("GET","/health")
            require(health_after==503,"HALTED operator health must be unhealthy")
            return {"loopback_http":base.replace(str(port),"<ephemeral-port>"),
                    "signed_policy":True,"valid_signed_execution":"ALLOW",
                    "unauthenticated":401,"incorrect_bearer":401,
                    "replayed_permit":"DENY","sdk_replay":"DENY",
                    "actor_mismatch":403,"malformed_json":400,
                    "audit_verified":True,"halt_health":503}
        finally:
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
check(5,"signed_operator_real_http_and_sdk",http_service_signed_end_to_end)

def env_info():
    versions={}
    for n in ["shards-kernel","cryptography","mcp","pip","httpx","pytest","pip-audit"]:
        try:versions[n]=metadata.version(n)
        except metadata.PackageNotFoundError:versions[n]=None
    return {"python":sys.version,"platform":platform.platform(),"kernel":platform.release(),
            "executable":sys.executable,"package_versions":versions,
            "wheel_sha256_expected":EXPECTED_WHEEL_SHA256,
            "run_utc":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())}
(OUT/"environment.json").write_text(json.dumps(env_info(),indent=2)+"\n")
results={"target":"shards-kernel==0.1.2","source":"published PyPI wheel only",
  "critical_disclaimer":"PARTIAL TEST EXECUTION; NO CERTIFICATION",
  "tests":tests,"gates":[],
  "run_utc":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())}
for gate,name in GATES.items():
    entries=[x for x in tests if x["gate"]==gate]
    failed=[x for x in entries if x["status"]=="FAIL" and x["mandatory"]]
    # These tests are deliberately non-exhaustive; PASSING individual probes
    # never promotes an entire mandatory gate to PASS.
    status="FAIL" if failed else "BLOCKED"
    results["gates"].append({"gate":gate,"name":name,"status":status,
      "tests_run":len(entries),"passed":sum(x["status"]=="PASS" for x in entries),
      "failed":len(failed),
      "limitation":"Mandatory specification is not fully exercised in this probe harness."})
results["verdict"]="NOT PRODUCTION READY"
(OUT/"results.json").write_text(json.dumps(results,indent=2)+"\n")
rows=["# SHARDS-KERNEL v0.1.2 — Partial independent runtime evidence",
      "","**Verdict: NOT PRODUCTION READY** — mandatory acceptance gates remain unverified.",
      "","This run uses the published PyPI wheel (never a checkout install).",
      "Individual PASS results are probes, **not gate certification**.",
      "","## Gate results","",
      "| Gate | Status | Executed | Failed |","|---|---|---:|---:|"]
for v in results["gates"]:
    rows.append(f"| {v['gate']}: {v['name']} | {v['status']} | {v['tests_run']} | {v['failed']} |")
rows += ["","## Failures and evidence",""]
for t in tests:
    if t["status"]=="FAIL":
        rows.append(f"- {t['id']}: {t['error_type']}: {t['error']}")
if not any(t["status"]=="FAIL" for t in tests):
    rows.append("No probe failures recorded; this does **not** establish full acceptance.")
rows += ["","## Unproven mandatory scope",
 "The suite has not established 1,000 iterations for every concurrency topology,",
 "crash injection at all ten boundaries, 10,000 decisions, disk exhaustion,",
 "live positive mTLS, independent MCP handshake/recovery, and operational restore.",
 "These remain BLOCKED; they are neither silently skipped nor reported as PASS.",
 "","## Deployment scope",
 "No production deployment is authorised by this evidence. Local, single-process",
 "signed-permit demonstrations are test capabilities only; the external tool",
 "side-effect probe uses an explicitly registered local test handler.",
 "","## Reproduction",
 "Run reproduce.sh from a clean network-enabled Linux host. It downloads the",
 "pinned wheel, verifies SHA-256, creates a fresh venv and executes the probes."]
(OUT/"production-readiness-report.md").write_text("\n".join(rows)+"\n")
(OUT/"deployment-envelope.md").write_text(
 "# Deployment envelope\n\nNOT APPROVED FOR PRODUCTION.\n\n"
 "Observed probes cover an isolated local Python kernel and installed-wheel CLI.\n"
 "No supported distributed writer, remote MCP, external transactional tool, "
 "or operational recovery guarantee has been certified by this harness.\n")
print("PROBE_RUN_COMPLETE",json.dumps({"cases":len(tests),"failures":sum(x["status"]=="FAIL" for x in tests)}),flush=True)
