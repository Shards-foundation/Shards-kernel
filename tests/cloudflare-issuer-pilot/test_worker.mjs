import assert from 'node:assert/strict';
import { test } from 'node:test';
import worker from '../../deploy/cloudflare/issuer-pilot/worker.mjs';
const enc = (s) => new TextEncoder().encode(s);
const hex = (b) => [...new Uint8Array(b)].map(n=>n.toString(16).padStart(2,'0')).join('');
const canonical = (x) => {
 if(x===null || typeof x === 'string' || typeof x === 'boolean' || typeof x === 'number')return JSON.stringify(x);
 if(Array.isArray(x))return '['+x.map(canonical).join(',')+']';
 return '{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+canonical(x[k])).join(',')+'}';
};
const fields=['permit_id','issuer','subject','jurisdiction','action','params','constraints','max_executions','valid_from_ms','valid_until_ms','evidence_hash','proposal_hash','nonce','key_id','version','algorithm','audience'];
const draftCanonical = (d,omitId=false) => enc(canonical(Object.fromEntries(fields.filter(k=>!(omitId&&k==='permit_id')).map(k=>[k,d[k]]))));
const sha = async (data) => hex(await crypto.subtle.digest('SHA-256',data));
const appdomain=enc('SHARDS-OFFLINE-APPROVAL-V1\0');
const permitdomain=enc('SHARDS-PERMIT-ED25519-V2\0');
const join=(a,b)=>{let out=new Uint8Array(a.length+b.length);out.set(a);out.set(b,a.length);return out};
async function fixture(){
 let issuer=await crypto.subtle.generateKey('Ed25519',true,['sign','verify']);
 let approver=await crypto.subtle.generateKey('Ed25519',true,['sign','verify']);
 const env={APPROVER_PUBLIC_KEY_HEX:hex(await crypto.subtle.exportKey('raw',approver.publicKey)),ISSUER_PUBLIC_KEY_HEX:hex(await crypto.subtle.exportKey('raw',issuer.publicKey)),ISSUER_PRIVATE_KEY_PKCS8_B64:Buffer.from(await crypto.subtle.exportKey('pkcs8',issuer.privateKey)).toString('base64'),ISSUANCE_ACCESS_TOKEN:'0123456789012345678901234567890123456789',ISSUER_NAME:'offline-issuer',ISSUER_KEY_ID:'issuer-key-1',ISSUER_AUDIENCE:'test-kernel'};
 const seen=new Set();
 env.ISSUANCE_DB={prepare(sql){assert.ok(sql.includes('INSERT INTO issued_permits'));return {bind(...args){return {async run(){if(seen.has(args[0]))throw Error('SQLITE_CONSTRAINT_PRIMARYKEY');seen.add(args[0]);return {success:true,meta:{changes:1}}}}}}}};
 const now=Date.now();
 const draft={permit_id:'',issuer:env.ISSUER_NAME,subject:'qwen-test-agent',jurisdiction:'default',action:'add',params:{a:7,b:8},constraints:{},max_executions:1,valid_from_ms:now-1000,valid_until_ms:now+120000,evidence_hash:'',proposal_hash:'f'.repeat(64),nonce:'a'.repeat(32),signature:'',key_id:env.ISSUER_KEY_ID,version:2,algorithm:'Ed25519',audience:env.ISSUER_AUDIENCE};
 draft.permit_id=await sha(draftCanonical(draft,true));
 let approval={schema:'shards.operator-approval.v1',reviewer:'external-operator',permit_sha256:await sha(draftCanonical(draft)),permit_id:draft.permit_id,approved_at_ms:now,expires_at_ms:now+60000};
 approval.signature_hex=hex(await crypto.subtle.sign('Ed25519',approver.privateKey,join(appdomain,enc(canonical(approval)))));
 const req=(body,token=env.ISSUANCE_ACCESS_TOKEN)=>new Request('https://issuer.example/v1/issue',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body:JSON.stringify(body)});
 return {env,draft,approval,req,issuer,approver};
}
async function reapprove(f) {
  // A coherent proposal: recompute ID, digest AND independent approver signature.
  f.draft.permit_id=await sha(draftCanonical(f.draft,true));
  f.approval.permit_id=f.draft.permit_id;
  f.approval.permit_sha256=await sha(draftCanonical(f.draft));
  const unsigned=Object.fromEntries(Object.entries(f.approval).filter(([key])=>key!=='signature_hex'));
  f.approval.signature_hex=hex(await crypto.subtle.sign('Ed25519',f.approver.privateKey,join(appdomain,enc(canonical(unsigned)))));
}
async function expectRefusal(f,code,status=403) {
  const response=await worker.fetch(f.req({draft:f.draft,approval:f.approval}),f.env);
  assert.equal(response.status,status);
  const body=await response.json();
  assert.equal(body.code,code);
  assert.equal(Object.hasOwn(body,'permit'),false);
}
test('disabled: no keys, no ledger, no signing',async()=>{const req=new Request('https://issuer.test/v1/issue',{method:'POST'}); const r=await worker.fetch(req,{});assert.equal(r.status,503);assert.equal((await r.json()).code,'ISSUER_NOT_PROVISIONED')});
test('GET /health is liveness only, not a signing-readiness assertion',async()=>{let r=await worker.fetch(new Request('https://issuer.test/health'),{});assert.equal(r.status,200);const body=await r.json();assert.equal(body.status,'UP');assert.equal(Object.hasOwn(body,'signing_enabled'),false)});
test('GET /v1/status reports locked without secrets and provisioned with complete bindings',async()=>{let f=await fixture();let locked=await (await worker.fetch(new Request('https://issuer.test/v1/status'),{})).json();assert.equal(locked.status,'LOCKED');assert.equal(locked.signing_enabled,false);let active=await (await worker.fetch(new Request('https://issuer.test/v1/status'),f.env)).json();assert.equal(active.status,'PROVISIONED');assert.equal(active.signing_enabled,true);});
test('GET /v1/issue method refused',async()=>{let r=await worker.fetch(new Request('https://issuer.test/v1/issue'),{});assert.equal(r.status,405)});
test('unknown routes denied',async()=>{let r=await worker.fetch(new Request('https://issuer.test/admin'),{});assert.equal(r.status,404)});
test('unauthenticated requests refused',async()=>{let f=await fixture();let r=await worker.fetch(f.req({draft:f.draft,approval:f.approval},'wrong'),f.env);assert.equal(r.status,401)});
test('valid independent approval issues signed v2 permit once, then replay denied',async()=>{const f=await fixture();const r=await worker.fetch(f.req({draft:f.draft,approval:f.approval}),f.env);assert.equal(r.status,200);const body=await r.json();assert.equal(body.status,'ISSUED');const sig=Uint8Array.from(body.permit.signature.match(/.{2}/g).map(h=>parseInt(h,16)));assert.equal(await crypto.subtle.verify('Ed25519',f.issuer.publicKey,sig,join(permitdomain,draftCanonical(body.permit))),true);const second=await worker.fetch(f.req({draft:f.draft,approval:f.approval}),f.env);assert.equal(second.status,409)});
test('bad approval signature denied',async()=>{const f=await fixture();f.approval.signature_hex='f'.repeat(128);let r=await worker.fetch(f.req({draft:f.draft,approval:f.approval}),f.env);assert.equal(r.status,403)});
test('approver and issuer same key refused',async()=>{const f=await fixture();f.env.ISSUER_PUBLIC_KEY_HEX=f.env.APPROVER_PUBLIC_KEY_HEX;let r=await worker.fetch(f.req({draft:f.draft,approval:f.approval}),f.env);assert.equal(r.status,503)});
test('post-approval mutation is rejected by canonical binding',async()=>{
 const f=await fixture();f.draft.params={a:7,b:9};await expectRefusal(f,'CANONICAL_MISMATCH');
});
test('independently approved, correctly rebound invalid add params rejected by tool validator',async()=>{
 const f=await fixture();f.draft.params={a:-1,b:8};await reapprove(f);
 assert.equal(f.approval.permit_id,f.draft.permit_id);await expectRefusal(f,'INVALID_ADD');
});
test('independently approved and rebound unsupported action triggers explicit allowlist',async()=>{
 const f=await fixture();f.draft.action='wallet.transfer';await reapprove(f);
 assert.equal(f.approval.permit_id,f.draft.permit_id);await expectRefusal(f,'TOOL_NOT_ALLOWED');
});
test('reject unpaired surrogate even with coherent independently signed echo approval',async()=>{
 const f=await fixture();f.draft.action='echo';f.draft.params={text:'\\uD800'};await reapprove(f);
 await expectRefusal(f,'NON_CANONICAL_UNICODE');
});
test('reject evidence hashes outside empty or hex-64 formats',async()=>{
 const f=await fixture();f.draft.evidence_hash='x'.repeat(350);await reapprove(f);
 await expectRefusal(f,'INVALID_BINDING');
});
test('malformed issuer keys never report ready or issue permits',async()=>{
 const f=await fixture();f.env.ISSUER_PRIVATE_KEY_PKCS8_B64='not-a-key';
 const status=await(await worker.fetch(new Request('https://issuer.test/v1/status'),f.env)).json();
 assert.equal(status.status,'LOCKED');assert.equal(status.signing_enabled,false);
 await expectRefusal(f,'CONFIG_INVALID',503);
});
test('wrong issuer public key cannot report signing ready',async()=>{
 const f=await fixture();const other=await crypto.subtle.generateKey('Ed25519',true,['sign','verify']);
 f.env.ISSUER_PUBLIC_KEY_HEX=hex(await crypto.subtle.exportKey('raw',other.publicKey));
 const status=await(await worker.fetch(new Request('https://issuer.test/v1/status'),f.env)).json();
 assert.equal(status.signing_enabled,false);await expectRefusal(f,'CONFIG_INVALID',503);
});
test('missing ledger denies',async()=>{const f=await fixture();delete f.env.ISSUANCE_DB;let r=await worker.fetch(f.req({draft:f.draft,approval:f.approval}),f.env);assert.equal(r.status,503)});
test('database error is 503 unavailable and signed permit never returned',async()=>{const f=await fixture();f.env.ISSUANCE_DB.prepare=()=>({bind:()=>({run:async()=>{throw Error('SQLITE_IOERR')}})});await expectRefusal(f,'LEDGER_UNAVAILABLE',503)});
