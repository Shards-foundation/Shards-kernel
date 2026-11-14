/**
 * Shards permit issuer pilot — Cloudflare Workers Free / EU D1.
 * FAIL CLOSED until a separately owned approval key, distinct issuer key,
 * bearer credential and durable ledger are configured.
 * No production custody, signer credentials or agent access is established.
 */
export const REVISION = 'shards-issuer-pilot-v0.1.1';
const encoder = new TextEncoder();
const PERMIT_DOMAIN = encoder.encode('SHARDS-PERMIT-ED25519-V2\0');
const APPROVAL_DOMAIN = encoder.encode('SHARDS-OFFLINE-APPROVAL-V1\0');
const FIELDS = ['permit_id','issuer','subject','jurisdiction','action','params','constraints','max_executions','valid_from_ms','valid_until_ms','evidence_hash','proposal_hash','nonce','signature','key_id','version','algorithm','audience'];
const SIGN_FIELDS = FIELDS.filter((field) => field !== 'signature');
const APPROVAL_FIELDS = ['schema','reviewer','permit_sha256','permit_id','approved_at_ms','expires_at_ms','signature_hex'];
const APPROVAL_SIGN_FIELDS = APPROVAL_FIELDS.filter((field) => field !== 'signature_hex');
const STRING_FIELDS = ['permit_id','issuer','subject','jurisdiction','action','evidence_hash','proposal_hash','nonce','signature','key_id','algorithm','audience'];
const REQUIRED_SECRETS = ['APPROVER_PUBLIC_KEY_HEX','ISSUER_PUBLIC_KEY_HEX','ISSUER_PRIVATE_KEY_PKCS8_B64','ISSUANCE_ACCESS_TOKEN','ISSUER_NAME','ISSUER_KEY_ID','ISSUER_AUDIENCE'];
const enc = (s) => encoder.encode(s);
const hex = (bytes) => [...new Uint8Array(bytes)].map((n) => n.toString(16).padStart(2, '0')).join('');
const unhex = (s) => new Uint8Array(s.match(/.{2}/g).map((chunk) => parseInt(chunk, 16)));
const sameKeys = (obj, keys) => obj && typeof obj === 'object' && !Array.isArray(obj) && Object.keys(obj).length === keys.length && keys.every((key) => Object.hasOwn(obj,key));
const int = (value) => Number.isSafeInteger(value) && value >= 0;
const isHex = (value, length) => typeof value === 'string' && value.length === length && /^[a-f0-9]+$/.test(value);
const safe = (value) => typeof value === 'string' && value.length > 0 && value.length <= 256 && value.trim() === value && !value.includes('*');
const digest = async (buffer) => hex(await crypto.subtle.digest('SHA-256',buffer));
const concat = (a,b) => { const out = new Uint8Array(a.length+b.length); out.set(a); out.set(b,a.length); return out; };
const B64 = (base64) => Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));

class PolicyRefusal extends Error {
  constructor(code, status=403) { super(code); this.code=code; this.status=status; }
}
function deny(code,status=403) { throw new PolicyRefusal(code,status); }

function validateUnicode(s) {
  // Python's ensure_ascii=False JSON rejects an unpaired UTF-16 surrogate.
  // JS JSON.stringify escapes it; without this check the signed bytes differ.
  for (let i=0; i<s.length; i++) {
    const ch=s.charCodeAt(i);
    if (ch >= 0xD800 && ch <= 0xDBFF) {
      const next=s.charCodeAt(++i);
      if (!(next >= 0xDC00 && next <= 0xDFFF)) deny('NON_CANONICAL_UNICODE');
    } else if (ch >= 0xDC00 && ch <= 0xDFFF) {
      deny('NON_CANONICAL_UNICODE');
    }
  }
  return s;
}
function canonical(x) {
  if (typeof x === 'string') return JSON.stringify(validateUnicode(x));
  if (x === null || typeof x === 'boolean') return JSON.stringify(x);
  if (typeof x === 'number' && Number.isSafeInteger(x)) return JSON.stringify(x);
  if (Array.isArray(x)) return '[' + x.map(canonical).join(',') + ']';
  if (x && typeof x === 'object' && Object.getPrototypeOf(x) === Object.prototype) {
    const members=Object.keys(x).sort().map((key) => JSON.stringify(validateUnicode(key))+':'+canonical(x[key]));
    return '{'+members.join(',')+'}';
  }
  deny('NON_CANONICAL_JSON');
}
function canonicalPermit(draft,omitId=false) {
  const fields=SIGN_FIELDS.filter((key) => !omitId || key !== 'permit_id');
  return enc(canonical(Object.fromEntries(fields.map((key)=>[key,draft[key]]))));
}
function canonicalApproval(approval) {
  const plain=Object.fromEntries(APPROVAL_SIGN_FIELDS.map((key)=>[key,approval[key]]));
  return concat(APPROVAL_DOMAIN,enc(canonical(plain)));
}
function validateDraftIdentity(d,env) {
  if (!sameKeys(d,FIELDS)) deny('INVALID_DRAFT_SHAPE');
  for (const field of STRING_FIELDS) if (typeof d[field] !== 'string') deny('INVALID_DRAFT_FIELD');
  if (d.version !== 2 || d.algorithm !== 'Ed25519' || d.signature !== '') deny('INVALID_PERMIT_VERSION');
  if (d.issuer !== env.ISSUER_NAME || d.key_id !== env.ISSUER_KEY_ID || d.audience !== env.ISSUER_AUDIENCE) deny('ISSUER_SCOPE_MISMATCH');
  if (![d.issuer,d.key_id,d.subject,d.audience,d.jurisdiction,d.action].every(safe)) deny('INVALID_SCOPE');
  if (!['echo','add'].includes(d.action)) deny('TOOL_NOT_ALLOWED');
}
function validateDraftTime(d,now) {
  if (d.max_executions !== 1 || !int(d.valid_from_ms) || !int(d.valid_until_ms)) deny('INVALID_LIFETIME');
  if (d.valid_until_ms <= d.valid_from_ms || d.valid_until_ms-d.valid_from_ms > 900000) deny('INVALID_LIFETIME');
  if (now < d.valid_from_ms || now > d.valid_until_ms) deny('PERMIT_NOT_CURRENT');
}
function validateDraftBindings(d) {
  // The empty evidence hash is an explicitly supported "no evidence" marker.
  if (!isHex(d.permit_id,64) || !isHex(d.nonce,32)) deny('INVALID_BINDING');
  if (!safe(d.proposal_hash) || !(d.evidence_hash === '' || isHex(d.evidence_hash,64))) deny('INVALID_BINDING');
}
function validateDraftParams(d) {
  if (!d.params || typeof d.params !== 'object' || Array.isArray(d.params)) deny('INVALID_PARAMS');
  if (!d.constraints || typeof d.constraints !== 'object' || Array.isArray(d.constraints)) deny('INVALID_PARAMS');
  if (Object.keys(d.constraints).length !== 0) deny('UNSUPPORTED_CONSTRAINT');
  if (d.action === 'echo' && !(sameKeys(d.params,['text']) && typeof d.params.text === 'string' && d.params.text.length <= 256)) deny('INVALID_ECHO');
  if (d.action === 'add' && !(sameKeys(d.params,['a','b']) && int(d.params.a) && int(d.params.b) && d.params.a <= 1000000 && d.params.b <= 1000000)) deny('INVALID_ADD');
}
function validateDraft(d,now,env) {
  validateDraftIdentity(d,env);
  validateDraftTime(d,now);
  validateDraftBindings(d);
  validateDraftParams(d);
}
function validateApproval(a,now,draft) {
  if (!sameKeys(a,APPROVAL_FIELDS) || a.schema !== 'shards.operator-approval.v1') deny('INVALID_APPROVAL_SHAPE');
  if (!safe(a.reviewer) || !isHex(a.permit_sha256,64) || !isHex(a.permit_id,64) || !isHex(a.signature_hex,128)) deny('INVALID_APPROVAL_SHAPE');
  if (!int(a.approved_at_ms) || !int(a.expires_at_ms)) deny('INVALID_APPROVAL_WINDOW');
  if (a.expires_at_ms <= a.approved_at_ms || a.expires_at_ms-a.approved_at_ms > 600000) deny('INVALID_APPROVAL_WINDOW');
  if (a.approved_at_ms < draft.valid_from_ms || a.approved_at_ms > draft.valid_until_ms) deny('APPROVAL_NOT_CURRENT');
  if (now < a.approved_at_ms || now > a.expires_at_ms) deny('APPROVAL_NOT_CURRENT');
  if (a.permit_id !== draft.permit_id) deny('APPROVAL_PERMIT_MISMATCH');
}
function json(status,body) {
  return new Response(JSON.stringify(body),{status,headers:{
    'content-type':'application/json; charset=utf-8','cache-control':'no-store',
    'x-content-type-options':'nosniff','referrer-policy':'no-referrer'
  }});
}
function present(env) {
  return !!(env && REQUIRED_SECRETS.every((key)=>typeof env[key] === 'string' && env[key].length>0)
    && env.ISSUANCE_DB && typeof env.ISSUANCE_DB.prepare === 'function');
}
function validConfigFields(env) {
  if (!isHex(env.APPROVER_PUBLIC_KEY_HEX,64) || !isHex(env.ISSUER_PUBLIC_KEY_HEX,64)) return false;
  if (env.APPROVER_PUBLIC_KEY_HEX === env.ISSUER_PUBLIC_KEY_HEX) return false;
  if (![env.ISSUER_NAME,env.ISSUER_KEY_ID,env.ISSUER_AUDIENCE].every(safe)) return false;
  return env.ISSUANCE_ACCESS_TOKEN.length >= 32;
}
async function signerReady(env) {
  if (!present(env) || !validConfigFields(env)) return false;
  try {
    const key = await crypto.subtle.importKey('pkcs8',B64(env.ISSUER_PRIVATE_KEY_PKCS8_B64),{name:'Ed25519'},false,['sign']);
    const publicKey = await crypto.subtle.importKey('raw',unhex(env.ISSUER_PUBLIC_KEY_HEX),{name:'Ed25519'},false,['verify']);
    const challenge=enc('SHARDS-ISSUER-CONFIG-PROBE-V1');
    const signature=await crypto.subtle.sign('Ed25519',key,challenge);
    return crypto.subtle.verify('Ed25519',publicKey,signature,challenge);
  } catch {
    return false;
  }
}
async function matchesBearer(header,actual) {
  if (typeof header !== 'string' || !header.startsWith('Bearer ') || typeof actual !== 'string' || actual.length<32) return false;
  const provided=header.slice(7);
  if (provided.length<32 || provided.length>1024) return false;
  const [a,b]=await Promise.all([crypto.subtle.digest('SHA-256',enc(provided)),crypto.subtle.digest('SHA-256',enc(actual))]);
  let difference=0;
  const aa=new Uint8Array(a),bb=new Uint8Array(b);
  for (let i=0;i<aa.length;i++) difference|=aa[i]^bb[i];
  return difference===0;
}
async function boundedBodyText(request,maximumBytes=8192) {
  if (!request.body) deny('BAD_JSON',400);
  const reader=request.body.getReader();
  let total=0;
  const parts=[];
  try {
    for (;;) {
      const chunk=await reader.read();
      if (chunk.done) break;
      total+=chunk.value.byteLength;
      if (total>maximumBytes) deny('BODY_TOO_LARGE',413);
      parts.push(chunk.value);
    }
  } finally {
    try { await reader.cancel(); } catch { /* already closed */ }
    reader.releaseLock();
  }
  const buffer=new Uint8Array(total);
  let pos=0;
  for (const part of parts) { buffer.set(part,pos); pos+=part.byteLength; }
  return new TextDecoder('utf-8',{fatal:true}).decode(buffer);
}
async function parseIssueRequest(request) {
  if ((request.headers.get('content-type')||'').split(';',1)[0] !== 'application/json') deny('CONTENT_TYPE_REQUIRED',415);
  const length=Number(request.headers.get('content-length'));
  if (Number.isFinite(length) && length>8192) deny('BODY_TOO_LARGE',413);
  let body;
  try {
    body=JSON.parse(await boundedBodyText(request));
  } catch(err) {
    if (err instanceof PolicyRefusal) throw err;
    deny('BAD_JSON',400);
  }
  if (!sameKeys(body,['draft','approval'])) deny('INVALID_ENVELOPE',400);
  return body;
}
async function verifyPinnedApproval(approval,env) {
  const key=await crypto.subtle.importKey('raw',unhex(env.APPROVER_PUBLIC_KEY_HEX),{name:'Ed25519'},false,['verify']);
  const valid=await crypto.subtle.verify('Ed25519',key,unhex(approval.signature_hex),canonicalApproval(approval));
  if (!valid) deny('APPROVAL_SIGNATURE_INVALID');
}
async function signDraft(draft,env) {
  const key=await crypto.subtle.importKey('pkcs8',B64(env.ISSUER_PRIVATE_KEY_PKCS8_B64),{name:'Ed25519'},false,['sign']);
  const message=concat(PERMIT_DOMAIN,canonicalPermit(draft));
  const signature=hex(await crypto.subtle.sign('Ed25519',key,message));
  const publicKey=await crypto.subtle.importKey('raw',unhex(env.ISSUER_PUBLIC_KEY_HEX),{name:'Ed25519'},false,['verify']);
  if (!await crypto.subtle.verify('Ed25519',publicKey,unhex(signature),message)) deny('ISSUER_KEY_MISMATCH',503);
  return {...draft,signature};
}
async function authoriseAndSign(body,env) {
  const {draft,approval}=body;
  const now=Date.now();
  validateDraft(draft,now,env);
  validateApproval(approval,now,draft);
  const expectedId=await digest(canonicalPermit(draft,true));
  const expectedHash=await digest(canonicalPermit(draft));
  if (expectedId!==draft.permit_id || expectedHash!==approval.permit_sha256) deny('CANONICAL_MISMATCH');
  await verifyPinnedApproval(approval,env);
  return signDraft(draft,env);
}
function assertUnexpired(draft,approval) {
  const now=Date.now();
  if (now < draft.valid_from_ms || now >= draft.valid_until_ms || now >= approval.expires_at_ms) {
    deny('EXPIRED_DURING_ISSUANCE');
  }
}
async function reservePermit(permit,approval,env) {
  try {
    const record=await env.ISSUANCE_DB.prepare(
      'INSERT INTO issued_permits (permit_id,approval_digest,issued_at_ms,subject,audience,action,valid_until_ms) VALUES (?,?,?,?,?,?,?)'
    ).bind(permit.permit_id,approval.permit_sha256,Date.now(),permit.subject,permit.audience,permit.action,permit.valid_until_ms).run();
    if (!record?.success || record.meta?.changes!==1) deny('LEDGER_UNAVAILABLE',503);
  } catch(err) {
    if (err instanceof PolicyRefusal) throw err;
    if (String(err?.message||'').includes('SQLITE_CONSTRAINT')) deny('APPROVAL_ALREADY_CONSUMED',409);
    deny('LEDGER_UNAVAILABLE',503);
  }
}
function issueError(err) {
  if (err instanceof PolicyRefusal) return json(err.status,{status:'DENY',code:err.code});
  return json(503,{status:'DENY',code:'ISSUER_UNAVAILABLE'});
}
async function issue(request,env) {
  if (!present(env)) return json(503,{status:'LOCKED',code:'ISSUER_NOT_PROVISIONED'});
  if (!await matchesBearer(request.headers.get('authorization'),env.ISSUANCE_ACCESS_TOKEN)) return json(401,{status:'DENY',code:'AUTH_REQUIRED'});
  if (!await signerReady(env)) return json(503,{status:'LOCKED',code:'CONFIG_INVALID'});
  try {
    const body=await parseIssueRequest(request);
    const permit=await authoriseAndSign(body,env);
    assertUnexpired(permit,body.approval);
    await reservePermit(permit,body.approval,env);
    // If expiry occurs during D1 I/O, do not return even a signed permit.
    // The one-use ledger entry stays consumed; a new approval is required.
    assertUnexpired(permit,body.approval);
    return json(200,{status:'ISSUED',permit});
  } catch(err) {
    return issueError(err);
  }
}
export default {
  async fetch(request,env) {
    try {
      const path=new URL(request.url).pathname;
      if (path==='/health' && request.method==='GET') return json(200,{
        service:'shards-permit-issuer-pilot',revision:REVISION,status:'UP',scope:'local-integration-not-production'
      });
      if (path==='/v1/status' && request.method==='GET') {
        const ready=await signerReady(env);
        return json(200,{service:'shards-permit-issuer-pilot',status:ready?'PROVISIONED':'LOCKED',
          signing_enabled:ready,scope:'approval-gated-echo-add-only'});
      }
      if (path==='/v1/issue' && request.method==='POST') return issue(request,env);
      if (path==='/v1/issue') return json(405,{status:'DENY',code:'METHOD_NOT_ALLOWED'});
      return json(404,{status:'DENY',code:'NOT_FOUND'});
    } catch {
      return json(503,{status:'DENY',code:'FAIL_CLOSED'});
    }
  }
};
