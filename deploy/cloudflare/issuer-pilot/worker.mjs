/**
 * Shards permit issuer pilot — Cloudflare Workers Free / D1
 * FAIL CLOSED until a separate approver key, private issuer key, caller bearer
 * and durable approval ledger are provisioned.
 * Compatible with Shards Kernel v2 Ed25519 and shards.operator-approval.v1.
 * NOT a hardware-backed KMS/HSM or a production-authorised signing service.
 */
export const REVISION = 'shards-issuer-pilot-v0.1.0';
const PERMIT_DOMAIN = new TextEncoder().encode('SHARDS-PERMIT-ED25519-V2\0');
const APPROVAL_DOMAIN = new TextEncoder().encode('SHARDS-OFFLINE-APPROVAL-V1\0');
const FIELDS = ['permit_id','issuer','subject','jurisdiction','action','params','constraints','max_executions','valid_from_ms','valid_until_ms','evidence_hash','proposal_hash','nonce','signature','key_id','version','algorithm','audience'];
const SIGN_FIELDS = FIELDS.filter((x) => x !== 'signature');
const APPROVAL_FIELDS = ['schema','reviewer','permit_sha256','permit_id','approved_at_ms','expires_at_ms','signature_hex'];
const APPROVAL_SIGN_FIELDS = APPROVAL_FIELDS.filter((x) => x !== 'signature_hex');
const STRING_FIELDS = ['permit_id','issuer','subject','jurisdiction','action','evidence_hash','proposal_hash','nonce','signature','key_id','algorithm','audience'];
const enc = (s) => new TextEncoder().encode(s);
const hex = (bytes) => [...new Uint8Array(bytes)].map((n) => n.toString(16).padStart(2, '0')).join('');
const unhex = (s) => new Uint8Array((s.match(/.{2}/g) || []).map((chunk) => parseInt(chunk, 16)));
const sameKeys = (obj, fields) => obj && typeof obj === 'object' && !Array.isArray(obj) && Object.keys(obj).length === fields.length && fields.every((s) => Object.hasOwn(obj, s));
const int = (x) => Number.isSafeInteger(x) && x >= 0;
const digest = async (u8) => hex(await crypto.subtle.digest('SHA-256', u8));
const concat = (a, b) => { const c = new Uint8Array(a.length + b.length); c.set(a); c.set(b, a.length); return c; };
const isHex = (s, n) => typeof s === 'string' && new RegExp('^[a-f0-9]{' + n + '}$').test(s);
const safe = (v) => typeof v === 'string' && v.length > 0 && v.length <= 256 && v.trim() === v && !v.includes('*');
const B64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
// Permit canonical JSON intentionally allows only JSON primitives and safe integers.
function canonical(x) {
  if (x === null || typeof x === 'string' || typeof x === 'boolean') return JSON.stringify(x);
  if (typeof x === 'number' && Number.isSafeInteger(x)) return JSON.stringify(x);
  if (Array.isArray(x)) return '[' + x.map(canonical).join(',') + ']';
  if (x && typeof x === 'object' && Object.getPrototypeOf(x) === Object.prototype) {
    return '{' + Object.keys(x).sort().map((k) => JSON.stringify(k) + ':' + canonical(x[k])).join(',') + '}';
  }
  throw new Error('NON_CANONICAL_JSON');
}
function canonicalPermit(draft, omitId = false) {
  const o = {};
  for (const k of SIGN_FIELDS) if (!omitId || k !== 'permit_id') o[k] = draft[k];
  return enc(canonical(o));
}
function canonicalApproval(approval) {
  const o = {};
  for (const k of APPROVAL_SIGN_FIELDS) o[k] = approval[k];
  return concat(APPROVAL_DOMAIN, enc(canonical(o)));
}
function validateDraft(d, now, env) {
  if (!sameKeys(d, FIELDS)) throw new Error('INVALID_DRAFT_SHAPE');
  for (const k of STRING_FIELDS) if (typeof d[k] !== 'string') throw new Error('INVALID_DRAFT_FIELD');
  if (d.version !== 2 || d.algorithm !== 'Ed25519' || d.signature !== '') throw new Error('INVALID_PERMIT_VERSION');
  if (d.issuer !== env.ISSUER_NAME || d.key_id !== env.ISSUER_KEY_ID || d.audience !== env.ISSUER_AUDIENCE) throw new Error('ISSUER_SCOPE_MISMATCH');
  if (![d.issuer,d.key_id,d.subject,d.audience,d.jurisdiction,d.action].every(safe)) throw new Error('INVALID_SCOPE');
  if (!['echo','add'].includes(d.action)) throw new Error('TOOL_NOT_ALLOWED');
  if (d.max_executions !== 1 || !int(d.valid_from_ms) || !int(d.valid_until_ms) || d.valid_until_ms <= d.valid_from_ms || d.valid_until_ms - d.valid_from_ms > 900000) throw new Error('INVALID_LIFETIME');
  if (now < d.valid_from_ms || now > d.valid_until_ms) throw new Error('PERMIT_NOT_CURRENT');
  if (!isHex(d.permit_id,64) || !isHex(d.nonce,32) || !safe(d.proposal_hash) || typeof d.evidence_hash !== 'string') throw new Error('INVALID_BINDING');
  if (!d.params || typeof d.params !== 'object' || Array.isArray(d.params) || !d.constraints || typeof d.constraints !== 'object' || Array.isArray(d.constraints)) throw new Error('INVALID_PARAMS');
  if (Object.keys(d.constraints).length !== 0) throw new Error('UNSUPPORTED_CONSTRAINT');
  if (d.action === 'echo' && !(sameKeys(d.params,['text']) && typeof d.params.text === 'string' && d.params.text.length <= 256)) throw new Error('INVALID_ECHO');
  if (d.action === 'add' && !(sameKeys(d.params,['a','b']) && int(d.params.a) && int(d.params.b) && d.params.a <= 1000000 && d.params.b <= 1000000)) throw new Error('INVALID_ADD');
}
function validateApproval(a, now, draft) {
  if (!sameKeys(a, APPROVAL_FIELDS) || a.schema !== 'shards.operator-approval.v1' || !safe(a.reviewer) || !isHex(a.permit_sha256,64) || !isHex(a.permit_id,64) || !isHex(a.signature_hex,128)) throw new Error('INVALID_APPROVAL_SHAPE');
  if (!int(a.approved_at_ms) || !int(a.expires_at_ms) || a.expires_at_ms <= a.approved_at_ms || a.expires_at_ms - a.approved_at_ms > 600000) throw new Error('INVALID_APPROVAL_WINDOW');
  if (a.approved_at_ms < draft.valid_from_ms || a.approved_at_ms > draft.valid_until_ms || now < a.approved_at_ms || now > a.expires_at_ms) throw new Error('APPROVAL_NOT_CURRENT');
  if (a.permit_id !== draft.permit_id) throw new Error('APPROVAL_PERMIT_MISMATCH');
}
function json(status, body) { return new Response(JSON.stringify(body), {status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff','referrer-policy':'no-referrer'}}); }
function configured(env) {
  return !!(env && env.APPROVER_PUBLIC_KEY_HEX && env.ISSUER_PUBLIC_KEY_HEX && env.ISSUER_PRIVATE_KEY_PKCS8_B64 && env.ISSUANCE_ACCESS_TOKEN && env.ISSUER_NAME && env.ISSUER_KEY_ID && env.ISSUER_AUDIENCE && env.ISSUANCE_DB);
}
async function matchesBearer(header, actual) {
  if (typeof header !== 'string' || !header.startsWith('Bearer ') || typeof actual !== 'string' || actual.length < 32) return false;
  const provided = header.slice(7);
  if (provided.length < 32 || provided.length > 1024) return false;
  const [a,b] = await Promise.all([crypto.subtle.digest('SHA-256', enc(provided)), crypto.subtle.digest('SHA-256', enc(actual))]);
  let xor = 0; const aa = new Uint8Array(a), bb = new Uint8Array(b);
  for (let i = 0; i < aa.length; i++) xor |= aa[i] ^ bb[i];
  return xor === 0;
}
async function issue(request, env) {
  if (!configured(env)) return json(503,{status:'LOCKED',code:'ISSUER_NOT_PROVISIONED'});
  if (!await matchesBearer(request.headers.get('authorization'), env.ISSUANCE_ACCESS_TOKEN)) return json(401,{status:'DENY',code:'AUTH_REQUIRED'});
  if (!isHex(env.APPROVER_PUBLIC_KEY_HEX,64) || !isHex(env.ISSUER_PUBLIC_KEY_HEX,64) || env.APPROVER_PUBLIC_KEY_HEX === env.ISSUER_PUBLIC_KEY_HEX || !safe(env.ISSUER_NAME) || !safe(env.ISSUER_KEY_ID) || !safe(env.ISSUER_AUDIENCE)) return json(503,{status:'LOCKED',code:'CONFIG_INVALID'});
  if ((request.headers.get('content-type') || '').split(';',1)[0] !== 'application/json') return json(415,{status:'DENY',code:'CONTENT_TYPE_REQUIRED'});
  const length = Number(request.headers.get('content-length'));
  if (Number.isFinite(length) && length > 8192) return json(413,{status:'DENY',code:'BODY_TOO_LARGE'});
  let body;
  try { const raw = await request.text(); if (raw.length > 8192) throw Error(); body = JSON.parse(raw); } catch { return json(400,{status:'DENY',code:'BAD_JSON'}); }
  if (!sameKeys(body,['draft','approval'])) return json(400,{status:'DENY',code:'INVALID_ENVELOPE'});
  const {draft,approval} = body;
  const now = Date.now();
  try {
    validateDraft(draft,now,env);
    validateApproval(approval,now,draft);
    const [expectedId,expectedApprovalHash] = await Promise.all([digest(canonicalPermit(draft,true)),digest(canonicalPermit(draft))]);
    if (expectedId !== draft.permit_id || expectedApprovalHash !== approval.permit_sha256) throw Error('CANONICAL_MISMATCH');
    const pub = await crypto.subtle.importKey('raw',unhex(env.APPROVER_PUBLIC_KEY_HEX),{name:'Ed25519'},false,['verify']);
    if (!await crypto.subtle.verify({name:'Ed25519'},pub,unhex(approval.signature_hex),canonicalApproval(approval))) throw Error('APPROVAL_SIGNATURE_INVALID');
    // The secret key never reaches agents or the response. It is import-only.
    const privateKey = await crypto.subtle.importKey('pkcs8',B64(env.ISSUER_PRIVATE_KEY_PKCS8_B64),{name:'Ed25519'},false,['sign']);
    const message = concat(PERMIT_DOMAIN,canonicalPermit(draft));
    const signature = hex(await crypto.subtle.sign({name:'Ed25519'},privateKey,message));
    const issuerPublicKey = await crypto.subtle.importKey('raw',unhex(env.ISSUER_PUBLIC_KEY_HEX),{name:'Ed25519'},false,['verify']);
    if (!await crypto.subtle.verify({name:'Ed25519'},issuerPublicKey,unhex(signature),message)) throw Error('ISSUER_KEY_MISMATCH');
    // Durable one-use reservation before any signed permit can leave.
    const result = await env.ISSUANCE_DB.prepare(
      'INSERT INTO issued_permits (permit_id,approval_digest,issued_at_ms,subject,audience,action,valid_until_ms) VALUES (?,?,?,?,?,?,?)'
    ).bind(draft.permit_id,approval.permit_sha256,now,draft.subject,draft.audience,draft.action,draft.valid_until_ms).run();
    if (!result?.success || result.meta?.changes !== 1) throw Error('LEDGER_WRITE_FAILED');
    return json(200,{status:'ISSUED',permit:{...draft,signature}});
  } catch (err) {
    if (String(err?.message || '').includes('SQLITE_CONSTRAINT')) return json(409,{status:'DENY',code:'APPROVAL_ALREADY_CONSUMED'});
    return json(403,{status:'DENY',code:'ISSUANCE_REFUSED'});
  }
}
export default {
  async fetch(request,env) {
    try {
      const url = new URL(request.url);
      if (request.method === 'GET' && url.pathname === '/health') return json(200,{service:'shards-permit-issuer-pilot',revision:REVISION,status:'LOCKED',signing_enabled:false,scope:'local-integration-not-production'});
      if (request.method === 'GET' && url.pathname === '/v1/status') return json(200,{service:'shards-permit-issuer-pilot',status:configured(env)?'PROVISIONED':'LOCKED',signing_enabled:configured(env),scope:'approval-gated-echo-add-only'});
      if (url.pathname === '/v1/issue' && request.method === 'POST') return issue(request,env);
      if (url.pathname === '/v1/issue') return json(405,{status:'DENY',code:'METHOD_NOT_ALLOWED'});
      return json(404,{status:'DENY',code:'NOT_FOUND'});
    } catch { return json(503,{status:'DENY',code:'FAIL_CLOSED'}); }
  }
};
