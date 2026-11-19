// Test-only child process: receives ephemeral in-memory credentials via stdin.
// Nothing here is deployed, and none of the keys are written to disk.
import { readFileSync } from 'node:fs';
import worker from '../../deploy/cloudflare/issuer-pilot/worker.mjs';
const input = JSON.parse(readFileSync(0, 'utf8'));
const used = new Set();
const env = {
  APPROVER_PUBLIC_KEY_HEX: input.approver_public_hex,
  ISSUER_PUBLIC_KEY_HEX: input.issuer_public_hex,
  ISSUER_PRIVATE_KEY_PKCS8_B64: input.issuer_private_pkcs8_b64,
  ISSUANCE_ACCESS_TOKEN: input.token,
  ISSUER_NAME: input.issuer,
  ISSUER_KEY_ID: input.key_id,
  ISSUER_AUDIENCE: input.audience,
  ISSUANCE_DB: {
    prepare() {
      return {
        bind(permitId) {
          return {
            async run() {
              if (used.has(permitId)) throw Error('SQLITE_CONSTRAINT_PRIMARYKEY');
              used.add(permitId);
              return { success: true, meta: { changes: 1 } };
            }
          };
        }
      };
    }
  }
};
const request = new Request('https://issuer.invalid/v1/issue', {
  method: 'POST',
  headers: {
    'Authorization': 'Bearer ' + input.token,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ draft: input.draft, approval: input.approval })
});
const response = await worker.fetch(request, env);
const body = await response.json();
process.stdout.write(JSON.stringify({status: response.status, body}) + '\n');
