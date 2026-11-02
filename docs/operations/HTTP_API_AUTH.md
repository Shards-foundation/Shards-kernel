# Shards-Kernel HTTP authentication and safe deployment

**Security boundary:** the HTTP transport authenticates callers using a bearer
credential. It does **not** grant tool execution permission; the kernel still
requires an appropriate signed permit and matching policy for tool invocation.

## Start a local development server

Create a high-entropy credential using the Python standard library:

```bash
export SHARDS_KERNEL_API_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
python -m shards_kernel.sdk.server
```

The server listens on `127.0.0.1:8080`. It will **refuse to start** if the
credential is missing, shorter than 32 characters, or whitespace-padded.
Do not commit, print in CI logs, or send this key to an AI agent. Use a secret
manager or a securely managed local environment variable.

Check health without credentials:

```bash
curl --fail http://127.0.0.1:8080/health
```

Read authenticated status:

```bash
curl --fail -H "Authorization: Bearer ${SHARDS_KERNEL_API_KEY}" \
  http://127.0.0.1:8080/status
```

A caller without a valid token receives HTTP 401 on `/status`, `/policy`,
`/evidence`, `/submit` and `/halt`. Only `/` and `/health` are public.
The default server supplies no cross-origin browser permission.

## Programmatic access

```python
import os
from shards_kernel.sdk.client import KernelClient

client = KernelClient(
    "http://127.0.0.1:8080",
    api_key=os.environ["SHARDS_KERNEL_API_KEY"],
)
print(client.status())
```

You may pass `api_key=` to `KernelServer`, `create_flask_app`, or
`create_fastapi_app`. If omitted, each reads `SHARDS_KERNEL_API_KEY` on
startup. Flask and FastAPI only expose `/` and `/health` anonymously by
default. FastAPI's optional `cors_origins` must be configured explicitly
when browser access is required; avoid wildcard origins for control APIs.

## External deployments

The example HTTP server is **not** a public production gateway. Keep its
listener on loopback behind an authenticated TLS reverse proxy, or use an
independent, hardened ingress that enforces TLS, IP/network restrictions,
request limits, logs, credential rotation, and per-agent identity. Any remote
bind requires an explicit `allow_remote_bind=True` for the basic and
convenience HTTP servers. That switch **does not add TLS** and should never
be taken as proof that a public listener is secure.

**Important operational limitations**

- One transport token is not per-agent authentication, identity proof,
  scoped operator roles, or revocable sessions. These require gateway-level
  identity and authorisation plus kernel-level permits.
- The lightweight built-in server is single-process/single-host; it does not
  implement robust reverse-proxy trust handling, rate limits, distributed
  consistency, recovery or production telemetry.
- Local SQLite audit persistence needs off-host backups, tested restore,
  access controls and independent integrity verification for production use.
- Do not expose `/halt` or `/evidence` directly to the internet.
- MCP stdio integration is a separate transport and is **not** secured by
  the HTTP bearer credential. Apply explicit authentication at any MCP
  gateway or remote MCP transport.
- Treat this change as one P0 remediation, not a security certification.
