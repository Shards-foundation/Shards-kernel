# Shards-Kernel Configuration Reference

**Version:** 0.1.0  
**Classification:** Reference  
**Last Updated:** January 2025

---

## 1. Overview

This document provides a complete reference for configuring Shards-Kernel.

---

## 2. Configuration Methods

### 2.1 Programmatic Configuration

Configure directly in Python code:

```python
from shards_kernel import StrictKernel, JurisdictionPolicy

policy = JurisdictionPolicy(
    allowed_actors=["agent-001"],
    allowed_tools=["read_file"],
    require_tool_call=True,
    max_intent_length=1000,
)

kernel = StrictKernel(
    kernel_id="my-kernel",
    policy=policy,
)
```

### 2.2 YAML Configuration

Load from YAML file:

```yaml
# shards_kernel.yaml
kernel:
  id: "prod-001"
  variant: "strict"

policy:
  allowed_actors:
    - agent-001
    - agent-002
  allowed_tools:
    - read_file
    - write_file
  require_tool_call: true
  max_intent_length: 1000

server:
  host: "0.0.0.0"
  port: 8080

logging:
  level: INFO
```

```python
import yaml
from shards_kernel import StrictKernel, JurisdictionPolicy

with open("shards_kernel.yaml") as f:
    config = yaml.safe_load(f)

policy = JurisdictionPolicy(**config["policy"])
kernel = StrictKernel(kernel_id=config["kernel"]["id"], policy=policy)
```

### 2.3 Environment Variables

Configure via environment:

```bash
export KERNELS_KERNEL_ID="prod-001"
export KERNELS_LOG_LEVEL="INFO"
export KERNELS_SERVER_PORT="8080"
export KERNELS_ALLOWED_ACTORS="agent-001,agent-002"
export KERNELS_ALLOWED_TOOLS="read_file,write_file"
```

```python
import os
from shards_kernel import StrictKernel, JurisdictionPolicy

policy = JurisdictionPolicy(
    allowed_actors=os.environ.get("KERNELS_ALLOWED_ACTORS", "").split(","),
    allowed_tools=os.environ.get("KERNELS_ALLOWED_TOOLS", "").split(","),
)

kernel = StrictKernel(
    kernel_id=os.environ.get("KERNELS_KERNEL_ID", "default"),
    policy=policy,
)
```

---

## 3. Kernel Configuration

### 3.1 Kernel ID

Unique identifier for the kernel instance.

| Property | Value |
|----------|-------|
| Type | `str` |
| Required | Yes |
| Default | None |
| Format | Alphanumeric with hyphens |

**Example:**
```python
kernel = StrictKernel(kernel_id="prod-001")
```

### 3.2 Kernel Variant

Choose the appropriate kernel variant.

| Variant | Use Case |
|---------|----------|
| `StrictKernel` | Production, maximum enforcement |
| `PermissiveKernel` | Development, relaxed rules |
| `EvidenceFirstKernel` | Audit-heavy, requires evidence |
| `DualChannelKernel` | Structured workflows, requires constraints |

---

## 4. Policy Configuration

### 4.1 allowed_actors

List of actors permitted to submit requests.

| Property | Value |
|----------|-------|
| Type | `List[str]` |
| Required | No |
| Default | `[]` (deny all) |

**Example:**
```python
policy = JurisdictionPolicy(
    allowed_actors=["agent-001", "agent-002", "admin-agent"],
)
```

**YAML:**
```yaml
policy:
  allowed_actors:
    - agent-001
    - agent-002
    - admin-agent
```

### 4.2 allowed_tools

List of tools permitted for execution.

| Property | Value |
|----------|-------|
| Type | `List[str]` |
| Required | No |
| Default | `[]` (deny all) |

**Example:**
```python
policy = JurisdictionPolicy(
    allowed_tools=["read_file", "write_file", "search", "calculate"],
)
```

### 4.3 require_tool_call

Whether requests must include a tool_call.

| Property | Value |
|----------|-------|
| Type | `bool` |
| Required | No |
| Default | `True` |

**Example:**
```python
# Strict: require tool_call
policy = JurisdictionPolicy(require_tool_call=True)

# Permissive: allow intent-only
policy = JurisdictionPolicy(require_tool_call=False)
```

### 4.4 max_intent_length

Maximum allowed length for intent field.

| Property | Value |
|----------|-------|
| Type | `int` |
| Required | No |
| Default | `1000` |
| Range | 1 - 100000 |

**Example:**
```python
policy = JurisdictionPolicy(max_intent_length=500)
```

### 4.5 custom_rules

List of custom rule functions.

| Property | Value |
|----------|-------|
| Type | `List[Callable]` |
| Required | No |
| Default | `[]` |

**Example:**
```python
from shards_kernel.jurisdiction import RuleResult

def business_hours_only(request):
    from datetime import datetime
    hour = datetime.utcnow().hour
    if 9 <= hour < 17:
        return RuleResult(allowed=True)
    return RuleResult(allowed=False, reason="Outside business hours")

policy = JurisdictionPolicy(
    allowed_actors=["agent"],
    allowed_tools=["tool"],
    custom_rules=[business_hours_only],
)
```

---

## 5. Server Configuration

### 5.1 Host

Network interface to bind to.

| Property | Value |
|----------|-------|
| Type | `str` |
| Required | No |
| Default | `"0.0.0.0"` |

**Values:**
- `"0.0.0.0"` - All interfaces
- `"127.0.0.1"` - Localhost only
- `"192.168.1.100"` - Specific interface

### 5.2 Port

TCP port to listen on.

| Property | Value |
|----------|-------|
| Type | `int` |
| Required | No |
| Default | `8080` |
| Range | 1 - 65535 |

### 5.3 Timeout

Request timeout in seconds.

| Property | Value |
|----------|-------|
| Type | `float` |
| Required | No |
| Default | `30.0` |

---

## 6. Logging Configuration

### 6.1 Log Level

Logging verbosity level.

| Level | Description |
|-------|-------------|
| `DEBUG` | Detailed debugging |
| `INFO` | Normal operations |
| `WARNING` | Potential issues |
| `ERROR` | Failures |
| `CRITICAL` | Severe failures |

**Environment:**
```bash
export KERNELS_LOG_LEVEL=INFO
```

### 6.2 Log Format

Log message format string.

**Default:**
```
%(asctime)s %(levelname)s %(name)s %(message)s
```

**JSON Format:**
```python
import logging
import json

class JSONFormatter(logging.Formatter):
    def format(self, record):
        return json.dumps({
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "message": record.getMessage(),
        })
```

### 6.3 Log Output

Configure log destination.

```python
import logging

# Console
handler = logging.StreamHandler()

# File
handler = logging.FileHandler("/var/log/shards_kernel/shards_kernel.log")

# Syslog
handler = logging.handlers.SysLogHandler(address="/dev/log")

logging.getLogger("kernels").addHandler(handler)
```

---

## 7. Evidence Configuration

### 7.1 Evidence Path

Directory for evidence storage.

| Property | Value |
|----------|-------|
| Type | `str` |
| Required | No |
| Default | `"./evidence"` |

**Environment:**
```bash
export KERNELS_EVIDENCE_PATH=/var/lib/shards_kernel/evidence
```

### 7.2 Evidence Rotation

Configure evidence rotation.

```yaml
evidence:
  path: /var/lib/shards_kernel/evidence
  rotation: weekly
  retention_days: 2555  # 7 years
  compression: gzip
```

### 7.3 Evidence Export Format

| Format | Use Case |
|--------|----------|
| JSON | Default, human-readable |
| JSONL | Streaming, large files |
| Parquet | Analytics, columnar |

---

## 8. Tool Configuration

### 8.1 Tool Registry

Register tools for execution.

```python
from shards_kernel.execution import ToolRegistry

registry = ToolRegistry()

@registry.register("read_file")
def read_file(params):
    path = params["path"]
    with open(path) as f:
        return {"content": f.read()}

kernel = StrictKernel(
    kernel_id="my-kernel",
    policy=policy,
    tool_registry=registry,
)
```

### 8.2 Tool Timeout

Configure per-tool timeouts.

```python
registry.register(
    "slow_tool",
    slow_tool_fn,
    timeout=60.0,  # 60 second timeout
)
```

### 8.3 Tool Schemas

Define tool parameter schemas.

```python
registry.register(
    "search",
    search_fn,
    description="Search for documents",
    params_schema={
        "type": "object",
        "properties": {
            "query": {"type": "string"},
            "limit": {"type": "integer", "default": 10},
        },
        "required": ["query"],
    },
)
```

---

## 9. Security Configuration

### 9.1 API Key

Configure API key authentication.

```python
from shards_kernel.sdk import KernelServer

server = KernelServer(
    kernel,
    api_key="your-secret-key",
)
```

**Client:**
```python
from shards_kernel.sdk import KernelClient

client = KernelClient(
    "http://localhost:8080",
    api_key="your-secret-key",
)
```

### 9.2 TLS Configuration

Configure TLS for secure connections.

```python
import ssl

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("cert.pem", "key.pem")

# Use with your HTTP server
```

### 9.3 CORS Configuration

Configure Cross-Origin Resource Sharing.

```python
from shards_kernel.integrations import create_fastapi_app

app = create_fastapi_app(
    kernel,
    cors_origins=["https://example.com"],
)
```

---

## 10. Complete Configuration Example

### 10.1 YAML Configuration File

```yaml
# /etc/shards_kernel/shards_kernel.yaml

# Kernel settings
kernel:
  id: "prod-001"
  variant: "strict"

# Jurisdiction policy
policy:
  allowed_actors:
    - agent-001
    - agent-002
    - admin-agent
  allowed_tools:
    - read_file
    - write_file
    - search
    - calculate
  require_tool_call: true
  max_intent_length: 1000

# Server settings
server:
  host: "0.0.0.0"
  port: 8080
  timeout: 30.0

# Logging settings
logging:
  level: INFO
  format: "%(asctime)s %(levelname)s %(name)s %(message)s"
  file: /var/log/shards_kernel/shards_kernel.log

# Evidence settings
evidence:
  path: /var/lib/shards_kernel/evidence
  rotation: weekly
  retention_days: 2555
  compression: gzip

# Security settings
security:
  api_key_required: true
  tls_enabled: true
  tls_cert: /etc/shards_kernel/cert.pem
  tls_key: /etc/shards_kernel/key.pem

# Monitoring settings
monitoring:
  metrics_enabled: true
  metrics_port: 9090
  health_check_path: /health
```

### 10.2 Loading Configuration

```python
import yaml
from shards_kernel import StrictKernel, JurisdictionPolicy

def load_config(path: str = "/etc/shards_kernel/shards_kernel.yaml"):
    with open(path) as f:
        return yaml.safe_load(f)

def create_kernel_from_config(config: dict):
    policy = JurisdictionPolicy(
        allowed_actors=config["policy"]["allowed_actors"],
        allowed_tools=config["policy"]["allowed_tools"],
        require_tool_call=config["policy"]["require_tool_call"],
        max_intent_length=config["policy"]["max_intent_length"],
    )
    
    return StrictKernel(
        kernel_id=config["kernel"]["id"],
        policy=policy,
    )

# Usage
config = load_config()
kernel = create_kernel_from_config(config)
```

---

## 11. Configuration Validation

### 11.1 Validate Configuration

```python
def validate_config(config: dict) -> list[str]:
    errors = []
    
    # Required fields
    if "kernel" not in config:
        errors.append("Missing 'kernel' section")
    elif "id" not in config["kernel"]:
        errors.append("Missing 'kernel.id'")
    
    if "policy" not in config:
        errors.append("Missing 'policy' section")
    
    # Value validation
    if config.get("policy", {}).get("max_intent_length", 0) < 1:
        errors.append("max_intent_length must be positive")
    
    return errors

# Usage
errors = validate_config(config)
if errors:
    raise ValueError(f"Configuration errors: {errors}")
```

---

## 12. Environment Variable Reference

| Variable | Description | Default |
|----------|-------------|---------|
| `KERNELS_KERNEL_ID` | Kernel identifier | `"default"` |
| `KERNELS_LOG_LEVEL` | Logging level | `"INFO"` |
| `KERNELS_SERVER_HOST` | Server host | `"0.0.0.0"` |
| `KERNELS_SERVER_PORT` | Server port | `8080` |
| `KERNELS_EVIDENCE_PATH` | Evidence directory | `"./evidence"` |
| `KERNELS_ALLOWED_ACTORS` | Comma-separated actors | `""` |
| `KERNELS_ALLOWED_TOOLS` | Comma-separated tools | `""` |
| `KERNELS_REQUIRE_TOOL_CALL` | Require tool_call | `"true"` |
| `KERNELS_MAX_INTENT_LENGTH` | Max intent length | `1000` |
| `KERNELS_API_KEY` | API authentication key | `""` |
