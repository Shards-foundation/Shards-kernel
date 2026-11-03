# Shards-Kernel Setup Guide

**Version:** 0.1.0  
**Classification:** Installation  
**Last Updated:** January 2025

---

## 1. System Requirements

### 1.1 Minimum Requirements

| Component | Requirement |
|-----------|-------------|
| Python | 3.11 or higher |
| OS | Linux, macOS, Windows |
| Memory | 512 MB RAM |
| Disk | 50 MB free space |
| Network | Not required (offline capable) |

### 1.2 Recommended Requirements

| Component | Recommendation |
|-----------|----------------|
| Python | 3.12 |
| OS | Ubuntu 22.04 LTS |
| Memory | 2 GB RAM |
| Disk | 1 GB free space |
| CPU | 2+ cores |

### 1.3 Dependencies

Shards-Kernel has **zero external dependencies**. It uses only Python standard library.

---

## 2. Installation Methods

### 2.1 From Source (Recommended)

```bash
# Clone repository
git clone https://github.com/Shards-foundation/Shards-kernel.git
cd Shards-kernel

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate  # Linux/macOS
# or: venv\Scripts\activate  # Windows

# Install in development mode
pip install -e .

# Verify installation
python -m shards_kernel info
```

### 2.2 PyPI

The published PyPI distribution is `shards-kernel`, the Python import namespace is `shards_kernel`, and the CLI command is `shards-kernel`:

```bash
python -m pip install "shards-kernel==0.1.0"
python -c "from shards_kernel import StrictKernel; print(StrictKernel)"
shards-kernel --help
```

Do **not** install or import the unrelated PyPI distribution `kernels` (maintained by Hugging Face).

### 2.3 From GitHub

To install the latest repository source instead of the published package, use:

```bash
python -m pip install "git+https://github.com/Shards-foundation/Shards-kernel.git"
```

### 2.4 Using Docker

```dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Clone and install
RUN git clone https://github.com/Shards-foundation/Shards-kernel.git . && \
    pip install -e .

# Run smoke test
RUN python -m shards_kernel info

CMD ["python", "-m", "shards_kernel", "info"]
```

```bash
# Build and run
docker build -t kernels .
docker run kernels
```

---

## 3. Verification

### 3.1 Check Installation

```bash
# Check version
python -m shards_kernel --version

# Check info
python -m shards_kernel info

# Run smoke test
./scripts/smoke.sh
```

### 3.2 Run Tests

```bash
# Run all tests
python -m unittest discover -s tests -v

# Run specific test
python -m unittest tests.test_state_machine -v
```

### 3.3 Verify Import

```python
# Verify imports work
from shards_kernel import (
    StrictKernel,
    PermissiveKernel,
    EvidenceFirstKernel,
    DualChannelKernel,
    Request,
    Receipt,
    ToolCall,
    Decision,
    KernelState,
    JurisdictionPolicy,
)

print("All imports successful!")
```

---

## 4. Configuration

### 4.1 Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `KERNELS_LOG_LEVEL` | Logging level | `INFO` |
| `KERNELS_LOG_FORMAT` | Log format | `%(asctime)s %(levelname)s %(message)s` |
| `KERNELS_EVIDENCE_PATH` | Evidence storage path | `./evidence/` |

```bash
# Set environment variables
export KERNELS_LOG_LEVEL=DEBUG
export KERNELS_EVIDENCE_PATH=/var/lib/shards_kernel/evidence
```

### 4.2 Configuration File

Create `shards_kernel.yaml`:

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

logging:
  level: INFO
  format: "%(asctime)s %(levelname)s %(message)s"

evidence:
  path: /var/lib/shards_kernel/evidence
  rotation: weekly
  retention_days: 2555  # 7 years
```

### 4.3 Load Configuration

```python
import yaml
from shards_kernel import StrictKernel, JurisdictionPolicy

# Load config
with open("shards_kernel.yaml") as f:
    config = yaml.safe_load(f)

# Create policy from config
policy = JurisdictionPolicy(
    allowed_actors=config["policy"]["allowed_actors"],
    allowed_tools=config["policy"]["allowed_tools"],
    require_tool_call=config["policy"]["require_tool_call"],
    max_intent_length=config["policy"]["max_intent_length"],
)

# Create kernel
kernel = StrictKernel(
    kernel_id=config["kernel"]["id"],
    policy=policy,
)
```

---

## 5. Development Setup

### 5.1 Clone and Setup

```bash
# Clone repository
git clone https://github.com/Shards-foundation/Shards-kernel.git
cd Shards-kernel

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate

# Install in development mode with extras
pip install -e ".[dev]"

# Install pre-commit hooks (optional)
pip install pre-commit
pre-commit install
```

### 5.2 Development Dependencies

```bash
# Install development tools
pip install pytest pytest-cov black isort mypy ruff
```

### 5.3 IDE Setup

**VS Code** (`.vscode/settings.json`):

```json
{
    "python.defaultInterpreterPath": "./venv/bin/python",
    "python.formatting.provider": "black",
    "python.linting.enabled": true,
    "python.linting.mypyEnabled": true,
    "python.testing.unittestEnabled": true,
    "python.testing.unittestArgs": [
        "-v",
        "-s",
        "./tests",
        "-p",
        "test_*.py"
    ]
}
```

**PyCharm**:
1. Open project
2. Set Python interpreter to `./venv/bin/python`
3. Mark `shards_kernel/` as Sources Root
4. Mark `tests/` as Test Sources Root

---

## 6. Reference Single-Host HTTP Service (not production certified)

**Scope:** This example demonstrates a local, loopback-only HTTP control interface.
It is *not* a production MCP Gateway, does not include durable evidence by
default, and must not be exposed to the public internet. The service requires
a transport bearer credential; an authenticated request still requires a
valid execution permit and policy decision before executing any tool.

Before using this example, install the checked-out repository and a virtual
environment under `/opt/shards_kernel`. Do not install the unrelated
`kernels` PyPI distribution.

### 6.1 Prepare a dedicated service identity and secret

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin kernels
sudo install -d -m 0700 -o root -g root /etc/shards_kernel
sudo python3 -c 'import secrets; from pathlib import Path; p=Path("/etc/shards_kernel/shards-kernel.env"); p.write_text("SHARDS_KERNEL_API_KEY=" + secrets.token_urlsafe(48) + "\n"); p.chmod(0o600)'
```

If the service account already exists, skip `useradd`. In a managed
deployment, inject the secret through a secret manager rather than generating
it locally. Do not print or commit the credential.

### 6.2 Install the service unit

Create `/etc/systemd/system/shards-kernel.service`:

```ini
[Unit]
Description=Shards-Kernel local reference HTTP service
After=network.target

[Service]
Type=simple
User=kernels
Group=kernels
WorkingDirectory=/opt/shards_kernel
EnvironmentFile=/etc/shards_kernel/shards-kernel.env
ExecStart=/opt/shards_kernel/venv/bin/python -m shards_kernel.sdk.server
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

The service needs the package installed in the specified virtual environment.
The default HTTP listener is `127.0.0.1:8080`. A reverse proxy must supply
TLS and additional network- and operator-level controls before any remote
use. For an independently hardened ingress, deploy and test it separately.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now shards-kernel.service
sudo systemctl status shards-kernel.service
curl --fail http://127.0.0.1:8080/health
```

To authenticate a local operator, retrieve credentials through the approved
secret-management process and send `Authorization: Bearer <credential>`.
Review [HTTP authentication](../operations/HTTP_API_AUTH.md) for limitations.

**Audit persistence:** by default this example does not configure a durable
SQLite ledger, so a process restart may lose in-memory evidence. Do not use it
for production decision records. Implement and test restart recovery, protected
storage, off-host backups and restore before approval.

## 7. Containers and Kubernetes — not supported for production rollout

The old Docker/Compose/Kubernetes examples have been removed because they
presented **non-operational configurations**:

- The old container command referred to a Python module that does not exist,
  while the server binds to loopback and does not become remotely reachable
  simply by publishing `8080`.
- The Compose example supplied no API secret and published an unauthenticated
  port on all host interfaces.
- The Kubernetes example set three replicas without a shared ledger,
  distributed nonce/permit consumption or coordination mechanism; it also
  pointed at a nonexistent `/ready` endpoint.

A production deployment manifest is **pending** until the gateway ingress,
identity, distributed state, storage, health/readiness and recovery contracts
are actually implemented and proven in staging. See production-readiness
[issue #63](https://github.com/Shards-foundation/Shards-kernel/issues/63).
Do not use a placeholder Kubernetes deployment to claim horizontal scaling.

---

## 8. Troubleshooting

### 8.1 Common Issues

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError: No module named 'shards_kernel'` | Install `shards-kernel` into the active Python environment using `python -m pip install shards-kernel`. |
| `Python version error` | Use Python 3.11+ |
| `Permission denied` | Check file permissions |
| `Import error` | Check virtual environment |

### 8.2 Debug Mode

```bash
# Enable debug logging
export KERNELS_LOG_LEVEL=DEBUG

# Run with verbose output
python -m shards_kernel info -v
```

### 8.3 Check Installation

```bash
# Check Python version
python --version

# Check pip packages
python -m pip show shards-kernel

# Check import
python -c "import shards_kernel; print(shards_kernel.__version__)"
```

---

## 9. Upgrade Guide

### 9.1 Upgrade Process

```bash
# Backup evidence
cp -r evidence/ evidence.backup/

# Pull latest code
git pull origin main

# Reinstall
pip install -e .

# Run tests
python -m unittest discover -s tests -v

# Verify
python -m shards_kernel info
```

### 9.2 Version Compatibility

| From | To | Notes |
|------|-----|-------|
| 0.1.x | 0.1.y | Compatible |
| 0.1.x | 0.2.x | Check changelog |

---

## 10. Uninstallation

```bash
# Uninstall package
python -m pip uninstall shards-kernel

# Remove source (if installed from source)
rm -rf /path/to/kernels

# Remove configuration
rm -rf ~/.kernels
rm -rf /opt/kernels
```
