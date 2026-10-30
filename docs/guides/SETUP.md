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

The distribution name is `shards-kernel`. After it is published:

```bash
python -m pip install shards-kernel
python -c "import shards_kernel"
```

A verified PyPI release is pending. Do **not** install the unrelated PyPI distribution `kernels` (maintained by Hugging Face). After an approved release, install `shards-kernel` and import `shards_kernel`. Until then, install this repository directly from GitHub.

### 2.3 From GitHub

This repository has no published release tarball (`shards_kernel-0.1.0.tar.gz` is not a release asset). Install from the Git repository:

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

## 6. Production Setup

### 6.1 System Service

Create `/etc/systemd/system/shards_kernel.service`:

```ini
[Unit]
Description=Shards-Kernel Control Plane
After=network.target

[Service]
Type=simple
User=kernels
Group=kernels
WorkingDirectory=/opt/kernels
Environment=KERNELS_LOG_LEVEL=INFO
ExecStart=/opt/shards_kernel/venv/bin/python -m shards_kernel.server
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable kernels
sudo systemctl start kernels
sudo systemctl status kernels
```

### 6.2 Directory Structure

```
/opt/shards_kernel/
├── venv/                 # Virtual environment
├── config/
│   └── shards_kernel.yaml      # Configuration
├── evidence/             # Evidence storage
├── logs/                 # Log files
└── scripts/              # Operational scripts
```

### 6.3 Permissions

```bash
# Create user
sudo useradd -r -s /bin/false kernels

# Set ownership
sudo chown -R kernels:kernels /opt/kernels

# Set permissions
sudo chmod 750 /opt/kernels
sudo chmod 700 /opt/shards_kernel/evidence
sudo chmod 640 /opt/shards_kernel/config/shards_kernel.yaml
```

### 6.4 Log Rotation

Create `/etc/logrotate.d/kernels`:

```
/opt/shards_kernel/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 640 kernels kernels
}
```

---

## 7. Container Setup

### 7.1 Dockerfile

```dockerfile
FROM python:3.11-slim

# Create non-root user
RUN useradd -r -s /bin/false kernels

# Set working directory
WORKDIR /app

# Copy source
COPY . .

# Install
RUN pip install --no-cache-dir -e .

# Switch to non-root user
USER kernels

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "from shards_kernel import StrictKernel; k = StrictKernel('health'); print(k.state)"

# Run
CMD ["python", "-m", "shards_kernel.server"]
```

### 7.2 Docker Compose

```yaml
version: '3.8'

services:
  kernels:
    build: .
    container_name: kernels
    restart: unless-stopped
    environment:
      - KERNELS_LOG_LEVEL=INFO
    volumes:
      - ./config:/app/config:ro
      - kernels-evidence:/app/evidence
    ports:
      - "8080:8080"
    healthcheck:
      test: ["CMD", "python", "-c", "import shards_kernel; print('ok')"]
      interval: 30s
      timeout: 5s
      retries: 3

volumes:
  kernels-evidence:
```

### 7.3 Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kernels
spec:
  replicas: 3
  selector:
    matchLabels:
      app: kernels
  template:
    metadata:
      labels:
        app: kernels
    spec:
      containers:
      - name: kernels
        image: kernels:latest
        ports:
        - containerPort: 8080
        env:
        - name: KERNELS_LOG_LEVEL
          value: "INFO"
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
        volumeMounts:
        - name: config
          mountPath: /app/config
          readOnly: true
        - name: evidence
          mountPath: /app/evidence
      volumes:
      - name: config
        configMap:
          name: kernels-config
      - name: evidence
        persistentVolumeClaim:
          claimName: kernels-evidence
```

---

## 8. Troubleshooting

### 8.1 Common Issues

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError: kernels` | Run `pip install -e .` |
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
pip list | grep kernels

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
pip uninstall kernels

# Remove source (if installed from source)
rm -rf /path/to/kernels

# Remove configuration
rm -rf ~/.kernels
rm -rf /opt/kernels
```
