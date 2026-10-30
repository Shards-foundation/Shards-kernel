# Shards-Kernel System Requirements

**Version:** 0.1.0  
**Classification:** Requirements  
**Last Updated:** January 2025

---

## 1. Overview

This document specifies the system requirements for deploying and operating Shards-Kernel.

---

## 2. Runtime Requirements

### 2.1 Python Version

| Version | Status | Notes |
|---------|--------|-------|
| 3.13+ | ✅ Supported | Recommended |
| 3.12 | ✅ Supported | Recommended |
| 3.11 | ✅ Supported | Minimum required |
| 3.10 | ⚠️ Untested | May work |
| 3.9 | ❌ Not supported | Missing features |
| <3.9 | ❌ Not supported | - |

### 2.2 Operating System

| OS | Version | Status |
|----|---------|--------|
| Ubuntu | 22.04 LTS | ✅ Recommended |
| Ubuntu | 20.04 LTS | ✅ Supported |
| Debian | 11+ | ✅ Supported |
| RHEL/CentOS | 8+ | ✅ Supported |
| macOS | 12+ | ✅ Supported |
| Windows | 10/11 | ✅ Supported |
| Alpine | 3.16+ | ✅ Supported |

### 2.3 Architecture

| Architecture | Status |
|--------------|--------|
| x86_64 (amd64) | ✅ Supported |
| arm64 (aarch64) | ✅ Supported |
| armv7 | ⚠️ Untested |

---

## 3. Hardware Requirements

### 3.1 Minimum Requirements

| Resource | Minimum | Notes |
|----------|---------|-------|
| CPU | 1 core | Any modern CPU |
| Memory | 256 MB | For kernel only |
| Disk | 50 MB | Installation |
| Network | Optional | Offline capable |

### 3.2 Recommended Requirements

| Resource | Recommended | Notes |
|----------|-------------|-------|
| CPU | 2+ cores | For concurrent requests |
| Memory | 1 GB | With evidence storage |
| Disk | 1 GB | For evidence retention |
| Network | 100 Mbps | For API access |

### 3.3 Production Requirements

| Resource | Production | Notes |
|----------|------------|-------|
| CPU | 4+ cores | For high throughput |
| Memory | 4 GB | For large audit logs |
| Disk | 100 GB SSD | For evidence retention |
| Network | 1 Gbps | For high traffic |

---

## 4. Dependencies

### 4.1 Core Dependencies

**Shards-Kernel has zero external dependencies.** It uses only Python standard library.

| Module | Purpose | Source |
|--------|---------|--------|
| hashlib | Cryptographic hashing | stdlib |
| json | Serialization | stdlib |
| dataclasses | Type definitions | stdlib |
| enum | Enumerations | stdlib |
| typing | Type hints | stdlib |
| time | Timestamps | stdlib |
| asyncio | Async support | stdlib |
| threading | Concurrency | stdlib |
| http.server | HTTP server | stdlib |
| urllib | HTTP client | stdlib |

### 4.2 Optional Dependencies

| Package | Purpose | Install |
|---------|---------|---------|
| fastapi | FastAPI integration | `pip install fastapi` |
| uvicorn | ASGI server | `pip install uvicorn` |
| flask | Flask integration | `pip install flask` |
| pyyaml | YAML config | `pip install pyyaml` |
| pytest | Testing | `pip install pytest` |

### 4.3 Development Dependencies

| Package | Purpose | Install |
|---------|---------|---------|
| pytest | Testing | `pip install pytest` |
| pytest-cov | Coverage | `pip install pytest-cov` |
| black | Formatting | `pip install black` |
| mypy | Type checking | `pip install mypy` |
| ruff | Linting | `pip install ruff` |

---

## 5. Network Requirements

### 5.1 Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 8080 | HTTP | Default API port |
| 443 | HTTPS | Secure API (with TLS) |

### 5.2 Firewall Rules

```bash
# Allow inbound API traffic
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT

# Allow outbound (for tool execution)
iptables -A OUTPUT -p tcp -j ACCEPT
```

### 5.3 TLS Requirements

For production:
- TLS 1.2 or higher
- Valid certificate from trusted CA
- Strong cipher suites

---

## 6. Storage Requirements

### 6.1 Evidence Storage

| Retention | Storage Estimate |
|-----------|------------------|
| 1 day | ~10 MB |
| 1 week | ~70 MB |
| 1 month | ~300 MB |
| 1 year | ~3.5 GB |
| 7 years | ~25 GB |

**Calculation:** ~10 KB per request × 1000 requests/day

### 6.2 Storage Recommendations

| Environment | Storage Type | Size |
|-------------|--------------|------|
| Development | Local SSD | 10 GB |
| Staging | Cloud SSD | 50 GB |
| Production | Cloud SSD | 500 GB |

### 6.3 Backup Requirements

| Data | Frequency | Retention |
|------|-----------|-----------|
| Evidence | Daily | 7 years |
| Configuration | On change | 1 year |
| Logs | Daily | 90 days |

---

## 7. Performance Requirements

### 7.1 Latency Targets

| Metric | Target | Maximum |
|--------|--------|---------|
| Decision latency (p50) | <1 ms | 5 ms |
| Decision latency (p99) | <10 ms | 50 ms |
| API response (p50) | <5 ms | 20 ms |
| API response (p99) | <50 ms | 200 ms |

### 7.2 Throughput Targets

| Environment | Target | Notes |
|-------------|--------|-------|
| Development | 100 req/s | Single kernel |
| Production | 10,000 req/s | With load balancing |

### 7.3 Scalability

| Scaling | Method |
|---------|--------|
| Vertical | Increase CPU/memory |
| Horizontal | Multiple kernel instances |

---

## 8. Security Requirements

### 8.1 Authentication

| Method | Status | Notes |
|--------|--------|-------|
| API Key | ✅ Supported | Header-based |
| OAuth 2.0 | 🔲 Planned | Future release |
| mTLS | 🔲 Planned | Future release |

### 8.2 Authorization

| Feature | Status |
|---------|--------|
| Actor allow list | ✅ Supported |
| Tool allow list | ✅ Supported |
| Custom rules | ✅ Supported |

### 8.3 Encryption

| Data State | Encryption |
|------------|------------|
| In transit | TLS 1.2+ |
| At rest | Application-level |

---

## 9. Monitoring Requirements

### 9.1 Metrics

| Metric | Type | Purpose |
|--------|------|---------|
| kernel_state | Gauge | Current state |
| requests_total | Counter | Request count |
| decisions_total | Counter | By decision type |
| latency_seconds | Histogram | Processing time |
| errors_total | Counter | Error count |

### 9.2 Logging

| Level | Purpose |
|-------|---------|
| ERROR | Failures requiring attention |
| WARN | Potential issues |
| INFO | Normal operations |
| DEBUG | Detailed debugging |

### 9.3 Alerting

| Condition | Severity | Action |
|-----------|----------|--------|
| Kernel halted | Critical | Page on-call |
| Error rate > 1% | High | Alert team |
| Latency p99 > 100ms | Medium | Investigate |
| Disk > 80% | Medium | Expand storage |

---

## 10. Compliance Requirements

### 10.1 Data Retention

| Requirement | Duration |
|-------------|----------|
| SOC 2 | 1 year minimum |
| GDPR | As needed |
| HIPAA | 6 years |
| Financial | 7 years |

### 10.2 Audit Requirements

| Requirement | Shards-Kernel Support |
|-------------|-----------------|
| Immutable logs | ✅ Hash chain |
| Tamper detection | ✅ Verification |
| Export capability | ✅ JSON export |
| External verification | ✅ Replay |

---

## 11. Compatibility Matrix

### 11.1 Python Packages

| Package | Compatible Versions |
|---------|---------------------|
| fastapi | 0.100+ |
| flask | 2.0+ |
| uvicorn | 0.20+ |
| pyyaml | 6.0+ |

### 11.2 Container Runtimes

| Runtime | Compatible Versions |
|---------|---------------------|
| Docker | 20.10+ |
| Podman | 4.0+ |
| containerd | 1.6+ |

### 11.3 Orchestration

| Platform | Compatible Versions |
|----------|---------------------|
| Kubernetes | 1.24+ |
| Docker Compose | 2.0+ |
| Docker Swarm | 20.10+ |

---

## 12. Version Compatibility

### 12.1 Shards-Kernel Versions

| Version | Python | Status |
|---------|--------|--------|
| 0.1.x | 3.11+ | Current |
| 0.2.x | 3.11+ | Planned |
| 1.0.x | 3.11+ | Planned |

### 12.2 API Compatibility

| API Version | Shards-Kernel Version |
|-------------|-----------------|
| v1 | 0.1.x - 1.x |

---

## 13. Checklist

### 13.1 Pre-Installation Checklist

- [ ] Python 3.11+ installed
- [ ] Sufficient disk space (50 MB minimum)
- [ ] Network access (if using API)
- [ ] Required ports available

### 13.2 Production Checklist

- [ ] TLS configured
- [ ] Monitoring enabled
- [ ] Alerting configured
- [ ] Backup strategy defined
- [ ] Evidence retention policy set
- [ ] Security review completed
