# Shards-Kernel Rulebook

**Version:** 0.1.0  
**Classification:** Governance  
**Last Updated:** January 2025

---

## 1. Overview

This rulebook defines the operational rules, policies, and constraints that govern Shards-Kernel deployments. All operators must adhere to these rules.

---

## 2. Fundamental Rules

### Rule 1: Fail-Closed is Mandatory

> **The kernel MUST deny by default. No implicit allows.**

**Rationale:** Safety requires explicit permission for every action.

**Enforcement:**
- Default policy denies all requests
- Every ALLOW must be explicitly configured
- Ambiguous requests result in DENY

**Violations:**
- Configuring default-allow policies
- Bypassing jurisdiction checks
- Ignoring validation failures

---

### Rule 2: Audit Everything

> **Every decision MUST be recorded before it takes effect.**

**Rationale:** Accountability requires complete audit trail.

**Enforcement:**
- Audit entry created before state transition
- No decision without corresponding entry
- Hash chain maintains integrity

**Violations:**
- Executing without audit entry
- Modifying audit entries
- Deleting audit history

---

### Rule 3: Halt is Sacred

> **The ability to halt MUST never be compromised.**

**Rationale:** Emergency stop is the ultimate safety mechanism.

**Enforcement:**
- Halt available from any non-terminal state
- Halt is immediate and unconditional
- No operation can prevent halt

**Violations:**
- Disabling halt capability
- Delaying halt execution
- Requiring approval for halt

---

### Rule 4: Separation of Concerns

> **Each component has exactly one responsibility.**

**Rationale:** Clear boundaries enable security and maintainability.

**Enforcement:**
- Kernel decides, does not execute
- Workers execute, do not decide
- Sensors observe, do not act
- Cockpit displays, does not bypass

**Violations:**
- Kernel making external calls
- Workers making decisions
- Sensors modifying state

---

### Rule 5: Evidence is Immutable

> **Once recorded, evidence MUST NOT be modified.**

**Rationale:** Integrity requires immutability.

**Enforcement:**
- Append-only ledger
- Hash chain verification
- No update or delete operations

**Violations:**
- Modifying existing entries
- Deleting entries
- Breaking hash chain

---

## 3. Operational Rules

### Rule 6: Policy Changes Require Review

> **All policy changes MUST be reviewed and approved.**

**Process:**
1. Propose policy change
2. Review by security team
3. Approve by architecture team
4. Test in staging
5. Deploy to production
6. Monitor for issues

**Documentation Required:**
- Change justification
- Risk assessment
- Rollback plan
- Approval signatures

---

### Rule 7: Evidence Must Be Preserved

> **Evidence MUST be preserved for the required retention period.**

**Retention Periods:**

| Evidence Type | Retention |
|---------------|-----------|
| Audit ledger | 7 years |
| Evidence bundles | 7 years |
| Policy snapshots | 3 years |
| Incident reports | 5 years |

**Storage Requirements:**
- Immutable storage
- Geographic redundancy
- Encryption at rest
- Access logging

---

### Rule 8: Incidents Require Post-Mortem

> **Every incident MUST have a documented post-mortem.**

**Post-Mortem Contents:**
1. Incident timeline
2. Root cause analysis
3. Impact assessment
4. Remediation actions
5. Prevention measures
6. Lessons learned

**Timeline:**
- Draft within 48 hours
- Final within 1 week
- Review within 2 weeks

---

### Rule 9: Changes Follow Process

> **All changes MUST follow the change management process.**

**Change Categories:**

| Category | Approval | Testing |
|----------|----------|---------|
| Emergency | 1 approver | Post-deploy |
| Standard | 2 approvers | Pre-deploy |
| Major | 3 approvers | Full cycle |

**Change Window:**
- Standard: Tuesday-Thursday, 10:00-16:00 UTC
- Emergency: Any time with approval
- Major: Scheduled maintenance window

---

### Rule 10: Monitoring is Required

> **All production kernels MUST be monitored.**

**Required Metrics:**

| Metric | Alert Threshold |
|--------|-----------------|
| Kernel state | != IDLE for > 5 min |
| Decision latency | p99 > 100ms |
| Deny rate | > 50% in 5 min |
| Error rate | > 1% in 5 min |
| Audit chain | Any verification failure |

**Required Dashboards:**
- Kernel health
- Decision distribution
- Latency percentiles
- Error breakdown

---

## 4. Security Rules

### Rule 11: Least Privilege

> **Actors and tools MUST have minimum necessary permissions.**

**Implementation:**
- Enumerate specific actors, not wildcards
- Enumerate specific tools, not wildcards
- Review permissions quarterly
- Remove unused permissions

**Anti-Patterns:**
- `allowed_actors: ["*"]`
- `allowed_tools: ["*"]`
- Permissions "just in case"

---

### Rule 12: Defense in Depth

> **Multiple layers of protection MUST be maintained.**

**Layers:**

| Layer | Control |
|-------|---------|
| Network | Firewall, TLS |
| Authentication | Token verification |
| Authorization | Jurisdiction policy |
| Audit | Hash-chained ledger |
| Monitoring | Anomaly detection |

**No single layer is sufficient.**

---

### Rule 13: Secrets Management

> **Secrets MUST be managed securely.**

**Requirements:**
- Secrets in vault, not code
- Rotation every 90 days
- Access logging
- Encryption in transit and at rest

**Prohibited:**
- Secrets in source code
- Secrets in logs
- Shared secrets
- Permanent secrets

---

### Rule 14: Vulnerability Response

> **Vulnerabilities MUST be addressed within SLA.**

**Response SLAs:**

| Severity | Response | Remediation |
|----------|----------|-------------|
| Critical | 4 hours | 24 hours |
| High | 24 hours | 7 days |
| Medium | 7 days | 30 days |
| Low | 30 days | 90 days |

**Process:**
1. Triage and classify
2. Assess impact
3. Develop fix
4. Test fix
5. Deploy fix
6. Verify remediation

---

## 5. Compliance Rules

### Rule 15: Audit Readiness

> **Systems MUST be audit-ready at all times.**

**Requirements:**
- Evidence exportable on demand
- Documentation current
- Access logs available
- Policies documented

**Audit Preparation:**
- Monthly self-assessment
- Quarterly internal audit
- Annual external audit

---

### Rule 16: Data Classification

> **All data MUST be classified and handled appropriately.**

**Classifications:**

| Level | Handling |
|-------|----------|
| Public | No restrictions |
| Internal | Access control |
| Confidential | Encryption, logging |
| Restricted | Encryption, MFA, audit |

**Audit Data Classification:** Confidential

---

### Rule 17: Access Control

> **Access MUST be controlled and logged.**

**Requirements:**
- Role-based access control
- Principle of least privilege
- Access reviews quarterly
- All access logged

**Access Levels:**

| Role | Permissions |
|------|-------------|
| Viewer | Read audit, view status |
| Operator | Viewer + restart, export |
| Admin | Operator + policy change |
| Security | Admin + halt, investigate |

---

## 6. Development Rules

### Rule 18: Code Review Required

> **All code changes MUST be reviewed.**

**Requirements:**
- At least 1 reviewer
- Security-sensitive: 2 reviewers
- Reviewer cannot be author
- All comments addressed

**Review Checklist:**
- [ ] Invariants preserved
- [ ] Tests included
- [ ] Documentation updated
- [ ] No security issues
- [ ] No performance regression

---

### Rule 19: Tests Must Pass

> **All tests MUST pass before merge.**

**Required Tests:**
- Unit tests (100% pass)
- Integration tests (100% pass)
- Security tests (100% pass)
- Smoke tests (100% pass)

**Coverage Requirements:**
- New code: 80% minimum
- Overall: 80% minimum

---

### Rule 20: Documentation Required

> **All features MUST be documented.**

**Documentation Types:**
- API documentation
- User guides
- Operational runbooks
- Architecture decisions

**Documentation Review:**
- Technical accuracy
- Completeness
- Clarity
- Currency

---

## 7. Rule Enforcement

### Enforcement Mechanisms

| Rule | Enforcement |
|------|-------------|
| Fail-closed | Code design |
| Audit everything | Code design |
| Halt is sacred | Code design |
| Separation | Architecture review |
| Evidence immutable | Code design |
| Policy review | Process |
| Evidence preservation | Automation |
| Post-mortem | Process |
| Change process | Tooling |
| Monitoring | Automation |

### Violation Handling

| Severity | Response |
|----------|----------|
| Minor | Coaching |
| Moderate | Formal warning |
| Major | Escalation |
| Critical | Immediate action |

### Exception Process

1. Document exception request
2. Risk assessment
3. Approval by security
4. Time-limited exception
5. Regular review
6. Remediation plan

---

## 8. Rule Updates

### Update Process

1. Propose rule change
2. Review by governance team
3. Comment period (2 weeks)
4. Approval by leadership
5. Communication to all
6. Effective date

### Version History

| Version | Date | Changes |
|---------|------|---------|
| 0.1.0 | Jan 2025 | Initial release |
