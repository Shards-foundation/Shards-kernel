# Security Policy

## Security commitment

Shards-Kernel is an open-source project focused on governance, authorization, and auditable execution boundaries for AI systems. Security is central to the purpose of this repository.

We take security reports seriously and aim to handle them responsibly, respectfully, and with appropriate care.

---

## Reporting a vulnerability

**Please do not open a public GitHub issue for sensitive security vulnerabilities.**

Instead, report vulnerabilities privately to:

**Email:** `shards-inc@engineer.com`

Include, where possible:

- affected repository, component, file, or interface
- description of the issue
- impact and expected risk
- reproduction steps or proof of concept
- environment and version details
- any suggested mitigation, if known

If you are unsure whether something is a security issue, report it anyway and explain your concern clearly.

---

## What to expect

When you send a report, we aim to:

1. acknowledge receipt
2. review the report for validity and impact
3. assess severity and affected scope
4. determine an appropriate remediation path
5. communicate follow-up where practical

Response times can vary depending on complexity, maintainer availability, and the quality of the report.

---

## Supported security scope

Security reports are most useful when they concern the behaviour, guarantees, or implementation of this repository’s actual supported surfaces.

Examples may include:

- authorization bypass
- permit validation failures
- replay protection defects
- audit-integrity weaknesses
- trust-boundary violations
- unsafe defaults
- authentication or transport weaknesses
- denial-of-service conditions with realistic impact
- documented behaviour that is materially false in a security-relevant way

---

## Out of scope

The following are generally **out of scope** unless they demonstrate a real security impact in this repository:

- purely theoretical issues without a practical exploit path
- reports against third-party services not controlled by this project
- best-practice suggestions without a concrete vulnerability
- social engineering tests against maintainers
- automated scanner output without triage or explanation
- self-hosted deployment mistakes outside the documented guarantees of the project
- issues that depend on unsupported, experimental, or explicitly out-of-scope configurations unless they expose a wider defect

Out-of-scope does **not** mean unimportant; it means it may not be treated as a repository vulnerability.

---

## Safe disclosure expectations

We ask reporters to:

- avoid public disclosure until maintainers have had a reasonable opportunity to assess and address the issue
- avoid accessing, modifying, or destroying data beyond what is necessary to demonstrate the problem
- avoid service disruption, privacy violations, or destructive testing
- avoid credential theft, persistence, or lateral movement
- provide enough detail for reproduction without escalating impact unnecessarily

Please act in good faith.

---

## No public issue first

For sensitive findings:

- **Do not** post exploit details in public issues
- **Do not** attach secrets, tokens, private keys, or personal data in public
- **Do not** assume a missing immediate response authorises broader testing

If a report is non-sensitive and you are explicitly asked to open a public issue, you may do so later.

---

## Severity and remediation

We review reports based on factors such as:

- exploitability
- impact
- scope
- trust-boundary implications
- whether the issue contradicts documented guarantees
- whether exploitation requires unsupported or unrealistic conditions

Fix timelines depend on severity and project constraints. Not every report will result in an immediate public advisory, patch release, or backport.

---

## Security boundaries

This project documents important limitations. A valid security review should distinguish between:

- what the repository **claims to guarantee**
- what it **does not claim to provide**
- what is **planned but not yet verified**
- what depends on external deployment, operator policy, or surrounding infrastructure

Reports are strongest when they show a real mismatch between documented guarantees and observed behaviour.

---

## Coordinated disclosure

Where appropriate, we prefer coordinated disclosure and may publish a fix, advisory, changelog note, or other security communication once remediation is ready.

We may credit reporters for valid findings unless anonymity is requested.

---

## Supported versions

Unless explicitly stated otherwise, security fixes are typically assessed against the current maintained branch and currently supported release line.

Older versions may not receive backported fixes.

---

## Contact

For private security reporting:

**Email:** `shards-inc@engineer.com`

If your report includes highly sensitive material, say so clearly in the subject line.
