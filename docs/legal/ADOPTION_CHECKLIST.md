# Legal documentation — pre-adoption review checklist

**Applies to:** [TERMS_OF_SERVICE.md](https://github.com/Shards-foundation/Shards-kernel/blob/main/TERMS_OF_SERVICE.md) and [PRIVACY_POLICY.md](https://github.com/Shards-foundation/Shards-kernel/blob/main/PRIVACY_POLICY.md)  
**Status:** draft documents only; NOT confirmed as adopted or legally complete.  
**Review date:** 2 November 2026

These documents describe the **Shards-Kernel v0.1.x open-source Python library**. The project is not represented as a hosted gateway, wallet service, public agent marketplace or trading service. If those products launch, **do not silently reuse** this library-focused privacy notice or terms.

## Required release-owner checks

- [ ] Confirm the contracting entity's legally registered name, registered-office address, company number, and the actual owner of the project/IP. The MIT [LICENSE](https://github.com/Shards-foundation/Shards-kernel/blob/main/LICENSE) currently names *Shards Inc Ltd*. Do **not** assume the GitHub organisation *Shards-foundation* is another legal entity, or confuse the entity with similarly named registered companies.
- [ ] Confirm that **shards-inc@engineer.com** is authorised and monitored for legal/privacy requests. It is currently listed as a security contact; approval for another purpose is not yet verified.
- [ ] Confirm who is controller for contributor/support data. Document real inboxes, GitHub communications, relevant cloud providers, access roles and the data-sharing / international-transfer map.
- [ ] Approve and operationalise a defensible retention schedule (for support, vulnerabilities, complaints, public contributions and any local hosted records). Identify record owners and deletion/backup procedures; do not state invented existing time limits.
- [ ] Implement a UK data-protection **complaint** process: contact channel, statutory acknowledgement within 30 days, investigation, updates and outcome. Independently implement the **subject-access request** process with its normally one-month response period (subject to permitted exceptions or extensions) and incident-response procedures.
- [ ] Independently inspect the **published PyPI wheel and source distribution** for network access, telemetry and logs before making categorical 'no data collected' statements. Recheck when adopting optional adapters or services.
- [ ] Confirm that operators receive local-only processing guidance, that any hosted controller–processor relationship uses an appropriate agreement and that operator-generated audit records are not misrepresented as publisher-collected data.
- [ ] Review cross-border transfers, third-party platform terms, analytics, site cookies, age restrictions and requirements for each actual website or managed product.
- [ ] Validate liability, consumer rights and governing-law language for the actual audience with a suitably qualified UK solicitor. In particular, preserve the existing MIT-licensed rights.
- [ ] Select the **effective date**, approve the final policies, and only then remove draft markings and reference them as adopted documents on GitHub or a live service.

## Evidence checked at drafting

- [MIT licence](https://github.com/Shards-foundation/Shards-kernel/blob/main/LICENSE) names Shards Inc Ltd.
- [Security policy](https://github.com/Shards-foundation/Shards-kernel/blob/main/SECURITY.md) supplies the existing security contact.
- [Agent quickstart](../AGENT_QUICKSTART.md) and [loopback operator guidance](../operations/LOOPBACK_OPERATOR_SERVICE.md) document local-only, not-yet-production-certified operation.
- [Two-agent identity guidance](../operations/TWO_AGENT_IDENTITY.md) documents actor identities and local SQLite audit records.
- [Public PyPI release](https://pypi.org/project/shards-kernel/0.1.0/) is available with wheel and source distribution.

## Regulatory references used

- [ICO privacy information checklist](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/the-right-to-be-informed/checklists/)
- [ICO — How to handle data protection complaints](https://ico.org.uk/for-organisations/how-to-deal-with-data-protection-complaints/)
- [ICO — The Data (Use and Access) Act 2025](https://ico.org.uk/about-the-ico/what-we-do/legislation-we-cover/data-use-and-access-act-2025/the-data-use-and-access-act-2025-duaa-summary-of-the-changes/)
- [UK Consumer Rights Act 2015, digital content liability restrictions](https://www.legislation.gov.uk/ukpga/2015/15/section/47)
- [ICO — Controller/processor contract requirements](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/accountability-and-governance/guide-to-accountability-and-governance/contracts/)

**Gate:** Do not describe these documents as adopted legal terms or a completed GDPR compliance review until the above items have been evidenced and approved.
