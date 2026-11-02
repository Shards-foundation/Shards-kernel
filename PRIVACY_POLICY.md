# Shards-Kernel — Privacy Policy

**Document status:** DRAFT — NOT ADOPTED; data-flow and publisher verification required before formal adoption  
**Draft date:** 2 November 2026  
**Scope:** the public Shards-Kernel open-source project, related project-operated communications, and the local software behaviour documented for v0.1.x

> **Important boundary:** Shards-Kernel is currently a distributable local Python library, **not** a central hosted Shards account, cloud telemetry service, trading venue or wallet custodian. Data stored by someone running the library is not automatically sent to, held by or controlled by the project publisher. If you deploy your own service using Shards-Kernel, your organisation must provide its own applicable privacy information.

## 1. Who is responsible?

The project [MIT licence](LICENSE) identifies **Shards Inc Ltd** as copyright holder; the repository is maintained in the [Shards-foundation GitHub organisation](https://github.com/Shards-foundation/Shards-kernel). The exact legal identity, company number and registered-office contact for privacy requests must be confirmed before this notice is adopted.

Existing public project contact: **shards-inc@engineer.com** (currently listed in [SECURITY.md](SECURITY.md) for security reports). This email must be confirmed as a monitored channel for privacy requests and complaints before the notice becomes effective.

For personal information the project team independently receives through support, reports or contributions, the legally responsible entity is generally the organisation determining the purpose and means of that processing (a **controller**). The entity running a Shards-Kernel deployment generally determines how its local agent records, audit logs and user data are handled. A software supplier is **not automatically** the controller or processor of data which never reaches it.

## 2. What information may be involved?

### Information you send to the project

Depending on how you engage with the maintainers, the project may receive:

- GitHub username, public profile, project contributions, issue and pull-request contents, comments and associated timestamps;
- name, email address, organisation or contact details voluntarily included in messages;
- support enquiries, feedback, diagnostic information, screenshots, excerpts of logs or security reports you choose to submit; and
- information needed to investigate abuse, vulnerabilities, rights requests, complaints or legally required disclosures.

Please minimise personal data in submissions and **never** send passwords, private keys, wallet seed phrases, live bearer tokens, sensitive client records or unredacted personal data through a public issue.

### Information in your own local deployment

The software may process or record data supplied by its operator or invoking agents, including agent or actor identifiers, request IDs, policy and permit metadata, timestamps, requested tool names and parameters, decisions, receipts, outcomes, hash-linked evidence and related diagnostics. Those fields **can** become personal data if they identify or relate to an individual.

The released reference includes in-memory evidence and optional operator-managed SQLite audit persistence. Logs and ledgers are handled within the environment configured by the operator. Operators set the purposes, authorised recipients, storage locations, retention and access protections for those records.

### Platform and network information

GitHub, PyPI, package installers, email providers and any optional external MCP or hosting services have their own systems, logs, cookies, authentication and privacy notices. The project team does not claim to control all those third-party processes.

On the reviewed v0.1.x reference architecture, there is no project-operated central service to which every installed kernel automatically sends its audit ledger or agent requests. This statement should be rechecked against the published distribution and any future telemetry, crash-reporting, hosting or remote integrations before formal adoption. Operator-added telemetry or third-party adapters may transmit information according to their own configuration.

## 3. Why project-maintainer personal data is used

Where the publisher acts as controller, the intended purposes and corresponding UK GDPR lawful bases are:

| Purpose | Examples | Intended lawful basis |
|---|---|---|
| Respond to contact and support requests | Replies, issue triage, requested technical assistance | Legitimate interests in responding and maintaining the project; contract where a separate actual support agreement applies |
| Develop and maintain the open-source project | Contributions, bug reports, release coordination | Legitimate interests in maintaining software and its community |
| Investigate security and abuse | Responsible disclosure, vulnerability triage, incident records | Legitimate interests in securing the project and users; legal obligation where applicable |
| Establish or defend legal rights | Disputes, required records, regulatory responses | Legitimate interests and/or legal obligation, as applicable |

The project is not presently represented as operating an advertising-profiling programme, paid user-account service or newsletter. If any such processing is introduced, its specific purposes, lawful basis and choices must be explained before collection. We do not treat someone's use of MIT-licensed software as automatic consent to marketing.

Where legitimate interests are relied on, the relevant interests are maintaining secure, usable open-source software, communicating with contributors and responding to legitimate project or security concerns. Those interests must be assessed against individuals' rights.

## 4. Data sharing and independent service providers

Project communications or contributions may be visible to other users if posted publicly on GitHub. Public repositories, forks, archives and cached copies may persist independently of an original post's removal.

Project maintainers may need to share relevant messages with authorised maintainers, infrastructure or communication providers, professional advisers, regulators or law enforcement where lawful and necessary. Do not assume these recipients have unrestricted access to privately held information.

GitHub and PyPI provide distribution and collaboration services under their own privacy notices. They are not equivalent to a self-hosted Shards-Kernel audit database. The project does not sell personal information supplied to it through support or security enquiries.

Before adopting this policy, the publisher must inventory the actual email, hosting, analytics, support and security vendors used for these communications, their roles and their cross-border transfer arrangements.

## 5. International transfers

Relevant platforms or service providers may process information outside the United Kingdom. Where the publisher itself makes a restricted international transfer of personal data subject to the UK GDPR, the responsible organisation must establish a valid transfer mechanism or other applicable legal basis, together with appropriate safeguards where required.

The country of hosting and transfer safeguards for each actual provider must be verified; this draft does **not** assert that a particular vendor, country or transfer mechanism has already been approved. Check the separate privacy notices of GitHub, PyPI and any provider you choose to use.

## 6. Retention and deletion

**Publisher-held correspondence:** The intended rule is to keep support messages, security records and complaints only for the period reasonably needed to resolve the matter, maintain accountability, address recurrence and satisfy applicable legal obligations. The operative retention schedule, review cadence, deletion method and any legal holds must be documented and verified **before adoption**; this draft does not invent a period already enforced in production.

**Public repository contributions:** Public issues, commits and discussions may remain part of repository history for as long as that history is maintained, subject to platform functionality, legal obligations and legitimate removal requests. Copies outside the publisher's control may not be removable.

**Local kernel data:** Retention of audit ledgers, receipts, agent identifiers, backup copies and optional integration logs is configured and enforced by the organisation deploying the software, not centrally by PyPI or automatically by the project publisher. The package does not, on its own, establish a GDPR-compliant retention schedule for deployments.

## 7. Security and data minimisation

Published reference features include signed permissions, explicit decisions and audit evidence, but no software library guarantees the security of an entire deployment. Maintainers should restrict access to contact and security correspondence and use appropriate technical and organisational controls.

Operators should use scoped identities and permits, protect signing keys and environment secrets, redact personal information from logs, encrypt storage and backups where appropriate, restrict evidence access, test deletion and recovery, and avoid embedding unnecessary personal information in immutable or hash-linked records. Do not assume that a hash makes an identifying record anonymous.

For vulnerability disclosure, follow [SECURITY.md](SECURITY.md) rather than posting exploit details or credentials publicly.

## 8. Your data protection rights

Where applicable, individuals may request access to their personal information, correction, erasure, restriction, portability, object to processing (including processing based on legitimate interests) or withdraw consent where consent is the legal basis. Rights can be subject to statutory conditions or exemptions.

Requests concerning information held by a separately deployed kernel should be directed to its **operator/controller**, because the project maintainers may not possess those records. Requests about GitHub or PyPI accounts or platform logs may also need to be directed to those providers.

For publisher-held information, use the confirmed privacy-contact channel. We may need reasonable identity verification before disclosing or changing personal information. **Subject access requests are separate from data-protection complaints:** under current UK guidance, an access request normally requires a response **within one month**, subject to permitted pauses, extensions and exceptions. Other rights requests have their own applicable requirements.

## 9. Complaints and regulator

You may raise a personal-data complaint with the responsible organisation. Under current UK data-protection complaint requirements, the organisation must offer a way to complain and **acknowledge receipt of the complaint within 30 days**, investigate appropriately, keep the complainant informed and provide an outcome without undue delay. **This 30-day complaint acknowledgement is a statutory obligation, not a substitute for the separate one-month subject-access response deadline in section 8.** See the [ICO complaint acknowledgement guidance](https://ico.org.uk/for-organisations/how-to-deal-with-data-protection-complaints/what-do-we-do-when-we-receive-a-complaint/).

You can also raise concerns with the UK **Information Commissioner's Office (ICO)** at https://ico.org.uk/make-a-complaint/ . You do not lose any statutory complaint or judicial rights by contacting the project first.

An operator based outside the UK may also be subject to local privacy rights and regulators; this policy does not replace the operator's own notice.

## 10. Children, automated decisions and high-impact uses

The Shards-Kernel package is developer-oriented and is not designed as a service directed at children. Do not place children's personal information or sensitive categories of data into prompts, tool parameters or immutable audit evidence without a valid and independently assessed purpose and safeguards.

The software can make deterministic **tool-execution decisions**, but that is not a claim that the publisher runs automated decisions about identifiable people. A downstream operator using the kernel to make consequential decisions about people must independently assess applicable automated decision-making and data protection requirements.

## 11. Cookies and changes to this notice

The local Python package does not itself provide the GitHub or PyPI website interface or set their website cookies. Those services' own notices and controls apply. A future Shards-operated website, analytics collector or hosted product would require a separate, fact-checked cookies and privacy assessment.

If the project's processing materially changes, this notice should be updated before the new processing starts, with appropriate notifications where required. The updated notice should state an adoption/effective date and document version.

## 12. Pre-adoption verification

**This is a review draft, not a representation that the publisher already operates every process described above.** Before it can be described as an effective privacy notice, verify and document:

1. the responsible legal entity's exact registered name, number, address and jurisdiction;
2. a monitored privacy contact and operational complaint-handling process;
3. actual personal-data categories, recipients, lawful bases, international transfers and implemented retention periods or criteria;
4. the deployed package's network and telemetry behaviour, any future Shards-operated website or hosted gateway and any cookies or analytics; and
5. the contractual controller/processor relationships for any real managed service, including any required data processing agreements.

The actual effective date must be assigned after adoption; the date above is the date this draft was prepared.

---

### Reference guidance (not a substitute for legal review)

- [ICO — What privacy information should we provide?](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/the-right-to-be-informed/what-privacy-information-should-we-provide/)
- [ICO — How to deal with data protection complaints](https://ico.org.uk/for-organisations/how-to-deal-with-data-protection-complaints/)
- [ICO — Controllers and processors](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/accountability-and-governance/guide-to-accountability-and-governance/contracts/)
