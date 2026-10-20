"""
Example: CrewAI Multi-Agent System with KERNELS Governance

This example demonstrates KERNELS governance for CrewAI multi-agent orchestration,
addressing the critical security challenge of agent-to-agent privilege escalation.

CrewAI Context:
- Multi-agent framework for collaborative AI systems
- Agents can delegate tasks to specialist agents
- Each agent has specific roles and tools
- Agents share context and collaborate on complex tasks

The Problem:
    Without governance, malicious or compromised agents can:
    - Escalate privileges by delegating to more powerful agents
    - Execute dangerous operations without authorization
    - Chain delegations to bypass security controls
    - Access resources outside their intended scope

The Solution:
    KERNELS provides:
    - Tool-level governance for all agent actions
    - Agent identity and role attestation
    - Inter-agent permission matrix
    - Delegation chain tracking
    - Complete audit trail of multi-agent interactions

Scenario:
    Research & Publishing Crew with 3 agents:
    1. Researcher: Can search web, read files (LOW RISK)
    2. Analyst: Can analyze data, create reports (MEDIUM RISK)
    3. Publisher: Can write files, send emails (HIGH RISK)

    Governance rules:
    - Researcher CANNOT write files or send emails
    - Analyst CANNOT send emails
    - Publisher CAN write and email, but only with permits
    - Delegation matrix prevents privilege escalation

Usage:
    python examples/09_crewai_multiagent_governance.py
"""

import json
import os

# KERNELS imports
from kernels.common.types import KernelConfig, VirtualClock
from kernels.variants.strict_kernel import StrictKernel
from kernels.integrations.crewai_adapter import CrewAIAdapter
from kernels.permits import PermitBuilder
from _permit import issue_permit


# ============================================================================
# Simulated Tool Implementations
# ============================================================================


def web_search(query: str) -> str:
    """Search the web (LOW RISK - read-only)."""
    print("\n🔍 WEB SEARCH:")
    print(f"   Query: {query}")
    print()
    return f"Search results for: {query}\n- Result 1\n- Result 2\n- Result 3"


def read_file(path: str) -> str:
    """Read file from filesystem (LOW RISK - read-only)."""
    print("\n📄 FILE READ:")
    print(f"   Path: {path}")
    print()
    return f"Contents of {path}: [simulated file data]"


def analyze_data(data: str, analysis_type: str) -> str:
    """Analyze data (MEDIUM RISK - computation only)."""
    print("\n📊 DATA ANALYSIS:")
    print(f"   Type: {analysis_type}")
    print(f"   Data length: {len(data)} chars")
    print()
    return f"Analysis results: {analysis_type} completed successfully"


def create_report(title: str, content: str) -> str:
    """Create report (MEDIUM RISK - internal only)."""
    print("\n📝 REPORT CREATION:")
    print(f"   Title: {title}")
    print(f"   Length: {len(content)} chars")
    print()
    return f"Report '{title}' created (internal)"


def write_file(path: str, content: str) -> str:
    """Write file to filesystem (HIGH RISK - persistent state change)."""
    print("\n🚨 FILE WRITE:")
    print(f"   Path: {path}")
    print(f"   Size: {len(content)} bytes")
    print()
    return f"File written to {path}"


def send_email(to: str, subject: str, body: str) -> str:
    """Send email (HIGH RISK - external communication)."""
    print("\n🚨 EMAIL SEND:")
    print(f"   To: {to}")
    print(f"   Subject: {subject}")
    print()
    return f"Email sent to {to}"


def publish_blog(title: str, content: str, publish: bool = False) -> str:
    """Publish blog post (CRITICAL RISK - public visibility)."""
    print("\n🚨 BLOG PUBLISH:")
    print(f"   Title: {title}")
    print(f"   Publish: {publish}")
    print()
    if publish:
        return f"Blog post '{title}' PUBLISHED PUBLICLY"
    else:
        return f"Blog post '{title}' saved as draft"


# ============================================================================
# Multi-Agent Governance Scenario
# ============================================================================


def main():
    print("=" * 80)
    print("KERNELS + CrewAI Multi-Agent Governance")
    print("=" * 80)
    print()
    print("Scenario: Research & Publishing Crew")
    print()
    print("Agents:")
    print("  1. Researcher: Web search, file reading (LOW RISK)")
    print("  2. Analyst: Data analysis, report creation (MEDIUM RISK)")
    print("  3. Publisher: File writing, email, blog publishing (HIGH RISK)")
    print()
    print("Governance Rules:")
    print("  - Researcher CANNOT write files or send emails")
    print("  - Analyst CANNOT send emails or publish blogs")
    print("  - Publisher CAN write/email/publish, but ONLY with permits")
    print("  - Delegation matrix prevents privilege escalation")
    print()
    print("=" * 80)
    print()

    # ========================================================================
    # Step 1: Set up KERNELS kernel
    # ========================================================================

    print("Step 1: Initialize KERNELS governance")
    print("-" * 80)

    kernel = StrictKernel()
    config = KernelConfig(
        kernel_id="crewai-research-crew",
        variant="strict",
        clock=VirtualClock(initial_ms=1000),
    )
    kernel.boot(config)

    # Set up cryptographic keyring
    keyring = {"crew-operator-2026": b"secret-hmac-key-32-bytes-crew-gov"}
    kernel.set_keyring(keyring)

    print("✓ Kernel booted with strict governance")
    print()

    # ========================================================================
    # Step 2: Create CrewAI adapter with multi-agent support
    # ========================================================================

    print("Step 2: Create CrewAI adapter")
    print("-" * 80)

    adapter = CrewAIAdapter(
        kernel=kernel,
        actor="crew-orchestrator",
        auto_register=True,
    )

    # Create agent identities
    researcher_id = adapter.create_agent_identity("Researcher")
    analyst_id = adapter.create_agent_identity("Analyst")
    publisher_id = adapter.create_agent_identity("Publisher")

    print("✓ Agent identities created:")
    print(f"  - Researcher: {researcher_id}")
    print(f"  - Analyst: {analyst_id}")
    print(f"  - Publisher: {publisher_id}")
    print()

    # ========================================================================
    # Step 3: Define delegation matrix (privilege escalation prevention)
    # ========================================================================

    print("Step 3: Define inter-agent delegation matrix")
    print("-" * 80)

    delegation_matrix = {
        researcher_id: [analyst_id],  # Researcher can delegate to Analyst only
        analyst_id: [publisher_id],  # Analyst can delegate to Publisher only
        publisher_id: [],  # Publisher cannot delegate (terminal agent)
    }

    print("✓ Delegation matrix configured:")
    print(f"  - {researcher_id} → [{analyst_id}]")
    print(f"  - {analyst_id} → [{publisher_id}]")
    print(f"  - {publisher_id} → [] (no delegation)")
    print()

    # ========================================================================
    # Step 4: Wrap tools with agent-specific governance
    # ========================================================================

    print("Step 4: Wrap tools with role-based governance")
    print("-" * 80)

    # Researcher tools (LOW RISK)
    researcher_search = adapter.wrap_tool(
        name="web_search",
        func=web_search,
        description="Search the web",
        actor=researcher_id,
        require_permit=True,
    )

    researcher_read = adapter.wrap_tool(
        name="read_file",
        func=read_file,
        description="Read file from filesystem",
        actor=researcher_id,
        require_permit=True,
    )

    # Analyst tools (MEDIUM RISK)
    analyst_analyze = adapter.wrap_tool(
        name="analyze_data",
        func=analyze_data,
        description="Analyze data",
        actor=analyst_id,
        require_permit=True,
    )

    analyst_report = adapter.wrap_tool(
        name="create_report",
        func=create_report,
        description="Create internal report",
        actor=analyst_id,
        require_permit=True,
    )

    # Publisher tools (HIGH RISK - REQUIRE PERMITS)
    publisher_write = adapter.wrap_tool(
        name="write_file",
        func=write_file,
        description="Write file to filesystem",
        actor=publisher_id,
        require_permit=True,  # HIGH RISK
    )

    publisher_email = adapter.wrap_tool(
        name="send_email",
        func=send_email,
        description="Send email",
        actor=publisher_id,
        require_permit=True,  # HIGH RISK
    )

    publisher_blog = adapter.wrap_tool(
        name="publish_blog",
        func=publish_blog,
        description="Publish blog post publicly",
        actor=publisher_id,
        require_permit=True,  # CRITICAL RISK
    )

    print("✓ Tools wrapped with governance:")
    print("  Researcher: web_search [NO PERMIT], read_file [NO PERMIT]")
    print("  Analyst: analyze_data [NO PERMIT], create_report [NO PERMIT]")
    print(
        "  Publisher: write_file [PERMIT REQUIRED], send_email [PERMIT REQUIRED], publish_blog [PERMIT REQUIRED]"
    )
    print()

    # ========================================================================
    # Step 5: Demonstrate ordinary operations with bound permits
    # ========================================================================

    print("Step 5: Execute safe operations (LOW/MEDIUM RISK)")
    print("-" * 80)

    # Researcher searches web
    print("Researcher searches web...")
    search_params = {"query": "AI governance best practices"}
    result = researcher_search._run(
        permit_token=issue_permit(
            keyring,
            "crew-operator-2026",
            subject=researcher_id,
            action="web_search",
            params=search_params,
            issuer="operator@company.com",
        ),
        **search_params,
    )
    print("✓ ALLOWED (permit bound to this call)")
    print(f"  Result: {result[:50]}...")
    print()

    # Researcher reads file
    print("Researcher reads file...")
    read_params = {"path": "/data/research/papers.txt"}
    result = researcher_read._run(
        permit_token=issue_permit(
            keyring,
            "crew-operator-2026",
            subject=researcher_id,
            action="read_file",
            params=read_params,
            issuer="operator@company.com",
        ),
        **read_params,
    )
    print("✓ ALLOWED (permit bound to this call)")
    print(f"  Result: {result[:50]}...")
    print()

    # Analyst analyzes data
    print("Analyst analyzes data...")
    analyze_params = {
        "data": "[research data from web search]",
        "analysis_type": "sentiment analysis",
    }
    result = analyst_analyze._run(
        permit_token=issue_permit(
            keyring,
            "crew-operator-2026",
            subject=analyst_id,
            action="analyze_data",
            params=analyze_params,
            issuer="operator@company.com",
        ),
        **analyze_params,
    )
    print("✓ ALLOWED (permit bound to this call)")
    print(f"  Result: {result}")
    print()

    # Analyst creates report
    print("Analyst creates internal report...")
    report_params = {"title": "AI Governance Analysis", "content": "[analysis results]"}
    result = analyst_report._run(
        permit_token=issue_permit(
            keyring,
            "crew-operator-2026",
            subject=analyst_id,
            action="create_report",
            params=report_params,
            issuer="operator@company.com",
        ),
        **report_params,
    )
    print("✓ ALLOWED (permit bound to this call)")
    print(f"  Result: {result}")
    print()

    # ========================================================================
    # Step 6: Attempt dangerous operation WITHOUT permit (should fail)
    # ========================================================================

    print("Step 6: Attempt file write WITHOUT permit (should be denied)")
    print("-" * 80)
    print("Publisher attempts to write file without authorization...")
    print()

    try:
        result = publisher_write._run(
            path="/var/www/blog/post.html", content="<html>Unauthorized content</html>"
        )
        print(f"✗ ERROR: Should have been denied! Result: {result}")
    except PermissionError as e:
        print("✓ CORRECTLY DENIED by KERNELS")
        print(f"  Error: {e}")
        print()
        print("This prevents unauthorized file system modifications!")
        print()

    # ========================================================================
    # Step 7: Execute WITH valid permit
    # ========================================================================

    print("Step 7: Execute file write WITH valid permit")
    print("-" * 80)

    # Operator creates permit for file write
    write_permit = (
        PermitBuilder()
        .issuer("operator@company.com")
        .subject(publisher_id)
        .jurisdiction("default")
        .action("write_file")
        .params(
            {
                "path": "/var/www/blog/approved-post.html",
                "content": "<html>Approved AI governance article</html>",
            }
        )
        .max_executions(1)
        .valid_from_ms(0)
        .valid_until_ms(10000000)
        .proposal_hash("proposal-crew-action")
        .build(keyring, "crew-operator-2026")
    )

    print("✓ Permit issued:")
    print(f"  Permit ID: {write_permit.permit_id[:16]}...")
    print(f"  Action: {write_permit.action}")
    print(f"  Subject: {write_permit.subject}")
    print()

    result = publisher_write._run(
        path="/var/www/blog/approved-post.html",
        content="<html>Approved AI governance article</html>",
        permit_token=write_permit,
    )

    print("✓ ALLOWED by KERNELS")
    print(f"  Result: {result}")
    print()

    # ========================================================================
    # Step 8: Demonstrate privilege escalation prevention
    # ========================================================================

    print("Step 8: Prevent privilege escalation via delegation")
    print("-" * 80)

    # Researcher tries to delegate directly to Publisher (bypassing Analyst)
    print("Checking: Can Researcher delegate directly to Publisher?")
    can_delegate = adapter.validate_delegation(
        from_agent=researcher_id,
        to_agent=publisher_id,
        task_type="file_write",
        delegation_matrix=delegation_matrix,
    )

    if can_delegate:
        print("✗ ERROR: Delegation should be blocked!")
    else:
        print("✓ DELEGATION BLOCKED")
        print(f"  {researcher_id} cannot delegate to {publisher_id}")
        print(f"  Allowed targets: {delegation_matrix[researcher_id]}")
        print()
        print("This prevents privilege escalation attacks!")
        print()

    # Valid delegation path
    print("Checking: Can Researcher delegate to Analyst?")
    can_delegate = adapter.validate_delegation(
        from_agent=researcher_id,
        to_agent=analyst_id,
        task_type="data_analysis",
        delegation_matrix=delegation_matrix,
    )

    if can_delegate:
        print("✓ DELEGATION ALLOWED")
        print(f"  {researcher_id} can delegate to {analyst_id}")
        print("  Valid delegation chain maintained")
        print()
    else:
        print("✗ ERROR: This delegation should be allowed!")
        print()

    # ========================================================================
    # Step 9: Multi-permit scenario (email + blog publish)
    # ========================================================================

    print("Step 9: Multi-operation workflow with permits")
    print("-" * 80)

    # Create permit for email
    email_permit = (
        PermitBuilder()
        .issuer("operator@company.com")
        .subject(publisher_id)
        .jurisdiction("default")
        .action("send_email")
        .params(
            {
                "to": "subscribers@company.com",
                "subject": "New AI Governance Article Published",
                "body": "Check out our latest article on AI governance...",
            }
        )
        .max_executions(1)
        .valid_from_ms(0)
        .valid_until_ms(10000000)
        .proposal_hash("proposal-crew-action")
        .build(keyring, "crew-operator-2026")
    )

    # Create permit for blog publish
    blog_permit = (
        PermitBuilder()
        .issuer("operator@company.com")
        .subject(publisher_id)
        .jurisdiction("default")
        .action("publish_blog")
        .params(
            {
                "title": "AI Governance Best Practices",
                "content": "<html>Comprehensive guide...</html>",
                "publish": True,
            }
        )
        .max_executions(1)
        .valid_from_ms(0)
        .valid_until_ms(10000000)
        .proposal_hash("proposal-crew-action")
        .build(keyring, "crew-operator-2026")
    )

    print("✓ Two permits issued:")
    print("  1. send_email → subscribers@company.com")
    print("  2. publish_blog → 'AI Governance Best Practices'")
    print()

    # Execute with permits
    print("Executing multi-operation workflow...")
    print()

    result1 = publisher_email._run(
        to="subscribers@company.com",
        subject="New AI Governance Article Published",
        body="Check out our latest article on AI governance...",
        permit_token=email_permit,
    )

    result2 = publisher_blog._run(
        title="AI Governance Best Practices",
        content="<html>Comprehensive guide...</html>",
        publish=True,
        permit_token=blog_permit,
    )

    print(f"✓ Email sent: {result1}")
    print(f"✓ Blog published: {result2}")
    print()

    # ========================================================================
    # Step 10: Export audit trail
    # ========================================================================

    print("Step 10: Export multi-agent audit trail")
    print("-" * 80)

    evidence = adapter.export_evidence()

    print("✓ Audit trail exported:")
    print(f"  Kernel: {evidence['kernel_id']}")
    print(f"  Total entries: {evidence['entry_count']}")
    print(f"  Root hash: {evidence['root_hash'][:16]}...")
    print()

    print("Audit summary by agent:")
    agent_actions = {}
    for entry in evidence["entries"]:
        actor = entry.get("actor", "unknown")
        if actor not in agent_actions:
            agent_actions[actor] = {"allow": 0, "deny": 0}

        if entry["decision"] == "ALLOW":
            agent_actions[actor]["allow"] += 1
        elif entry["decision"] == "DENY":
            agent_actions[actor]["deny"] += 1

    for actor, stats in agent_actions.items():
        print(f"  {actor}: {stats['allow']} ALLOW, {stats['deny']} DENY")

    print()

    # ========================================================================
    # Summary
    # ========================================================================

    print("=" * 80)
    print("SUMMARY: CrewAI Multi-Agent Governance with KERNELS")
    print("=" * 80)
    print()
    print("What KERNELS prevents in multi-agent systems:")
    print()
    print("WITHOUT KERNELS:")
    print("  ✗ Any agent can execute any dangerous operation")
    print("  ✗ Agents can delegate to bypass security controls")
    print("  ✗ Privilege escalation via delegation chains")
    print("  ✗ No audit trail of inter-agent interactions")
    print("  ✗ No role-based access control")
    print()
    print("WITH KERNELS:")
    print("  ✓ Dangerous operations require cryptographic permits")
    print("  ✓ Delegation matrix prevents privilege escalation")
    print("  ✓ Agent identity and role attestation")
    print("  ✓ Complete audit trail of all agent actions")
    print("  ✓ Tool-level governance per agent role")
    print()
    print("Multi-Agent Security Model:")
    print("  - Each agent has unique cryptographic identity")
    print("  - Tools are wrapped with agent-specific governance")
    print("  - Delegation requires explicit authorization")
    print("  - Audit trail tracks delegation chains")
    print("  - Permits are bound to specific agent identities")
    print()
    print("Integration usage:")
    print("  from kernels.integrations import CrewAIAdapter")
    print()
    print("  adapter = CrewAIAdapter(kernel)")
    print("  governed_tool = adapter.wrap_tool('tool_name', func, actor='agent-id')")
    print()
    print("  # Validate delegation")
    print("  adapter.validate_delegation(from_agent, to_agent, task, matrix)")
    print()
    print("=" * 80)

    # Export evidence
    os.makedirs("/tmp", exist_ok=True)
    with open("/tmp/crewai_multiagent_audit.json", "w") as f:
        json.dump(evidence, f, indent=2)

    print()
    print("Full audit trail saved to: /tmp/crewai_multiagent_audit.json")
    print()


if __name__ == "__main__":
    main()
