"""
Example: LangChain Agent with Shards-Kernel Governance

This example demonstrates how to integrate Shards-Kernel governance into a LangChain
agent workflow. It shows:

1. Wrapping dangerous tools with permit requirements
2. Allowing safe tools without permits
3. Full audit trail of agent decisions
4. Preventing unauthorized actions (the "47 emails" scenario)

The scenario: A customer support agent that can:
- Search knowledge base (permit bound to the query)
- Calculate refunds (permit bound to the amount)
- Send emails (dangerous, requires permit)
- Access database (dangerous, requires permit)

Without Shards-Kernel: The agent could send emails without authorization.
With Shards-Kernel: Every dangerous action requires a cryptographically signed permit.
"""

from typing import Dict, Any
import json

# Shards-Kernel imports
from shards_kernel.common.types import KernelConfig, VirtualClock
from shards_kernel.variants.strict_kernel import StrictKernel
from shards_kernel.integrations.langchain_adapter import LangChainAdapter
from shards_kernel.permits import PermitBuilder
from _permit import issue_permit

# Simulate LangChain (these would normally be from langchain imports)
# For demonstration, we implement minimal versions


class SimulatedLLM:
    """Simulated LLM that decides which tools to call."""

    def decide_action(
        self, user_query: str, available_tools: list[str]
    ) -> Dict[str, Any]:
        """Simple rule-based decision (in real LangChain, this would be LLM-powered)."""
        if "email" in user_query.lower():
            return {
                "tool": "send_email",
                "params": {
                    "to": "customer@example.com",
                    "subject": "Refund processed",
                    "body": "Your refund of $50 has been processed.",
                },
            }
        elif "database" in user_query.lower() or "data" in user_query.lower():
            return {
                "tool": "database_query",
                "params": {
                    "query": "SELECT * FROM customers WHERE email = 'customer@example.com'",
                },
            }
        elif "search" in user_query.lower():
            return {"tool": "search_kb", "params": {"query": user_query}}
        elif "refund" in user_query.lower() or "calculate" in user_query.lower():
            return {"tool": "calculate_refund", "params": {"amount": 50.0}}
        else:
            return {"tool": "search_kb", "params": {"query": user_query}}


# ============================================================================
# Tool Implementations (these would be real functions in production)
# ============================================================================


def search_knowledge_base(query: str) -> str:
    """Search internal knowledge base. Safe operation."""
    return f"KB Results for '{query}': Found 3 articles about refund policy."


def calculate_refund(amount: float, reason: str = "customer request") -> Dict[str, Any]:
    """Calculate refund amount. Safe operation, read-only."""
    tax_refund = amount * 0.1
    return {
        "refund_amount": amount,
        "tax_refund": tax_refund,
        "total": amount + tax_refund,
        "reason": reason,
    }


def send_email(to: str, subject: str, body: str) -> str:
    """
    Send email to customer. DANGEROUS operation.

    In production, this would actually send email via SMTP/SES/etc.
    This is the kind of tool that caused the "47 emails" incident.
    """
    print("\n🚨 EMAIL SENT:")
    print(f"   To: {to}")
    print(f"   Subject: {subject}")
    print(f"   Body: {body}\n")
    return f"Email sent to {to}"


def database_query(query: str) -> Dict[str, Any]:
    """
    Execute database query. DANGEROUS operation.

    In production, could leak PII or modify data.
    """
    print("\n🚨 DATABASE QUERY EXECUTED:")
    print(f"   Query: {query}\n")
    return {
        "rows": [
            {"id": 1, "email": "customer@example.com", "name": "John Doe"},
        ],
        "count": 1,
    }


# ============================================================================
# Main Example
# ============================================================================


def main():
    print("=" * 80)
    print("Shards-Kernel + LangChain Integration Example")
    print("=" * 80)
    print()
    print("Scenario: Customer support agent with 4 tools")
    print("  - search_kb (safe)")
    print("  - calculate_refund (safe)")
    print("  - send_email (DANGEROUS - requires permit)")
    print("  - database_query (DANGEROUS - requires permit)")
    print()
    print("=" * 80)
    print()

    # ========================================================================
    # Step 1: Set up kernel with governance
    # ========================================================================

    print("Step 1: Initialize Shards-Kernel governance")
    print("-" * 80)

    kernel = StrictKernel()
    config = KernelConfig(
        kernel_id="customer-support-agent",
        variant="strict",
        clock=VirtualClock(initial_ms=1000),
    )
    kernel.boot(config)

    # Set up cryptographic keyring for permit verification
    keyring = {"operator-key-2024": b"secret-hmac-key-32-bytes-long-1234"}
    kernel.set_keyring(keyring)

    print("✓ Kernel booted with keyring configured")
    print("  (Dangerous tools now require cryptographically signed permits)")
    print()

    # ========================================================================
    # Step 2: Create LangChain adapter and wrap tools
    # ========================================================================

    print("Step 2: Wrap tools with governance")
    print("-" * 80)

    adapter = LangChainAdapter(kernel, actor="support-agent-v1")

    # Wrap safe tools
    # Note: In strict mode with keyring configured, even safe tools require permits
    # This ensures complete governance and audit trail
    search_tool = adapter.wrap_tool(
        "search_kb",
        search_knowledge_base,
        description="Search knowledge base",
    )

    refund_tool = adapter.wrap_tool(
        "calculate_refund",
        calculate_refund,
        description="Calculate refund amount",
    )

    # Wrap dangerous tools (permit required)
    email_tool = adapter.wrap_tool(
        "send_email",
        send_email,
        description="Send email to customer",
        require_permit=True,  # DANGEROUS
    )

    adapter.wrap_tool(
        "database_query",
        database_query,
        description="Query customer database",
        require_permit=True,  # DANGEROUS
    )

    print("✓ Wrapped 4 tools:")
    print("  - search_kb (permit bound to the query)")
    print("  - calculate_refund (permit bound to the amount)")
    print("  - send_email (PERMIT REQUIRED)")
    print("  - database_query (PERMIT REQUIRED)")
    print()

    # ========================================================================
    # Step 3: Demonstrate ordinary operations with bound permits
    # ========================================================================

    print("Step 3: Execute ordinary operations with bound permits")
    print("-" * 80)

    # Every tool call carries a permit bound to the exact parameters.
    search_params = {"query": "refund policy"}
    search_permit = issue_permit(
        keyring,
        "operator-key-2024",
        subject="support-agent-v1",
        action="search_kb",
        params=search_params,
    )
    search_result = search_tool.run(permit_token=search_permit, **search_params)
    if not search_result.was_allowed:
        raise SystemExit(f"search_kb should have been allowed: {search_result.error}")
    print(f"✓ search_kb executed: {search_result.result}")

    refund_params = {"amount": 50.0, "reason": "defective product"}
    refund_permit = issue_permit(
        keyring,
        "operator-key-2024",
        subject="support-agent-v1",
        action="calculate_refund",
        params=refund_params,
    )
    refund_result = refund_tool.run(permit_token=refund_permit, **refund_params)
    if not refund_result.was_allowed:
        raise SystemExit(f"calculate_refund should have been allowed: {refund_result.error}")
    print(f"✓ calculate_refund executed: {refund_result.result}")
    print()

    # ========================================================================
    # Step 4: Demonstrate permit denial (dangerous operation without permit)
    # ========================================================================

    print("Step 4: Attempt dangerous operation WITHOUT permit")
    print("-" * 80)
    print("Attempting to send email without permit...")
    print()

    email_result = email_tool.run(
        permit_token=None,  # No permit provided
        to="customer@example.com",
        subject="Test",
        body="This should be blocked",
    )

    if not email_result.was_allowed:
        print("✓ CORRECTLY DENIED by kernel")
        print(f"  Reason: {email_result.error}")
        print(f"  Decision: {email_result.decision}")
        print()
        print("This is the '47 emails' prevention in action!")
        print("Without Shards-Kernel, the email would have been sent.")
        print()
    else:
        print("✗ ERROR: Should have been denied!")
        print()

    # ========================================================================
    # Step 5: Create permit and execute authorized operation
    # ========================================================================

    print("Step 5: Execute dangerous operation WITH valid permit")
    print("-" * 80)

    # Operator creates and signs a permit
    builder = PermitBuilder()
    email_permit = (
        builder.issuer("operator@company.com")
        .subject("support-agent-v1")  # Must match actor
        .jurisdiction("default")  # Must match kernel jurisdiction
        .action("send_email")  # Must match tool name
        .params(
            {
                "to": "customer@example.com",
                "subject": "Refund processed",
                "body": "Your refund of $50 has been processed.",
            }
        )  # Must match exact params
        .constraints({"max_time_ms": 5000})
        .max_executions(1)  # Single-use permit
        .valid_from_ms(0)
        .valid_until_ms(1000000)
        .evidence_hash("")
        .proposal_hash("proposal-123-refund-email")
        .build(keyring, "operator-key-2024")
    )

    print("✓ Permit created and signed:")
    print(f"  Permit ID: {email_permit.permit_id[:16]}...")
    print(f"  Issuer: {email_permit.issuer}")
    print(f"  Action: {email_permit.action}")
    print(f"  Max uses: {email_permit.max_executions}")
    print()

    # Execute with permit
    email_result2 = email_tool.run(
        permit_token=email_permit,
        to="customer@example.com",
        subject="Refund processed",
        body="Your refund of $50 has been processed.",
    )

    if email_result2.was_allowed:
        print("✓ ALLOWED by kernel (permit verified)")
        print(f"  Result: {email_result2.result}")
        print(f"  Audit hash: {email_result2.audit_hash[:16]}...")
        print()
    else:
        print("✗ ERROR: Should have been allowed!")
        print()

    # ========================================================================
    # Step 6: Demonstrate replay protection
    # ========================================================================

    print("Step 6: Attempt to replay single-use permit")
    print("-" * 80)
    print("Attempting to reuse the same permit...")
    print()

    email_result3 = email_tool.run(
        permit_token=email_permit,  # Same permit, same parameters, second use
        to="customer@example.com",
        subject="Refund processed",
        body="Your refund of $50 has been processed.",
    )

    if not email_result3.was_allowed:
        print("✓ CORRECTLY DENIED (replay detected)")
        print(f"  Reason: {email_result3.error}")
        print()
        print("Nonce registry prevented permit reuse!")
        print("Single-use permit can only authorize one execution.")
        print()
    else:
        print("✗ ERROR: Replay should have been denied!")
        print()

    # ========================================================================
    # Step 7: Export audit trail
    # ========================================================================

    print("Step 7: Export audit trail")
    print("-" * 80)

    evidence = adapter.export_evidence()

    print("✓ Audit trail exported:")
    print(f"  Kernel: {evidence['kernel_id']}")
    print(f"  Total entries: {evidence['entry_count']}")
    print(f"  Root hash: {evidence['root_hash'][:16]}...")
    print()

    print("Audit entries:")
    for i, entry in enumerate(evidence["entries"], 1):
        decision_str = entry["decision"]
        tool = entry.get("tool_name", "N/A")
        permit_status = entry.get("permit_verification", "N/A")

        print(f"  {i}. [{decision_str}] {tool}")
        print(f"     Permit: {permit_status}")
        if entry.get("permit_denial_reasons"):
            print(f"     Denial: {', '.join(entry['permit_denial_reasons'])}")
        print(f"     Hash: {entry['entry_hash'][:16]}...")
        print()

    # ========================================================================
    # Step 8: Summary
    # ========================================================================

    print("=" * 80)
    print("SUMMARY: What Shards-Kernel Prevented")
    print("=" * 80)
    print()
    print("WITHOUT Shards-Kernel:")
    print("  ✗ Agent could send emails without authorization")
    print("  ✗ Agent could query database without oversight")
    print("  ✗ No audit trail of tool usage")
    print("  ✗ No replay protection")
    print()
    print("WITH Shards-Kernel:")
    print("  ✓ Dangerous tools require cryptographically signed permits")
    print("  ✓ Replay protection prevents permit reuse")
    print("  ✓ Complete immutable audit trail (hash-chained)")
    print("  ✓ Fail-closed enforcement (deny by default)")
    print()
    print("This is governance that works DURING execution, not as an afterthought.")
    print()
    print("=" * 80)

    # Export evidence to file
    with open("/tmp/agent_audit.json", "w") as f:
        json.dump(evidence, f, indent=2)

    print()
    print("Full audit trail saved to: /tmp/agent_audit.json")
    print()


if __name__ == "__main__":
    main()
