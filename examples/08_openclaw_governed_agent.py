"""
Example: OpenClaw/Moltbook Agent with Shards-Kernel Governance

This example demonstrates how to integrate Shards-Kernel governance into OpenClaw
(formerly Clawdbot/Moltbook), addressing security concerns raised by researchers.

OpenClaw Context (Jan 2026):
- 60,000+ GitHub stars in 72 hours
- Autonomous AI assistant with broad system permissions
- Security researchers concerned about unchecked access to:
  * Email accounts and calendars
  * Shell command execution
  * Filesystem operations
  * Messaging platforms

The Problem:
    "OpenClaw's design has drawn scrutiny from cybersecurity researchers due to
    the broad permissions it requires to function effectively, as the software
    can access email accounts, calendars, messaging platforms, and other sensitive
    services."
    — CNBC, Feb 2026

The Solution:
    Shards-Kernel provides cryptographic permit-based governance for OpenClaw tools,
    ensuring dangerous operations require explicit authorization with complete
    audit trails.

Integration Approach:
    - OpenClaw tools (AgentSkills) are JavaScript/TypeScript functions
    - Shards-Kernel GenericAdapter wraps Python implementations of these tools
    - Each dangerous operation requires a cryptographically signed permit
    - All executions are logged in an immutable audit chain

Usage:
    # Without Shards-Kernel: OpenClaw can execute any tool without oversight
    agent.run("Delete all my emails from last month")  # Executes immediately!

    # With Shards-Kernel: Dangerous tools require permits
    agent.run("Delete all my emails from last month")  # DENIED: MISSING_PERMIT
"""

import json
import os

# Shards-Kernel imports
from shards_kernel.common.types import KernelConfig, VirtualClock
from shards_kernel.variants.strict_kernel import StrictKernel
from shards_kernel.integrations.generic_adapter import GenericAdapter
from shards_kernel.permits import PermitBuilder


# ============================================================================
# OpenClaw AgentSkill Implementations (Python versions)
# ============================================================================
# In real OpenClaw, these would be TypeScript/JavaScript skills.
# Here we show Python equivalents to demonstrate governance.


def shell_execute(command: str) -> str:
    """
    Execute shell command (OpenClaw: system.run skill).

    DANGEROUS: Can execute arbitrary commands with user's permissions.

    Without governance: "rm -rf /" could be executed by mistake.
    With Shards-Kernel: Requires cryptographically signed permit.
    """
    print("\n🚨 SHELL EXECUTION:")
    print(f"   Command: {command}")
    print()

    # In production, this would use subprocess
    # return subprocess.run(command, shell=True, capture_output=True).stdout.decode()
    return f"Simulated execution of: {command}"


def email_delete(mailbox: str, filter_query: str) -> str:
    """
    Delete emails matching filter (OpenClaw: email skill).

    DANGEROUS: Can permanently delete user's emails.

    Without governance: Agent could delete important emails.
    With Shards-Kernel: Requires permit with exact filter parameters.
    """
    print("\n🚨 EMAIL DELETION:")
    print(f"   Mailbox: {mailbox}")
    print(f"   Filter: {filter_query}")
    print()

    return f"Deleted emails from {mailbox} matching: {filter_query}"


def calendar_create_event(title: str, start_time: str, attendees: str) -> str:
    """
    Create calendar event (OpenClaw: calendar skill).

    MODERATE RISK: Can spam calendars or create unwanted meetings.

    Without governance: Agent could schedule meetings without confirmation.
    With Shards-Kernel: Requires permit for each event creation.
    """
    print("\n📅 CALENDAR EVENT:")
    print(f"   Title: {title}")
    print(f"   Start: {start_time}")
    print(f"   Attendees: {attendees}")
    print()

    return f"Created event '{title}' at {start_time} with {attendees}"


def web_browse(url: str, action: str = "read") -> str:
    """
    Browse web pages (OpenClaw: browser.* skills).

    LOW RISK for reading, HIGH RISK for actions.

    Without governance: Could submit forms, make purchases, etc.
    With Shards-Kernel: Write actions require permits.
    """
    if action in ["submit", "click", "purchase"]:
        print("\n🚨 WEB ACTION:")
        print(f"   URL: {url}")
        print(f"   Action: {action}")
        print()

    return f"Browsed {url} with action: {action}"


def slack_send_message(channel: str, message: str, mention_all: bool = False) -> str:
    """
    Send Slack message (OpenClaw: Slack integration).

    DANGEROUS with @channel/@here mentions.

    Without governance: Could spam team channels.
    With Shards-Kernel: Mentions require permits.
    """
    if mention_all:
        print("\n🚨 SLACK @CHANNEL:")
        print(f"   Channel: {channel}")
        print(f"   Message: {message}")
        print()

    return f"Sent to #{channel}: {message}"


# ============================================================================
# Main Example
# ============================================================================


def main():
    print("=" * 80)
    print("Shards-Kernel + OpenClaw Integration Example")
    print("=" * 80)
    print()
    print("Scenario: Securing OpenClaw AgentSkills with Shards-Kernel governance")
    print()
    print("OpenClaw tools (simulated in Python):")
    print("  - shell_execute (DANGEROUS)")
    print("  - email_delete (DANGEROUS)")
    print("  - calendar_create_event (MODERATE RISK)")
    print("  - web_browse (LOW RISK for read, HIGH RISK for actions)")
    print("  - slack_send_message (DANGEROUS with @channel)")
    print()
    print("=" * 80)
    print()

    # ========================================================================
    # Step 1: Set up kernel with governance
    # ========================================================================

    print("Step 1: Initialize Shards-Kernel governance for OpenClaw")
    print("-" * 80)

    kernel = StrictKernel()
    config = KernelConfig(
        kernel_id="openclaw-agent",
        variant="strict",
        clock=VirtualClock(initial_ms=1000),
    )
    kernel.boot(config)

    # Set up cryptographic keyring
    keyring = {"openclaw-operator-2026": b"secret-hmac-key-32-bytes-openclaw"}
    kernel.set_keyring(keyring)

    print("✓ Kernel booted with keyring configured")
    print("  (All dangerous OpenClaw tools now require permits)")
    print()

    # ========================================================================
    # Step 2: Wrap OpenClaw AgentSkills with GenericAdapter
    # ========================================================================

    print("Step 2: Wrap OpenClaw AgentSkills with governance")
    print("-" * 80)

    adapter = GenericAdapter(kernel, actor="openclaw-assistant")

    # Wrap each tool using decorator pattern
    governed_shell = adapter.create_wrapper(
        name="shell_execute",
        func=shell_execute,
        description="Execute shell command (DANGEROUS)",
        raise_on_deny=True,
    )

    governed_email_delete = adapter.create_wrapper(
        name="email_delete",
        func=email_delete,
        description="Delete emails (DANGEROUS)",
        raise_on_deny=True,
    )

    governed_calendar = adapter.create_wrapper(
        name="calendar_create_event",
        func=calendar_create_event,
        description="Create calendar event",
        raise_on_deny=True,
    )

    governed_web_action = adapter.create_wrapper(
        name="web_browse",
        func=web_browse,
        description="Browse web with actions",
        raise_on_deny=True,
    )

    adapter.create_wrapper(
        name="slack_send_message",
        func=slack_send_message,
        description="Send Slack message",
        raise_on_deny=True,
    )

    print("✓ Wrapped 5 OpenClaw AgentSkills:")
    print("  - shell_execute [PERMIT REQUIRED]")
    print("  - email_delete [PERMIT REQUIRED]")
    print("  - calendar_create_event [PERMIT REQUIRED]")
    print("  - web_browse [PERMIT REQUIRED]")
    print("  - slack_send_message [PERMIT REQUIRED]")
    print()

    # ========================================================================
    # Step 3: Attempt dangerous operation WITHOUT permit
    # ========================================================================

    print("Step 3: Attempt shell execution WITHOUT permit")
    print("-" * 80)
    print("Simulating: Agent wants to run 'rm -rf /tmp/cache'")
    print()

    try:
        result = governed_shell(command="rm -rf /tmp/cache")
        print(f"✗ ERROR: Should have been denied! Result: {result}")
    except Exception as e:
        print("✓ CORRECTLY DENIED by kernel")
        print(f"  Error: {e}")
        print()
        print("This prevents the '60k GitHub stars' honeypot attack!")
        print("Without Shards-Kernel, a malicious prompt could execute arbitrary commands.")
        print()

    # ========================================================================
    # Step 4: Attempt email deletion WITHOUT permit
    # ========================================================================

    print("Step 4: Attempt email deletion WITHOUT permit")
    print("-" * 80)
    print("Simulating: Agent wants to delete work emails")
    print()

    try:
        result = governed_email_delete(
            mailbox="inbox",
            filter_query="from:boss@company.com",
        )
        print(f"✗ ERROR: Should have been denied! Result: {result}")
    except Exception as e:
        print("✓ CORRECTLY DENIED by kernel")
        print(f"  Error: {e}")
        print()
        print("Prevents accidental data loss from AI misinterpretation!")
        print()

    # ========================================================================
    # Step 5: Execute WITH valid permit
    # ========================================================================

    print("Step 5: Execute calendar event WITH valid permit")
    print("-" * 80)

    # Operator creates and signs a permit
    calendar_permit = (
        PermitBuilder()
        .issuer("operator@company.com")
        .subject("openclaw-assistant")
        .jurisdiction("default")
        .action("calendar_create_event")
        .params(
            {
                "title": "Team standup",
                "start_time": "2026-02-10 09:00",
                "attendees": "team@company.com",
            }
        )
        .constraints({})
        .max_executions(1)
        .valid_from_ms(0)
        .valid_until_ms(10000000)
        .evidence_hash("")
        .proposal_hash("proposal-calendar-standup")
        .build(keyring, "openclaw-operator-2026")
    )

    print("✓ Permit created and signed:")
    print(f"  Permit ID: {calendar_permit.permit_id[:16]}...")
    print(f"  Action: {calendar_permit.action}")
    print(f"  Event: {calendar_permit.params['title']}")
    print()

    # Execute with permit
    result = governed_calendar(
        title="Team standup",
        start_time="2026-02-10 09:00",
        attendees="team@company.com",
        permit_token=calendar_permit,
    )

    print("✓ ALLOWED by kernel")
    print(f"  Result: {result}")
    print()

    # ========================================================================
    # Step 6: Execute web action WITH permit
    # ========================================================================

    print("Step 6: Execute web action WITH valid permit")
    print("-" * 80)

    web_permit = (
        PermitBuilder()
        .issuer("operator@company.com")
        .subject("openclaw-assistant")
        .jurisdiction("default")
        .action("web_browse")
        .params(
            {
                "url": "https://company.com/api/submit",
                "action": "submit",
            }
        )
        .constraints({})
        .max_executions(1)
        .valid_from_ms(0)
        .valid_until_ms(10000000)
        .evidence_hash("")
        .proposal_hash("proposal-web-submit")
        .build(keyring, "openclaw-operator-2026")
    )

    print("✓ Web action permit created")
    print(f"  URL: {web_permit.params['url']}")
    print(f"  Action: {web_permit.params['action']}")
    print()

    result = governed_web_action(
        url="https://company.com/api/submit",
        action="submit",
        permit_token=web_permit,
    )

    print("✓ ALLOWED by kernel")
    print(f"  Result: {result}")
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

    print("Audit summary:")
    for i, entry in enumerate(evidence["entries"], 1):
        decision = entry["decision"]
        tool = entry.get("tool_name", "N/A")
        permit_status = entry.get("permit_verification", "N/A")

        print(f"  {i}. [{decision}] {tool} (Permit: {permit_status})")

    print()

    # ========================================================================
    # Step 8: Summary
    # ========================================================================

    print("=" * 80)
    print("SUMMARY: OpenClaw + Shards-Kernel Integration")
    print("=" * 80)
    print()
    print("What Shards-Kernel prevents in OpenClaw:")
    print()
    print("WITHOUT Shards-Kernel (current OpenClaw security concerns):")
    print("  ✗ Agent can execute shell commands without authorization")
    print("  ✗ Agent can delete emails without confirmation")
    print("  ✗ Agent can create calendar events for entire team")
    print("  ✗ Agent can submit web forms / make purchases")
    print("  ✗ Agent can send @channel Slack messages")
    print("  ✗ No audit trail of what agent did")
    print("  ✗ No replay protection")
    print()
    print("WITH Shards-Kernel:")
    print("  ✓ Dangerous operations require cryptographically signed permits")
    print("  ✓ Replay protection prevents permit reuse")
    print("  ✓ Complete immutable audit trail (hash-chained)")
    print("  ✓ Fail-closed enforcement (deny by default)")
    print("  ✓ Addresses security researcher concerns")
    print()
    print("Integration usage:")
    print("  from shards_kernel.integrations import GenericAdapter")
    print()
    print("  adapter = GenericAdapter(kernel, actor='openclaw-assistant')")
    print("  governed_tool = adapter.create_wrapper('skill_name', skill_fn)")
    print()
    print("  # Tool now requires permit")
    print("  result = governed_tool(**params, permit_token=permit)")
    print()
    print("=" * 80)

    # Export evidence
    os.makedirs("/tmp", exist_ok=True)
    with open("/tmp/openclaw_audit.json", "w") as f:
        json.dump(evidence, f, indent=2)

    print()
    print("Full audit trail saved to: /tmp/openclaw_audit.json")
    print()


if __name__ == "__main__":
    main()
