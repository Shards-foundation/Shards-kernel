"""
Example: AutoGPT Autonomous Agent with KERNELS Governance & Kill-Switch

This example demonstrates KERNELS governance for AutoGPT autonomous agents,
including autonomous loop monitoring and kill-switch functionality.

AutoGPT Context:
- One of the first autonomous AI agent frameworks
- Runs in continuous loops until goal completion
- Can execute shell commands, write files, browse web
- No built-in safety limits in original implementation

The Problem:
    Without governance, AutoGPT can:
    - Run indefinitely consuming resources
    - Execute dangerous commands without authorization
    - Create infinite loops or recursive operations
    - Cause system damage through unchecked file/shell access

The Solution:
    KERNELS provides:
    - Autonomous loop monitoring with configurable limits
    - Kill-switch that halts unsafe execution
    - Per-command risk scoring
    - Permit-based authorization for dangerous operations
    - Complete audit trail of autonomous actions

Scenario:
    AutoGPT agent tasked with "research and publish article on AI governance"

    Without KERNELS: Agent could:
    - Execute arbitrary shell commands
    - Write files anywhere in filesystem
    - Make unlimited web requests
    - Run for hours consuming resources

    With KERNELS: Agent requires:
    - Permits for file writes
    - Permits for shell execution
    - Runtime limits (kill-switch after 1 hour)
    - Iteration limits (kill-switch after 100 steps)
    - Human oversight for high-risk operations

Usage:
    python examples/10_autogpt_autonomous_governance.py
"""

import json
import os

# KERNELS imports
from kernels.common.types import KernelConfig, VirtualClock
from kernels.variants.strict_kernel import StrictKernel
from kernels.integrations.autogpt_adapter import AutoGPTAdapter
from kernels.permits import PermitBuilder
from _permit import issue_permit


# ============================================================================
# Simulated AutoGPT Command Implementations
# ============================================================================


def execute_shell(command: str) -> str:
    """Execute shell command (CRITICAL RISK)."""
    print("\n🚨 SHELL EXECUTION:")
    print(f"   Command: {command}")
    print()
    # In production: subprocess.run(command, shell=True, capture_output=True)
    return f"Simulated execution of: {command}"


def execute_python(code: str) -> str:
    """Execute Python code (HIGH RISK)."""
    print("\n🚨 PYTHON EXECUTION:")
    print(f"   Code: {code[:50]}...")
    print()
    # In production: exec(code)
    return "Simulated execution of Python code"


def write_file(path: str, content: str) -> str:
    """Write file to filesystem (HIGH RISK)."""
    print("\n🚨 FILE WRITE:")
    print(f"   Path: {path}")
    print(f"   Size: {len(content)} bytes")
    print()
    return f"File written to {path}"


def read_file(path: str) -> str:
    """Read file from filesystem (LOW RISK)."""
    print("\n📄 FILE READ:")
    print(f"   Path: {path}")
    print()
    return f"Contents of {path}: [simulated file data]"


def browse_website(url: str) -> str:
    """Browse website (LOW RISK)."""
    print("\n🌐 WEB BROWSE:")
    print(f"   URL: {url}")
    print()
    return f"Content from {url}: [simulated web data]"


def send_email(to: str, subject: str, body: str) -> str:
    """Send email (MEDIUM-HIGH RISK)."""
    print("\n📧 EMAIL SEND:")
    print(f"   To: {to}")
    print(f"   Subject: {subject}")
    print()
    return f"Email sent to {to}"


def make_api_call(endpoint: str, method: str = "GET", data: str = "") -> str:
    """Make API call (MEDIUM RISK)."""
    print("\n🔌 API CALL:")
    print(f"   Endpoint: {endpoint}")
    print(f"   Method: {method}")
    print()
    return f"API response from {endpoint}"


def delete_file(path: str) -> str:
    """Delete file (HIGH RISK)."""
    print("\n🚨 FILE DELETE:")
    print(f"   Path: {path}")
    print()
    return f"File deleted: {path}"


# ============================================================================
# Autonomous Agent Governance Scenario
# ============================================================================


def main():
    print("=" * 80)
    print("KERNELS + AutoGPT Autonomous Agent Governance")
    print("=" * 80)
    print()
    print("Scenario: AutoGPT agent with autonomous loop monitoring")
    print()
    print("Task: Research and publish article on AI governance")
    print()
    print("Commands available:")
    print("  - execute_shell (CRITICAL RISK - 1.0)")
    print("  - execute_python (HIGH RISK - 0.9)")
    print("  - write_file (HIGH RISK - 0.8)")
    print("  - delete_file (HIGH RISK - 0.9)")
    print("  - send_email (MEDIUM-HIGH RISK - 0.7)")
    print("  - make_api_call (MEDIUM RISK - 0.5)")
    print("  - browse_website (LOW RISK - 0.3)")
    print("  - read_file (LOW RISK - 0.2)")
    print()
    print("Safety Limits (Kill-Switch):")
    print("  - Max iterations: 100")
    print("  - Max runtime: 1 hour")
    print("  - Max denials: 10")
    print()
    print("=" * 80)
    print()

    # ========================================================================
    # Step 1: Set up KERNELS kernel
    # ========================================================================

    print("Step 1: Initialize KERNELS governance with kill-switch")
    print("-" * 80)

    kernel = StrictKernel()
    config = KernelConfig(
        kernel_id="autogpt-agent",
        variant="strict",
        clock=VirtualClock(initial_ms=1000),
    )
    kernel.boot(config)

    # Set up cryptographic keyring
    keyring = {"autogpt-operator-2026": b"secret-hmac-key-32-bytes-autogpt"}
    kernel.set_keyring(keyring)

    print("✓ Kernel booted with strict governance")
    print()

    # ========================================================================
    # Step 2: Create AutoGPT adapter with monitoring
    # ========================================================================

    print("Step 2: Create AutoGPT adapter with autonomous loop monitoring")
    print("-" * 80)

    adapter = AutoGPTAdapter(
        kernel=kernel,
        actor="autogpt-agent",
        auto_register=True,
        enable_monitoring=True,
        max_autonomous_iterations=100,
        max_runtime_seconds=3600,  # 1 hour
    )

    print("✓ Adapter created with autonomous loop monitoring:")
    print("  - Max iterations: 100")
    print("  - Max runtime: 3600 seconds (1 hour)")
    print("  - Max denials before halt: 10")
    print()

    # ========================================================================
    # Step 3: Wrap AutoGPT commands with governance
    # ========================================================================

    print("Step 3: Wrap AutoGPT commands with risk-based governance")
    print("-" * 80)

    # High/Critical risk commands
    governed_shell = adapter.wrap_command(
        "execute_shell",
        execute_shell,
        "Execute shell command",
        risk_score=1.0,
    )

    adapter.wrap_command(
        "execute_python",
        execute_python,
        "Execute Python code",
        risk_score=0.9,
    )

    governed_write = adapter.wrap_command(
        "write_file",
        write_file,
        "Write file to filesystem",
        risk_score=0.8,
    )

    adapter.wrap_command(
        "delete_file",
        delete_file,
        "Delete file",
        risk_score=0.9,
    )

    # Medium risk commands
    adapter.wrap_command(
        "send_email",
        send_email,
        "Send email",
        risk_score=0.7,
    )

    adapter.wrap_command(
        "make_api_call",
        make_api_call,
        "Make API call",
        risk_score=0.5,
    )

    # Low risk commands
    governed_browse = adapter.wrap_command(
        "browse_website",
        browse_website,
        "Browse website",
        risk_score=0.3,
    )

    governed_read = adapter.wrap_command(
        "read_file",
        read_file,
        "Read file",
        risk_score=0.2,
    )

    print("✓ Commands wrapped with risk scores:")
    print("  - execute_shell: 1.0 (CRITICAL)")
    print("  - execute_python: 0.9 (HIGH)")
    print("  - write_file: 0.8 (HIGH)")
    print("  - delete_file: 0.9 (HIGH)")
    print("  - send_email: 0.7 (MEDIUM-HIGH)")
    print("  - make_api_call: 0.5 (MEDIUM)")
    print("  - browse_website: 0.3 (LOW)")
    print("  - read_file: 0.2 (LOW)")
    print()

    # ========================================================================
    # Step 4: Execute low-risk operations with permits bound to the call
    # ========================================================================

    print("Step 4: Execute LOW RISK operations (permits bound to the call)")
    print("-" * 80)

    # These should succeed because they're low risk
    print("Agent browses web for research...")
    browse_params = {"url": "https://example.com/ai-governance"}
    result = governed_browse(
        permit_token=issue_permit(
            keyring,
            "autogpt-operator-2026",
            subject="autogpt-agent",
            action="browse_website",
            params=browse_params,
            issuer="operator@company.com",
        ),
        **browse_params,
    )
    print("✓ ALLOWED (risk: 0.3)")
    print(f"  Result: {result[:50]}...")
    print()

    print("Agent reads existing research file...")
    read_params = {"path": "/data/research/notes.txt"}
    result = governed_read(
        permit_token=issue_permit(
            keyring,
            "autogpt-operator-2026",
            subject="autogpt-agent",
            action="read_file",
            params=read_params,
            issuer="operator@company.com",
        ),
        **read_params,
    )
    print("✓ ALLOWED (risk: 0.2)")
    print(f"  Result: {result[:50]}...")
    print()

    # ========================================================================
    # Step 5: Attempt HIGH RISK operation WITHOUT permit (should fail)
    # ========================================================================

    print("Step 5: Attempt HIGH RISK shell execution WITHOUT permit")
    print("-" * 80)
    print("Agent attempts to execute shell command without authorization...")
    print()

    try:
        result = governed_shell(command="rm -rf /tmp/cache")
        print(f"✗ ERROR: Should have been denied! Result: {result}")
    except PermissionError as e:
        print("✓ CORRECTLY DENIED by KERNELS")
        print(f"  Error: {e}")
        print()
        print("Kill-switch prevents unauthorized shell execution!")
        print()

    # ========================================================================
    # Step 6: Execute WITH valid permit
    # ========================================================================

    print("Step 6: Execute file write WITH valid permit")
    print("-" * 80)

    # Operator creates permit for file write
    write_permit = (
        PermitBuilder()
        .issuer("operator@company.com")
        .subject("autogpt-agent")
        .jurisdiction("default")
        .action("write_file")
        .params(
            {
                "path": "/var/www/blog/ai-governance-article.md",
                "content": "# AI Governance Best Practices\n\n[article content]",
            }
        )
        .max_executions(1)
        .valid_from_ms(0)
        .valid_until_ms(10000000)
        .proposal_hash("proposal-write-file")
        .build(keyring, "autogpt-operator-2026")
    )

    print("✓ Permit issued for file write:")
    print(f"  Permit ID: {write_permit.permit_id[:16]}...")
    print("  Path: /var/www/blog/ai-governance-article.md")
    print()

    result = governed_write(
        path="/var/www/blog/ai-governance-article.md",
        content="# AI Governance Best Practices\n\n[article content]",
        permit_token=write_permit,
    )

    print("✓ ALLOWED by KERNELS")
    print(f"  Result: {result}")
    print()

    # ========================================================================
    # Step 7: Demonstrate autonomous loop monitoring
    # ========================================================================

    print("Step 7: Autonomous loop monitoring statistics")
    print("-" * 80)

    print("Current autonomous loop stats:")
    if adapter.monitor:
        stats = adapter.monitor.stats
        print(f"  - Total iterations: {stats.total_iterations}")
        print(f"  - Commands executed: {stats.commands_executed}")
        print(f"  - Commands denied: {stats.commands_denied}")
        print(f"  - High-risk actions: {stats.high_risk_actions}")
        print(f"  - Runtime: {stats.last_action_time - stats.start_time:.2f} seconds")
        print()

    # ========================================================================
    # Step 8: Simulate autonomous loop approaching limits
    # ========================================================================

    print("Step 8: Simulate autonomous loop approaching iteration limit")
    print("-" * 80)

    # Manually set iteration count to near limit for demonstration
    if adapter.monitor:
        adapter.monitor.stats.total_iterations = 98

        print("Simulating 98 autonomous iterations...")
        print(f"Current iterations: {adapter.monitor.stats.total_iterations}/100")
        print()

        # Execute 2 more commands (should succeed). Each call still needs a
        # permit bound to the exact parameters, including low-risk tools.
        print("Executing command 99...")
        try:
            final_browse = {"url": "https://example.com/final-research"}
            result = governed_browse(
                permit_token=issue_permit(
                    keyring,
                    "autogpt-operator-2026",
                    subject="autogpt-agent",
                    action="browse_website",
                    params=final_browse,
                    issuer="operator@company.com",
                ),
                **final_browse,
            )
            print("✓ Command 99 executed successfully")
            print()
        except RuntimeError as e:
            print(f"✗ Unexpected error: {e}")
            print()

        print("Executing command 100...")
        try:
            final_read = {"path": "/data/final-notes.txt"}
            result = governed_read(
                permit_token=issue_permit(
                    keyring,
                    "autogpt-operator-2026",
                    subject="autogpt-agent",
                    action="read_file",
                    params=final_read,
                    issuer="operator@company.com",
                ),
                **final_read,
            )
            print("✓ Command 100 executed successfully")
            print()
        except RuntimeError as e:
            print(f"✗ Unexpected error: {e}")
            print()

        # Try command 101 (should trigger kill-switch)
        print("Attempting command 101 (should trigger kill-switch)...")
        try:
            result = governed_browse(url="https://example.com/post-limit")
            print("✗ ERROR: Kill-switch should have activated!")
        except RuntimeError as e:
            print("✓ KILL-SWITCH ACTIVATED")
            print(f"  Reason: {e}")
            print()
            print("Autonomous loop halted after reaching iteration limit!")
            print("This prevents runaway agents from consuming unlimited resources.")
            print()

    # ========================================================================
    # Step 9: Export audit trail with autonomous stats
    # ========================================================================

    print("Step 9: Export audit trail with autonomous loop statistics")
    print("-" * 80)

    evidence = adapter.export_evidence()

    print("✓ Audit trail exported:")
    print(f"  Kernel: {evidence['kernel_id']}")
    print(f"  Total entries: {evidence['entry_count']}")
    print(f"  Root hash: {evidence['root_hash'][:16]}...")
    print()

    if "autonomous_loop_stats" in evidence:
        loop_stats = evidence["autonomous_loop_stats"]
        print("Autonomous loop statistics:")
        print(f"  - Total iterations: {loop_stats['total_iterations']}")
        print(f"  - Commands executed: {loop_stats['commands_executed']}")
        print(f"  - Commands denied: {loop_stats['commands_denied']}")
        print(f"  - High-risk actions: {loop_stats['high_risk_actions']}")
        print(f"  - Runtime: {loop_stats['runtime_seconds']:.2f} seconds")
        print(f"  - Halted: {loop_stats['halted']}")
        print(f"  - Halt reason: {loop_stats['halt_reason']}")
        print()

    # ========================================================================
    # Summary
    # ========================================================================

    print("=" * 80)
    print("SUMMARY: AutoGPT Autonomous Agent Governance with KERNELS")
    print("=" * 80)
    print()
    print("What KERNELS prevents in autonomous agents:")
    print()
    print("WITHOUT KERNELS:")
    print("  ✗ Agent can run indefinitely consuming resources")
    print("  ✗ Agent can execute dangerous commands without authorization")
    print("  ✗ No safety limits or kill-switch")
    print("  ✗ Agent can create infinite loops")
    print("  ✗ No audit trail of autonomous actions")
    print()
    print("WITH KERNELS:")
    print("  ✓ Autonomous loop monitoring with configurable limits")
    print("  ✓ Kill-switch activates on unsafe behavior")
    print("  ✓ Risk-based command authorization")
    print("  ✓ Dangerous operations require cryptographic permits")
    print("  ✓ Complete audit trail with autonomous statistics")
    print()
    print("Kill-Switch Triggers:")
    print("  - Maximum iterations exceeded (prevents runaway loops)")
    print("  - Maximum runtime exceeded (prevents resource exhaustion)")
    print("  - Maximum denials exceeded (detects repeated failures)")
    print("  - Manual halt via operator command")
    print()
    print("Risk Scoring (0.0-1.0):")
    print("  - 0.0-0.3: LOW RISK (allowed without permits)")
    print("  - 0.4-0.6: MEDIUM RISK (requires permits)")
    print("  - 0.7-0.9: HIGH RISK (requires permits + auditing)")
    print("  - 1.0: CRITICAL RISK (requires permits + human oversight)")
    print()
    print("Integration usage:")
    print("  from kernels.integrations import AutoGPTAdapter")
    print()
    print("  adapter = AutoGPTAdapter(kernel, enable_monitoring=True)")
    print()
    print("  @adapter.governed_command('cmd_name', risk_score=0.8)")
    print("  def my_command(arg: str) -> str:")
    print("      return execute(arg)")
    print()
    print("  # Execute with permit")
    print("  result = my_command(arg='value', permit_token=permit)")
    print()
    print("=" * 80)

    # Export evidence
    os.makedirs("/tmp", exist_ok=True)
    with open("/tmp/autogpt_autonomous_audit.json", "w") as f:
        json.dump(evidence, f, indent=2)

    print()
    print("Full audit trail saved to: /tmp/autogpt_autonomous_audit.json")
    print()


if __name__ == "__main__":
    main()
