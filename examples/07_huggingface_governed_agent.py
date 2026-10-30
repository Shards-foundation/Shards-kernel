"""
Example: Hugging Face Agent with Shards-Kernel Governance

This example demonstrates how to integrate Shards-Kernel governance into Hugging Face
Transformers agents.

Note: This is a standalone example that works without installing transformers.
For real usage with Hugging Face, you would:
    pip install transformers
    from transformers import Agent

The scenario: Research agent that can:
- Search web (safe)
- Read documents (safe)
- Execute code (dangerous - requires permit)
- Access files (dangerous - requires permit)

Without Shards-Kernel: Agent could execute arbitrary code without authorization.
With Shards-Kernel: Code execution requires cryptographically signed permit.
"""

import json

# Shards-Kernel imports
from shards_kernel.common.types import KernelConfig, VirtualClock
from shards_kernel.variants.strict_kernel import StrictKernel
from shards_kernel.integrations.huggingface_adapter import (
    HuggingFaceAdapter,
)
from shards_kernel.permits import PermitBuilder


# ============================================================================
# Tool Implementations
# ============================================================================


def web_search(query: str) -> str:
    """Search the web. Safe operation."""
    return f"Web results for '{query}': Found 5 articles about AI governance."


def read_document(file_path: str) -> str:
    """Read a document. Safe operation."""
    return f"Document content from {file_path}: Lorem ipsum..."


def execute_python_code(code: str) -> str:
    """
    Execute Python code. DANGEROUS operation.

    In production, this would use exec() or subprocess.
    This is exactly the kind of tool that needs governance.
    """
    print("\n🚨 EXECUTING CODE:")
    print(f"   {code}")
    print()
    return f"Code executed: {code}"


def access_filesystem(path: str, operation: str) -> str:
    """
    Access filesystem. DANGEROUS operation.

    Could read sensitive files, modify system files, etc.
    """
    print("\n🚨 FILESYSTEM ACCESS:")
    print(f"   Path: {path}")
    print(f"   Operation: {operation}")
    print()
    return f"Filesystem operation '{operation}' on {path}"


# ============================================================================
# Main Example
# ============================================================================


def main():
    print("=" * 80)
    print("Shards-Kernel + Hugging Face Integration Example")
    print("=" * 80)
    print()
    print("Scenario: Research agent with 4 tools")
    print("  - web_search (safe)")
    print("  - read_document (safe)")
    print("  - execute_python_code (DANGEROUS - requires permit)")
    print("  - access_filesystem (DANGEROUS - requires permit)")
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
        kernel_id="hf-research-agent",
        variant="strict",
        clock=VirtualClock(initial_ms=1000),
    )
    kernel.boot(config)

    # Set up cryptographic keyring
    keyring = {"research-key-2024": b"secret-hmac-key-32-bytes-long-5678"}
    kernel.set_keyring(keyring)

    print("✓ Kernel booted with keyring configured")
    print("  (Dangerous tools now require cryptographically signed permits)")
    print()

    # ========================================================================
    # Step 2: Create Hugging Face adapter and wrap tools
    # ========================================================================

    print("Step 2: Wrap tools for Hugging Face compatibility")
    print("-" * 80)

    adapter = HuggingFaceAdapter(kernel, actor="research-agent-v1")

    # Wrap tools with proper HF schemas
    adapter.wrap_tool(
        name="web_search",
        func=web_search,
        description="Search the web for information",
        inputs={"query": "string"},
        output_type="string",
    )

    adapter.wrap_tool(
        name="read_document",
        func=read_document,
        description="Read a document from path",
        inputs={"file_path": "string"},
        output_type="string",
    )

    code_tool = adapter.wrap_tool(
        name="execute_python_code",
        func=execute_python_code,
        description="Execute Python code (DANGEROUS)",
        inputs={"code": "text"},
        output_type="string",
    )

    filesystem_tool = adapter.wrap_tool(
        name="access_filesystem",
        func=access_filesystem,
        description="Access filesystem (DANGEROUS)",
        inputs={"path": "string", "operation": "string"},
        output_type="string",
    )

    print("✓ Wrapped 4 tools for Hugging Face:")
    print("  - web_search (inputs: {query: string})")
    print("  - read_document (inputs: {file_path: string})")
    print("  - execute_python_code (inputs: {code: text}) [PERMIT REQUIRED]")
    print("  - access_filesystem (inputs: {path, operation}) [PERMIT REQUIRED]")
    print()

    # In real usage with transformers:
    # from transformers import Agent
    # agent = Agent(tools=[search_tool, document_tool, code_tool, filesystem_tool])

    # ========================================================================
    # Step 3: Attempt dangerous operation WITHOUT permit
    # ========================================================================

    print("Step 3: Attempt code execution WITHOUT permit")
    print("-" * 80)
    print("Attempting to execute code without authorization...")
    print()

    try:
        result = code_tool(code="import os; os.system('rm -rf /')")
        print(f"✗ ERROR: Should have been denied! Result: {result}")
    except Exception as e:
        print("✓ CORRECTLY DENIED by kernel")
        print(f"  Error: {e}")
        print()
        print("This prevents unauthorized code execution!")
        print()

    # ========================================================================
    # Step 4: Create permit and execute authorized operation
    # ========================================================================

    print("Step 4: Execute code WITH valid permit")
    print("-" * 80)

    # Operator creates and signs a permit
    builder = PermitBuilder()
    code_permit = (
        builder.issuer("operator@research-lab.com")
        .subject("research-agent-v1")
        .jurisdiction("default")
        .action("execute_python_code")
        .params({"code": "print('Hello from governed agent')"})
        .constraints({"max_time_ms": 5000})
        .max_executions(1)
        .valid_from_ms(0)
        .valid_until_ms(1000000)
        .evidence_hash("")
        .proposal_hash("proposal-456-safe-code")
        .build(keyring, "research-key-2024")
    )

    print("✓ Permit created and signed:")
    print(f"  Permit ID: {code_permit.permit_id[:16]}...")
    print(f"  Action: {code_permit.action}")
    print(f"  Authorized code: {code_permit.params['code']}")
    print()

    # Execute with permit
    result = code_tool(
        code="print('Hello from governed agent')",
        permit_token=code_permit,
    )

    print("✓ ALLOWED by kernel")
    print(f"  Result: {result}")
    print()

    # ========================================================================
    # Step 5: Execute another dangerous operation with permit
    # ========================================================================

    print("Step 5: Execute filesystem access WITH valid permit")
    print("-" * 80)

    # Create filesystem permit (note: new permit, fresh nonce)
    fs_permit = (
        PermitBuilder()  # New builder instance = new nonce
        .issuer("operator@research-lab.com")
        .subject("research-agent-v1")
        .jurisdiction("default")
        .action("access_filesystem")
        .params({"path": "/data/research", "operation": "read"})
        .constraints({})
        .max_executions(1)
        .valid_from_ms(0)
        .valid_until_ms(1000000)
        .evidence_hash("")
        .proposal_hash("proposal-789-fs-read")
        .build(keyring, "research-key-2024")
    )

    print("✓ Filesystem permit created")
    print(f"  Path: {fs_permit.params['path']}")
    print(f"  Operation: {fs_permit.params['operation']}")
    print()

    # Execute with permit
    result = filesystem_tool(
        path="/data/research",
        operation="read",
        permit_token=fs_permit,
    )

    print("✓ ALLOWED by kernel")
    print(f"  Result: {result}")
    print()

    # ========================================================================
    # Step 6: Export audit trail
    # ========================================================================

    print("Step 6: Export audit trail")
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
    # Step 7: Summary
    # ========================================================================

    print("=" * 80)
    print("SUMMARY: Hugging Face + Shards-Kernel Integration")
    print("=" * 80)
    print()
    print("✓ Tools wrapped with Hugging Face-compatible interface")
    print("✓ Dangerous operations require cryptographically signed permits")
    print("✓ PermitInjector enables automatic permit assignment")
    print("✓ Complete audit trail of all tool executions")
    print("✓ Compatible with Hugging Face Transformers Agent framework")
    print()
    print("Integration usage:")
    print("  from transformers import Agent")
    print("  from shards_kernel.integrations import HuggingFaceAdapter")
    print()
    print("  adapter = HuggingFaceAdapter(kernel)")
    print("  tools = [adapter.wrap_tool(...), ...]")
    print("  agent = Agent(tools=tools, ...)")
    print()
    print("=" * 80)

    # Export evidence
    with open("/tmp/hf_agent_audit.json", "w") as f:
        json.dump(evidence, f, indent=2)

    print()
    print("Full audit trail saved to: /tmp/hf_agent_audit.json")
    print()


if __name__ == "__main__":
    main()
