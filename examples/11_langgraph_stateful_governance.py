"""
Example: LangGraph Stateful Workflow with KERNELS Governance

This example demonstrates KERNELS governance for LangGraph stateful workflows,
including state transition validation and workflow invariants enforcement.

LangGraph Context:
- Extension of LangChain for stateful agent workflows
- Nodes represent workflow steps with state management
- Edges define transitions between nodes
- State persists across workflow execution
- Supports conditional routing and cycles

The Problem:
    Without governance, LangGraph workflows can:
    - Execute invalid state transitions
    - Violate business logic constraints
    - Proceed past critical errors
    - Modify state without authorization
    - No audit trail of state mutations

The Solution:
    KERNELS provides:
    - Node-level execution governance
    - State transition validation
    - Workflow invariants enforcement
    - Rollback on policy violation
    - Complete audit trail of state changes

Scenario:
    E-commerce order processing workflow

    Steps:
    1. Validate order (check inventory, pricing)
    2. Process payment (requires permit)
    3. Update inventory (requires permit)
    4. Send confirmation (requires permit)

    Invariants:
    - Total price must not exceed budget
    - Inventory cannot go negative
    - Payment must be processed before shipping

Usage:
    python examples/11_langgraph_stateful_governance.py
"""

from typing import Dict, Any
import json
import os

# KERNELS imports
from kernels.common.types import KernelConfig, VirtualClock
from kernels.variants.strict_kernel import StrictKernel
from kernels.integrations.langgraph_adapter import LangGraphAdapter
from _permit import issue_permit


# ============================================================================
# E-commerce Order Processing Workflow
# ============================================================================


def validate_order(state: Dict[str, Any]) -> Dict[str, Any]:
    """Validate order details. The caller supplies a permit for this state."""
    print("\n📋 VALIDATING ORDER:")
    print(f"   Order ID: {state.get('order_id')}")
    print(f"   Total: ${state.get('total_price', 0)}")
    print()

    # Check inventory
    items = state.get("items", [])
    inventory = state.get("inventory", {})

    for item in items:
        item_id = item["id"]
        quantity = item["quantity"]
        available = inventory.get(item_id, 0)

        if available < quantity:
            state["validation_errors"] = state.get("validation_errors", [])
            state["validation_errors"].append(
                f"Insufficient inventory for {item_id}: {available} < {quantity}"
            )

    # Mark as validated
    state["order_validated"] = len(state.get("validation_errors", [])) == 0

    return state


def process_payment(state: Dict[str, Any]) -> Dict[str, Any]:
    """Process payment (HIGH RISK - requires permit)."""
    print("\n💳 PROCESSING PAYMENT:")
    print(f"   Amount: ${state.get('total_price', 0)}")
    print(f"   Payment method: {state.get('payment_method', 'unknown')}")
    print()

    # Simulate payment processing
    state["payment_processed"] = True
    state["payment_timestamp"] = 1234567890

    return state


def update_inventory(state: Dict[str, Any]) -> Dict[str, Any]:
    """Update inventory (HIGH RISK - requires permit)."""
    print("\n📦 UPDATING INVENTORY:")

    items = state.get("items", [])
    inventory = state.get("inventory", {})

    for item in items:
        item_id = item["id"]
        quantity = item["quantity"]
        inventory[item_id] = inventory.get(item_id, 0) - quantity
        print(f"   {item_id}: {inventory[item_id] + quantity} → {inventory[item_id]}")

    state["inventory"] = inventory
    state["inventory_updated"] = True

    print()

    return state


def send_confirmation(state: Dict[str, Any]) -> Dict[str, Any]:
    """Send order confirmation email (MEDIUM RISK - requires permit)."""
    print("\n📧 SENDING CONFIRMATION:")
    print(f"   To: {state.get('customer_email', 'unknown')}")
    print(f"   Order ID: {state.get('order_id')}")
    print()

    state["confirmation_sent"] = True

    return state


def ship_order(state: Dict[str, Any]) -> Dict[str, Any]:
    """Ship order (HIGH RISK - requires permit)."""
    print("\n🚚 SHIPPING ORDER:")
    print(f"   Order ID: {state.get('order_id')}")
    print(f"   Address: {state.get('shipping_address', 'unknown')}")
    print()

    state["order_shipped"] = True
    state["shipping_timestamp"] = 1234567900

    return state


# ============================================================================
# Workflow Governance Scenario
# ============================================================================


def main():
    print("=" * 80)
    print("KERNELS + LangGraph Stateful Workflow Governance")
    print("=" * 80)
    print()
    print("Scenario: E-commerce order processing workflow")
    print()
    print("Workflow Steps:")
    print("  1. Validate order (permit bound to the current state)")
    print("  2. Process payment (HIGH RISK - permit required)")
    print("  3. Update inventory (HIGH RISK - permit required)")
    print("  4. Send confirmation (MEDIUM RISK - permit required)")
    print("  5. Ship order (HIGH RISK - permit required)")
    print()
    print("Workflow Invariants:")
    print("  - Total price must not exceed customer budget")
    print("  - Inventory cannot go negative")
    print("  - Payment must be processed before shipping")
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
        kernel_id="ecommerce-workflow",
        variant="strict",
        clock=VirtualClock(initial_ms=1000),
    )
    kernel.boot(config)

    # Set up cryptographic keyring
    keyring = {"workflow-operator-2026": b"secret-hmac-key-32-bytes-workflow"}
    kernel.set_keyring(keyring)

    print("✓ Kernel booted with strict governance")
    print()

    # ========================================================================
    # Step 2: Create LangGraph adapter
    # ========================================================================

    print("Step 2: Create LangGraph adapter with invariants")
    print("-" * 80)

    adapter = LangGraphAdapter(
        kernel=kernel,
        actor="ecommerce-workflow",
        auto_register=True,
        enforce_invariants=True,
    )

    # Define workflow invariants
    adapter.add_invariant(
        name="budget_limit",
        description="Total price must not exceed customer budget",
        validator=lambda state: state.get("total_price", 0)
        <= state.get("customer_budget", 10000),
        enforce=True,
    )

    adapter.add_invariant(
        name="positive_inventory",
        description="Inventory levels must remain non-negative",
        validator=lambda state: all(
            qty >= 0 for qty in state.get("inventory", {}).values()
        ),
        enforce=True,
    )

    adapter.add_invariant(
        name="payment_before_shipping",
        description="Payment must be processed before shipping",
        validator=lambda state: (
            not state.get("order_shipped", False)
            or state.get("payment_processed", False)
        ),
        enforce=True,
    )

    print("✓ Invariants configured:")
    print("  - budget_limit: Total price ≤ customer budget")
    print("  - positive_inventory: All inventory levels ≥ 0")
    print("  - payment_before_shipping: Payment required before ship")
    print()

    # ========================================================================
    # Step 3: Wrap workflow nodes
    # ========================================================================

    print("Step 3: Wrap workflow nodes with governance")
    print("-" * 80)

    # Every node is authorised by a permit for the state it receives
    governed_validate = adapter.wrap_node(
        "validate_order",
        validate_order,
        "Validate order details",
        require_permit=False,
    )

    # High risk nodes (require permits)
    governed_payment = adapter.wrap_node(
        "process_payment",
        process_payment,
        "Process payment",
        require_permit=True,
    )

    governed_inventory = adapter.wrap_node(
        "update_inventory",
        update_inventory,
        "Update inventory levels",
        require_permit=True,
    )

    governed_confirmation = adapter.wrap_node(
        "send_confirmation",
        send_confirmation,
        "Send order confirmation",
        require_permit=True,
    )

    governed_shipping = adapter.wrap_node(
        "ship_order",
        ship_order,
        "Ship order to customer",
        require_permit=True,
    )

    print("✓ Workflow nodes wrapped:")
    print("  - validate_order [NO PERMIT]")
    print("  - process_payment [PERMIT REQUIRED]")
    print("  - update_inventory [PERMIT REQUIRED]")
    print("  - send_confirmation [PERMIT REQUIRED]")
    print("  - ship_order [PERMIT REQUIRED]")
    print()

    # ========================================================================
    # Step 4: Initialize workflow state
    # ========================================================================

    print("Step 4: Initialize workflow state")
    print("-" * 80)

    workflow_state = {
        "order_id": "ORD-2026-001",
        "customer_email": "customer@example.com",
        "customer_budget": 1000.0,
        "shipping_address": "123 Main St, City, State 12345",
        "payment_method": "credit_card",
        "items": [
            {"id": "ITEM-A", "quantity": 2, "price": 50.0},
            {"id": "ITEM-B", "quantity": 1, "price": 100.0},
        ],
        "total_price": 200.0,
        "inventory": {
            "ITEM-A": 10,
            "ITEM-B": 5,
        },
        "validation_errors": [],
        "order_validated": False,
        "payment_processed": False,
        "inventory_updated": False,
        "confirmation_sent": False,
        "order_shipped": False,
    }

    print("✓ Workflow state initialized:")
    print(f"  - Order ID: {workflow_state['order_id']}")
    print(f"  - Total: ${workflow_state['total_price']}")
    print(f"  - Budget: ${workflow_state['customer_budget']}")
    print(f"  - Items: {len(workflow_state['items'])}")
    print()

    # ========================================================================
    # Step 5: Execute workflow (validate order)
    # ========================================================================

    print("Step 5: Execute workflow step 1 - Validate order")
    print("-" * 80)

    workflow_state = governed_validate(
        workflow_state,
        permit_token=issue_permit(
            keyring,
            "workflow-operator-2026",
            subject="ecommerce-workflow",
            action="validate_order",
            params=dict(workflow_state),
            issuer="operator@company.com",
        ),
    )

    print(f"✓ Order validated: {workflow_state['order_validated']}")
    if workflow_state.get("validation_errors"):
        print(f"  Validation errors: {workflow_state['validation_errors']}")
    print()

    # ========================================================================
    # Step 6: Attempt payment processing WITHOUT permit (should fail)
    # ========================================================================

    print("Step 6: Attempt payment processing WITHOUT permit (should be denied)")
    print("-" * 80)

    try:
        workflow_state = governed_payment(workflow_state)
        print("✗ ERROR: Should have been denied!")
    except PermissionError as e:
        print("✓ CORRECTLY DENIED by KERNELS")
        print(f"  Error: {e}")
        print()
        print("Payment processing requires cryptographic permit!")
        print()

    # ========================================================================
    # Step 7: Execute WITH valid permits
    # ========================================================================

    print("Step 7: Execute workflow WITH valid permits")
    print("-" * 80)

    def state_permit(action: str, state: dict):
        return issue_permit(
            keyring,
            "workflow-operator-2026",
            subject="ecommerce-workflow",
            action=action,
            params=dict(state),
            issuer="operator@company.com",
        )

    print("✓ Each step is authorised for the state it will receive:")
    print("  - process_payment")
    print("  - update_inventory")
    print("  - send_confirmation")
    print("  - ship_order")
    print()

    # Execute workflow with permits
    print("Executing workflow...")
    print()

    # Step 2: Process payment
    workflow_state = governed_payment(
        workflow_state,
        permit_token=state_permit("process_payment", workflow_state),
    )
    print(f"✓ Payment processed: {workflow_state['payment_processed']}")
    print()

    # Step 3: Update inventory
    workflow_state = governed_inventory(
        workflow_state,
        permit_token=state_permit("update_inventory", workflow_state),
    )
    print(f"✓ Inventory updated: {workflow_state['inventory_updated']}")
    print(f"  New inventory: {workflow_state['inventory']}")
    print()

    # Step 4: Send confirmation
    workflow_state = governed_confirmation(
        workflow_state,
        permit_token=state_permit("send_confirmation", workflow_state),
    )
    print(f"✓ Confirmation sent: {workflow_state['confirmation_sent']}")
    print()

    # Step 5: Ship order
    workflow_state = governed_shipping(
        workflow_state,
        permit_token=state_permit("ship_order", workflow_state),
    )
    print(f"✓ Order shipped: {workflow_state['order_shipped']}")
    print()

    # ========================================================================
    # Step 8: Demonstrate invariant enforcement
    # ========================================================================

    print("Step 8: Demonstrate workflow invariant enforcement")
    print("-" * 80)

    # Create a state that violates budget invariant
    invalid_state = workflow_state.copy()
    invalid_state["total_price"] = 2000.0  # Exceeds budget of $1000

    print("Attempting state with total_price = $2000 (exceeds budget of $1000)...")
    print()

    try:
        adapter.check_invariants(invalid_state)
        print("✗ ERROR: Invariant check should have failed!")
    except RuntimeError as e:
        print("✓ INVARIANT VIOLATION DETECTED")
        print(f"  Error: {e}")
        print()
        print("Workflow halted due to invariant violation!")
        print("This prevents business logic errors from propagating.")
        print()

    # ========================================================================
    # Step 9: View state transitions
    # ========================================================================

    print("Step 9: View workflow state transitions")
    print("-" * 80)

    transitions = adapter.get_transitions()

    print(f"Total state transitions: {len(transitions)}")
    print()

    for i, transition in enumerate(transitions, 1):
        print(f"{i}. {transition.from_node or 'START'} → {transition.to_node}")
        print(f"   Allowed: {transition.was_allowed}")
        print(f"   Permit verified: {transition.permit_verified}")
        print()

    # ========================================================================
    # Step 10: Export audit trail
    # ========================================================================

    print("Step 10: Export workflow audit trail")
    print("-" * 80)

    evidence = adapter.export_evidence()

    print("✓ Audit trail exported:")
    print(f"  Kernel: {evidence['kernel_id']}")
    print(f"  Total entries: {evidence['entry_count']}")
    print(f"  Root hash: {evidence['root_hash'][:16]}...")
    print()

    if "workflow_data" in evidence:
        workflow_data = evidence["workflow_data"]
        print("Workflow-specific data:")
        print(f"  - Nodes: {len(workflow_data['nodes'])}")
        print(f"  - Transitions: {len(workflow_data['transitions'])}")
        print(f"  - Invariants: {len(workflow_data['invariants'])}")
        print()

    # ========================================================================
    # Summary
    # ========================================================================

    print("=" * 80)
    print("SUMMARY: LangGraph Stateful Workflow Governance with KERNELS")
    print("=" * 80)
    print()
    print("What KERNELS prevents in stateful workflows:")
    print()
    print("WITHOUT KERNELS:")
    print("  ✗ Workflows can execute invalid state transitions")
    print("  ✗ Business logic constraints can be violated")
    print("  ✗ No authorization for critical workflow steps")
    print("  ✗ State mutations are not audited")
    print("  ✗ Workflows continue past errors")
    print()
    print("WITH KERNELS:")
    print("  ✓ Node-level execution governance")
    print("  ✓ Workflow invariants enforced throughout execution")
    print("  ✓ State transitions validated and audited")
    print("  ✓ Critical steps require cryptographic permits")
    print("  ✓ Rollback on policy violation")
    print("  ✓ Complete audit trail of state mutations")
    print()
    print("Workflow Invariants:")
    print("  - Define conditions that must hold throughout execution")
    print("  - Enforced before and after each node execution")
    print("  - Violations halt workflow with clear error messages")
    print("  - Examples: budget limits, resource constraints, dependencies")
    print()
    print("State Transition Tracking:")
    print("  - Every node execution is recorded")
    print("  - State before and after each transition")
    print("  - Permit verification status")
    print("  - Timeline of workflow progression")
    print()
    print("Integration usage:")
    print("  from kernels.integrations import LangGraphAdapter")
    print()
    print("  adapter = LangGraphAdapter(kernel, enforce_invariants=True)")
    print()
    print("  # Define invariants")
    print("  adapter.add_invariant('name', 'description', validator_fn)")
    print()
    print("  # Wrap nodes")
    print("  governed_node = adapter.wrap_node('node_name', node_fn)")
    print()
    print("  # Execute with permit")
    print("  new_state = governed_node(state, permit_token=permit)")
    print()
    print("=" * 80)

    # Export evidence
    os.makedirs("/tmp", exist_ok=True)
    with open("/tmp/langgraph_workflow_audit.json", "w") as f:
        json.dump(evidence, f, indent=2)

    print()
    print("Full audit trail saved to: /tmp/langgraph_workflow_audit.json")
    print()


if __name__ == "__main__":
    main()
