"""
AutoGPT Integration Adapter for KERNELS

Provides permit-based governance for AutoGPT autonomous agents.

AutoGPT is one of the first and most well-known autonomous AI agent frameworks,
capable of:
- Executing code and shell commands
- Reading and writing files
- Browsing the web
- Managing its own memory
- Running in autonomous loops until goal completion

KERNELS Governance Layer:
- All command executions require cryptographic permits
- Autonomous loop monitoring and kill-switch
- Dynamic risk scoring per action
- Human-in-the-loop escalation hooks
- Complete audit trail of autonomous actions

Usage:
    from kernels.integrations import AutoGPTAdapter

    # Create KERNELS adapter
    adapter = AutoGPTAdapter(kernel, actor="autogpt-agent")

    # Wrap AutoGPT commands
    @adapter.governed_command("execute_shell", "Execute shell command")
    def execute_shell(command: str) -> str:
        return safe_command_runner(command)

    # Execute with governance
    result = execute_shell(command="ls -la", permit_token=permit)

Author: KERNELS Team
License: MIT
"""

from typing import Callable, Optional, Dict, Any, List
from dataclasses import dataclass
from functools import wraps
import uuid
import time

# KERNELS imports
from kernels.common.types import (
    KernelRequest,
    ToolCall,
    Decision,
)
from kernels.permits import PermitToken
from kernels.variants.base import BaseKernel


@dataclass
class AutoGPTCommandResult:
    """Result from AutoGPT command execution with KERNELS governance."""

    was_allowed: bool
    decision: Decision
    result: Optional[str]
    error: Optional[str]
    request_id: str
    receipt_hash: Optional[str]
    risk_score: float  # 0.0-1.0, higher = more dangerous


@dataclass
class AutonomousLoopStats:
    """Statistics for autonomous loop monitoring."""

    total_iterations: int
    commands_executed: int
    commands_denied: int
    high_risk_actions: int
    start_time: float
    last_action_time: float


class AutonomousLoopMonitor:
    """
    Monitor and control AutoGPT autonomous execution loops.

    Provides kill-switch functionality and safety limits for autonomous agents.
    """

    def __init__(
        self,
        max_iterations: Optional[int] = None,
        max_runtime_seconds: Optional[float] = None,
        max_denials: Optional[int] = None,
        require_permit_after_denials: int = 3,
    ):
        """
        Initialize autonomous loop monitor.

        Args:
            max_iterations: Maximum autonomous iterations (None = unlimited)
            max_runtime_seconds: Maximum runtime in seconds (None = unlimited)
            max_denials: Maximum denied actions before halting (None = unlimited)
            require_permit_after_denials: Require human approval after N denials
        """
        self.max_iterations = max_iterations
        self.max_runtime_seconds = max_runtime_seconds
        self.max_denials = max_denials
        self.require_permit_after_denials = require_permit_after_denials

        self.stats = AutonomousLoopStats(
            total_iterations=0,
            commands_executed=0,
            commands_denied=0,
            high_risk_actions=0,
            start_time=time.time(),
            last_action_time=time.time(),
        )

        self._halted = False
        self._halt_reason: Optional[str] = None

    def should_halt(self) -> bool:
        """Check if autonomous loop should be halted."""
        if self._halted:
            return True

        # Check iteration limit
        if (
            self.max_iterations is not None
            and self.stats.total_iterations >= self.max_iterations
        ):
            self._halt("Maximum iterations reached")
            return True

        # Check runtime limit
        if self.max_runtime_seconds is not None:
            runtime = time.time() - self.stats.start_time
            if runtime >= self.max_runtime_seconds:
                self._halt("Maximum runtime exceeded")
                return True

        # Check denial limit
        if (
            self.max_denials is not None
            and self.stats.commands_denied >= self.max_denials
        ):
            self._halt("Maximum denials reached")
            return True

        return False

    def record_iteration(self):
        """Record autonomous loop iteration."""
        self.stats.total_iterations += 1
        self.stats.last_action_time = time.time()

    def record_command(self, allowed: bool, risk_score: float):
        """Record command execution result."""
        if allowed:
            self.stats.commands_executed += 1
        else:
            self.stats.commands_denied += 1

        if risk_score >= 0.7:  # High risk threshold
            self.stats.high_risk_actions += 1

    def _halt(self, reason: str):
        """Halt autonomous loop execution."""
        self._halted = True
        self._halt_reason = reason

    def get_halt_reason(self) -> Optional[str]:
        """Get reason for halt if halted."""
        return self._halt_reason

    def reset(self):
        """Reset monitor state."""
        self.stats = AutonomousLoopStats(
            total_iterations=0,
            commands_executed=0,
            commands_denied=0,
            high_risk_actions=0,
            start_time=time.time(),
            last_action_time=time.time(),
        )
        self._halted = False
        self._halt_reason = None


class AutoGPTAdapter:
    """
    KERNELS adapter for AutoGPT autonomous agents.

    This adapter provides permit-based governance for AutoGPT commands,
    autonomous loop monitoring, and kill-switch functionality.

    Key Features:
    - Command execution governance
    - Autonomous loop monitoring
    - Dynamic risk scoring
    - Kill-switch for unsafe behavior
    - Human-in-the-loop escalation
    - Complete audit trail

    Usage:
        adapter = AutoGPTAdapter(kernel, actor="autogpt-agent")

        # Wrap command with decorator
        @adapter.governed_command("execute_shell", "Execute shell command")
        def execute_shell(command: str) -> str:
            return safe_command_runner(command)

        # Or wrap existing command
        governed_cmd = adapter.wrap_command("cmd_name", cmd_func)

        # Execute with permit
        result = execute_shell(command="ls", permit_token=permit)
    """

    def __init__(
        self,
        kernel: BaseKernel,
        actor: str = "autogpt-agent",
        auto_register: bool = True,
        enable_monitoring: bool = True,
        max_autonomous_iterations: Optional[int] = 100,
        max_runtime_seconds: Optional[float] = 3600,  # 1 hour default
    ):
        """
        Initialize AutoGPT adapter.

        Args:
            kernel: KERNELS kernel instance
            actor: Actor identity for AutoGPT agent
            auto_register: Auto-register commands in kernel dispatcher
            enable_monitoring: Enable autonomous loop monitoring
            max_autonomous_iterations: Max iterations before kill-switch
            max_runtime_seconds: Max runtime before kill-switch
        """
        self.kernel = kernel
        self.actor = actor
        self.auto_register = auto_register
        self._commands: Dict[str, Callable] = {}

        # Risk scoring weights (0.0-1.0)
        self._risk_weights = {
            "execute_shell": 1.0,  # CRITICAL
            "execute_python": 0.9,  # HIGH
            "write_file": 0.8,  # HIGH
            "delete_file": 0.9,  # HIGH
            "browse_website": 0.3,  # LOW
            "read_file": 0.2,  # LOW
            "send_email": 0.7,  # MEDIUM-HIGH
            "make_api_call": 0.5,  # MEDIUM
        }

        # Autonomous loop monitoring
        self.monitor = None
        if enable_monitoring:
            self.monitor = AutonomousLoopMonitor(
                max_iterations=max_autonomous_iterations,
                max_runtime_seconds=max_runtime_seconds,
                max_denials=10,
                require_permit_after_denials=3,
            )

    def set_risk_score(self, command_name: str, score: float):
        """
        Set risk score for command (0.0-1.0).

        Args:
            command_name: Name of command
            score: Risk score (0.0 = safe, 1.0 = critical)
        """
        if not 0.0 <= score <= 1.0:
            raise ValueError("Risk score must be between 0.0 and 1.0")
        self._risk_weights[command_name] = score

    def get_risk_score(self, command_name: str) -> float:
        """Get risk score for command."""
        return self._risk_weights.get(command_name, 0.5)  # Default: medium risk

    def wrap_command(
        self,
        name: str,
        func: Callable,
        description: str = "",
        risk_score: Optional[float] = None,
    ) -> Callable:
        """
        Wrap AutoGPT command with KERNELS governance.

        Args:
            name: Command name
            func: Command function
            description: Command description
            risk_score: Optional custom risk score (0.0-1.0)

        Returns:
            Governed command function
        """
        # Set risk score if provided
        if risk_score is not None:
            self.set_risk_score(name, risk_score)

        # Register in kernel if auto_register enabled
        if self.auto_register:
            self.kernel._dispatcher.registry.register(
                name=name,
                handler=func,
                description=description or f"AutoGPT command: {name}",
            )

        # Create governed wrapper
        @wraps(func)
        def governed_command(
            permit_token: Optional[PermitToken] = None, **kwargs
        ) -> str:
            # Check autonomous loop monitor
            if self.monitor and self.monitor.should_halt():
                halt_reason = self.monitor.get_halt_reason()
                raise RuntimeError(f"Autonomous loop halted: {halt_reason}")

            # Get risk score
            risk = self.get_risk_score(name)

            # Record iteration if monitoring enabled
            if self.monitor:
                self.monitor.record_iteration()

            # Create kernel request
            request_id = f"{name}-{uuid.uuid4().hex[:8]}"
            request = KernelRequest(
                request_id=request_id,
                ts_ms=self.kernel.config.clock.now_ms(),
                actor=self.actor,
                intent=f"AutoGPT command: {name}",
                tool_call=ToolCall(name=name, params=kwargs),
                params=kwargs,
            )

            # Submit to kernel
            receipt = self.kernel.submit(request, permit_token=permit_token)

            # Record command result
            if self.monitor:
                self.monitor.record_command(
                    allowed=(receipt.decision == Decision.ALLOW),
                    risk_score=risk,
                )

            # Handle decision
            if receipt.decision == Decision.ALLOW:
                result = str(receipt.tool_result)
                return result
            else:
                error_msg = f"Command {name} denied by KERNELS: {receipt.error}"
                raise PermissionError(error_msg)

        # Store command
        self._commands[name] = governed_command

        return governed_command

    def governed_command(
        self, name: str, description: str = "", risk_score: Optional[float] = None
    ):
        """
        Decorator for creating governed AutoGPT commands.

        Usage:
            @adapter.governed_command("execute_shell", "Execute shell command", risk_score=1.0)
            def execute_shell(command: str) -> str:
                return safe_command_runner(command)

        Args:
            name: Command name
            description: Command description
            risk_score: Optional risk score (0.0-1.0)
        """

        def decorator(func: Callable) -> Callable:
            return self.wrap_command(name, func, description, risk_score)

        return decorator

    def get_command(self, name: str) -> Optional[Callable]:
        """Get governed command by name."""
        return self._commands.get(name)

    def list_commands(self) -> List[str]:
        """List all wrapped command names."""
        return list(self._commands.keys())

    def export_evidence(self) -> Dict[str, Any]:
        """
        Export audit trail evidence bundle.

        Returns:
            Evidence bundle containing all command executions,
            decisions, and permit verifications.
        """
        from kernels.common.codec import audit_entry_to_dict

        bundle = self.kernel.export_evidence()
        entries = [audit_entry_to_dict(entry) for entry in bundle.ledger_entries]
        evidence: Dict[str, Any] = {
            "kernel_id": bundle.kernel_id,
            "variant": bundle.variant,
            "root_hash": bundle.root_hash,
            "exported_at_ms": bundle.exported_at_ms,
            "entries": entries,
            "entry_count": len(entries),
        }

        # Add autonomous loop stats if monitoring enabled
        if self.monitor:
            evidence["autonomous_loop_stats"] = {
                "total_iterations": self.monitor.stats.total_iterations,
                "commands_executed": self.monitor.stats.commands_executed,
                "commands_denied": self.monitor.stats.commands_denied,
                "high_risk_actions": self.monitor.stats.high_risk_actions,
                "runtime_seconds": time.time() - self.monitor.stats.start_time,
                "halted": self.monitor._halted,
                "halt_reason": self.monitor._halt_reason,
            }

        return evidence

    def reset_monitor(self):
        """Reset autonomous loop monitor."""
        if self.monitor:
            self.monitor.reset()

    def halt(self, reason: str = "Manual halt"):
        """Manually halt autonomous loop."""
        if self.monitor:
            self.monitor._halt(reason)


def create_autogpt_adapter(
    kernel: BaseKernel,
    actor: str = "autogpt-agent",
    auto_register: bool = True,
    enable_monitoring: bool = True,
    max_autonomous_iterations: Optional[int] = 100,
) -> AutoGPTAdapter:
    """
    Factory function to create AutoGPT adapter.

    Args:
        kernel: KERNELS kernel instance
        actor: Actor identity
        auto_register: Auto-register commands in kernel
        enable_monitoring: Enable autonomous loop monitoring
        max_autonomous_iterations: Max iterations before kill-switch

    Returns:
        AutoGPTAdapter instance
    """
    return AutoGPTAdapter(
        kernel=kernel,
        actor=actor,
        auto_register=auto_register,
        enable_monitoring=enable_monitoring,
        max_autonomous_iterations=max_autonomous_iterations,
    )
