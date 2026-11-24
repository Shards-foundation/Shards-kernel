"""Public execution scope for trusted provider handlers.

The kernel binds one immutable scope immediately before dispatch. A provider
handler can then correlate its own durable effect record with the kernel
request and permit without receiving either value as an agent-controlled
tool parameter.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass
from typing import Iterator, Optional


@dataclass(frozen=True)
class ExecutionScope:
    """Kernel-authored identity of the tool invocation in progress."""

    request_id: str
    actor: str
    tool_name: str
    permit_id: Optional[str]
    params_sha256: str


_CURRENT_SCOPE: ContextVar[Optional[ExecutionScope]] = ContextVar(
    "shards_kernel_execution_scope", default=None
)


def current_execution_scope() -> Optional[ExecutionScope]:
    """Return the scope bound by the kernel, or ``None`` outside dispatch."""
    return _CURRENT_SCOPE.get()


@contextmanager
def execution_scope(scope: ExecutionScope) -> Iterator[ExecutionScope]:
    """Bind ``scope`` for the duration of a synchronous dispatch."""
    token: Token[Optional[ExecutionScope]] = _CURRENT_SCOPE.set(scope)
    try:
        yield scope
    finally:
        _CURRENT_SCOPE.reset(token)
