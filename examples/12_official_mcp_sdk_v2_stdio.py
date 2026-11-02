"""Local stdio MCP v2 example, not a remotely exposed service.

Usage:
  python -m pip install -e ".[mcp]"
  export SHARDS_KERNEL_MCP_KEY="<strong secret supplied by operator>"
  python examples/12_official_mcp_sdk_v2_stdio.py

Do not give this environment variable to an LLM or log it.
This process can only execute the explicit "repeat" tool with a matching
operator-signed permit, issued separately; no tool signs its own permits.
"""

from __future__ import annotations

import os
import time

from shards_kernel.common.types import KernelConfig
from shards_kernel.integrations.mcp_sdk_v2 import create_official_mcp_server
from shards_kernel.jurisdiction.policy import JurisdictionPolicy
from shards_kernel.variants.strict_kernel import StrictKernel


class WallClock:
    """Use real UTC milliseconds for permit expiry (not a frozen demo clock)."""

    def now_ms(self) -> int:
        return time.time_ns() // 1_000_000


def main() -> None:
    key = os.environ.get("SHARDS_KERNEL_MCP_KEY", "")
    if len(key.encode("utf-8")) < 32:
        raise SystemExit("SHARDS_KERNEL_MCP_KEY must contain at least 32 bytes")

    kernel = StrictKernel()
    kernel.boot(KernelConfig(kernel_id="local-mcp", variant="strict", clock=WallClock()))
    kernel.set_keyring({"operator": key.encode("utf-8")})
    kernel.set_policy(
        JurisdictionPolicy(
            allowed_actors=frozenset({"local-mcp-agent"}),
            allowed_tools=frozenset({"repeat"}),
        )
    )

    server = create_official_mcp_server(
        kernel,
        actor="local-mcp-agent",
        handlers={"repeat": lambda text: text},
    )
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
