"""
Shards-Kernel Integrations

Adapters and integrations for popular frameworks.
"""

from shards_kernel.integrations.fastapi_adapter import create_fastapi_app
from shards_kernel.integrations.flask_adapter import create_flask_app
from shards_kernel.integrations.mcp_adapter import MCPAdapter
from shards_kernel.integrations.langchain_adapter import (
    LangChainAdapter,
    GovernedTool,
    LangChainToolResult,
    create_langchain_adapter,
)
from shards_kernel.integrations.huggingface_adapter import (
    HuggingFaceAdapter,
    GovernedHFTool,
    HFToolResult,
    PermitInjector,
    create_huggingface_adapter,
)
from shards_kernel.integrations.generic_adapter import (
    GenericAdapter,
    MoltbookAdapter,
    ToolExecutionResult,
    create_generic_adapter,
    create_moltbook_adapter,
)
from shards_kernel.integrations.crewai_adapter import (
    CrewAIAdapter,
    GovernedCrewAITool,
    CrewAIToolResult,
    create_crewai_adapter,
)
from shards_kernel.integrations.autogpt_adapter import (
    AutoGPTAdapter,
    AutoGPTCommandResult,
    AutonomousLoopMonitor,
    create_autogpt_adapter,
)
from shards_kernel.integrations.langgraph_adapter import (
    LangGraphAdapter,
    StateTransition,
    WorkflowInvariant,
    create_langgraph_adapter,
)

__all__ = [
    # Deployment/Serving
    "create_fastapi_app",
    "create_flask_app",
    "MCPAdapter",
    # Agent Frameworks
    "LangChainAdapter",
    "GovernedTool",
    "LangChainToolResult",
    "create_langchain_adapter",
    "LangGraphAdapter",
    "StateTransition",
    "WorkflowInvariant",
    "create_langgraph_adapter",
    "CrewAIAdapter",
    "GovernedCrewAITool",
    "CrewAIToolResult",
    "create_crewai_adapter",
    "AutoGPTAdapter",
    "AutoGPTCommandResult",
    "AutonomousLoopMonitor",
    "create_autogpt_adapter",
    # Model Hubs
    "HuggingFaceAdapter",
    "GovernedHFTool",
    "HFToolResult",
    "PermitInjector",
    "create_huggingface_adapter",
    # Generic
    "GenericAdapter",
    "MoltbookAdapter",
    "ToolExecutionResult",
    "create_generic_adapter",
    "create_moltbook_adapter",
]
