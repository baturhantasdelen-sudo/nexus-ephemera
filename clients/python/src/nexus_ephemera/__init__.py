"""Thin asyncio client for a same-user nexus-ephemera broker.

`TenantClient.execute_payload` sends exact payload bytes and scoped tenant
authorization to an enterprise daemon. Legacy `NexusClient.execute` sends
only a hash to a reference-mode daemon; it cannot bypass enterprise admission.
`NexusClient.metrics` reads five integer counters in reference mode. The broker secret is
not requested and is not returned. Unix sockets must be mode ``0600`` and
owned by the current user before the client connects. Windows pipes must
belong to the same user. Neither check is mTLS.
"""

from .client import NexusClient, TenantClient
from .ecosystem import (
    DUPLICATE_PROVIDER_STATUS,
    ActionReceipt,
    EcosystemGuard,
    LangChainToolGuard,
    PortkeyGuardrail,
    ProviderEdge,
    ToolRoute,
    activepieces_step,
    canonical_payload,
    composio_action,
    crewai_tool_call,
    endpoint_is_strict,
    handle_mcp_message,
)
from .errors import (
    CleanupIncomplete,
    IpcError,
    IdempotencyConflict,
    IdempotencyUnavailable,
    IdentityRejected,
    IdentityUnavailable,
    Inconclusive,
    IoFailure,
    Malformed,
    PayloadTooLarge,
    ProtocolError,
    RateLimited,
    TargetDenied,
    TimedOut,
)
from .models import (
    DEFAULT_UNIX_SOCK,
    DEFAULT_WINDOWS_PIPE,
    ENDPOINT_MAX,
    HARD_PAYLOAD_CAP,
    KEY_MAX,
    PAYLOAD_HASH_MAX,
    MetricsSnapshot,
    Receipt,
)

__all__ = [
    "DEFAULT_UNIX_SOCK",
    "DEFAULT_WINDOWS_PIPE",
    "ENDPOINT_MAX",
    "HARD_PAYLOAD_CAP",
    "KEY_MAX",
    "PAYLOAD_HASH_MAX",
    "DUPLICATE_PROVIDER_STATUS",
    "ActionReceipt",
    "EcosystemGuard",
    "LangChainToolGuard",
    "PortkeyGuardrail",
    "ProviderEdge",
    "ToolRoute",
    "CleanupIncomplete",
    "IpcError",
    "IdempotencyConflict",
    "IdempotencyUnavailable",
    "IdentityRejected",
    "IdentityUnavailable",
    "Inconclusive",
    "IoFailure",
    "Malformed",
    "MetricsSnapshot",
    "NexusClient",
    "TenantClient",
    "PayloadTooLarge",
    "ProtocolError",
    "RateLimited",
    "Receipt",
    "TargetDenied",
    "TimedOut",
    "activepieces_step",
    "canonical_payload",
    "composio_action",
    "crewai_tool_call",
    "endpoint_is_strict",
    "handle_mcp_message",
]
