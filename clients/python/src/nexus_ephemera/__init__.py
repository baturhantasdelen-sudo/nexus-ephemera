"""Thin asyncio client for a same-user nexus-ephemera broker.

`NexusClient.execute` sends an endpoint, a payload hash, and an idempotency
key. `NexusClient.metrics` reads five integer counters. The broker secret is
not requested and is not returned. Unix sockets must be mode ``0600`` and
owned by the current user before the client connects. Windows pipes must
belong to the same user. Neither check is mTLS.
"""

from .client import NexusClient
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
    "PayloadTooLarge",
    "ProtocolError",
    "RateLimited",
    "Receipt",
    "TargetDenied",
    "TimedOut",
]
