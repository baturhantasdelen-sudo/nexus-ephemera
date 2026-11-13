"""Wire values shared by the client. No secret material belongs here."""

from __future__ import annotations

from typing import TypedDict

HARD_PAYLOAD_CAP: int = 64 * 1024
ENDPOINT_MAX: int = 2048
PAYLOAD_HASH_MAX: int = 128
KEY_MAX: int = 128
DEFAULT_UNIX_SOCK: str = "/var/run/nexus-ephemera.sock"
DEFAULT_WINDOWS_PIPE: str = r"\\.\pipe\nexus-ephemera"
U64_MAX: int = (1 << 64) - 1

# Rust `NexusClient` retries a refused connect after this pause.
RETRY_PAUSE_SECONDS: float = 0.02


class Receipt(TypedDict):
    """Successful broker receipt. `seal_report` is `complete` or `retained`."""

    transport_status: int
    seal_report: str
    binding_digest_hex: str
    target_endpoint: str
    payload_hash: str
    idempotency_key: str


class MetricsSnapshot(TypedDict):
    """Five process counters. The snapshot has no endpoint, hash, key, or secret."""

    wipe_success_count: int
    quarantine_trigger_total: int
    cleanup_incomplete_rate: int
    ipc_auth_failure_total: int
    p95_dispatch_latency_us: int
