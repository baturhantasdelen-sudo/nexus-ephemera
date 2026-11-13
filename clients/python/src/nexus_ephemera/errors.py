"""Client failures. These mirror the broker's `IpcError` names."""

from __future__ import annotations

from .models import Receipt


class IpcError(Exception):
    """Base class for broker client failures."""


class IoFailure(IpcError):
    """Transport failure. Permission failures are not retried."""

    def __init__(self, message: str, *, permission_denied: bool = False) -> None:
        super().__init__(message)
        self.permission_denied = permission_denied


class IdentityRejected(IpcError):
    """The socket mode, owner, or peer user does not match this process."""


class IdentityUnavailable(IpcError):
    """Peer pid or user id could not be read. The client does not write."""


class PayloadTooLarge(IpcError):
    """A frame, endpoint, or payload hash is outside its own limit."""

    def __init__(self, limit: int) -> None:
        super().__init__(f"ipc: payload exceeds {limit} bytes")
        self.limit = limit


class TimedOut(IpcError):
    """The attempt did not finish inside the client timeout."""

    def __init__(self, message: str = "ipc: request timed out") -> None:
        super().__init__(message)


class TargetDenied(IpcError):
    """The broker allowlist rejected the endpoint before any provider call."""

    def __init__(self, message: str = "ipc: endpoint is not on the allowlist") -> None:
        super().__init__(message)


class Malformed(IpcError):
    """The frame or the call fields are not the broker wire contract."""

    def __init__(self, message: str = "ipc: malformed frame") -> None:
        super().__init__(message)


class CleanupIncomplete(IpcError):
    """The provider ran and the seal is `partial` or `failed`.

    `receipt` is the same shape as a success receipt. It is not a success.
    """

    def __init__(self, receipt: Receipt) -> None:
        self.receipt = receipt
        super().__init__(
            "ipc: cleanup "
            f"{receipt['seal_report']} after transport {receipt['transport_status']}"
        )


class IdempotencyConflict(IpcError):
    def __init__(
        self, message: str = "ipc: idempotency key was reused for a different call"
    ) -> None:
        super().__init__(message)


class IdempotencyUnavailable(IpcError):
    def __init__(self, message: str = "ipc: idempotency cache is full") -> None:
        super().__init__(message)


class Inconclusive(IpcError):
    def __init__(self, message: str = "ipc: provider outcome is inconclusive") -> None:
        super().__init__(message)


class RateLimited(IpcError):
    def __init__(self, message: str = "ipc: principal rate limit") -> None:
        super().__init__(message)


class ProtocolError(IpcError):
    """Local configuration or an unrecognized broker rejection."""


def io_failure(exc: OSError) -> IoFailure:
    """Map an OS error without copying a payload into the message."""

    winerror = getattr(exc, "winerror", None)
    denied = isinstance(exc, PermissionError) or winerror == 5 or exc.errno in {1, 13}
    detail = exc.strerror or exc.__class__.__name__
    return IoFailure(f"ipc io: {detail}", permission_denied=denied)


def error_from_code(code: str) -> IpcError:
    """Map a rejected frame's `code` field. Unknown codes stay fail-closed."""

    if code == "target_denied":
        return TargetDenied()
    if code == "payload_too_large":
        return PayloadTooLarge(0)
    if code == "timed_out":
        return TimedOut()
    if code == "identity_rejected":
        return IdentityRejected("ipc: caller identity rejected")
    if code == "identity_unavailable":
        return IdentityUnavailable("ipc: caller identity unavailable")
    if code == "malformed":
        return Malformed()
    if code == "cleanup_incomplete":
        return ProtocolError("ipc: cleanup status missing receipt")
    if code == "idempotency_conflict":
        return IdempotencyConflict()
    if code == "idempotency_unavailable":
        return IdempotencyUnavailable()
    if code == "inconclusive":
        return Inconclusive()
    if code == "rate_limited":
        return RateLimited()
    return ProtocolError("ipc: request rejected")
