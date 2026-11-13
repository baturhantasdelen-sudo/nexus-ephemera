"""Same-user broker client.

The public operations are `execute` and `metrics`. The broker secret is not a
request field and not a return value. Mutable frame buffers are overwritten
after use. Python `str` and `bytes` objects cannot be overwritten; they are
released for collection and are not stored on the client.
"""

from __future__ import annotations

import asyncio
import math
import time
from collections.abc import Awaitable, Callable
from typing import TypeVar

from . import transport
from .errors import (
    IpcError,
    IoFailure,
    PayloadTooLarge,
    ProtocolError,
    TimedOut,
    io_failure,
)
from .framing import (
    encode_request,
    load_json_object,
    parse_call,
    parse_metrics,
    validate_call,
    wipe,
    write_frame,
    read_frame,
)
from .models import HARD_PAYLOAD_CAP, RETRY_PAUSE_SECONDS, MetricsSnapshot, Receipt

_T = TypeVar("_T")


class NexusClient:
    """One configuration for short-lived connections to a local broker."""

    __slots__ = ("_listen", "_max_payload", "_timeout")

    def __init__(
        self,
        listen: str,
        *,
        timeout: float = 5.0,
        max_payload_bytes: int = HARD_PAYLOAD_CAP,
    ) -> None:
        if not isinstance(listen, str) or listen == "":
            raise ProtocolError("listen path is empty")
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(float(timeout))
            or float(timeout) <= 0
        ):
            raise ProtocolError("timeout must be greater than zero")
        if (
            isinstance(max_payload_bytes, bool)
            or not isinstance(max_payload_bytes, int)
            or not 1 <= max_payload_bytes <= HARD_PAYLOAD_CAP
        ):
            raise ProtocolError("payload limit is outside 1..=65536")
        self._listen = listen
        self._timeout = float(timeout)
        self._max_payload = max_payload_bytes

    async def execute(
        self,
        endpoint: str,
        payload_hash: str,
        idempotency_key: str,
    ) -> Receipt:
        """Send one call and return the receipt.

        `CleanupIncomplete` is raised for a `partial` or `failed` seal. The
        attached receipt is not a success. Rejected targets raise `TargetDenied`
        and are not written to a provider by the broker.
        """

        validate_call(endpoint, payload_hash, idempotency_key)

        async def once() -> Receipt:
            return await self._call(endpoint, payload_hash, idempotency_key)

        return await self._retry(once)

    async def metrics(self) -> MetricsSnapshot:
        """Read the broker's five counters. The frame carries no call fields."""

        async def once() -> MetricsSnapshot:
            return await self._metrics_once()

        return await self._retry(once)

    def __repr__(self) -> str:
        return (
            f"NexusClient(listen={self._listen!r}, timeout={self._timeout!r}, "
            f"max_payload_bytes={self._max_payload!r})"
        )

    async def _retry(self, operation: Callable[[], Awaitable[_T]]) -> _T:
        deadline = time.monotonic() + self._timeout
        last: IpcError = TimedOut()
        while time.monotonic() < deadline:
            try:
                return await operation()
            except IpcError as err:
                if not _retryable(err):
                    raise
                last = err
                await asyncio.sleep(RETRY_PAUSE_SECONDS)
        raise last

    async def _call(self, endpoint: str, payload_hash: str, idempotency_key: str) -> Receipt:
        body = encode_request("call", endpoint, payload_hash, idempotency_key)
        try:
            if len(body) > self._max_payload:
                raise PayloadTooLarge(self._max_payload)
            parsed = await self._exchange(body)
        finally:
            wipe(body)
        return parse_call(
            parsed,
            endpoint=endpoint,
            payload_hash=payload_hash,
            idempotency_key=idempotency_key,
        )

    async def _metrics_once(self) -> MetricsSnapshot:
        body = encode_request("metrics", "", "", "")
        try:
            if len(body) > self._max_payload:
                raise PayloadTooLarge(self._max_payload)
            parsed = await self._exchange(body)
        finally:
            wipe(body)
        return parse_metrics(parsed)

    async def _exchange(self, body: bytearray) -> object:
        try:
            stream = await transport.open_broker(self._listen, self._timeout)
        except OSError as exc:
            raise io_failure(exc) from exc
        try:
            await write_frame(stream, body, self._max_payload, self._timeout)
            raw = await read_frame(stream, self._max_payload, self._timeout)
            try:
                return load_json_object(raw)
            finally:
                wipe(raw)
        finally:
            await stream.close()


def _retryable(err: IpcError) -> bool:
    if isinstance(err, IoFailure):
        return not err.permission_denied
    return isinstance(err, TimedOut)
