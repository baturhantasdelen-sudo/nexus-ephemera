"""Length-prefixed JSON frames shared with the Rust broker.

A frame is a 4-byte little-endian length followed by that many JSON bytes.
The length is at least 1 and at most the configured payload cap, which itself
cannot exceed `HARD_PAYLOAD_CAP` (64 KiB).
"""

from __future__ import annotations

import asyncio
import ctypes
import json
from typing import Protocol

from .errors import (
    CleanupIncomplete,
    IoFailure,
    Malformed,
    PayloadTooLarge,
    TimedOut,
    error_from_code,
    io_failure,
)
from .models import (
    ENDPOINT_MAX,
    KEY_MAX,
    PAYLOAD_HASH_MAX,
    U64_MAX,
    MetricsSnapshot,
    Receipt,
)


class Stream(Protocol):
    """Byte stream used by one broker attempt."""

    async def readexactly(self, n: int) -> bytes:
        """Read exactly `n` bytes or raise."""

    async def write(self, data: bytes | bytearray | memoryview) -> None:
        """Write the whole buffer before returning."""

    async def close(self) -> None:
        """Release the socket or pipe handle."""


def wipe(buffer: bytearray) -> None:
    """Overwrite a mutable buffer. Immutable `str` and `bytes` cannot be wiped."""

    size = len(buffer)
    if size == 0:
        return
    try:
        ctypes.memset((ctypes.c_char * size).from_buffer(buffer), 0, size)
    except BufferError:
        for index in range(size):
            buffer[index] = 0


def valid_idempotency_key(key: str) -> bool:
    """Match the broker: 1..=128 bytes, each an ASCII graphic character."""

    return 1 <= len(key) <= KEY_MAX and all(0x21 <= ord(char) <= 0x7E for char in key)


def utf8_len(value: str) -> int:
    return len(value.encode("utf-8"))


def encode_request(
    op: str,
    endpoint: str,
    payload_hash: str,
    idempotency_key: str,
) -> bytearray:
    """Serialize one request. The caller wipes the returned buffer."""

    text = json.dumps(
        {
            "op": op,
            "endpoint": endpoint,
            "payload_hash": payload_hash,
            "idempotency_key": idempotency_key,
        },
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise Malformed() from exc
    return bytearray(encoded)


async def write_frame(
    stream: Stream,
    body: bytes | bytearray | memoryview,
    max_payload: int,
    timeout: float,
) -> None:
    """Write a length prefix and body. The 4-byte prefix is wiped afterward."""

    size = len(body)
    if size == 0 or size > max_payload:
        raise PayloadTooLarge(max_payload)
    header = bytearray(size.to_bytes(4, "little"))
    try:
        await asyncio.wait_for(stream.write(header), timeout)
        await asyncio.wait_for(stream.write(body), timeout)
    except TimeoutError as exc:
        raise TimedOut() from exc
    except OSError as exc:
        raise io_failure(exc) from exc
    finally:
        wipe(header)


async def read_frame(stream: Stream, max_payload: int, timeout: float) -> bytearray:
    """Read one frame. A zero or oversized length is rejected before the body."""

    try:
        header_bytes = await asyncio.wait_for(stream.readexactly(4), timeout)
    except TimeoutError as exc:
        raise TimedOut() from exc
    except asyncio.IncompleteReadError as exc:
        raise IoFailure("ipc io: unexpected eof") from exc
    except OSError as exc:
        raise io_failure(exc) from exc
    header = bytearray(header_bytes)
    try:
        if len(header) != 4:
            raise IoFailure("ipc io: unexpected eof")
        length = int.from_bytes(header, "little")
    finally:
        wipe(header)
    if length == 0 or length > max_payload:
        raise PayloadTooLarge(max_payload)
    try:
        body = await asyncio.wait_for(stream.readexactly(length), timeout)
    except TimeoutError as exc:
        raise TimedOut() from exc
    except asyncio.IncompleteReadError as exc:
        raise IoFailure("ipc io: unexpected eof") from exc
    except OSError as exc:
        raise io_failure(exc) from exc
    if len(body) != length:
        raise IoFailure("ipc io: unexpected eof")
    return bytearray(body)


def load_json_object(raw: bytearray) -> object:
    """Parse JSON without chaining the decoder exception, which retains the doc."""

    try:
        parsed: object = json.loads(raw)
    except json.JSONDecodeError:
        raise Malformed() from None
    return parsed


def parse_call(
    value: object,
    *,
    endpoint: str,
    payload_hash: str,
    idempotency_key: str,
) -> Receipt:
    """Turn a call response into a receipt or a typed error."""

    mapping = _object_map(value)
    kind = _text(_required(mapping, "kind"))
    code = _text(_required(mapping, "code"))
    if kind == "rejected":
        raise error_from_code(code)
    if kind not in {"receipt", "cleanup_incomplete"}:
        raise Malformed()
    receipt = _receipt(mapping)
    if (
        receipt["target_endpoint"] != endpoint
        or receipt["payload_hash"] != payload_hash
        or receipt["idempotency_key"] != idempotency_key
    ):
        raise Malformed()
    seal = receipt["seal_report"]
    if kind == "receipt" and seal in {"complete", "retained"}:
        return receipt
    if kind in {"receipt", "cleanup_incomplete"} and seal in {"partial", "failed"}:
        raise CleanupIncomplete(receipt)
    raise Malformed()


def parse_metrics(value: object) -> MetricsSnapshot:
    """Accept a metrics frame and return only the five counters."""

    mapping = _object_map(value)
    if _text(_required(mapping, "kind")) != "metrics":
        raise Malformed()
    snapshot: MetricsSnapshot = {
        "wipe_success_count": _u64(_required(mapping, "wipe_success_count")),
        "quarantine_trigger_total": _u64(_required(mapping, "quarantine_trigger_total")),
        "cleanup_incomplete_rate": _u64(_required(mapping, "cleanup_incomplete_rate")),
        "ipc_auth_failure_total": _u64(_required(mapping, "ipc_auth_failure_total")),
        "p95_dispatch_latency_us": _u64(_required(mapping, "p95_dispatch_latency_us")),
    }
    return snapshot


def validate_call(endpoint: str, payload_hash: str, idempotency_key: str) -> None:
    """Reject a call before a socket or pipe is opened."""

    if (
        not isinstance(endpoint, str)
        or not isinstance(payload_hash, str)
        or not isinstance(idempotency_key, str)
    ):
        raise Malformed()
    if endpoint == "" or payload_hash == "":
        raise Malformed()
    if utf8_len(endpoint) > ENDPOINT_MAX:
        raise PayloadTooLarge(ENDPOINT_MAX)
    if utf8_len(payload_hash) > PAYLOAD_HASH_MAX:
        raise PayloadTooLarge(PAYLOAD_HASH_MAX)
    if not valid_idempotency_key(idempotency_key):
        raise Malformed()


def _object_map(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise Malformed()
    mapped: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise Malformed()
        mapped[key] = item
    return mapped


def _required(mapping: dict[str, object], name: str) -> object:
    if name not in mapping:
        raise Malformed()
    return mapping[name]


def _text(value: object) -> str:
    if not isinstance(value, str):
        raise Malformed()
    return value


def _u64(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise Malformed()
    if value < 0 or value > U64_MAX:
        raise Malformed()
    return value


def _u16(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise Malformed()
    if value < 0 or value > 65535:
        raise Malformed()
    return value


def _receipt(mapping: dict[str, object]) -> Receipt:
    return {
        "transport_status": _u16(_required(mapping, "transport_status")),
        "seal_report": _text(_required(mapping, "seal_report")),
        "binding_digest_hex": _text(_required(mapping, "binding_digest_hex")),
        "target_endpoint": _text(_required(mapping, "target_endpoint")),
        "payload_hash": _text(_required(mapping, "payload_hash")),
        "idempotency_key": _text(_required(mapping, "idempotency_key")),
    }

