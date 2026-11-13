"""Broker wire tests. The in-memory pair never opens a socket."""

from __future__ import annotations

import asyncio
import json
import sys
import uuid
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest

from nexus_ephemera import (
    HARD_PAYLOAD_CAP,
    NexusClient,
    CleanupIncomplete,
    IdentityRejected,
    IdempotencyConflict,
    Inconclusive,
    IoFailure,
    Malformed,
    PayloadTooLarge,
    ProtocolError,
    RateLimited,
    TargetDenied,
    TimedOut,
)
from nexus_ephemera import transport
from nexus_ephemera.errors import IdentityUnavailable
from nexus_ephemera.framing import Stream, read_frame, wipe, write_frame
from nexus_ephemera.identity import (
    assess_peer,
    require_private_unix_socket,
    unpack_ucred,
)
import struct

_ENDPOINT = "https://provider.example/charge"
_HASH = "hash"
_KEY = "sample-key"


class MemoryStream:
    def __init__(
        self,
        inbound: asyncio.Queue[bytes | None],
        outbound: asyncio.Queue[bytes | None],
    ) -> None:
        self._inbound = inbound
        self._outbound = outbound
        self._buf = bytearray()

    async def readexactly(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = await self._inbound.get()
            if chunk is None:
                raise asyncio.IncompleteReadError(bytes(self._buf), n)
            self._buf.extend(chunk)
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    async def write(self, data: bytes | bytearray | memoryview) -> None:
        await self._outbound.put(bytes(data))

    async def close(self) -> None:
        await self._outbound.put(None)


def _pair() -> tuple[MemoryStream, MemoryStream]:
    left: asyncio.Queue[bytes | None] = asyncio.Queue()
    right: asyncio.Queue[bytes | None] = asyncio.Queue()
    return MemoryStream(left, right), MemoryStream(right, left)


def _frame(payload: object) -> bytes:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return len(raw).to_bytes(4, "little") + raw


def _receipt(
    payload: dict[str, Any],
    *,
    kind: str = "receipt",
    seal: str = "complete",
    code: str = "",
) -> dict[str, object]:
    return {
        "kind": kind,
        "code": code,
        "transport_status": 204,
        "seal_report": seal,
        "binding_digest_hex": "ab",
        "target_endpoint": payload.get("endpoint", ""),
        "payload_hash": payload.get("payload_hash", ""),
        "idempotency_key": payload.get("idempotency_key", ""),
    }


async def _serve(
    stream: MemoryStream,
    responder: Callable[[dict[str, Any]], dict[str, object]],
    seen: list[dict[str, Any]],
) -> None:
    header = await stream.readexactly(4)
    length = int.from_bytes(header, "little")
    body = await stream.readexactly(length)
    parsed = json.loads(bytes(body))
    assert isinstance(parsed, dict)
    seen.append(parsed)
    await stream.write(_frame(responder(parsed)))


async def _run(
    monkeypatch: pytest.MonkeyPatch,
    responder: Callable[[dict[str, Any]], dict[str, object]],
    call: Callable[[NexusClient], Awaitable[object]],
    *,
    timeout: float = 2.0,
    max_payload_bytes: int = HARD_PAYLOAD_CAP,
) -> tuple[object, list[dict[str, Any]], int]:
    client_stream, server_stream = _pair()
    seen: list[dict[str, Any]] = []
    opens = 0

    async def open_broker(listen: str, timeout: float) -> Stream:
        nonlocal opens
        opens += 1
        assert listen == "local"
        assert timeout > 0
        return client_stream

    monkeypatch.setattr(transport, "open_broker", open_broker)
    task = asyncio.create_task(_serve(server_stream, responder, seen))
    try:
        result = await call(
            NexusClient("local", timeout=timeout, max_payload_bytes=max_payload_bytes)
        )
    finally:
        if not task.done():
            await client_stream.close()
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception:
                pass
        else:
            await task
    return result, seen, opens


def test_wipe_overwrites_the_buffer() -> None:
    buffer = bytearray(b"secret-material")
    wipe(buffer)
    assert buffer == bytearray(len(buffer))
    assert bytes(buffer).count(0) == len(buffer)


def test_frame_prefix_is_little_endian() -> None:
    class Capture:
        def __init__(self) -> None:
            self.chunks: list[bytes] = []

        async def readexactly(self, n: int) -> bytes:
            raise AssertionError(n)

        async def write(self, data: bytes | bytearray | memoryview) -> None:
            self.chunks.append(bytes(data))

        async def close(self) -> None:
            return None

    stream = Capture()
    asyncio.run(write_frame(stream, b"{}", 64, 1))
    assert stream.chunks[0] == b"\x02\x00\x00\x00"
    assert stream.chunks[1] == b"{}"


def test_zero_and_oversized_lengths_do_not_read_a_body() -> None:
    class Scripted:
        def __init__(self, header: bytes) -> None:
            self._header = header
            self.reads = 0

        async def readexactly(self, n: int) -> bytes:
            self.reads += 1
            assert n == 4
            return self._header

        async def write(self, data: bytes | bytearray | memoryview) -> None:
            raise AssertionError(data)

        async def close(self) -> None:
            return None

    async def check(header: bytes) -> int:
        stream = Scripted(header)
        with pytest.raises(PayloadTooLarge) as caught:
            await read_frame(stream, 1024, 1)
        assert caught.value.limit == 1024
        return stream.reads

    assert asyncio.run(check(b"\x00\x00\x00\x00")) == 1
    assert asyncio.run(check((2048).to_bytes(4, "little"))) == 1


def test_private_socket_rule_and_peer_cred() -> None:
    require_private_unix_socket(0o600, 7, 7, is_socket=True)
    require_private_unix_socket(0o100600, 7, 7, is_socket=True)
    with pytest.raises(IdentityRejected):
        require_private_unix_socket(0o640, 7, 7, is_socket=True)
    with pytest.raises(IdentityRejected):
        require_private_unix_socket(0o600, 8, 7, is_socket=True)
    with pytest.raises(IdentityRejected):
        require_private_unix_socket(0o600, 7, 7, is_socket=False)
    assert unpack_ucred(struct.pack("=iII", 42, 7, 9)) == (42, 7)
    assess_peer(42, 7, 7)
    with pytest.raises(IdentityRejected):
        assess_peer(42, 8, 7)
    with pytest.raises(IdentityUnavailable):
        assess_peer(0, 7, 7)
    with pytest.raises(IdentityUnavailable):
        unpack_ucred(b"short")


def test_package_has_no_secret_reader() -> None:
    root = Path(__file__).resolve().parents[1] / "src" / "nexus_ephemera"
    for path in root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "def get_secret" not in text
        assert "def read_secret" not in text
    assert "get_secret" not in dir(NexusClient)
    client = NexusClient("local")
    assert not hasattr(client, "get_secret")


def test_constructor_rejects_bad_limits() -> None:
    with pytest.raises(ProtocolError):
        NexusClient("")
    with pytest.raises(ProtocolError):
        NexusClient("local", timeout=0)
    with pytest.raises(ProtocolError):
        NexusClient("local", timeout=float("nan"))
    with pytest.raises(ProtocolError):
        NexusClient("local", max_payload_bytes=0)
    with pytest.raises(ProtocolError):
        NexusClient("local", max_payload_bytes=HARD_PAYLOAD_CAP + 1)


def test_invalid_calls_do_not_connect(monkeypatch: pytest.MonkeyPatch) -> None:
    async def scenario() -> None:
        opens = 0

        async def open_broker(listen: str, timeout: float) -> Stream:
            nonlocal opens
            opens += 1
            raise AssertionError((listen, timeout))

        monkeypatch.setattr(transport, "open_broker", open_broker)
        client = NexusClient("local")
        with pytest.raises(PayloadTooLarge) as endpoint:
            await client.execute("a" * 2049, _HASH, _KEY)
        assert endpoint.value.limit == 2048
        with pytest.raises(PayloadTooLarge) as wide:
            await client.execute("é" * 1025, _HASH, _KEY)
        assert wide.value.limit == 2048
        with pytest.raises(PayloadTooLarge) as hashed:
            await client.execute(_ENDPOINT, "h" * 129, _KEY)
        assert hashed.value.limit == 128
        with pytest.raises(Malformed):
            await client.execute("", _HASH, _KEY)
        with pytest.raises(Malformed):
            await client.execute(_ENDPOINT, "", _KEY)
        with pytest.raises(Malformed):
            await client.execute(_ENDPOINT, _HASH, "")
        with pytest.raises(Malformed):
            await client.execute(_ENDPOINT, _HASH, "has space")
        with pytest.raises(Malformed):
            await client.execute(_ENDPOINT, _HASH, "k" * 129)
        tiny = NexusClient("local", max_payload_bytes=32)
        with pytest.raises(PayloadTooLarge) as framed:
            await tiny.execute(_ENDPOINT, _HASH, _KEY)
        assert framed.value.limit == 32
        assert opens == 0

    asyncio.run(scenario())


def test_execute_returns_receipt_and_sends_only_call_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        result, seen, opens = await _run(
            monkeypatch,
            lambda payload: _receipt(payload),
            lambda client: client.execute(_ENDPOINT, _HASH, _KEY),
        )
        assert isinstance(result, dict)
        assert result["seal_report"] == "complete"
        assert result["transport_status"] == 204
        assert result["target_endpoint"] == _ENDPOINT
        assert seen[0]["op"] == "call"
        assert set(seen[0]) == {"op", "endpoint", "payload_hash", "idempotency_key"}
        assert "secret" not in seen[0]
        assert opens == 1

    asyncio.run(scenario())


def test_metrics_snapshot_is_five_integers(monkeypatch: pytest.MonkeyPatch) -> None:
    async def scenario() -> None:
        def respond(payload: dict[str, Any]) -> dict[str, object]:
            assert payload == {
                "op": "metrics",
                "endpoint": "",
                "payload_hash": "",
                "idempotency_key": "",
            }
            return {
                "kind": "metrics",
                "wipe_success_count": 2,
                "quarantine_trigger_total": 1,
                "cleanup_incomplete_rate": 0,
                "ipc_auth_failure_total": 4,
                "p95_dispatch_latency_us": 15,
            }

        result, _seen, _opens = await _run(
            monkeypatch, respond, lambda client: client.metrics()
        )
        assert result == {
            "wipe_success_count": 2,
            "quarantine_trigger_total": 1,
            "cleanup_incomplete_rate": 0,
            "ipc_auth_failure_total": 4,
            "p95_dispatch_latency_us": 15,
        }

    asyncio.run(scenario())


def test_partial_and_failed_seals_are_not_receipts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        for kind, seal in (
            ("receipt", "partial"),
            ("receipt", "failed"),
            ("cleanup_incomplete", "failed"),
        ):
            with pytest.raises(CleanupIncomplete) as caught:
                await _run(
                    monkeypatch,
                    lambda payload, kind=kind, seal=seal: _receipt(
                        payload, kind=kind, seal=seal
                    ),
                    lambda client: client.execute(_ENDPOINT, _HASH, _KEY),
                )
            assert caught.value.receipt["seal_report"] == seal

    asyncio.run(scenario())


def test_mismatched_seal_and_correlation_are_malformed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        with pytest.raises(Malformed):
            await _run(
                monkeypatch,
                lambda payload: _receipt(payload, kind="cleanup_incomplete", seal="complete"),
                lambda client: client.execute(_ENDPOINT, _HASH, _KEY),
            )
        with pytest.raises(Malformed):
            await _run(
                monkeypatch,
                lambda payload: _receipt(payload, seal="nope"),
                lambda client: client.execute(_ENDPOINT, _HASH, _KEY),
            )

        def swapped(payload: dict[str, Any]) -> dict[str, object]:
            body = _receipt(payload)
            body["target_endpoint"] = "https://evil.example/charge"
            return body

        with pytest.raises(Malformed):
            await _run(
                monkeypatch,
                swapped,
                lambda client: client.execute(_ENDPOINT, _HASH, _KEY),
            )
        with pytest.raises(Malformed):
            await _run(
                monkeypatch,
                lambda _payload: {"kind": "receipt", "transport_status": True},
                lambda client: client.execute(_ENDPOINT, _HASH, _KEY),
            )

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("target_denied", TargetDenied),
        ("idempotency_conflict", IdempotencyConflict),
        ("inconclusive", Inconclusive),
        ("rate_limited", RateLimited),
        ("forged", ProtocolError),
    ],
)
def test_rejected_codes(
    monkeypatch: pytest.MonkeyPatch,
    code: str,
    expected: type[Exception],
) -> None:
    async def scenario() -> None:
        with pytest.raises(expected):
            await _run(
                monkeypatch,
                lambda _payload: {
                    "kind": "rejected",
                    "code": code,
                    "transport_status": 0,
                    "seal_report": "",
                    "binding_digest_hex": "",
                    "target_endpoint": "",
                    "payload_hash": "",
                    "idempotency_key": "",
                },
                lambda client: client.execute(_ENDPOINT, _HASH, _KEY),
            )

    asyncio.run(scenario())


def test_io_failure_retries_and_identity_does_not(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        client_stream, server_stream = _pair()
        opens = 0

        async def open_broker(listen: str, timeout: float) -> Stream:
            nonlocal opens
            opens += 1
            if opens == 1:
                raise IoFailure("ipc io: unavailable")
            return client_stream

        monkeypatch.setattr(transport, "open_broker", open_broker)
        task = asyncio.create_task(
            _serve(server_stream, lambda payload: _receipt(payload), [])
        )
        client = NexusClient("local", timeout=2)
        result = await client.execute(_ENDPOINT, _HASH, _KEY)
        await task
        assert result["seal_report"] == "retained" or result["seal_report"] == "complete"
        assert opens == 2

        denied = 0

        async def reject(listen: str, timeout: float) -> Stream:
            nonlocal denied
            denied += 1
            raise IdentityRejected("ipc: caller identity rejected")

        monkeypatch.setattr(transport, "open_broker", reject)
        with pytest.raises(IdentityRejected):
            await client.execute(_ENDPOINT, _HASH, _KEY)
        assert denied == 1

        blocked = 0

        async def forbid(listen: str, timeout: float) -> Stream:
            nonlocal blocked
            blocked += 1
            raise IoFailure("ipc io: access denied", permission_denied=True)

        monkeypatch.setattr(transport, "open_broker", forbid)
        with pytest.raises(IoFailure):
            await client.execute(_ENDPOINT, _HASH, _KEY)
        assert blocked == 1

    asyncio.run(scenario())


def test_timeout_is_retried_until_the_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    async def scenario() -> None:
        opens = 0

        async def open_broker(listen: str, timeout: float) -> Stream:
            nonlocal opens
            opens += 1
            raise TimedOut()

        monkeypatch.setattr(transport, "open_broker", open_broker)
        client = NexusClient("local", timeout=0.05)
        with pytest.raises(TimedOut):
            await client.metrics()
        assert opens >= 2

    asyncio.run(scenario())


@pytest.mark.skipif(sys.platform == "win32", reason="unix socket")
def test_live_unix_socket_checks_mode_before_connect() -> None:
    asyncio.run(_live_unix())


async def _live_unix() -> None:
    import os
    import tempfile

    directory = tempfile.mkdtemp(prefix="nexus-ephemera-py-")
    os.chmod(directory, 0o700)
    path = os.path.join(directory, "broker.sock")
    accepts = 0

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        nonlocal accepts
        accepts += 1
        header = await reader.readexactly(4)
        length = int.from_bytes(header, "little")
        body = json.loads(await reader.readexactly(length))
        assert isinstance(body, dict)
        raw = json.dumps(_receipt(body), separators=(",", ":")).encode("utf-8")
        writer.write(len(raw).to_bytes(4, "little") + raw)
        await writer.drain()
        writer.close()

    server = await asyncio.start_unix_server(handler, path)
    os.chmod(path, 0o600)
    try:
        client = NexusClient(path, timeout=2)
        receipt = await client.execute(_ENDPOINT, _HASH, _KEY)
        assert receipt["seal_report"] == "complete"
        assert accepts == 1
        os.chmod(path, 0o640)
        with pytest.raises(IdentityRejected):
            await client.metrics()
        assert accepts == 1
    finally:
        server.close()
        await server.wait_closed()
        os.unlink(path)
        os.rmdir(directory)


@pytest.mark.skipif(sys.platform != "win32", reason="named pipe")
def test_live_named_pipe_roundtrip() -> None:
    asyncio.run(_live_pipe())


async def _live_pipe() -> None:
    import ctypes
    import threading
    from ctypes import wintypes

    name = rf"\\.\pipe\nexus-ephemera-py-{uuid.uuid4().hex}"
    ready = threading.Event()
    error: list[BaseException] = []
    seen: list[dict[str, Any]] = []

    def serve() -> None:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateNamedPipeW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
        ]
        kernel.CreateNamedPipeW.restype = ctypes.c_void_p
        kernel.ConnectNamedPipe.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        kernel.ConnectNamedPipe.restype = wintypes.BOOL
        kernel.ReadFile.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
        ]
        kernel.ReadFile.restype = wintypes.BOOL
        kernel.WriteFile.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
        ]
        kernel.WriteFile.restype = wintypes.BOOL
        kernel.FlushFileBuffers.argtypes = [ctypes.c_void_p]
        kernel.FlushFileBuffers.restype = wintypes.BOOL
        kernel.DisconnectNamedPipe.argtypes = [ctypes.c_void_p]
        kernel.DisconnectNamedPipe.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel.CloseHandle.restype = wintypes.BOOL
        raw = kernel.CreateNamedPipeW(
            name,
            0x00000003,
            0x00000008,
            1,
            65536,
            65536,
            0,
            None,
        )
        handle = raw if isinstance(raw, int) else None
        invalid = ctypes.c_void_p(-1).value
        if handle in (None, 0, invalid):
            error.append(ctypes.WinError(ctypes.get_last_error()))
            ready.set()
            return
        try:
            ready.set()
            connected = bool(kernel.ConnectNamedPipe(handle, None))
            if not connected and ctypes.get_last_error() != 535:
                error.append(ctypes.WinError(ctypes.get_last_error()))
                return

            def read_exact(size: int) -> bytes:
                out = bytearray()
                while len(out) < size:
                    chunk = ctypes.create_string_buffer(size - len(out))
                    got = wintypes.DWORD(0)
                    ok = kernel.ReadFile(
                        handle, chunk, len(chunk), ctypes.byref(got), None
                    )
                    if not ok or got.value == 0:
                        raise OSError(ctypes.get_last_error())
                    out += chunk.raw[: int(got.value)]
                return bytes(out)

            header = read_exact(4)
            body = read_exact(int.from_bytes(header, "little"))
            parsed = json.loads(body)
            assert isinstance(parsed, dict)
            seen.append(parsed)
            raw_body = json.dumps(_receipt(parsed), separators=(",", ":")).encode("utf-8")
            frame = len(raw_body).to_bytes(4, "little") + raw_body
            sent = 0
            while sent < len(frame):
                view = ctypes.create_string_buffer(frame[sent:])
                wrote = wintypes.DWORD(0)
                ok = kernel.WriteFile(
                    handle, view, len(view) - 1, ctypes.byref(wrote), None
                )
                if not ok or wrote.value == 0:
                    raise OSError(ctypes.get_last_error())
                sent += int(wrote.value)
            kernel.FlushFileBuffers(handle)
            leftover = ctypes.create_string_buffer(1)
            ignored = wintypes.DWORD(0)
            kernel.ReadFile(handle, leftover, 1, ctypes.byref(ignored), None)
        except BaseException as exc:
            error.append(exc)
        finally:
            kernel.DisconnectNamedPipe(handle)
            kernel.CloseHandle(handle)
            ready.set()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    assert ready.wait(5)
    if error:
        raise error[0]
    client_error: list[BaseException] = []
    receipt: dict[str, object] | None = None
    try:
        receipt = await NexusClient(name, timeout=5).execute(_ENDPOINT, _HASH, _KEY)
    except BaseException as exc:
        client_error.append(exc)
    finally:
        thread.join(10)
    if client_error:
        raise client_error[0]
    if error:
        raise error[0]
    assert receipt is not None
    assert receipt["seal_report"] == "complete"
    assert receipt["transport_status"] == 204
    assert seen and seen[0]["op"] == "call"
    assert "secret" not in seen[0]
    assert not thread.is_alive()
