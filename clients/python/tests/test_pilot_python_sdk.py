"""Phase 3 pilot for the Python client: framing, peer socket, worker cap, timeout."""

from __future__ import annotations

import asyncio
import ctypes
import os
from pathlib import Path
import socket
import sys
import threading
import tempfile
import time

import pytest

from nexus_ephemera import NexusClient, TargetDenied, TimedOut
from nexus_ephemera import transport
from nexus_ephemera.errors import IdentityUnavailable, IoFailure
from nexus_ephemera.framing import Stream, read_frame, wipe, write_frame
from nexus_ephemera.identity import peer_socket_ready


def test_pilot_live_python_to_daemon() -> None:
    """CI must supply the exact binary built by its Rust release test step."""
    binary = os.environ.get("NEXUS_DAEMON_EXE")
    if not binary:
        pytest.skip("live pilot requires NEXUS_DAEMON_EXE")
    assert Path(binary).is_file(), "configured daemon is missing"

    async def scenario(private: Path) -> None:
        listen = (
            rf"\\.\pipe\nexus-python-pilot-{os.getpid()}"
            if sys.platform == "win32" else str(private / "p.sock")
        )
        if sys.platform != "win32":
            private.chmod(0o700)
        process = await asyncio.create_subprocess_exec(
            binary, "--listen", listen, "--allow", "https://provider.example/charge",
            "--timeout-ms", "2000", "--max-connections", "3",
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            assert process.stdin is not None and process.stdout is not None
            process.stdin.write(b"public-test-fixture-secret")
            await process.stdin.drain()
            process.stdin.close()
            ready = await asyncio.wait_for(process.stdout.readline(), 15)
            if ready != b"ready\n":
                _, stderr = await asyncio.wait_for(process.communicate(), 5)
                diagnostic = stderr.replace(b"public-test-fixture-secret", b"[REDACTED]")
                pytest.fail(
                    f"daemon startup failed (exit={process.returncode}): "
                    + diagnostic.decode(errors="replace")
                )
            client = NexusClient(listen, timeout=3)
            first = await client.execute("https://provider.example/charge", "hash", "live-key")
            replay = await client.execute("https://provider.example/charge", "hash", "live-key")
            assert first == replay
            with pytest.raises(TargetDenied):
                await client.execute("https://provider.example/charge?x=1", "hash", "denied")
            _, stderr = await asyncio.wait_for(process.communicate(), 15)
            assert process.returncode == 0, stderr.decode(errors="replace")
            assert b"shutdown seal=complete" in stderr
            assert b"public-test-fixture-secret" not in stderr
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()

    with tempfile.TemporaryDirectory(prefix="nx-", dir="/tmp" if sys.platform != "win32" else None) as private:
        asyncio.run(scenario(Path(private)))


class _Memory:
    def __init__(self, inbound: asyncio.Queue[bytes | None]) -> None:
        self._inbound = inbound
        self._outbound: asyncio.Queue[bytes | None] = asyncio.Queue()
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

    async def written(self) -> bytes:
        chunk = await self._outbound.get()
        assert chunk is not None
        return chunk


def test_pilot_frame_is_little_endian_and_the_caller_wipes_the_body() -> None:
    body = bytearray(b'{"op":"call","endpoint":"https://provider.example/charge"}')
    prefix = len(body).to_bytes(4, "little")
    assert int.from_bytes(prefix, "little") == len(body)
    assert prefix == len(body).to_bytes(4, "big")[::-1]

    async def scenario() -> None:
        inbound: asyncio.Queue[bytes | None] = asyncio.Queue()
        stream = _Memory(inbound)
        await write_frame(stream, body, 1024, 1)
        header = await stream.written()
        payload = await stream.written()
        framed = header + payload
        assert framed[:4] == prefix
        assert framed[4:] == bytes(body)
        inbound.put_nowait(framed)
        echoed = await read_frame(stream, 1024, 1)
        try:
            assert bytes(echoed) == bytes(body)
        finally:
            wipe(echoed)

    asyncio.run(scenario())
    wipe(body)
    assert bytes(body) == b"\x00" * len(body)


def test_pilot_transport_socket_wrapper_exposes_a_peer_fd() -> None:
    class TransportSocket:
        def fileno(self) -> int:
            return 11

        def getsockopt(self, level: int, optname: int, buflen: int) -> bytes:
            return b"\x00" * buflen

    wrapper = TransportSocket()
    assert not isinstance(wrapper, socket.socket)
    assert peer_socket_ready(wrapper) == 11
    with pytest.raises(IdentityUnavailable):
        peer_socket_ready(object())


def test_pilot_timeout_budget_is_enforced_with_wait_for(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        async def open_broker(listen: str, timeout: float) -> Stream:
            await asyncio.sleep(30)
            raise AssertionError((listen, timeout))

        monkeypatch.setattr(transport, "open_broker", open_broker)
        started = time.monotonic()
        with pytest.raises(TimedOut):
            await NexusClient("local", timeout=0.05).metrics()
        assert time.monotonic() - started < 1

    asyncio.run(scenario())


def test_pilot_client_surfaces_target_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    async def scenario() -> None:
        async def open_broker(listen: str, timeout: float) -> Stream:
            assert listen == "pilot"
            assert timeout > 0
            inbound: asyncio.Queue[bytes | None] = asyncio.Queue()
            stream = _Memory(inbound)
            raw = (
                b'{"kind":"rejected","code":"target_denied","transport_status":0,'
                b'"seal_report":"failed","binding_digest_hex":"","target_endpoint":"",'
                b'"payload_hash":"","idempotency_key":""}'
            )
            inbound.put_nowait(len(raw).to_bytes(4, "little") + raw)
            return stream

        monkeypatch.setattr(transport, "open_broker", open_broker)
        with pytest.raises(TargetDenied):
            await NexusClient("pilot", timeout=1).execute(
                "https://provider.example/charge",
                "hash",
                "pilot-key",
            )

    asyncio.run(scenario())


@pytest.mark.skipif(sys.platform != "win32", reason="named-pipe worker cap")
def test_pilot_windows_worker_cap_is_32_and_overlapped_stays_aligned() -> None:
    from nexus_ephemera._windows import _MAX_WORKERS, _OVERLAPPED, _await_worker

    pointer = ctypes.sizeof(ctypes.c_void_p)
    expected = 32 if pointer == 8 else 20
    assert ctypes.sizeof(_OVERLAPPED) == expected
    assert _MAX_WORKERS == 32

    async def scenario() -> None:
        release = threading.Event()
        entered = 0
        lock = threading.Lock()
        ready = threading.Event()

        def hold() -> None:
            nonlocal entered
            with lock:
                entered += 1
                if entered == _MAX_WORKERS:
                    ready.set()
            assert release.wait(5)

        tasks = [asyncio.create_task(_await_worker(hold)) for _ in range(_MAX_WORKERS)]
        try:
            assert await asyncio.to_thread(ready.wait, 2)
            with pytest.raises(IoFailure, match="pending operation capacity exhausted"):
                await _await_worker(hold)
        finally:
            release.set()
            await asyncio.gather(*tasks)
        assert await _await_worker(lambda: "recovered") == "recovered"

    asyncio.run(scenario())
