"""Unix domain socket transport. The socket is checked before connect."""

from __future__ import annotations

import sys

from .errors import IdentityUnavailable, IoFailure
from .framing import Stream

if sys.platform == "win32":

    async def open_socket(listen: str, timeout: float) -> Stream:
        raise IoFailure("ipc io: unix sockets are unavailable")

else:
    import asyncio
    import os
    import socket
    import stat

    from .errors import TimedOut, io_failure
    from .identity import assess_peer, require_private_unix_socket, unpack_ucred

    class _UnixStream:
        def __init__(
            self,
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            self._reader = reader
            self._writer = writer

        async def readexactly(self, n: int) -> bytes:
            try:
                return await self._reader.readexactly(n)
            except asyncio.IncompleteReadError as exc:
                raise IoFailure("ipc io: unexpected eof") from exc

        async def write(self, data: bytes | bytearray | memoryview) -> None:
            self._writer.write(data)
            await self._writer.drain()

        async def close(self) -> None:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                return

    def _check_file(path: str) -> None:
        try:
            info = os.stat(path)
        except OSError as exc:
            raise io_failure(exc) from exc
        require_private_unix_socket(
            info.st_mode,
            info.st_uid,
            os.getuid(),
            is_socket=stat.S_ISSOCK(info.st_mode),
        )

    def _check_peer(sock: socket.socket) -> None:
        if sys.platform == "linux":
            try:
                raw = sock.getsockopt(socket.SOL_SOCKET, 17, 12)
            except OSError as exc:
                raise IdentityUnavailable("ipc: caller identity unavailable") from exc
            pid, uid = unpack_ucred(raw)
            assess_peer(pid, uid, os.getuid())
            return
        if sys.platform == "darwin":
            _check_darwin_peer(sock)
            return
        raise IdentityUnavailable("ipc: caller identity unavailable")

    def _check_darwin_peer(sock: socket.socket) -> None:
        import ctypes

        libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        getpeereid = libc.getpeereid
        getpeereid.argtypes = [
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_uint32),
        ]
        getpeereid.restype = ctypes.c_int
        uid = ctypes.c_uint32()
        group = ctypes.c_uint32()
        if getpeereid(sock.fileno(), ctypes.byref(uid), ctypes.byref(group)) != 0:
            raise IdentityUnavailable("ipc: caller identity unavailable")
        try:
            raw_pid = sock.getsockopt(0, 0x002, 4)
        except OSError as exc:
            raise IdentityUnavailable("ipc: caller identity unavailable") from exc
        if len(raw_pid) != 4:
            raise IdentityUnavailable("ipc: caller identity unavailable")
        pid = int.from_bytes(raw_pid, sys.byteorder)
        assess_peer(pid, int(uid.value), os.getuid())

    async def open_socket(listen: str, timeout: float) -> Stream:
        _check_file(listen)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(listen),
                timeout,
            )
        except TimeoutError as exc:
            raise TimedOut() from exc
        except OSError as exc:
            raise io_failure(exc) from exc
        verified = False
        try:
            sock = writer.get_extra_info("socket")
            if not isinstance(sock, socket.socket):
                raise IdentityUnavailable("ipc: caller identity unavailable")
            _check_peer(sock)
            verified = True
            return _UnixStream(reader, writer)
        finally:
            if not verified:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
