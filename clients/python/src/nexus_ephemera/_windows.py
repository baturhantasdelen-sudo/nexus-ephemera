"""Windows named-pipe transport.

Pipe reads use overlapped I/O and a wait so a stalled broker cannot pin a
worker past the client timeout. The server process user SID is compared
before the first write. This is not mTLS.
"""

from __future__ import annotations

import sys

from .errors import IoFailure
from .framing import Stream

if sys.platform != "win32":

    async def open_pipe(listen: str, timeout: float) -> Stream:
        """Named pipes exist only on Windows."""

        raise IoFailure("ipc io: named pipes are unavailable")

else:
    import asyncio
    import ctypes
    import threading
    from ctypes import wintypes

    from .errors import IdentityRejected, IdentityUnavailable, TimedOut
    from .framing import wipe

    _GENERIC_READ_WRITE = 0xC0000000
    _OPEN_EXISTING = 3
    _FILE_FLAG_OVERLAPPED = 0x40000000
    _PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    _TOKEN_QUERY = 0x0008
    _TOKEN_USER = 1
    _SECURITY_MAX_SID_SIZE = 68
    _ERROR_BROKEN_PIPE = 109
    _ERROR_NO_DATA = 232
    _ERROR_PIPE_NOT_CONNECTED = 233
    _ERROR_OPERATION_ABORTED = 995
    _ERROR_IO_PENDING = 997
    _WAIT_OBJECT_0 = 0
    _WAIT_TIMEOUT = 258

    class _OVERLAPPED(ctypes.Structure):
        _fields_ = (
            ("Internal", ctypes.c_size_t),
            ("InternalHigh", ctypes.c_size_t),
            ("Offset", wintypes.DWORD),
            ("OffsetHigh", wintypes.DWORD),
            ("hEvent", ctypes.c_void_p),
        )

    class _SidAndAttributes(ctypes.Structure):
        _fields_ = (
            ("Sid", ctypes.c_void_p),
            ("Attributes", wintypes.DWORD),
        )

    class _TokenUser(ctypes.Structure):
        _fields_ = (("User", _SidAndAttributes),)

    class _Dlls:
        def __init__(self) -> None:
            self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            self.advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
            self._bind()

        def _bind(self) -> None:
            k32 = self.kernel32
            adv = self.advapi32
            k32.CreateFileW.argtypes = [
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.c_void_p,
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.c_void_p,
            ]
            k32.CreateFileW.restype = ctypes.c_void_p
            k32.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
            k32.WaitNamedPipeW.restype = wintypes.BOOL
            k32.CloseHandle.argtypes = [ctypes.c_void_p]
            k32.CloseHandle.restype = wintypes.BOOL
            k32.CreateEventW.argtypes = [
                ctypes.c_void_p,
                wintypes.BOOL,
                wintypes.BOOL,
                wintypes.LPCWSTR,
            ]
            k32.CreateEventW.restype = ctypes.c_void_p
            k32.ResetEvent.argtypes = [ctypes.c_void_p]
            k32.ResetEvent.restype = wintypes.BOOL
            k32.ReadFile.argtypes = [
                ctypes.c_void_p,
                ctypes.c_void_p,
                wintypes.DWORD,
                ctypes.c_void_p,
                ctypes.c_void_p,
            ]
            k32.ReadFile.restype = wintypes.BOOL
            k32.WriteFile.argtypes = [
                ctypes.c_void_p,
                ctypes.c_void_p,
                wintypes.DWORD,
                ctypes.c_void_p,
                ctypes.c_void_p,
            ]
            k32.WriteFile.restype = wintypes.BOOL
            k32.GetOverlappedResult.argtypes = [
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.POINTER(wintypes.DWORD),
                wintypes.BOOL,
            ]
            k32.GetOverlappedResult.restype = wintypes.BOOL
            k32.WaitForSingleObject.argtypes = [ctypes.c_void_p, wintypes.DWORD]
            k32.WaitForSingleObject.restype = wintypes.DWORD
            k32.CancelIoEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            k32.CancelIoEx.restype = wintypes.BOOL
            k32.GetNamedPipeServerProcessId.argtypes = [
                ctypes.c_void_p,
                ctypes.POINTER(wintypes.DWORD),
            ]
            k32.GetNamedPipeServerProcessId.restype = wintypes.BOOL
            k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            k32.OpenProcess.restype = ctypes.c_void_p
            k32.GetCurrentProcess.argtypes = []
            k32.GetCurrentProcess.restype = ctypes.c_void_p
            adv.OpenProcessToken.argtypes = [
                ctypes.c_void_p,
                wintypes.DWORD,
                ctypes.POINTER(ctypes.c_void_p),
            ]
            adv.OpenProcessToken.restype = wintypes.BOOL
            adv.GetTokenInformation.argtypes = [
                ctypes.c_void_p,
                wintypes.DWORD,
                ctypes.c_void_p,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
            ]
            adv.GetTokenInformation.restype = wintypes.BOOL
            adv.GetLengthSid.argtypes = [ctypes.c_void_p]
            adv.GetLengthSid.restype = wintypes.DWORD
            adv.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            adv.EqualSid.restype = wintypes.BOOL

    _DLLS: list[_Dlls] = []

    def _dlls() -> _Dlls:
        if not _DLLS:
            _DLLS.append(_Dlls())
        return _DLLS[0]

    def _invalid_handle() -> int | None:
        return ctypes.c_void_p(-1).value

    def _handle_of(raw: object) -> int | None:
        if raw is None:
            return None
        if isinstance(raw, int):
            value = raw
        else:
            candidate = getattr(raw, "value", None)
            if not isinstance(candidate, int):
                return None
            value = candidate
        invalid = _invalid_handle()
        if value == 0 or value == -1 or value == invalid:
            return None
        return value

    def _milliseconds(timeout: float) -> int:
        millis = int(timeout * 1000)
        if millis < 1:
            return 1
        if millis > 0xFFFFFFFE:
            return 0xFFFFFFFE
        return millis

    def _raise_open(err: int) -> None:
        if err == 5:
            raise IoFailure("ipc io: access denied", permission_denied=True)
        if err == 2:
            raise IoFailure("ipc io: pipe not found")
        if err == 231:
            raise IoFailure("ipc io: pipe busy")
        raise IoFailure(f"ipc io: winerror {err}")

    def _create_file(path: str) -> tuple[int | None, int]:
        raw = _dlls().kernel32.CreateFileW(
            path,
            _GENERIC_READ_WRITE,
            0,
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_OVERLAPPED,
            None,
        )
        handle = _handle_of(raw)
        if handle is None:
            return None, int(ctypes.get_last_error())
        return handle, 0

    def _open_handle(path: str, timeout: float) -> int:
        handle, err = _create_file(path)
        if handle is not None:
            return handle
        if err == 231 and bool(
            _dlls().kernel32.WaitNamedPipeW(path, _milliseconds(timeout))
        ):
            handle, err = _create_file(path)
            if handle is not None:
                return handle
        _raise_open(err)
        raise IoFailure("ipc io: pipe open failed")

    def _close_handle(handle: int) -> None:
        if handle:
            _dlls().kernel32.CloseHandle(handle)

    def _create_event() -> int:
        raw = _dlls().kernel32.CreateEventW(None, True, False, None)
        handle = _handle_of(raw)
        if handle is None:
            raise IoFailure("ipc io: event")
        return handle

    def _require_layout() -> None:
        pointer = ctypes.sizeof(ctypes.c_void_p)
        expected = 32 if pointer == 8 else 20
        if ctypes.sizeof(_OVERLAPPED) != expected:
            raise IoFailure("ipc io: overlapped layout")

    def _server_pid(handle: int) -> int:
        pid = wintypes.DWORD(0)
        ok = _dlls().kernel32.GetNamedPipeServerProcessId(handle, ctypes.byref(pid))
        if not ok or pid.value == 0:
            raise IdentityUnavailable("ipc: caller identity unavailable")
        return int(pid.value)

    def _current_process_handle() -> int:
        """Return the process pseudo-handle. It is `(HANDLE)-1` and must stay open."""

        raw = _dlls().kernel32.GetCurrentProcess()
        if isinstance(raw, int) and raw != 0:
            return raw
        candidate = getattr(raw, "value", None)
        if isinstance(candidate, int) and candidate != 0:
            return candidate
        raise IdentityUnavailable("ipc: caller identity unavailable")

    def _token(process: int) -> int:
        out = ctypes.c_void_p()
        ok = _dlls().advapi32.OpenProcessToken(process, _TOKEN_QUERY, ctypes.byref(out))
        handle = _handle_of(out.value if ok else None)
        if handle is None:
            raise IdentityUnavailable("ipc: caller identity unavailable")
        return handle

    def _sid_bytes(token: int) -> bytes:
        adv = _dlls().advapi32
        needed = wintypes.DWORD(0)
        adv.GetTokenInformation(token, _TOKEN_USER, None, 0, ctypes.byref(needed))
        size = int(needed.value)
        if size <= 0 or size > 4096:
            raise IdentityUnavailable("ipc: caller identity unavailable")
        buf = ctypes.create_string_buffer(size)
        if not adv.GetTokenInformation(
            token, _TOKEN_USER, buf, size, ctypes.byref(needed)
        ):
            raise IdentityUnavailable("ipc: caller identity unavailable")
        user = _TokenUser.from_buffer(buf)
        if not user.User.Sid:
            raise IdentityUnavailable("ipc: caller identity unavailable")
        length = int(adv.GetLengthSid(user.User.Sid))
        if length <= 0 or length > _SECURITY_MAX_SID_SIZE:
            raise IdentityUnavailable("ipc: caller identity unavailable")
        return ctypes.string_at(user.User.Sid, length)

    def _sids_equal(left: bytes, right: bytes) -> bool:
        first = ctypes.create_string_buffer(left)
        second = ctypes.create_string_buffer(right)
        try:
            return bool(_dlls().advapi32.EqualSid(first, second))
        finally:
            ctypes.memset(first, 0, len(left))
            ctypes.memset(second, 0, len(right))

    def _same_user(pid: int) -> bool:
        k32 = _dlls().kernel32
        raw = k32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        process = _handle_of(raw)
        if process is None:
            raise IdentityUnavailable("ipc: caller identity unavailable")
        remote = 0
        local = 0
        try:
            remote = _token(process)
            local = _token(_current_process_handle())
            return _sids_equal(_sid_bytes(remote), _sid_bytes(local))
        finally:
            if remote:
                k32.CloseHandle(remote)
            if local:
                k32.CloseHandle(local)
            k32.CloseHandle(process)

    def _require_server_user(handle: int) -> None:
        try:
            same = _same_user(_server_pid(handle))
        except IdentityUnavailable:
            raise
        except OSError as exc:
            raise IdentityUnavailable("ipc: caller identity unavailable") from exc
        if not same:
            raise IdentityRejected("ipc: caller identity rejected")

    class _Pipe:
        def __init__(self, handle: int, timeout: float) -> None:
            _require_layout()
            self._handle = handle
            self._timeout_ms = _milliseconds(timeout)
            self._event = 0
            self._lock = threading.Lock()
            self._op = threading.Lock()
            self._busy = 0
            self._idle = threading.Event()
            self._idle.set()
            self._closed = False
            self._event = _create_event()

        async def readexactly(self, n: int) -> bytes:
            return await asyncio.to_thread(self._read_exact, n)

        async def write(self, data: bytes | bytearray | memoryview) -> None:
            payload = bytearray(data)
            try:
                await asyncio.to_thread(self._write_all, payload)
            finally:
                wipe(payload)

        async def close(self) -> None:
            await asyncio.to_thread(self._close)

        def _begin(self) -> None:
            with self._lock:
                if self._closed:
                    raise IoFailure("ipc io: closed")
                if self._busy == 0:
                    self._idle.clear()
                self._busy += 1

        def _end(self) -> None:
            with self._lock:
                self._busy -= 1
                if self._busy == 0:
                    self._idle.set()

        def _read_exact(self, n: int) -> bytes:
            with self._op:
                self._begin()
                out = bytearray()
                copied = b""
                try:
                    while len(out) < n:
                        chunk = self._read_some(n - len(out))
                        if not chunk:
                            raise IoFailure("ipc io: unexpected eof")
                        out += chunk
                    copied = bytes(out)
                finally:
                    wipe(out)
                    self._end()
            return copied

        def _write_all(self, payload: bytearray) -> None:
            with self._op:
                self._begin()
                try:
                    if not payload:
                        return
                    view = (ctypes.c_char * len(payload)).from_buffer(payload)
                    base = ctypes.addressof(view)
                    sent = 0
                    total = len(payload)
                    while sent < total:
                        wrote = self._transfer(base + sent, total - sent, write=True)
                        if wrote <= 0:
                            raise IoFailure("ipc io: short write")
                        sent += wrote
                finally:
                    self._end()

        def _read_some(self, size: int) -> bytes:
            buf = ctypes.create_string_buffer(size)
            try:
                count = self._transfer(ctypes.addressof(buf), size, write=False)
                if count <= 0:
                    return b""
                return buf.raw[:count]
            finally:
                ctypes.memset(buf, 0, size)

        def _transfer(self, address: int, size: int, *, write: bool) -> int:
            k32 = _dlls().kernel32
            overlapped = _OVERLAPPED()
            overlapped.hEvent = self._event
            with self._lock:
                if self._closed or self._handle == 0:
                    raise IoFailure("ipc io: closed")
                k32.ResetEvent(self._event)
                starter = k32.WriteFile if write else k32.ReadFile
                immediate = wintypes.DWORD(0)
                ok = bool(
                    starter(
                        self._handle,
                        address,
                        size,
                        ctypes.addressof(immediate),
                        ctypes.addressof(overlapped),
                    )
                )
                err = int(ctypes.get_last_error())
                handle = self._handle
                transferred_now = int(immediate.value)
            if ok:
                return transferred_now
            if err != _ERROR_IO_PENDING:
                _raise_transfer(err, write)
            if not ok:
                waited = int(k32.WaitForSingleObject(self._event, self._timeout_ms))
                if waited == _WAIT_TIMEOUT:
                    with self._lock:
                        if self._handle:
                            k32.CancelIoEx(self._handle, ctypes.addressof(overlapped))
                    k32.WaitForSingleObject(self._event, 5000)
                    raise TimedOut()
                if waited != _WAIT_OBJECT_0:
                    raise IoFailure("ipc io: wait failed")
            return _overlapped_count(handle, overlapped, write)

        def _close(self) -> None:
            k32 = _dlls().kernel32
            with self._lock:
                self._closed = True
                handle = self._handle
            if handle:
                k32.CancelIoEx(handle, None)
            self._idle.wait((self._timeout_ms / 1000) + 5)
            with self._lock:
                if self._handle:
                    k32.CloseHandle(self._handle)
                    self._handle = 0
                if self._event:
                    k32.CloseHandle(self._event)
                    self._event = 0

    def _overlapped_count(handle: int, overlapped: _OVERLAPPED, write: bool) -> int:
        transferred = wintypes.DWORD(0)
        ok = _dlls().kernel32.GetOverlappedResult(
            handle,
            ctypes.addressof(overlapped),
            ctypes.byref(transferred),
            False,
        )
        if not ok:
            err = int(ctypes.get_last_error())
            if err == _ERROR_OPERATION_ABORTED:
                raise TimedOut()
            _raise_transfer(err, write)
        return int(transferred.value)

    def _raise_transfer(err: int, write: bool) -> None:
        if not write and err in {
            _ERROR_BROKEN_PIPE,
            _ERROR_NO_DATA,
            _ERROR_PIPE_NOT_CONNECTED,
        }:
            raise IoFailure("ipc io: unexpected eof")
        if err == 5:
            raise IoFailure("ipc io: access denied", permission_denied=True)
        raise IoFailure(f"ipc io: winerror {err}")

    async def open_pipe(listen: str, timeout: float) -> Stream:
        handle = _open_handle(listen, timeout)
        accepted = False
        try:
            _require_server_user(handle)
            pipe = _Pipe(handle, timeout)
            accepted = True
            return pipe
        finally:
            if not accepted:
                _close_handle(handle)
