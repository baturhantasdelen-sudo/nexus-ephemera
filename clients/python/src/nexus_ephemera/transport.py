"""Open the platform broker endpoint. Tests replace `open_broker`."""

from __future__ import annotations

import sys

from .framing import Stream


async def open_broker(listen: str, timeout: float) -> Stream:
    """Connect and identify the server before the caller writes a frame."""

    if sys.platform == "win32":
        from . import _windows

        return await _windows.open_pipe(listen, timeout)
    from . import _unix

    return await _unix.open_socket(listen, timeout)
