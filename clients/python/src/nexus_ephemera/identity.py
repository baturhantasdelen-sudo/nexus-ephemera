"""Local peer checks shared by the Unix client and the tests.

The Windows named-pipe SID comparison lives next to the pipe handle. It uses
the same rule: a missing pid is unavailable, and a different user is rejected.
"""

from __future__ import annotations

import stat
import struct

from .errors import IdentityRejected, IdentityUnavailable


def peer_socket_ready(sock: object) -> int:
    """Return a usable fd when the object can answer a peer-credential check.

    asyncio wraps the connected socket in ``TransportSocket``. That wrapper is
    not a ``socket.socket``, but it exposes ``fileno`` and ``getsockopt``, which
    is what ``SO_PEERCRED`` and ``getpeereid`` need.
    """

    fileno = getattr(sock, "fileno", None)
    getsockopt = getattr(sock, "getsockopt", None)
    if not callable(fileno) or not callable(getsockopt):
        raise IdentityUnavailable("ipc: caller identity unavailable")
    try:
        fd = fileno()
    except (OSError, AttributeError, TypeError, ValueError) as exc:
        raise IdentityUnavailable("ipc: caller identity unavailable") from exc
    if isinstance(fd, bool) or not isinstance(fd, int) or fd < 0:
        raise IdentityUnavailable("ipc: caller identity unavailable")
    return fd


def assess_peer(pid: int, uid: int, current_uid: int) -> None:
    """Accept a connected peer only when its pid is live and its uid is ours."""

    if pid <= 0:
        raise IdentityUnavailable("ipc: caller identity unavailable")
    if uid != current_uid:
        raise IdentityRejected("ipc: caller identity rejected")


def require_private_unix_socket(
    mode: int,
    owner_uid: int,
    current_uid: int,
    *,
    is_socket: bool,
) -> None:
    """Require mode `0600`, the current uid, and a socket file.

    This runs before `connect`. A group-readable socket is rejected even when
    the path is otherwise local.
    """

    if not is_socket or stat.S_IMODE(mode) != 0o600 or owner_uid != current_uid:
        raise IdentityRejected(
            "ipc: unix socket must be mode 0600 and owned by the current user"
        )


def unpack_ucred(raw: bytes) -> tuple[int, int]:
    """Decode Linux `struct ucred` (`pid`, `uid`, `gid`) and return pid and uid."""

    if len(raw) != 12:
        raise IdentityUnavailable("ipc: caller identity unavailable")
    pid, uid, _gid = struct.unpack("=iII", raw)
    return pid, uid
