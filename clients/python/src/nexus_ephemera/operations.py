"""Day-2 drills for key grace, quarantine, and closed store failures.

The drill MAC below is a local grace-window check. Broker request signatures
and tenant tokens stay in the Rust daemon.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from dataclasses import dataclass

from .errors import IdempotencyUnavailable, Inconclusive, TargetDenied

SHED_STATUS = 503
_DRILL = b"nexus-operations-rotation-v1\0"


@dataclass
class _Previous:
    secret: bytes
    valid_until: int


class RotationDrill:
    """Accept a retired drill key only until its grace instant."""

    def __init__(self, secret: bytes) -> None:
        if not secret or len(secret) > 4096:
            raise ValueError("secret length")
        self._current = secret
        self._previous: _Previous | None = None

    def rotate(self, nxt: bytes, now: int, grace_ms: int) -> None:
        if not nxt or nxt == self._current or not 0 <= grace_ms <= 24 * 60 * 60 * 1000:
            raise ValueError("rotation")
        retired = self._current
        self._current = nxt
        self._previous = None if grace_ms == 0 else _Previous(retired, now + grace_ms)

    def sign(self, now: int, key: str) -> str:
        return _mac(self._current, now, key)

    def verify(self, presented: str, now: int, signed_at: int, key: str) -> None:
        if _accepts(self._current, presented, now, signed_at, key):
            return
        previous = self._previous
        if previous is not None and now < previous.valid_until and _accepts(
            previous.secret, presented, now, signed_at, key
        ):
            return
        raise TargetDenied()


class TenantQuarantine:
    """Block one account after repeated denials. Other accounts stay open."""

    def __init__(self, threshold: int, block_for_ms: int) -> None:
        if threshold < 1 or block_for_ms < 1:
            raise ValueError("quarantine")
        self._threshold = threshold
        self._block_for_ms = block_for_ms
        self._denials: dict[str, int] = {}
        self._until: dict[str, int] = {}
        self._lock = threading.RLock()

    def ensure(self, account: str, now: int) -> None:
        with self._lock:
            until = self._until.get(account)
            if until is not None and now < until:
                raise TargetDenied()
            if until is not None:
                self._denials.pop(account, None)
                self._until.pop(account, None)

    def record_success(self, account: str) -> None:
        with self._lock:
            self._denials.pop(account, None)
            self._until.pop(account, None)

    def record_denial(self, account: str, now: int) -> None:
        with self._lock:
            self.ensure(account, now)
            if account not in self._denials and len(self._denials) >= 4096:
                raise Inconclusive()
            count = self._denials.get(account, 0) + 1
            self._denials[account] = count
            if count >= self._threshold:
                self._until[account] = now + self._block_for_ms


def shed_status(message: str) -> int | None:
    if "capacity exhausted" in message:
        return SHED_STATUS
    return None


def close_store_outage(err: Exception) -> Exception:
    if isinstance(err, (IdempotencyUnavailable, Inconclusive, TimeoutError)):
        return Inconclusive()
    return err


def _mac(secret: bytes, signed_at: int, key: str) -> str:
    encoded = key.encode("utf-8")
    material = _DRILL + signed_at.to_bytes(8, "little") + len(encoded).to_bytes(8, "little") + encoded
    return hmac.new(secret, material, hashlib.sha256).hexdigest()


def _accepts(secret: bytes, presented: str, now: int, signed_at: int, key: str) -> bool:
    digest = _mac(secret, signed_at, key)
    fresh = abs(signed_at - now) <= 5000
    return len(presented) == len(digest) and hmac.compare_digest(presented, digest) and fresh
