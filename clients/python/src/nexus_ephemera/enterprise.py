"""Enterprise helpers that never receive the broker secret.

The audit chain matches the Rust ledger: SHA-256 links and a Merkle root.
That root is tamper-evident only when it is stored outside the exported log.
It is not a MAC and not mTLS. Tenant HMAC tokens are verified by the Rust
library, which holds the daemon secret. This module enforces the directory
allowlist and role check before a broker call. The shared store is the atomic
claim adapter used by more than one local caller. It is not a network service.
"""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .ecosystem import endpoint_is_strict
from .errors import (
    IdempotencyConflict,
    IdempotencyUnavailable,
    Inconclusive,
    Malformed,
    ProtocolError,
    TargetDenied,
)
from .framing import valid_idempotency_key

WORKER_CAP = 32
DUPLICATE_PROVIDER_STATUS = 409


@dataclass(frozen=True)
class AuditEvent:
    kind: str
    service_account_id: str
    endpoint: str
    payload_hash: str
    idempotency_key: str
    seal_report: str
    binding_digest_hex: str
    transport_status: int


@dataclass(frozen=True)
class ServiceAccount:
    id: str
    roles: tuple[str, ...]
    attributes: tuple[tuple[str, str], ...]
    allowlist: tuple[str, ...]


@dataclass(frozen=True)
class SharedReceipt:
    target_endpoint: str
    payload_hash: str
    binding_digest_hex: str
    transport_status: int
    seal_report: str
    idempotency_key: str
    duplicate_status: int | None
    service_account_id: str


class AuditLedger:
    """Hash-chained JSON events. Modification breaks ``verify``."""

    def __init__(self) -> None:
        self._previous = bytes(32)
        self._events: list[bytes] = []
        self._links: list[bytes] = []
        self._previous_links: list[bytes] = []

    def append(self, event: AuditEvent) -> bytes:
        encoded = canonical_event(event)
        sequence = len(self._events) + 1
        link = chain_link(self._previous, sequence, encoded)
        self._previous_links.append(self._previous)
        self._events.append(encoded)
        self._links.append(link)
        self._previous = link
        return link

    def verify(self) -> bool:
        previous = bytes(32)
        for index, encoded in enumerate(self._events):
            sequence = index + 1
            if self._previous_links[index] != previous:
                return False
            if self._links[index] != chain_link(previous, sequence, encoded):
                return False
            previous = self._links[index]
        return previous == self._previous and merkle_root(self._links) == self.merkle_root()

    def merkle_root(self) -> bytes:
        return merkle_root(self._links)

    def export_json(self) -> str:
        records: list[str] = []
        for index, encoded in enumerate(self._events):
            records.append(
                "{"
                f'"event":{encoded.decode("ascii")},'
                f'"link":"{self._links[index].hex()}",'
                f'"previous":"{self._previous_links[index].hex()}",'
                f'"sequence":{index + 1}'
                "}"
            )
        body = ",".join(records)
        return (
            "{"
            f'"head":"{self._previous.hex()}",'
            f'"merkle_root":"{self.merkle_root().hex()}",'
            f'"records":[{body}]'
            "}"
        )


class TenantDirectory:
    """Role and allowlist check. The HMAC token stays in the Rust verifier."""

    def __init__(self, accounts: Sequence[ServiceAccount]) -> None:
        stored: dict[str, ServiceAccount] = {}
        for account in accounts:
            if not _ident(account.id) or account.id in stored:
                raise Malformed()
            if not account.roles or any(not _ident(role) for role in account.roles):
                raise Malformed()
            if any(pair[0] == "secret" or not _ident(pair[0]) for pair in account.attributes):
                raise Malformed()
            if not account.allowlist or any(not endpoint_is_strict(item) for item in account.allowlist):
                raise Malformed()
            stored[account.id] = account
        if not stored:
            raise Malformed()
        self._accounts = stored

    def allow(
        self,
        service_account_id: str,
        role: str,
        endpoint: str,
        attributes: Mapping[str, str] | None = None,
    ) -> str:
        """Return the endpoint when this account may call it."""

        if not endpoint_is_strict(endpoint):
            raise TargetDenied()
        account = self._accounts.get(service_account_id)
        if account is None or role not in account.roles or endpoint not in account.allowlist:
            raise TargetDenied()
        presented = tuple(sorted((key, value) for key, value in (attributes or {}).items()))
        if presented != tuple(sorted(account.attributes)):
            raise TargetDenied()
        return endpoint


class SharedStore:
    """One lock for every caller. Pending and inconclusive entries do not retry."""

    def __init__(self, cap: int = 8) -> None:
        if cap < 1:
            raise Malformed()
        self._cap = cap
        self._lock = threading.Lock()
        self._sealed = False
        self._slots: dict[str, tuple[str, str, str]] = {}
        self._receipts: dict[str, SharedReceipt] = {}
        self.provider_hits = 0

    def execute(
        self,
        service_account_id: str,
        endpoint: str,
        payload_hash: str,
        idempotency_key: str,
        binding_digest_hex: str,
        *,
        interrupt: bool = False,
    ) -> SharedReceipt:
        _validate(service_account_id, endpoint, payload_hash, idempotency_key, binding_digest_hex)
        slot_key = f"{service_account_id}\x1f{idempotency_key}"
        with self._lock:
            if self._sealed:
                raise ProtocolError("shared idempotency store is sealed")
            slot = self._slots.get(slot_key)
            if slot is not None:
                return self._replay(slot_key, slot, endpoint, payload_hash)
            if len(self._slots) >= self._cap:
                raise IdempotencyUnavailable()
            self._slots[slot_key] = ("pending", endpoint, payload_hash)
        if interrupt:
            with self._lock:
                self._slots[slot_key] = ("inconclusive", endpoint, payload_hash)
            raise Inconclusive()
        receipt = SharedReceipt(
            target_endpoint=endpoint,
            payload_hash=payload_hash,
            binding_digest_hex=binding_digest_hex,
            transport_status=204,
            seal_report="retained",
            idempotency_key=idempotency_key,
            duplicate_status=None,
            service_account_id=service_account_id,
        )
        with self._lock:
            current = self._slots.get(slot_key)
            if current != ("pending", endpoint, payload_hash):
                raise Inconclusive()
            self._slots[slot_key] = ("done", endpoint, payload_hash)
            self._receipts[slot_key] = receipt
            self.provider_hits += 1
        return receipt

    def quarantine_for_rotation(self) -> None:
        with self._lock:
            self._sealed = True

    def redis_claim_command(self, service_account_id: str, idempotency_key: str) -> str:
        if not _ident(service_account_id) or not valid_idempotency_key(idempotency_key):
            raise Malformed()
        return f"SET nexus:idem:{service_account_id}:{idempotency_key} pending NX"

    def _replay(
        self, slot_key: str, slot: tuple[str, str, str], endpoint: str, payload_hash: str
    ) -> SharedReceipt:
        state, stored_endpoint, stored_hash = slot
        if stored_endpoint != endpoint or stored_hash != payload_hash:
            raise IdempotencyConflict()
        if state == "done":
            cached = self._receipts[slot_key]
            return SharedReceipt(
                target_endpoint=cached.target_endpoint,
                payload_hash=cached.payload_hash,
                binding_digest_hex=cached.binding_digest_hex,
                transport_status=cached.transport_status,
                seal_report=cached.seal_report,
                idempotency_key=cached.idempotency_key,
                duplicate_status=DUPLICATE_PROVIDER_STATUS,
                service_account_id=cached.service_account_id,
            )
        raise Inconclusive()


class WorkerGate:
    """Bound of 32 in-flight operations. The 33rd call fails closed."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._inflight = 0

    def try_acquire(self) -> _Permit:
        with self._lock:
            if self._inflight >= WORKER_CAP:
                raise ProtocolError("ipc io: pending operation capacity exhausted")
            self._inflight += 1
        return _Permit(self)

    def _release(self) -> None:
        with self._lock:
            self._inflight -= 1


class _Permit:
    def __init__(self, gate: WorkerGate) -> None:
        self._gate = gate
        self._open = True

    def release(self) -> None:
        if self._open:
            self._open = False
            self._gate._release()


def canonical_event(event: AuditEvent) -> bytes:
    if event.kind not in {"receipt", "target_denied", "idempotency_conflict", "retained"}:
        raise Malformed()
    if not _ident(event.service_account_id):
        raise Malformed()
    for field in (
        event.endpoint,
        event.payload_hash,
        event.idempotency_key,
        event.seal_report,
        event.binding_digest_hex,
    ):
        if not _printable(field):
            raise Malformed()
    if isinstance(event.transport_status, bool) or not isinstance(event.transport_status, int):
        raise Malformed()
    encoded = (
        "{"
        f'"binding_digest_hex":{_json(event.binding_digest_hex)},'
        f'"endpoint":{_json(event.endpoint)},'
        f'"idempotency_key":{_json(event.idempotency_key)},'
        f'"kind":{_json(event.kind)},'
        f'"payload_hash":{_json(event.payload_hash)},'
        f'"seal_report":{_json(event.seal_report)},'
        f'"service_account_id":{_json(event.service_account_id)},'
        f'"transport_status":{event.transport_status}'
        "}"
    )
    return encoded.encode("ascii")


def chain_link(previous: bytes, sequence: int, event: bytes) -> bytes:
    hasher = hashlib.sha256()
    hasher.update(b"nexus-enterprise-audit-v1")
    hasher.update(previous)
    hasher.update(sequence.to_bytes(8, "little"))
    hasher.update(hashlib.sha256(event).digest())
    return hasher.digest()


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"nexus-merkle-empty-v1").digest()
    level = list(leaves)
    while len(level) > 1:
        nxt: list[bytes] = []
        index = 0
        while index < len(level):
            left = level[index]
            right = level[index + 1] if index + 1 < len(level) else level[index]
            nxt.append(_pair(left, right))
            index += 2
        level = nxt
    return level[0]


def _pair(left: bytes, right: bytes) -> bytes:
    hasher = hashlib.sha256()
    hasher.update(b"nexus-merkle-pair-v1")
    hasher.update(left)
    hasher.update(right)
    return hasher.digest()


def _json(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _ident(value: str) -> bool:
    if not 1 <= len(value) <= 32 or not value[0].isascii() or not value[0].islower():
        return False
    return all(char.isascii() and (char.islower() or char.isdigit() or char in "_-") for char in value)


def _printable(value: str) -> bool:
    return all(char.isascii() and (char.isprintable()) for char in value)


def _validate(
    service_account_id: str,
    endpoint: str,
    payload_hash: str,
    idempotency_key: str,
    binding_digest_hex: str,
) -> None:
    if not _ident(service_account_id) or not valid_idempotency_key(idempotency_key):
        raise Malformed()
    if not endpoint_is_strict(endpoint):
        raise TargetDenied()
    if (
        not payload_hash
        or len(payload_hash) > 128
        or not payload_hash.isascii()
        or not payload_hash.isprintable()
        or " " in payload_hash
    ):
        raise Malformed()
    if len(binding_digest_hex) != 64 or any(char not in "0123456789abcdefABCDEF" for char in binding_digest_hex):
        raise Malformed()
