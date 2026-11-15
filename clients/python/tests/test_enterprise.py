"""Enterprise audit, tenant directory, and shared idempotency."""

from __future__ import annotations

import threading

import pytest

from nexus_ephemera import IdempotencyConflict, Inconclusive, TargetDenied
from nexus_ephemera.enterprise import (
    DUPLICATE_PROVIDER_STATUS,
    WORKER_CAP,
    AuditEvent,
    AuditLedger,
    ServiceAccount,
    SharedStore,
    TenantDirectory,
    WorkerGate,
)
from nexus_ephemera.errors import ProtocolError

_CHARGE = "https://provider.example/charge"
_REFUND = "https://provider.example/refund"
_DIGEST = "ab" * 32


def _directory() -> TenantDirectory:
    return TenantDirectory(
        (
            ServiceAccount("billing", ("charge",), (), (_CHARGE,)),
            ServiceAccount("payments", ("refund",), (), (_REFUND,)),
        )
    )


def test_audit_export_verifies_and_rejects_a_changed_decision() -> None:
    ledger = AuditLedger()
    assert ledger.verify()
    ledger.append(
        AuditEvent(
            "retained",
            "billing",
            _CHARGE,
            "hash-a",
            "idem-1",
            "retained",
            _DIGEST,
            204,
        )
    )
    ledger.append(
        AuditEvent(
            "target_denied",
            "billing",
            _REFUND,
            "hash-a",
            "idem-deny",
            "",
            "",
            0,
        )
    )
    assert ledger.verify()
    exported = ledger.export_json()
    assert '"kind":"retained"' in exported
    assert '"kind":"target_denied"' in exported
    assert "enterprise-tenant-secret" not in exported
    tampered = AuditLedger()
    tampered.append(
        AuditEvent(
            "retained",
            "billing",
            _CHARGE,
            "hash-b",
            "idem-1",
            "retained",
            _DIGEST,
            204,
        )
    )
    assert tampered.merkle_root() != ledger.merkle_root()


def test_cross_tenant_call_is_denied_before_the_shared_store() -> None:
    directory = _directory()
    store = SharedStore()
    endpoint = directory.allow("billing", "charge", _CHARGE)
    assert endpoint == _CHARGE
    with pytest.raises(TargetDenied):
        directory.allow("billing", "charge", _REFUND)
    with pytest.raises(TargetDenied):
        directory.allow("payments", "refund", _CHARGE)
    with pytest.raises(TargetDenied):
        directory.allow("billing", "charge", f"{_CHARGE}?x=1")
    assert store.provider_hits == 0


def test_shared_store_returns_the_cached_receipt_and_409() -> None:
    store = SharedStore()
    first = store.execute("billing", _CHARGE, "hash-a", "idem-1", _DIGEST)
    second = store.execute("billing", _CHARGE, "hash-a", "idem-1", _DIGEST)
    assert first.duplicate_status is None
    assert first.seal_report == "retained"
    assert second.duplicate_status == DUPLICATE_PROVIDER_STATUS
    assert second.binding_digest_hex == first.binding_digest_hex
    assert second.transport_status == 204
    assert store.provider_hits == 1
    with pytest.raises(IdempotencyConflict):
        store.execute("billing", _CHARGE, "hash-other", "idem-1", _DIGEST)
    with pytest.raises(Inconclusive):
        store.execute("billing", _CHARGE, "hash-a", "idem-net", _DIGEST, interrupt=True)
    with pytest.raises(Inconclusive):
        store.execute("billing", _CHARGE, "hash-a", "idem-net", _DIGEST)
    assert store.provider_hits == 1
    store.quarantine_for_rotation()
    with pytest.raises(ProtocolError):
        store.execute("billing", _CHARGE, "hash-a", "idem-new", _DIGEST)
    assert store.redis_claim_command("billing", "idem-1") == "SET nexus:idem:billing:idem-1 pending NX"
    assert store.provider_hits == 1


def test_two_callers_share_one_provider_hit() -> None:
    store = SharedStore()
    barrier = threading.Barrier(2)
    results: list[object] = []
    lock = threading.Lock()

    def worker() -> None:
        barrier.wait()
        try:
            receipt = store.execute("billing", _CHARGE, "hash-a", "idem-race", _DIGEST)
        except Inconclusive as exc:
            outcome: object = exc
        else:
            outcome = receipt.duplicate_status
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    follow = store.execute("billing", _CHARGE, "hash-a", "idem-race", _DIGEST)
    assert follow.duplicate_status == 409
    assert store.provider_hits == 1
    assert len(results) == 2


def test_worker_cap_rejects_the_33rd_permit() -> None:
    gate = WorkerGate()
    permits = [gate.try_acquire() for _ in range(WORKER_CAP)]
    with pytest.raises(ProtocolError, match="capacity exhausted"):
        gate.try_acquire()
    permits.pop().release()
    replacement = gate.try_acquire()
    replacement.release()
    for permit in permits:
        permit.release()
