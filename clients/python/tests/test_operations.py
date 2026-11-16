"""Day-2 drills: rotation grace, quarantine, shedding, and closed exports."""

from nexus_ephemera.enterprise import WORKER_CAP, AuditEvent, AuditLedger, WorkerGate, verify_export
from nexus_ephemera.errors import IdempotencyUnavailable, Inconclusive, ProtocolError, TargetDenied
from nexus_ephemera.operations import RotationDrill, TenantQuarantine, close_store_outage, shed_status

NOW = 1_700_000_000_000


def test_operations_rotation_quarantine_and_closed_export() -> None:
    drill = RotationDrill(b"operations-broker-secret-v1")
    old = drill.sign(NOW, "idem-rotate")
    drill.rotate(b"operations-broker-secret-v2", NOW, 10_000)
    fresh = drill.sign(NOW, "idem-rotate")
    drill.verify(old, NOW + 1_000, NOW, "idem-rotate")
    drill.verify(fresh, NOW + 1_000, NOW, "idem-rotate")
    try:
        drill.verify(old, NOW + 10_001, NOW, "idem-rotate")
    except TargetDenied:
        pass
    else:
        raise AssertionError("expired grace key was accepted")
    try:
        drill.verify("00" * 32, NOW + 1_000, NOW, "idem-rotate")
    except TargetDenied:
        pass
    else:
        raise AssertionError("foreign mac was accepted")

    gate = WorkerGate()
    permits = [gate.try_acquire() for _ in range(WORKER_CAP)]
    try:
        gate.try_acquire()
    except ProtocolError as exc:
        assert shed_status(str(exc)) == 503
    else:
        raise AssertionError("33rd worker was admitted")
    permits.pop().release()
    gate.try_acquire()
    for permit in permits:
        permit.release()

    quarantine = TenantQuarantine(3, 30_000)
    quarantine.record_denial("billing", NOW)
    quarantine.record_denial("billing", NOW)
    quarantine.ensure("billing", NOW)
    quarantine.record_denial("billing", NOW)
    try:
        quarantine.ensure("billing", NOW + 1_000)
    except TargetDenied:
        pass
    else:
        raise AssertionError("quarantine did not block")
    quarantine.ensure("billing", NOW + 30_000)

    outage = close_store_outage(IdempotencyUnavailable())
    assert isinstance(outage, Inconclusive)
    assert "redis://" not in str(outage)
    assert "ghp_operations_token_value" not in str(outage)

    ledger = AuditLedger()
    ledger.append(
        AuditEvent(
            "retained",
            "billing",
            "https://provider.example/charge",
            "sha256:payload",
            "idem-rotate",
            "retained",
            "ab" * 32,
            204,
        )
    )
    exported = ledger.export_json()
    assert verify_export(exported, ledger.checkpoint())
    assert "retained" in exported
    assert "operations-broker-secret" not in exported
    assert "ghp_operations_token_value" not in exported
    assert "The queue is stuck" not in exported
    assert not verify_export(exported.replace("retained", "receipt", 1), ledger.checkpoint())
