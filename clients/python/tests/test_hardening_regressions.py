"""Negative acceptance tests for the enterprise audit findings."""
from __future__ import annotations

import asyncio
import gc
import hashlib
import json
import threading
from typing import Mapping

import pytest

from nexus_ephemera import (CleanupIncomplete, EcosystemGuard, IdempotencyConflict,
    IdempotencyUnavailable, Malformed, PortkeyGuardrail, RateLimited, ToolRoute, handle_mcp_message)
from nexus_ephemera.enterprise import (AuditEvent, AuditLedger, ServiceAccount,
    TenantDirectory, WorkerGate, verify_export)
from nexus_ephemera.errors import ProtocolError, TargetDenied
from nexus_ephemera.models import Receipt

ENDPOINT = "https://provider.example/charge"
ROUTE = ToolRoute("charge", ENDPOINT, ("amount",))


class BoundBroker:
    def __init__(self) -> None:
        self.calls = 0
        self.payloads: list[bytes] = []
        self.block: asyncio.Event | None = None
        self.status = 204
        self.seal = "retained"

    async def execute_payload(self, endpoint: str, payload: bytes, key: str) -> Receipt:
        self.calls += 1
        self.payloads.append(payload)
        if self.block is not None:
            await self.block.wait()
        return {"target_endpoint": endpoint, "payload_hash": hashlib.sha256(payload).hexdigest(),
            "idempotency_key": key, "binding_digest_hex": "ab" * 32,
            "seal_report": self.seal, "transport_status": self.status}


def test_malformed_body_is_not_retained_by_exception_chain() -> None:
    async def scenario() -> None:
        guard = EcosystemGuard(BoundBroker(), [ROUTE], [ENDPOINT])
        with pytest.raises(Malformed) as caught:
            await PortkeyGuardrail(guard).before_request(ENDPOINT, b'{"api_key":"CANARY",', "invalid")
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None
        assert "CANARY" not in str(caught.value)
        frame = caught.value.__traceback__
        while frame:
            if frame.tb_frame.f_code.co_name == "before_request":
                assert frame.tb_frame.f_locals["body"] == b""
            frame = frame.tb_next
    asyncio.run(scenario())


def test_deep_json_is_rejected_without_decoder_context() -> None:
    from nexus_ephemera.framing import load_json_object
    body = b'[' * 2000 + b'"CANARY"' + b']' * 2000
    with pytest.raises(Malformed) as caught:
        load_json_object(bytearray(body))
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    quoted = {"message": '[\\"' * 1000}
    assert load_json_object(bytearray(json.dumps(quoted).encode("utf-8"))) == quoted
    ledger = AuditLedger()
    assert not verify_export(body.decode("ascii"), ledger.checkpoint())

    async def scenario() -> None:
        guard = EcosystemGuard(BoundBroker(), [ROUTE], [ENDPOINT])
        with pytest.raises(Malformed) as caught:
            await PortkeyGuardrail(guard).before_request(ENDPOINT, body, "deep-json")
        assert caught.value.__cause__ is None and caught.value.__context__ is None
    asyncio.run(scenario())


def test_guard_rejects_conflict_and_capacity_before_dispatch() -> None:
    async def scenario() -> None:
        broker = BoundBroker()
        guard = EcosystemGuard(broker, [ROUTE], [ENDPOINT], cache_capacity=1)
        await guard.authorize("charge", {"amount": "10"}, "one")
        assert (await guard.authorize("charge", {"amount": "10"}, "one")).replayed
        with pytest.raises(IdempotencyConflict):
            await guard.authorize("charge", {"amount": "11"}, "one")
        with pytest.raises(IdempotencyUnavailable):
            await guard.authorize("charge", {"amount": "10"}, "two")
        assert broker.calls == 1
    asyncio.run(scenario())


def test_pending_budget_and_cancellation_release_capacity() -> None:
    async def scenario() -> None:
        broker = BoundBroker()
        broker.block = asyncio.Event()
        guard = EcosystemGuard(broker, [ROUTE], [ENDPOINT], pending_capacity=2)
        tasks = [asyncio.create_task(guard.authorize("charge", {"amount": "1"}, str(n))) for n in range(2)]
        for _ in range(20):
            if guard._pending == 2:
                break
            await asyncio.sleep(0)
        with pytest.raises(RateLimited):
            await guard.authorize("charge", {"amount": "1"}, "overflow")
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        assert guard._pending == 0
        broker.block.set()
        await guard.authorize("charge", {"amount": "1"}, "recovered")
    asyncio.run(scenario())


def test_mutating_original_input_cannot_change_dispatched_bytes() -> None:
    async def scenario() -> None:
        broker = BoundBroker()
        broker.block = asyncio.Event()
        guard = EcosystemGuard(broker, [ROUTE], [ENDPOINT])
        params = {"amount": "10"}
        task = asyncio.create_task(guard.authorize("charge", params, "immutable"))
        while not broker.payloads:
            await asyncio.sleep(0)
        params["amount"] = "999"
        broker.block.set()
        receipt = await task
        assert json.loads(broker.payloads[0])["params"]["amount"] == "10"
        assert receipt.payload_hash == hashlib.sha256(broker.payloads[0]).hexdigest()
    asyncio.run(scenario())


def test_mcp_never_labels_failed_provider_or_cleanup_as_success() -> None:
    async def scenario() -> None:
        broker = BoundBroker()
        broker.status = 503
        guard = EcosystemGuard(broker, [ROUTE], [ENDPOINT])
        message: Mapping[str, object] = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "charge", "arguments": {"amount": "1"}, "idempotency_key": "failure"}}
        for _ in range(2):
            assert "error" in await handle_mcp_message(guard, dict(message))
        assert broker.calls == 1
        broker = BoundBroker()
        broker.seal = "partial"
        guard = EcosystemGuard(broker, [ROUTE], [ENDPOINT])
        response = await handle_mcp_message(guard, dict(message))
        assert response["error"]["data"]["seal_report"] == "partial"  # type: ignore[index]
    asyncio.run(scenario())


def test_worker_permit_returns_on_unwind_drop_and_concurrent_release() -> None:
    gate = WorkerGate()
    with pytest.raises(RuntimeError):
        with gate.try_acquire():
            raise RuntimeError("public fixture")
    permit = gate.try_acquire()
    threads = [threading.Thread(target=permit.release) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert gate._inflight == 0
    permit = gate.try_acquire()
    del permit
    gc.collect()
    assert gate._inflight == 0
    permits = [gate.try_acquire() for _ in range(32)]
    with pytest.raises(ProtocolError):
        gate.try_acquire()
    for item in permits:
        item.release()


def test_audit_requires_external_checkpoint_closed_schema_and_no_raw_metadata() -> None:
    event = AuditEvent("receipt", "billing", ENDPOINT, "LOW_ENTROPY_CANARY", "idem-CANARY",
                       "retained", "ab" * 32, 204)
    ledger = AuditLedger()
    ledger.append(event)
    exported = ledger.export_json()
    checkpoint = ledger.checkpoint()
    assert verify_export(exported, checkpoint)
    assert "LOW_ENTROPY_CANARY" not in exported and "idem-CANARY" not in exported
    altered = json.loads(exported)
    altered["records"][0]["event"]["unsigned_extra"] = "hidden"
    assert not verify_export(json.dumps(altered), checkpoint)
    assert not verify_export(exported.replace('"schema":', '"schema":"nexus-audit-v2","schema":', 1), checkpoint)
    rewritten = AuditLedger()
    rewritten.append(event)
    assert rewritten.merkle_root() != checkpoint.merkle_root
    assert not verify_export(rewritten.export_json(), checkpoint)
    assert verify_export(rewritten.export_json(), rewritten.checkpoint())
    assert not verify_export(AuditLedger().export_json(), checkpoint)
    key = ledger._key
    ledger.close()
    assert not any(key)
    with pytest.raises(ProtocolError):
        ledger.append(event)


def test_multi_role_configuration_cannot_default_to_union_permissions() -> None:
    read = "https://provider.example/read"
    with pytest.raises(Malformed):
        TenantDirectory([ServiceAccount("billing", ("reader", "writer"), (), (read, ENDPOINT))])
    directory = TenantDirectory([ServiceAccount("billing", ("reader", "writer"), (), (read, ENDPOINT),
        (("reader", (read,)), ("writer", (ENDPOINT,))))])
    assert directory.allow("billing", "reader", read) == read
    with pytest.raises(TargetDenied):
        directory.allow("billing", "reader", ENDPOINT)
