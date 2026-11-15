"""Ecosystem adapters. The counting broker stands in for the daemon."""

from __future__ import annotations

import asyncio
import hashlib

import pytest

from nexus_ephemera import (
    DUPLICATE_PROVIDER_STATUS,
    EcosystemGuard,
    IdempotencyConflict,
    LangChainToolGuard,
    Malformed,
    PortkeyGuardrail,
    ProviderEdge,
    TargetDenied,
    ToolRoute,
    activepieces_step,
    canonical_payload,
    composio_action,
    crewai_tool_call,
    handle_mcp_message,
)
from nexus_ephemera.models import Receipt

_ENDPOINT = "https://provider.example/charge"
_CANONICAL = b'{"params":{"amount":"10","currency":"usd"},"tool":"charge"}'
_ROUTE = ToolRoute("charge", _ENDPOINT, ("amount", "currency"))


class CountingBroker:
    def __init__(self, edge: ProviderEdge | None = None) -> None:
        self.calls = 0
        self.edge = edge
        self._cache: dict[str, Receipt] = {}

    async def execute(
        self, endpoint: str, payload_hash: str, idempotency_key: str
    ) -> Receipt:
        cached = self._cache.get(idempotency_key)
        if cached is not None:
            if (
                cached["target_endpoint"] != endpoint
                or cached["payload_hash"] != payload_hash
            ):
                raise IdempotencyConflict()
            return cached
        self.calls += 1
        if self.edge is not None:
            assert self.edge.submit(idempotency_key) == 204
        receipt: Receipt = {
            "transport_status": 204,
            "seal_report": "retained",
            "binding_digest_hex": "ab" * 32,
            "target_endpoint": endpoint,
            "payload_hash": payload_hash,
            "idempotency_key": idempotency_key,
        }
        self._cache[idempotency_key] = receipt
        return receipt


def _guard(broker: CountingBroker | None = None) -> tuple[EcosystemGuard, CountingBroker]:
    broker = broker or CountingBroker()
    return EcosystemGuard(broker, (_ROUTE,), (_ENDPOINT,)), broker


def test_canonical_tool_payload_is_stable() -> None:
    raw = canonical_payload("charge", {"currency": "usd", "amount": "10"})
    assert raw == _CANONICAL
    assert hashlib.sha256(raw).hexdigest() == hashlib.sha256(_CANONICAL).hexdigest()


def test_mcp_tool_call_returns_seal_report_and_replay_stays_cached() -> None:
    async def scenario() -> None:
        edge = ProviderEdge()
        guard, broker = _guard(CountingBroker(edge))
        listed = await handle_mcp_message(guard, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert broker.calls == 0
        tools = listed["result"]
        assert isinstance(tools, dict)
        names = tools["tools"]
        assert isinstance(names, list)
        assert names[0]["name"] == "charge"
        assert "secret" not in str(names)

        message = {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "charge",
                "arguments": {"currency": "usd", "amount": "10"},
                "idempotency_key": "mcp-1",
            },
        }
        first = await handle_mcp_message(guard, message)
        result = first["result"]
        assert isinstance(result, dict)
        assert result["content"] == [{"type": "text", "text": "seal_report=retained"}]
        nexus = result["nexus"]
        assert isinstance(nexus, dict)
        assert nexus["seal_report"] == "retained"
        assert nexus["target_endpoint"] == _ENDPOINT
        assert nexus["replayed"] is False
        assert nexus["duplicate_status"] is None
        assert broker.calls == 1
        assert edge.accepted == 1

        second = await handle_mcp_message(guard, message)
        replay = second["result"]
        assert isinstance(replay, dict)
        again = replay["nexus"]
        assert isinstance(again, dict)
        assert again["replayed"] is True
        assert again["duplicate_status"] == DUPLICATE_PROVIDER_STATUS
        assert again["binding_digest_hex"] == nexus["binding_digest_hex"]
        assert again["seal_report"] == "retained"
        assert broker.calls == 1
        assert edge.accepted == 1
        assert edge.submit("mcp-1") == 409

    asyncio.run(scenario())


def test_mcp_rejects_unknown_and_tampered_targets_before_dispatch() -> None:
    async def scenario() -> None:
        guard, broker = _guard()
        unknown = await handle_mcp_message(
            guard,
            {
                "jsonrpc": "2.0",
                "id": "a",
                "method": "tools/call",
                "params": {
                    "name": "transfer",
                    "arguments": {"amount": "10"},
                    "idempotency_key": "nope",
                },
            },
        )
        error = unknown["error"]
        assert isinstance(error, dict)
        assert error["code"] == -32003
        assert "sk-" not in str(error)
        hijack = {
            "amount": "10",
            "currency": "usd",
            "endpoint": "https://evil.example/charge",
            "api_key": "sk-live",
        }
        with pytest.raises(Malformed) as raised:
            await guard.authorize("charge", hijack, "tamper")
        assert "sk-live" not in str(raised.value)
        assert "evil.example" not in str(raised.value)
        assert broker.calls == 0

    asyncio.run(scenario())


def test_langchain_and_portkey_stop_unlisted_routes() -> None:
    async def scenario() -> None:
        guard, broker = _guard()
        receipt = await LangChainToolGuard(guard).before_invoke(
            "charge",
            {"amount": "10", "currency": "usd"},
            "lc-1",
        )
        assert receipt.seal_report == "retained"
        assert receipt.target_endpoint == _ENDPOINT
        assert broker.calls == 1

        portkey = PortkeyGuardrail(guard)
        body = canonical_payload("charge", {"amount": "10", "currency": "usd"})
        forwarded = await portkey.before_request(_ENDPOINT, body, "pk-1")
        assert forwarded.seal_report == "retained"
        assert broker.calls == 2

        with pytest.raises(TargetDenied):
            await portkey.before_request("https://evil.example/charge", body, "pk-2")
        with pytest.raises(TargetDenied):
            await portkey.before_request(f"{_ENDPOINT}?x=1", body, "pk-3")
        with pytest.raises(TargetDenied):
            await portkey.before_request(f"{_ENDPOINT}#frag", body, "pk-4")
        with pytest.raises(Malformed):
            await portkey.before_request(_ENDPOINT, body + b" ", "pk-5")
        assert broker.calls == 2

    asyncio.run(scenario())


def test_agent_frameworks_block_credential_tampering_and_replay() -> None:
    async def scenario() -> None:
        edge = ProviderEdge()
        guard, broker = _guard(CountingBroker(edge))
        params: dict[str, object] = {"amount": "10", "currency": "usd"}
        with pytest.raises(Malformed):
            await crewai_tool_call(
                guard,
                "charge",
                {"amount": "10", "api_key": "sk-crew"},
                "crew-1",
            )
        first = await composio_action(guard, "charge", params, "agent-1")
        second = await activepieces_step(guard, "charge", dict(params), "agent-1")
        assert first.seal_report == "retained"
        assert second.replayed is True
        assert second.duplicate_status == 409
        assert second.binding_digest_hex == first.binding_digest_hex
        assert broker.calls == 1
        assert edge.accepted == 1
        changed = {"amount": "11", "currency": "usd"}
        with pytest.raises(IdempotencyConflict):
            await activepieces_step(guard, "charge", changed, "agent-1")
        assert broker.calls == 1
        assert edge.accepted == 1

    asyncio.run(scenario())
