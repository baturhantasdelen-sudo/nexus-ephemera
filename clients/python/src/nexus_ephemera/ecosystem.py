"""Agent-framework adapters that call the local broker and never see its secret.

MCP, LangChain, Portkey, CrewAI, Composio, and Activepieces all enter through
one guard. The tool name selects an operator route. Call parameters cannot
replace that route or carry a provider credential. The daemon allowlist and
HMAC still run on ``NexusClient.execute``. This module does not sign, does
not hold the key, and does not treat the binding digest as a MAC or as mTLS.

A repeated key returns the broker's cached receipt. ``duplicate_status`` is
409 on that replay: the status a second raw provider submission would get.
The broker does not submit that second call. ``transport_status`` stays the
status stored on the cached receipt.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol, cast

from .errors import (
    IdempotencyConflict,
    Malformed,
    PayloadTooLarge,
    ProtocolError,
    TargetDenied,
)
from .framing import valid_idempotency_key
from .models import HARD_PAYLOAD_CAP, Receipt

_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,31}$")
_FORBIDDEN = frozenset(
    {
        "access_token",
        "api_key",
        "apikey",
        "authorization",
        "credential",
        "endpoint",
        "listen",
        "password",
        "private_key",
        "secret",
        "token",
        "url",
    }
)
_MAX_PARAMS = 16
_MAX_VALUE_BYTES = 256
DUPLICATE_PROVIDER_STATUS = 409


class Broker(Protocol):
    """The subset of ``NexusClient`` these adapters are allowed to call."""

    async def execute(
        self, endpoint: str, payload_hash: str, idempotency_key: str
    ) -> Receipt:
        """Ask the local broker to authorize one call."""


@dataclass(frozen=True)
class ToolRoute:
    """One tool name bound to one exact allowlisted https endpoint."""

    name: str
    endpoint: str
    allowed_params: tuple[str, ...]


@dataclass(frozen=True)
class ActionReceipt:
    """Broker receipt plus the agent loop's replay mark.

    ``binding_digest_hex`` is the broker's binding digest. It is not a MAC
    and it is not mTLS. The daemon's HMAC stays on the upstream request.
    """

    transport_status: int
    seal_report: str
    binding_digest_hex: str
    target_endpoint: str
    payload_hash: str
    idempotency_key: str
    replayed: bool
    duplicate_status: int | None

    def trace(self) -> dict[str, object]:
        """Fields safe to place on an MCP result. No secret is included."""

        return {
            "transport_status": self.transport_status,
            "seal_report": self.seal_report,
            "binding_digest_hex": self.binding_digest_hex,
            "target_endpoint": self.target_endpoint,
            "payload_hash": self.payload_hash,
            "idempotency_key": self.idempotency_key,
            "replayed": self.replayed,
            "duplicate_status": self.duplicate_status,
        }


class ProviderEdge:
    """Reference provider duplicate status. This is not the broker."""

    def __init__(self) -> None:
        self._seen: set[str] = set()
        self.accepted = 0

    def submit(self, idempotency_key: str) -> int:
        if not valid_idempotency_key(idempotency_key):
            raise Malformed()
        if idempotency_key in self._seen:
            return DUPLICATE_PROVIDER_STATUS
        self._seen.add(idempotency_key)
        self.accepted += 1
        return 204


class EcosystemGuard:
    """Bind tool calls to operator routes and the local broker."""

    def __init__(
        self,
        broker: Broker,
        routes: Sequence[ToolRoute],
        allowlist: Sequence[str],
    ) -> None:
        if not isinstance(allowlist, Sequence) or isinstance(allowlist, (str, bytes)):
            raise ProtocolError("allowlist is not a list of endpoints")
        cleaned = tuple(allowlist)
        if not cleaned or any(not endpoint_is_strict(item) for item in cleaned):
            raise ProtocolError("allowlist endpoint is not a strict https target")
        by_name: dict[str, ToolRoute] = {}
        by_endpoint: dict[str, str] = {}
        for route in routes:
            _check_route(route, cleaned)
            if route.name in by_name or route.endpoint in by_endpoint:
                raise ProtocolError("tool route is not unique")
            by_name[route.name] = route
            by_endpoint[route.endpoint] = route.name
        self._broker = broker
        self._routes = by_name
        self._by_endpoint = by_endpoint
        self._allowlist = cleaned
        self._seen: dict[str, tuple[str, str, str]] = {}
        self._lock = asyncio.Lock()

    def tools(self) -> tuple[ToolRoute, ...]:
        return tuple(self._routes[name] for name in sorted(self._routes))

    def route_for_endpoint(self, endpoint: str) -> ToolRoute | None:
        if not endpoint_is_strict(endpoint):
            return None
        name = self._by_endpoint.get(endpoint)
        if name is None:
            return None
        return self._routes[name]

    async def authorize(
        self,
        tool_name: str,
        params: Mapping[str, object],
        idempotency_key: str,
    ) -> ActionReceipt:
        """Hash the canonical tool call and return the broker receipt."""

        if not valid_idempotency_key(idempotency_key):
            raise Malformed()
        route = self._routes.get(tool_name)
        if route is None or route.endpoint not in self._allowlist:
            raise TargetDenied()
        if not endpoint_is_strict(route.endpoint):
            raise TargetDenied()
        snapshot = _snapshot_params(params, route.allowed_params)
        raw = canonical_payload(route.name, snapshot)
        if len(raw) > HARD_PAYLOAD_CAP:
            raise PayloadTooLarge(HARD_PAYLOAD_CAP)
        payload_hash = hashlib.sha256(raw).hexdigest()
        async with self._lock:
            receipt = await self._broker.execute(
                route.endpoint, payload_hash, idempotency_key
            )
            return self._accept(route.endpoint, payload_hash, idempotency_key, receipt)

    def _accept(
        self,
        endpoint: str,
        payload_hash: str,
        idempotency_key: str,
        receipt: Receipt,
    ) -> ActionReceipt:
        if (
            receipt["target_endpoint"] != endpoint
            or receipt["payload_hash"] != payload_hash
            or receipt["idempotency_key"] != idempotency_key
            or receipt["seal_report"] not in {"retained", "complete"}
        ):
            raise IdempotencyConflict()
        observed = (endpoint, payload_hash, receipt["binding_digest_hex"])
        previous = self._seen.get(idempotency_key)
        if previous is None:
            self._seen[idempotency_key] = observed
            replayed = False
        elif previous != observed:
            raise IdempotencyConflict()
        else:
            replayed = True
        return ActionReceipt(
            transport_status=receipt["transport_status"],
            seal_report=receipt["seal_report"],
            binding_digest_hex=receipt["binding_digest_hex"],
            target_endpoint=receipt["target_endpoint"],
            payload_hash=receipt["payload_hash"],
            idempotency_key=receipt["idempotency_key"],
            replayed=replayed,
            duplicate_status=DUPLICATE_PROVIDER_STATUS if replayed else None,
        )


class LangChainToolGuard:
    """Run before a LangChain tool body. The body does not receive a key."""

    def __init__(self, guard: EcosystemGuard) -> None:
        self._guard = guard

    async def before_invoke(
        self,
        tool_name: str,
        tool_input: Mapping[str, object],
        idempotency_key: str,
    ) -> ActionReceipt:
        if not isinstance(tool_input, Mapping):
            raise Malformed()
        return await self._guard.authorize(tool_name, tool_input, idempotency_key)


class PortkeyGuardrail:
    """Stop a Portkey upstream request that is not an allowlisted route.

    The URL has to be exactly one configured tool endpoint. The body has to
    be the canonical tool payload. Anything else raises before ``execute``.
    """

    def __init__(self, guard: EcosystemGuard) -> None:
        self._guard = guard

    async def before_request(
        self, url: str, body: bytes, idempotency_key: str
    ) -> ActionReceipt:
        route = self._guard.route_for_endpoint(url)
        if route is None:
            raise TargetDenied()
        if not isinstance(body, bytes) or len(body) > HARD_PAYLOAD_CAP:
            raise PayloadTooLarge(HARD_PAYLOAD_CAP)
        params = _params_from_canonical(route, body)
        return await self._guard.authorize(route.name, params, idempotency_key)


async def crewai_tool_call(
    guard: EcosystemGuard,
    tool_name: str,
    tool_input: Mapping[str, object],
    idempotency_key: str,
) -> ActionReceipt:
    """CrewAI tool entry. Parameters cannot select the endpoint or a key."""

    return await guard.authorize(tool_name, tool_input, idempotency_key)


async def composio_action(
    guard: EcosystemGuard,
    action: str,
    params: Mapping[str, object],
    idempotency_key: str,
) -> ActionReceipt:
    """Composio action entry. The action name is a registry key, not a URL."""

    return await guard.authorize(action, params, idempotency_key)


async def activepieces_step(
    guard: EcosystemGuard,
    step: str,
    params: Mapping[str, object],
    idempotency_key: str,
) -> ActionReceipt:
    """Activepieces step entry. The step name is a registry key, not a URL."""

    return await guard.authorize(step, params, idempotency_key)


async def handle_mcp_message(
    guard: EcosystemGuard, message: object
) -> dict[str, object]:
    """Answer one MCP JSON-RPC message. Tool calls carry ``seal_report``."""

    if not isinstance(message, dict):
        return _rpc_error(None, -32700, "ipc: malformed frame")
    fields = _string_key_map(message)
    rpc_id = _rpc_id(fields)
    if fields.get("jsonrpc") != "2.0" or not isinstance(fields.get("method"), str):
        return _rpc_error(rpc_id, -32600, "ipc: malformed frame")
    method = fields["method"]
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "nexus-ephemera", "version": "0.2.0"},
            },
        }
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rpc_id, "result": {"tools": _tool_specs(guard)}}
    if method != "tools/call":
        return _rpc_error(rpc_id, -32601, "ipc: malformed frame")
    try:
        params = fields.get("params")
        if not isinstance(params, dict):
            raise Malformed()
        call = _string_key_map(params)
        name = call.get("name")
        arguments = call.get("arguments")
        key = call.get("idempotency_key")
        if not isinstance(name, str) or not isinstance(key, str):
            raise Malformed()
        if not isinstance(arguments, dict):
            raise Malformed()
        receipt = await guard.authorize(name, _string_key_map(arguments), key)
    except TargetDenied as exc:
        return _rpc_error(rpc_id, -32003, str(exc))
    except IdempotencyConflict as exc:
        return _rpc_error(rpc_id, -32009, str(exc))
    except (Malformed, PayloadTooLarge) as exc:
        return _rpc_error(rpc_id, -32602, str(exc))
    return {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": f"seal_report={receipt.seal_report}",
                }
            ],
            "isError": False,
            "nexus": receipt.trace(),
        },
    }


def canonical_payload(tool_name: str, params: Mapping[str, str | int]) -> bytes:
    """Stable ASCII JSON. Key order cannot change the hash."""

    body = {"params": {key: params[key] for key in sorted(params)}, "tool": tool_name}
    encoded = json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return encoded.encode("ascii")


def endpoint_is_strict(value: str) -> bool:
    """Match the daemon's strict https target rule, including ``?`` and ``#``."""

    if not isinstance(value, str) or not value.startswith("https://"):
        return False
    rest = value[len("https://") :]
    if rest == "" or "//" in rest:
        return False
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError:
        return False
    if any(byte < 0x21 or byte > 0x7E or byte in b"@?#%\\" for byte in raw):
        return False
    return all(segment not in {".", ".."} for segment in rest.split("/"))


def _check_route(route: ToolRoute, allowlist: tuple[str, ...]) -> None:
    if not isinstance(route, ToolRoute):
        raise ProtocolError("tool route is not a registry entry")
    if not isinstance(route.name, str) or _NAME.fullmatch(route.name) is None:
        raise ProtocolError("tool name is not a registry key")
    if route.endpoint not in allowlist or not endpoint_is_strict(route.endpoint):
        raise ProtocolError("tool endpoint is not on the allowlist")
    if len(route.allowed_params) > _MAX_PARAMS:
        raise ProtocolError("tool parameter list is too large")
    seen: set[str] = set()
    for name in route.allowed_params:
        if (
            not isinstance(name, str)
            or _NAME.fullmatch(name) is None
            or name.casefold() in _FORBIDDEN
            or name in seen
        ):
            raise ProtocolError("tool parameter is not admissible")
        seen.add(name)


def _snapshot_params(
    params: Mapping[str, object], allowed: tuple[str, ...]
) -> dict[str, str | int]:
    if not isinstance(params, Mapping):
        raise Malformed()
    if len(params) > _MAX_PARAMS:
        raise Malformed()
    allowed_set = set(allowed)
    snapshot: dict[str, str | int] = {}
    for key, value in params.items():
        if not isinstance(key, str) or key.casefold() in _FORBIDDEN:
            raise Malformed()
        if _NAME.fullmatch(key) is None or key not in allowed_set:
            raise Malformed()
        snapshot[key] = _param_value(value)
    if allowed and not snapshot:
        raise Malformed()
    return snapshot


def _param_value(value: object) -> str | int:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise Malformed()
    if isinstance(value, int):
        if abs(value) > 10**12:
            raise Malformed()
        return value
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise Malformed()
    if len(value.encode("utf-8")) > _MAX_VALUE_BYTES:
        raise PayloadTooLarge(_MAX_VALUE_BYTES)
    return value


def _params_from_canonical(route: ToolRoute, body: bytes) -> dict[str, str | int]:
    try:
        text = body.decode("ascii")
        parsed = cast(object, json.loads(text))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise Malformed() from exc
    if not isinstance(parsed, dict):
        raise Malformed()
    fields = _string_key_map(parsed)
    if set(fields) != {"params", "tool"} or fields.get("tool") != route.name:
        raise Malformed()
    raw_params = fields["params"]
    if not isinstance(raw_params, dict):
        raise Malformed()
    snapshot = _snapshot_params(_string_key_map(raw_params), route.allowed_params)
    if canonical_payload(route.name, snapshot) != body:
        raise Malformed()
    return snapshot


def _tool_specs(guard: EcosystemGuard) -> list[dict[str, object]]:
    specs: list[dict[str, object]] = []
    for route in guard.tools():
        properties: dict[str, object] = {
            name: {"type": ["integer", "string"]} for name in route.allowed_params
        }
        specs.append(
            {
                "name": route.name,
                "description": (
                    "Local broker route. The tool call does not receive a "
                    "provider credential."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": properties,
                    "additionalProperties": False,
                },
            }
        )
    return specs


def _string_key_map(value: Mapping[object, object]) -> dict[str, object]:
    mapped: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise Malformed()
        mapped[key] = item
    return mapped


def _rpc_id(fields: Mapping[str, object]) -> object:
    rpc_id = fields.get("id")
    if isinstance(rpc_id, str) and len(rpc_id) <= 128 and _printable(rpc_id):
        return rpc_id
    if isinstance(rpc_id, int) and not isinstance(rpc_id, bool) and abs(rpc_id) < 2**53:
        return rpc_id
    return None


def _printable(value: str) -> bool:
    return all(32 <= ord(char) <= 126 for char in value)


def _rpc_error(rpc_id: object, code: int, message: str) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "error": {"code": code, "message": message},
    }
