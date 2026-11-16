"""Support-agent GitHub issue adapter. The agent object has no provider token."""

from __future__ import annotations

import json
import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from ..enterprise import DUPLICATE_PROVIDER_STATUS, AuditEvent, AuditLedger
from ..errors import IdempotencyConflict, Inconclusive, Malformed, TargetDenied
from ..framing import valid_idempotency_key, load_json_object

_POLICY_PATH = Path(__file__).resolve().parents[5] / "policies" / "pilot_support_agent.json"
_MARKER = "<!-- nexus-idempotency:{key} -->"


@dataclass(frozen=True)
class GithubIssuePolicy:
    service_account_id: str
    owner: str
    repo: str
    endpoint: str

    @classmethod
    def load(cls, raw: bytes | None = None) -> GithubIssuePolicy:
        data = raw if raw is not None else _POLICY_PATH.read_bytes()
        if not data or len(data) > 65536:
            raise Malformed()
        payload = load_json_object(bytearray(data))
        if not isinstance(payload, dict) or set(payload) != {
            "role", "service_account_id", "provider", "method", "owner", "repo",
            "endpoint", "allowed_fields", "denied_capabilities",
        }:
            raise Malformed()
        if (
            payload.get("role") != "support_agent"
            or payload.get("service_account_id") != "support"
            or payload.get("provider") != "github_issues"
            or payload.get("method") != "POST"
        ):
            raise Malformed()
        owner = payload.get("owner")
        repo = payload.get("repo")
        endpoint = payload.get("endpoint")
        fields = payload.get("allowed_fields")
        denied = payload.get("denied_capabilities")
        if not isinstance(owner, str) or not isinstance(repo, str) or not isinstance(endpoint, str):
            raise Malformed()
        if any(not re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,63}", name) or name.endswith(".") for name in (owner, repo)):
            raise Malformed()
        if not isinstance(fields, list) or not all(isinstance(value, str) for value in fields):
            raise Malformed()
        if not isinstance(denied, list) or not all(isinstance(value, str) for value in denied):
            raise Malformed()
        expected = f"https://api.github.com/repos/{owner}/{repo}/issues"
        if endpoint != expected or sorted(fields or []) != ["body", "title"]:
            raise Malformed()
        if sorted(denied or []) != ["delete", "infrastructure", "transfer"]:
            raise Malformed()
        return cls("support", owner, repo, endpoint)

    def authorize_target(self, endpoint: str) -> None:
        if endpoint != self.endpoint:
            raise TargetDenied()


@dataclass(frozen=True)
class IssueReceipt:
    target_endpoint: str
    payload_hash: str
    transport_status: int
    seal_report: str
    idempotency_key: str
    duplicate_status: int | None


class IssueProvider:
    def create(self, body: bytes, idempotency_key: str, authorization: bytes) -> str:
        raise NotImplementedError

    def find(self, idempotency_key: str) -> str:
        raise NotImplementedError


class ReferenceGithubIssueTransport:
    """Reference-only scripted transport; not durable and not a production broker.

    Production agents use TenantClient.execute_payload; only Rust owns secrets.
    """

    def __init__(self, policy: GithubIssuePolicy, token: bytes) -> None:
        if not token or len(token) > 256 or b"Bearer " in token or any(byte < 0x21 or byte > 0x7E for byte in token):
            raise Malformed()
        self._policy = policy
        self._token = token
        self._slots: dict[str, IssueReceipt | None] = {}
        self._lock = threading.RLock()

    def __repr__(self) -> str:
        return f"ReferenceGithubIssueTransport(endpoint={self._policy.endpoint!r})"

    def prepare(self, title: str, body: str, idempotency_key: str) -> tuple[bytes, str]:
        if not valid_idempotency_key(idempotency_key) or not _field(title, 256, False) or not _field(body, 8192, True):
            raise Malformed()
        marked = body + "\n\n" + _MARKER.format(key=idempotency_key)
        encoded = ("{" + f'"body":{_json(marked)},"title":{_json(title)}' + "}").encode("ascii")
        import hashlib

        return encoded, hashlib.sha256(encoded).hexdigest()

    def open_fields(
        self,
        provider: IssueProvider,
        fields: Mapping[str, str],
        idempotency_key: str,
        ledger: AuditLedger,
    ) -> IssueReceipt:
        if sorted(fields) != ["body", "title"] or any(not isinstance(value, str) for value in fields.values()):
            raise Malformed()
        return self.open_issue(provider, fields["title"], fields["body"], idempotency_key, ledger)

    def open_issue(
        self, provider: IssueProvider, title: str, body: str,
        idempotency_key: str, ledger: AuditLedger,
    ) -> IssueReceipt:
        # Atomic claim, dispatch and audit for this reference instance only.
        failure: type[Malformed] | type[Inconclusive] | type[IdempotencyConflict] = Inconclusive
        with self._lock:
            try:
                return self._open_issue(provider, title, body, idempotency_key, ledger)
            except Malformed:
                failure = Malformed
            except IdempotencyConflict:
                failure = IdempotencyConflict
            except Exception:
                failure = Inconclusive
        # Raise after the handler: no chained exception retains provider data.
        raise failure()

    def _open_issue(
        self,
        provider: IssueProvider,
        title: str,
        body: str,
        idempotency_key: str,
        ledger: AuditLedger,
    ) -> IssueReceipt:
        raw, payload_hash = self.prepare(title, body, idempotency_key)
        self._policy.authorize_target(self._policy.endpoint)
        existing = self._slots.get(idempotency_key)
        if existing is not None:
            if existing.payload_hash != payload_hash or existing.target_endpoint != self._policy.endpoint:
                raise IdempotencyConflict()
            return IssueReceipt(
                target_endpoint=existing.target_endpoint,
                payload_hash=existing.payload_hash,
                transport_status=existing.transport_status,
                seal_report=existing.seal_report,
                idempotency_key=existing.idempotency_key,
                duplicate_status=DUPLICATE_PROVIDER_STATUS,
            )
        if idempotency_key in self._slots:
            raise Inconclusive()
        if len(self._slots) >= 1024:
            raise Inconclusive()
        self._slots[idempotency_key] = None
        ledger.append(AuditEvent("retained", self._policy.service_account_id,
            self._policy.endpoint, payload_hash, idempotency_key, "retained", "", 0))
        try:
            receipt = self._resolve(provider, raw, payload_hash, idempotency_key)
        except Malformed:
            self._slots[idempotency_key] = None
            raise
        except Inconclusive:
            self._slots[idempotency_key] = None
            raise
        ledger.append(
            AuditEvent(
                "audit_v2",
                self._policy.service_account_id,
                receipt.target_endpoint,
                receipt.payload_hash,
                receipt.idempotency_key,
                "retained",
                "",
                receipt.transport_status,
            )
        )
        self._slots[idempotency_key] = receipt
        return receipt

    def _resolve(
        self, provider: IssueProvider, body: bytes, payload_hash: str, idempotency_key: str
    ) -> IssueReceipt:
        created = provider.create(body, idempotency_key, b"Bearer " + self._token)
        if created == "created":
            return _receipt(self._policy.endpoint, payload_hash, idempotency_key, 201, None)
        if created in {"timeout", "server"}:
            return self._reconcile(provider, body, payload_hash, idempotency_key)
        raise Malformed()

    def _reconcile(
        self, provider: IssueProvider, body: bytes, payload_hash: str, idempotency_key: str
    ) -> IssueReceipt:
        found = provider.find(idempotency_key)
        if found == "found":
            return _receipt(self._policy.endpoint, payload_hash, idempotency_key, 201, DUPLICATE_PROVIDER_STATUS)
        raise Inconclusive()



def _receipt(
    endpoint: str, payload_hash: str, idempotency_key: str, status: int, duplicate_status: int | None
) -> IssueReceipt:
    return IssueReceipt(endpoint, payload_hash, status, "retained", idempotency_key, duplicate_status)


def _field(value: str, limit: int, multiline: bool) -> bool:
    if not value or len(value) > limit:
        return False
    for char in value:
        if char == " ":
            continue
        if multiline and char in "\n\t":
            continue
        if not char.isascii() or not char.isprintable():
            return False
    return True


def _json(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)
