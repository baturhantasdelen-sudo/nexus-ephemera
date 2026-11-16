"""Field pilot decisions for the support-agent account. The HMAC token stays in Rust."""

from __future__ import annotations

import threading

from nexus_ephemera.adapters.github import GithubIssuePolicy, GithubIssueTransport, IssueProvider, IssueReceipt
from nexus_ephemera.enterprise import (
    WORKER_CAP,
    AuditEvent,
    AuditLedger,
    ServiceAccount,
    TenantDirectory,
    verify_export,
)
from nexus_ephemera.errors import IdempotencyConflict, Inconclusive, TargetDenied

ACCOUNT = "support_agent_service_account"
ROLE = "support_agent"
ISSUES = "https://api.github.com/repos/pilot-org/support-queue/issues"
SECRET_REPO = "https://api.github.com/repos/pilot-org/secret-admin-repo/issues"


class Script(IssueProvider):
    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.creates = 0
        self.stored = False

    def create(self, body: bytes, idempotency_key: str, authorization: bytes) -> str:
        del body, idempotency_key
        if not authorization.startswith(b"Bearer ") or b"ghp_field_token_value" not in authorization:
            return "rejected"
        self.creates += 1
        if self.mode == "success":
            self.stored = True
            return "created"
        if self.mode == "timeout-stored":
            self.stored = True
            return "timeout"
        if self.mode == "server-stored":
            self.stored = True
            return "server"
        if self.mode == "unavailable":
            return "timeout"
        if self.creates == 1:
            return "timeout"
        self.stored = True
        return "created"

    def find(self, idempotency_key: str) -> str:
        del idempotency_key
        if self.mode == "unavailable":
            return "unavailable"
        return "found" if self.stored else "missing"


class FieldPilot:
    def __init__(self) -> None:
        policy = GithubIssuePolicy.load()
        self._directory = TenantDirectory([
            ServiceAccount(ACCOUNT, (ROLE,), (), (ISSUES,), ((ROLE, (ISSUES,)),)),
        ])
        self._transport = GithubIssueTransport(policy, b"ghp_field_token_value")
        self._call = threading.Lock()

    def __repr__(self) -> str:
        return f"FieldPilot(service_account={ACCOUNT!r})"

    def execute(
        self,
        provider: IssueProvider,
        method: str,
        endpoint: str,
        title: str,
        body: str,
        idempotency_key: str,
        ledger: AuditLedger,
    ) -> IssueReceipt:
        with self._call:
            try:
                self._directory.allow(ACCOUNT, ROLE, endpoint)
            except TargetDenied:
                _note(ledger, "target_denied", endpoint, idempotency_key, 0)
                raise
            if method != "POST":
                _note(ledger, "target_denied", endpoint, idempotency_key, 0)
                raise TargetDenied()
            try:
                receipt = self._transport.open_issue(provider, title, body, idempotency_key, ledger)
            except IdempotencyConflict:
                _note(ledger, "idempotency_conflict", endpoint, idempotency_key, 0)
                raise
            if receipt.duplicate_status is None:
                _note(
                    ledger,
                    "retained",
                    receipt.target_endpoint,
                    receipt.idempotency_key,
                    receipt.transport_status,
                )
            return receipt


def _note(ledger: AuditLedger, kind: str, endpoint: str, idempotency_key: str, status: int) -> None:
    ledger.append(AuditEvent(kind, ACCOUNT, endpoint, "denied", idempotency_key, "retained" if kind == "retained" else "", "aa" * 32, status))


def test_field_pilot_denies_foreign_routes_and_reconciles() -> None:
    assert WORKER_CAP == 32
    pilot = FieldPilot()
    assert "ghp_field_token_value" not in repr(pilot)
    ledger = AuditLedger()
    provider = Script("success")
    for method, endpoint in (("POST", SECRET_REPO), ("DELETE", ISSUES), ("PUT", ISSUES)):
        try:
            pilot.execute(provider, method, endpoint, "Printer jam", "The queue is stuck", "field-denied", ledger)
        except TargetDenied:
            continue
        raise AssertionError(method)
    assert provider.creates == 0
    opened = pilot.execute(provider, "POST", ISSUES, "Printer jam", "The queue is stuck", "field-1", ledger)
    assert getattr(opened, "duplicate_status", None) is None
    replay = pilot.execute(provider, "POST", ISSUES, "Printer jam", "The queue is stuck", "field-1", ledger)
    assert getattr(replay, "duplicate_status", None) == 409
    assert provider.creates == 1
    try:
        pilot.execute(provider, "POST", ISSUES, "Other title", "The queue is stuck", "field-1", ledger)
    except IdempotencyConflict:
        pass
    else:
        raise AssertionError("different body reused the key")
    assert provider.creates == 1
    timed = Script("timeout-stored")
    reconciled = pilot.execute(timed, "POST", ISSUES, "Printer jam", "The queue is stuck", "field-timeout", ledger)
    assert getattr(reconciled, "duplicate_status", None) == 409
    assert timed.creates == 1
    failed = Script("server-stored")
    server = pilot.execute(failed, "POST", ISSUES, "Printer jam", "The queue is stuck", "field-5xx", ledger)
    assert getattr(server, "duplicate_status", None) == 409
    assert failed.creates == 1
    retried = Script("retry")
    opened_retry = pilot.execute(retried, "POST", ISSUES, "Printer jam", "The queue is stuck", "field-retry", ledger)
    assert getattr(opened_retry, "duplicate_status", None) is None
    assert retried.creates == 2
    unknown = Script("unavailable")
    try:
        pilot.execute(unknown, "POST", ISSUES, "Printer jam", "The queue is stuck", "field-unknown", ledger)
    except Inconclusive:
        pass
    else:
        raise AssertionError("unknown timeout was treated as success")
    assert unknown.creates == 1
    try:
        pilot.execute(unknown, "POST", ISSUES, "Printer jam", "The queue is stuck", "field-unknown", ledger)
    except Inconclusive:
        pass
    else:
        raise AssertionError("inconclusive key was dispatched again")
    assert unknown.creates == 1
    assert ledger.verify()
    exported = ledger.export_json()
    assert verify_export(exported, ledger.checkpoint())
    for kind in ("target_denied", "idempotency_conflict", "retained", "audit_v2"):
        assert kind in exported
    assert "ghp_field_token_value" not in exported
    assert "The queue is stuck" not in exported
    raced = Script("success")
    barrier = threading.Barrier(2)
    outcomes: list[object] = []

    def race() -> None:
        barrier.wait()
        try:
            outcomes.append(pilot.execute(raced, "POST", ISSUES, "Printer jam", "The queue is stuck", "field-race", ledger))
        except Inconclusive:
            outcomes.append(Inconclusive())

    threads = [threading.Thread(target=race) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert raced.creates == 1
    cached = pilot.execute(raced, "POST", ISSUES, "Printer jam", "The queue is stuck", "field-race", ledger)
    assert cached.duplicate_status == 409
    assert raced.creates == 1


    assert "The queue is stuck" not in exported