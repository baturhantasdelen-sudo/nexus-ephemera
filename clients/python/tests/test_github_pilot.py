"""GitHub issue pilot: allowlist, schema lock, timeout reconciliation, no token."""

from __future__ import annotations

from nexus_ephemera.adapters.github import GithubIssuePolicy, GithubIssueTransport
from nexus_ephemera.enterprise import AuditLedger
from nexus_ephemera.errors import IdempotencyConflict, Inconclusive, Malformed, TargetDenied

TOKEN = b"ghp_pilot_token_value"


class Script:
    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.creates = 0
        self.stored = False
        self.saw_token = False

    def create(self, body: bytes, idempotency_key: str, authorization: bytes) -> str:
        del body
        if authorization != b"Bearer " + TOKEN:
            return "rejected"
        self.saw_token = True
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
        if self.creates == 1:
            return "timeout"
        self.stored = True
        return "created"

    def find(self, idempotency_key: str) -> str:
        del idempotency_key
        return "found" if self.stored else "missing"


def test_support_agent_issue_contract() -> None:
    policy = GithubIssuePolicy.load()
    assert policy.endpoint == "https://api.github.com/repos/pilot-org/support-queue/issues"
    transport = GithubIssueTransport(policy, TOKEN)
    assert "ghp_pilot_token_value" not in repr(transport)
    ledger = AuditLedger()
    provider = Script("success")
    first = transport.open_issue(provider, "Printer jam", "The queue is stuck", "issue-1", ledger)
    assert first.transport_status == 201
    assert first.duplicate_status is None
    assert first.seal_report == "retained"
    replay = transport.open_issue(provider, "Printer jam", "The queue is stuck", "issue-1", ledger)
    assert replay.duplicate_status == 409
    assert replay.payload_hash == first.payload_hash
    assert provider.creates == 1
    try:
        transport.open_issue(provider, "Other title", "The queue is stuck", "issue-1", ledger)
    except IdempotencyConflict:
        pass
    else:
        raise AssertionError("different body reused the key")
    assert provider.creates == 1
    try:
        transport.open_fields(
            provider,
            {"title": "Printer jam", "body": "The queue is stuck", "token": "ghp_pilot_token_value"},
            "issue-extra",
            ledger,
        )
    except Malformed:
        pass
    else:
        raise AssertionError("extra field was accepted")
    for denied in (
        "https://api.github.com/orgs/pilot-org/transfers",
        "https://api.github.com/repos/pilot-org/support-queue/contents/README.md",
        "https://api.github.com/repos/pilot-org/support-queue/actions",
    ):
        try:
            policy.authorize_target(denied)
        except TargetDenied:
            continue
        raise AssertionError(denied)
    assert provider.creates == 1
    timed = Script("timeout-stored")
    reconciled = transport.open_issue(timed, "Printer jam", "The queue is stuck", "issue-timeout", ledger)
    assert reconciled.duplicate_status == 409
    assert timed.creates == 1
    failed = Script("server-stored")
    server = transport.open_issue(failed, "Printer jam", "The queue is stuck", "issue-5xx", ledger)
    assert server.duplicate_status == 409
    assert failed.creates == 1
    retried = Script("timeout-missing")
    opened = transport.open_issue(retried, "Printer jam", "The queue is stuck", "issue-retry", ledger)
    assert opened.duplicate_status is None
    assert retried.creates == 2
    assert ledger.verify()
    exported = ledger.export_json()
    assert "audit_v2" in exported
    assert "ghp_pilot_token_value" not in exported
    unknown = Script("timeout-stored")
    unknown.stored = False

    class Blind(Script):
        def find(self, idempotency_key: str) -> str:
            del idempotency_key
            return "unavailable"

    blind = Blind("timeout-stored")
    try:
        transport.open_issue(blind, "Printer jam", "The queue is stuck", "issue-unknown", ledger)
    except Inconclusive:
        pass
    else:
        raise AssertionError("unknown timeout was treated as success")
    assert blind.creates == 1
    try:
        transport.open_issue(blind, "Printer jam", "The queue is stuck", "issue-unknown", ledger)
    except Inconclusive:
        pass
    else:
        raise AssertionError("inconclusive key was dispatched again")
    assert blind.creates == 1
