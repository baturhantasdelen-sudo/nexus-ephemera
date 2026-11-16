"""Persistent negative tests for the adversarial review findings."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from nexus_ephemera.adapters.github import GithubIssuePolicy, ReferenceGithubIssueTransport, IssueProvider
from nexus_ephemera.enterprise import AuditLedger
from nexus_ephemera.errors import Inconclusive, Malformed, TargetDenied
from nexus_ephemera.operations import RotationDrill


class AcceptedWithoutReply(IssueProvider):
    def __init__(self) -> None:
        self.creates = 0

    def create(self, body: bytes, idempotency_key: str, authorization: bytes) -> str:
        self.creates += 1
        return "timeout"

    def find(self, idempotency_key: str) -> str:
        # A lagging index cannot prove non-acceptance of the first create.
        return "missing"


def test_accepted_lost_reply_and_search_lag_never_repeat_the_write() -> None:
    transport = ReferenceGithubIssueTransport(GithubIssuePolicy.load(), b"fixture")
    provider = AcceptedWithoutReply()
    ledger = AuditLedger()
    for _ in range(3):
        with pytest.raises(Inconclusive):
            transport.open_issue(provider, "title", "body", "lost-reply", ledger)
    assert provider.creates == 1


def test_concurrent_same_key_has_one_atomic_reference_claim() -> None:
    transport = ReferenceGithubIssueTransport(GithubIssuePolicy.load(), b"fixture")
    provider = AcceptedWithoutReply()
    barrier = threading.Barrier(16)

    def execute() -> None:
        barrier.wait()
        with pytest.raises(Inconclusive):
            transport.open_issue(provider, "title", "body", "shared-key", AuditLedger())

    with ThreadPoolExecutor(max_workers=16) as executor:
        list(executor.map(lambda _: execute(), range(16)))
    assert provider.creates == 1


def test_closed_audit_rejects_before_dispatch_and_cannot_turn_into_cached_success() -> None:
    transport = ReferenceGithubIssueTransport(GithubIssuePolicy.load(), b"fixture")
    provider = AcceptedWithoutReply()
    ledger = AuditLedger()
    ledger.close()
    for _ in range(2):
        with pytest.raises(Inconclusive):
            transport.open_issue(provider, "title", "body", "closed-ledger", ledger)
    assert provider.creates == 0


def test_policy_decoder_discards_secret_document_and_duplicate_fields() -> None:
    for raw in (b'{"secret":"DECODER_CANARY",', b'{"role":"a","role":"b"}'):
        with pytest.raises(Malformed) as caught:
            GithubIssuePolicy.load(raw)
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None
        assert "DECODER_CANARY" not in str(caught.value)
        assert not hasattr(caught.value, "doc")


def test_rotation_drill_has_unambiguous_timestamp_and_key_binding() -> None:
    drill = RotationDrill(b"fixture")
    presented = drill.sign(12, "3")
    with pytest.raises(TargetDenied):
        drill.verify(presented, 12, 1, "23")
