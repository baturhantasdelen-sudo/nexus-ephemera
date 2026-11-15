# Enterprise runbooks

These procedures cover the enterprise adapters in `nexus_ephemera::enterprise` and `nexus_ephemera.enterprise`. They do not turn the process-local daemon cache into a durable database. The default `nexus-daemon` idempotency cache still dies with the process. Pending and inconclusive entries must not be dispatched again.

The audit hash chain and Merkle root show whether an exported log was modified. They are not a MAC, not mTLS, and not protection from a process that can rewrite both the log and the stored root. Keep the Merkle root outside the log host. The binding digest on a receipt is still not a remote authenticator. Tenant HMAC tokens are checked by the Rust verifier with a key derived from the broker secret. The Python directory enforces role and allowlist membership and does not accept that secret.

Same-user IPC remains an account boundary. It does not isolate every process of that user, and it does not create container-namespace tenant IDs.

## Emergency: stop dispatch

1. Stop new client traffic at the operator edge.
2. Call `SharedIdempotency::quarantine_for_rotation` (Python: `SharedStore.quarantine_for_rotation`). Further claims fail closed and do not reach the provider.
3. Export `AuditLedger::export_json` and record `merkle_root` in a separate store. A later `verify_export` that fails means the export was modified.
4. Do not delete Pending or Inconclusive slots to "unblock" a retry. Those slots exist because the provider outcome is unknown.

## Key rotation

1. Quarantine the shared store. Do not reuse it under the new secret. Cached receipts belong to the old key.
2. Stop `nexus-daemon`. The old secret is only in that process's stdin and is wiped on shutdown of the broker admission.
3. Start a new daemon with the new secret on stdin, not argv. Old tenant tokens fail verification.
4. Issue new tenant tokens from the new process. Token lifetime is at most 24 hours.
5. Open a new shared store. Replaying an old idempotency key against a wiped store would be a new provider call, so operators must reconcile inconclusive keys before issuing those keys again.

## Failover

1. A second `ClusterNode` uses the same `SharedIdempotency` value.
2. The node that wins `claim` is the only one allowed to commit with that fence.
3. If the leader stops after the claim and before commit, the slot stays Pending. The standby receives `Inconclusive` and must not call the provider.
4. A finished call returns the cached receipt. `duplicate_status` is 409 and `transport_status` stays the first status. The provider hit counter does not increase.
5. The Redis adapter command is `SET nexus:idem:<account>:<key> pending NX`. A failed NX means the key is already claimed. Treat that as inconclusive or cached, never as a second dispatch. This tree does not open a Redis connection.

## Saturation and network loss

The worker gate allows 32 in-flight acquisitions. The 33rd fails with the capacity error and does not queue more work. Release a permit before accepting another call.

A provider timeout or reset after a claim commits Inconclusive and does not count a successful provider hit. The same key stays inconclusive. Do not retry it automatically.

## Checks

```text
cargo test --test chaos_resilience -- --test-threads=1
```

From `clients/python`:

```text
python -m pytest tests/test_enterprise.py
python -m mypy --strict
```
