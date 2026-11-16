# Enterprise deployment and recovery

## Mandatory production gate

Without `--enterprise-config`, nexus-daemon is a local reference provider, not a production HTTP gateway. `ReferenceClusterNode`, `ReferenceIdempotency`, and Python `ReferenceSharedStore` are in-process models. Production execution uses `enterprise_runtime::{TenantAuthority, EnterpriseAdmission, RedisIdempotency, HttpPayloadTransport}`.

Enterprise requests carry tenant authorization and the actual base64 payload. The server recomputes the hash, checks the current policy-bound token, role/action, exact endpoint and parameter allowlist, then claims idempotency before external effects. Legacy hash-only calls cannot bypass this gate. Client filters are supplementary. Verified HTTPS forwards the exact validated bytes; redirects and environment proxies are disabled. Private DER roots never disable certificate/hostname verification. The actual HTTP status is preserved.

## Operator configuration

Use a dedicated service account and private configuration/checkpoint directories. Unix socket directories require owner service UID and 0700; sockets require 0600. Apply equivalent service-only Windows ACLs. Broker keys enter via stdin, never argv/config/logs. Scoped tenant bearer tokens also require credential protection.

Example enterprise.json (public fixtures; substitute endpoints/paths):

```json
{
  "accounts": [{
    "id": "billing", "roles": ["charge", "read"],
    "attributes": [["region", "eu"]],
    "allowlist": ["https://provider.example/charge", "https://provider.example/read"],
    "role_endpoints": {"charge": ["https://provider.example/charge"], "read": ["https://provider.example/read"]},
    "role_params": {"charge": ["amount"], "read": []}
  }],
  "redis_url": "redis://127.0.0.1:6379", "namespace": "billing-generation-1",
  "capacity": 4096, "checkpoint_path": "/private-anchors/billing-instance-1.json"
}
```

Start with `--enterprise-config enterprise.json --listen PRIVATE_ENDPOINT --allow https://provider.example/charge --allow https://provider.example/read`. Optional `provider_ca_der` configures a trusted private CA file. To issue a short-lived token, separately invoke `--enterprise-config enterprise.json --issue-tenant-token billing charge 60000` with the same key on stdin. The output is a scoped token, never the broker key. Complete policy fingerprints bind tokens; policy changes invalidate old tokens. Maximum lifetime: 24 hours.

Redis must use AOF, appendfsync always, and maxmemory-policy noeviction. Only literal loopback addresses or Unix sockets permit plaintext; remote Redis requires verified TLS. Restrict network access and credentials. The implementation requires INFO persistence, CONFIG GET, and its Lua/hash commands. Provision a fresh namespace deliberately with `--provision-store`; never automate bootstrap after data loss. Protect Redis credentials and config files. Redis library credential copies are outside managed LockedBuffer guarantees.

## Durable claims and failover

Atomic Lua claims/commits use a bounded Redis hash, tenant-scoped keys, endpoint/body fingerprints and commit fences. Claim/reconnect never silently recreates a missing namespace. Pending, Inconclusive and Done records never expire or evict automatically. A full store rejects work. Reconcile and rotate a drained generation rather than deleting uncertainty.

1. One leader claims before provider dispatch. Competitors receive a cached receipt or Inconclusive, never a second dispatch grant.
2. Timeout, cancellation, crash or missing commit leaves Pending/Inconclusive. Do not retry under a new business key.
3. Cached receipts preserve real provider and cleanup statuses. Partial/Failed remain errors. Failure to persist the completion audit creates a cached Partial and closes that admission instance.
4. Reconcile uncertain keys against authoritative provider records and the tenant-scoped provider idempotency key.
5. AOF is not consensus or exactly-once across disk loss/asynchronous replica failover. Require provider-native idempotency and a documented no-data-loss failover policy. Do not promote stale replicas.

Emergency stop: stop ingress, call `RedisIdempotency::quarantine_for_rotation`, drain active workers, reconcile uncertainty, then rotate keys/namespaces. Quarantine stops new claims; it does not cancel accepted remote operations. Never delete Pending/Inconclusive merely to unblock retries.

## Audit integrity

Audit v2 uses a strict bounded schema, hash chain and Merkle root. Metadata is domain-separated HMAC references under a random ledger key, not raw endpoints/account IDs/idempotency keys/plaintext hashes. Rust stores that key in managed locked memory. Python helpers do not promise a locked Python heap. `verify_export(export, trusted_checkpoint)` requires an independently trusted head/root/count. Unknown/duplicate fields, rewrite and truncation are rejected. A root solely supplied by the export is insufficient.

The ledger allows 1024 records and rejects appends after close. `FileCheckpointSink` fsyncs snapshots and enforces a monotonic stream. Give each daemon instance a unique path: startup rejects an existing anchor rather than overwriting it with an empty stream. Retain export plus checkpoint; crashes between writes are detectable. Unix parent-directory metadata is fsynced. Local files are NOT WORM storage or remote notarization. Production requires a CheckpointSink backed by independently administered append-only/immutable storage and independently authenticated retained checkpoints. Sink failure blocks admission before dispatch; post-dispatch failure is explicit Partial. Rotate a full stream after draining.

## Resource and verification gates

A mandatory 32-slot owned RAII gate bounds server admission; the 33rd is rejected. Python bounds pending callers and cached receipts. Permit release is idempotent and survives unwind/context exit. Provider/Redis timeouts do not prove remote cancellation.

Required checks: fmt, all-feature Clippy with warnings denied, release workspace tests, pytest and strict mypy. The additional enterprise-redis CI job runs actual AOF Redis with separate processes, crash/Pending, fences, cached Partial, conflicts, capacity, quarantine and missing-namespace checks. Ignored backend tests are explicitly selected there; locally skipped tests are not backend proof.

Production acceptance additionally requires real customer/provider retry tests, Redis restart/failover/data-loss drills, independently retained audit anchors and Linux/macOS/Windows evidence for the exact commit. Local test success alone is not enterprise certification. Same-user IPC is an account boundary, not isolation from every same-user process, container namespace or privileged host administrator. Managed-memory guarantees exclude arbitrary Python/TLS/kernel buffers, registers and hardware attacks. Disable exception logging that captures secret local variables.

## Day-2 drills

`cargo test --test operations_resilience` exercises the local drills below. They do not replace the enterprise-redis CI job.

- Rotate the broker signing key and the tenant HMAC key with a grace window. The new key signs the next request immediately. The retired key verifies only until the grace instant, then returns `TargetDenied`. An unknown or expired key returns `TargetDenied`. The request MAC canonical input is unchanged.
- Fill all 32 worker permits. The 33rd admission is rejected and reported as HTTP 503. Releasing a permit admits one more caller.
- Three `TargetDenied` observations quarantine that tenant until the block interval ends. The block does not delete Pending or Inconclusive idempotency records.
- A Redis outage is closed as `Inconclusive`. The error text is static and does not include a URL, token, or broker secret. Do not mint a new business key to retry it.
- An audit sink that cannot persist blocks dispatch. The provider counter stays at zero until the sink accepts the checkpoint.
- Telemetry export is the audit-v2 document plus its Merkle root. `verify_export` rejects a changed kind. The export must not contain signing secrets, provider tokens, or issue bodies.

