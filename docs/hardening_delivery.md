# Hardening delivery and production gates

## Implemented
- Reserve idempotency keys before provider dispatch. Unknown outcomes do not expire into duplicate side effects. Capacity exhaustion rejects new work.
- Preserve CleanupIncomplete even when the provider result is unknown.
- Enforce broker policy and consumed state in the shared split-dispatch admission gate.
- Reject nonce counter exhaustion instead of wrapping.
- Retain the Windows pipe name when rejecting rate-limited clients; use a rolling one-second principal window.
- Install the current-user descriptor when creating the Windows pipe, inside ipc_os; unsafe code remains outside the main crate. ACL storage is explicitly aligned.
- Reject hard-linked Unix lock files and poll cancellation in bounded intervals.
- Bound each complete frame read/write by one shared deadline.
- Keep full process-local audit records and an eviction anchor for verification; recover a poisoned audit mutex.
- Use subtle for equal-length byte comparisons. Redaction as a whole is NOT constant time and exposes output length/match positions.
- Add request/response fuzz entry points and a cargo-fuzz harness; add macOS to CI.

## Required release gates
1. Windows same-user connection and subsequent-instance tests must pass on a supported host. The diagnosed AppContainer failure is addressed using its exact package SID alongside the user SID, with strict read-back validation and a matching mandatory label. Validate both ordinary and AppContainer deployment environments; never grant Everyone or ALL APPLICATION PACKAGES.
2. Linux/macOS CI must pass; Windows execution cannot validate Unix syscalls or fork behavior.
3. Run a bounded nightly cargo-fuzz campaign, retain corpus and crashes; harness compilation alone is not a campaign.
4. For financial/non-repeatable operations: durable pending journal, crash recovery, provider reconciliation and provider-side idempotency are required. Current tombstones are intentionally process-local.
5. For hard cancellation of arbitrary providers: separate supervised provider process with bounded IPC, not unsafe thread termination. Current worker isolation prevents wipe deadlock but cannot terminate blocked foreign code.
6. Bindings remain version-v1, length-prefixed local summaries, not an HMAC authorization token. Before remote authorization, design a versioned MAC/signature protocol binding context and idempotency key with receiver-side replay checks. Do not silently change the deployed schema.
7. Local audit chains are neither authenticated nor durable. For compliance, external signed checkpoints and explicit loss handling are required.

No commit, tag or production certification is implied by this delivery.
