# Enterprise integration

This guide is for teams embedding `nexus-ephemera` 0.2.0. The guarantee is **verified wiping of managed memory and bounded retention (Sensitive-Memory Lifecycle Protection)**. It is not a claim of zero residue on hardware.

## Threat-model boundary

| In scope | Out of scope |
| --- | --- |
| Core dumps, unencrypted swap and pagefile residue, `fork` inheritance of locked pages, forensic residue inside managed buffers, log disclosure of registered secrets | Cold boot, DMA, physical DRAM reads, privileged `ptrace`, and other hardware or kernel reads |

`mlock` or `VirtualLock` must succeed before a buffer becomes active. A failed unlock quarantines the buffer and does not report success. Linux additionally applies `MADV_DONTDUMP` and `MADV_DONTFORK` to locked ranges. `MADV_DONTFORK` drops the range from the child address space; it does not leave the child a zero-filled copy. These calls are OS hints. They do not stop a privileged tracer or a hardware attack. Audit flags report them only after hardening succeeded and this context locked at least one buffer.

## EphemeralContext lifecycle

Create one context per task. Contexts do not share buffers.

1. `EphemeralContext::open` calls `harden_process_memory` and rejects a policy that does not require `mlock`. Hardening failure fails closed.
2. `insert` copies bytes into a locked buffer, charges the page-rounded lock span, and returns a `BufferGrant` bound to that `task_id`.
3. A grant presented to another context returns `ContextMismatch`. Reads require an operation permit and an `Active` context. After apoptosis is engaged, reads are denied.
4. Exceeding `max_bytes` (including page rounding and an auxiliary sanitizer charge), or passing `timeout`, seals the context and wipes managed buffers.
5. `seal` or `Drop` from `Active` is terminal. `reopen` does not return to `Active`.

Terminal states:

| State | Meaning |
| --- | --- |
| `Closed` | Wipe completed |
| `Quarantined` | Unlock or rollback failed; process apoptosis is triggered |
| `Failed` | A new locked allocation failed after existing buffers were wiped |

## Broker contract

The in-process command the agent is allowed to send is:

```text
ExecuteWithPolicy { context_id, target_endpoint, payload_hash, idempotency_key }
```

`SecureTransactionAgent::admit` calls `harden_process_memory` before the context is opened. The agent keeps the key inside an `EphemeralContext`. `SecureTransport::dispatch` receives `AuthorizedCall`: endpoint, payload hash, an in-process `call_nonce`, `issued_at_unix_ms`, `binding_digest_hex`, and `idempotency_key`. The digest is SHA-256 over the key, endpoint, payload hash, nonce, and timestamp. The idempotency key is not an input to that digest. It is an in-process IPC/API boundary, not a MAC and not mTLS. It does not authenticate a remote peer. The call struct has no key field.

Rules enforced before dispatch:

| Tag | Behavior |
| --- | --- |
| `SingleUse` | The authority is consumed before `dispatch`. The operation permit stays held across digest, dispatch, and seal, so apoptosis cannot finish wiping during the call. A panic during dispatch still seals through `Drop`. A second execute returns `SingleUseConsumed`. |
| `ExpiresAt` | A deadline in the past seals the context and returns `Expired` without dispatch. |
| `ProviderBound` | Any other endpoint returns `ProviderMismatch` without dispatch. |
| `Allowlist` | Exact endpoint match against the admitted list. An empty list is rejected at admission. Prefixes do not match. |
| `LocalOnly` | Execute returns `LocalOnlyDenied`. |
| `NoPlaintextExport` | Required for broker admission. `Display` and `Debug` render `[REDACTED]`. |

The receipt contains the endpoint, payload hash, binding digest, transport status, `seal_report`, and the client `idempotency_key`. The digest is not key material and not a remote authenticator. The idempotency key is not part of the digest. Do not log the digest next to other identifiers if your policy forbids that.

`seal_report` is `Retained` when the call did not seal, and `Complete`, `Partial`, or `Failed` when it did. `execute` returns `CleanupIncomplete` for `Partial` and `Failed`. A transport status of 200 does not override a failed seal.

`nexus-daemon` runs that same agent in another process. The key is read from the daemon's stdin, not from argv, and only after process hardening. The stdin read is capped at 4097 bytes. `NexusClient` sends the endpoint, payload hash, and idempotency key over a Unix socket (mode `0600`, same UID, non-zero PID, checked by the client before it writes) or a Windows named pipe (remote clients rejected, owner-only DACL for the current user, server SID checked by the client before it writes). A repeated key with the same endpoint and payload hash returns the cached receipt and does not dispatch again. A repeated key with a different endpoint or payload hash is a conflict and does not dispatch. The cache is in-memory, TTL-bounded, and dies with the process. The wire result is a receipt only when the seal is `Complete` or `Retained`. `Partial`, `Failed`, and an unknown seal are not success. The digest on that receipt is not a remote authenticator. A privileged administrator is outside the pipe DACL. Operational counters are integers only; see `docs/operational_guide.md`.

## Reading an AuditSummaryReport

`seal`, budget exhaustion, expiry, drop, unlock failure, and allocation failure each store one report. It has no secret field and no plaintext hash.

| Field | How to read it |
| --- | --- |
| `context_id` | Task id. Not a secret. |
| `closing_reason` | `ExplicitSeal`, `BudgetExceeded`, `Expired`, `Drop`, `UnlockFailure`, or `AllocationFailed`. |
| `managed_buffers_count` | Buffers owned at close. |
| `total_bytes_wiped` | Page-rounded locked spans charged to the context, including a broker sanitizer copy when that copy was charged. This is not the raw payload length. |
| `quarantined_allocations_count` | Buffers whose unlock failed, plus sanitizer wipe failures noted before seal. |
| `platform_protections_active` | `mlock` is true only when hardening succeeded and at least one buffer was locked. Linux `madv_dontdump` / `madv_dontfork` follow that same observation. An empty seal reports all three as false. |
| `final_status` | `Complete` (clean wipe), `Partial` (quarantine), or `Failed` (allocation failure after a clean wipe). |

`Partial` means the process must not be treated as clean. `Failed` means the context is dead even though the wipe of existing buffers succeeded.

## Log sanitization

Register secret bytes with `LogSanitizer::register` or use `SecureTransactionAgent::sanitize_log` before the agent is wiped.

- Matching spans are replaced with the exact token `[REDACTED]`, and only when both ends of the match sit on UTF-8 character boundaries.
- Registered secrets are borrowed from locked buffers for a single pass. A denied permit returns before any line copy is allocated. The output builder is zeroized if redaction unwinds.
- The filter does not return the secret.
- An empty secret is rejected.
- After `wipe` or a single-use seal, the filter no longer knows the secret and will not redact new lines. Redact logs before seal.
- Broker errors do not include secret bytes. Do not interpolate caller-supplied key material into your own `Display` or tracing fields.

`String` and `Vec<u8>` implement `ExportBoundary::ALLOWS_PLAINTEXT_EXPORT = true`. `NoPlaintextExport` and `SecureTransactionAgent` do not. Do not add a method that returns the locked bytes as either of those exportable types.

## Build, test, and measure

```text
cargo test --workspace --release
cargo fmt --all -- --check
cargo bench --bench lifecycle_bench
cargo run --example broker_transaction
```

`lifecycle_bench` reports nearest-rank p95 and p99, in microseconds, for locked allocation, in-place seal/open, and broker `execute`. Run it on the target operating system. A Windows run does not execute the Linux `fork` probe's `MADV_DONTFORK` assertion; that probe runs in CI on Ubuntu.
