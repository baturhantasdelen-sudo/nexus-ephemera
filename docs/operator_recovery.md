# Operator recovery and lifecycle

This is a privileged operational boundary, separate from agent IPC. Do not expose
Redis administrative credentials to agents. Restrict access to the operator
binary/configuration through host identity and normal privileged change control.

## Read-only uncertainty inspection

Create a separate private JSON file with ONLY redis_url, namespace and capacity,
matching the existing daemon namespace. Protect it and its directory with native
file controls. Store the ORIGINAL request key (no newline) in a private file.

    nexus-operator inspect /private/operator.json ACCOUNT /private/request-key

Output is one of missing/pending/inconclusive/recorded. No payload, receipt,
fingerprint, token or Redis URL is printed. Both files are bounded private reads;
process hardening runs first. The operator command never provisions, mutates,
unlocks, retries or deletes a claim. A read error is not converted to missing.
Exit 0 reports a diagnostic state after successful cleanup, exit 1 is denied or
unavailable, and exit 3 is incomplete cleanup. Never ignore the exit status.
There is no agent-facing inspection API. Host-authorized operators can inspect
any configured account; this is not a tenant self-service authorization API.

## Reconciliation

Freeze further execution of the disputed business operation, preserve audit and
Redis generation, then check provider-native operation records using a separate
read-only privileged identity. Record provider identifiers, decision, reviewer
and time in the customer's restricted incident system. Never copy title/body or
tokens into general telemetry. A Missing search result is not authorization to
repeat a POST. Unresolved uncertainty stays blocked. Any compensating action is
a separately authorized operation with its own record, not deletion of the claim.

## Restart, upgrade and rollback

1. Stop admission and drain bounded native I/O. Send SIGTERM on Unix; require
   successful exit and shutdown seal=complete. SIGKILL/abort cannot promise wiping.
2. Preserve Redis claims, fences, schema and sealed generation. Backups must be
   coordinated with provider reconciliation; restoring stale Redis can replay work.
3. Verify the closed audit stream with an independently retained checkpoint;
   retain files and marker. Configure a NEW unique audit stream for the next daemon.
4. Validate candidate binary/SDK/protocol/schema compatibility in staging, native
   package --check, and secret revocation/rotation behavior before switching paths.
5. Reuse the SAME live Redis namespace. Do not move old tags or overwrite releases.
   Roll back code only if schema/claim/audit compatibility was proven. Otherwise
   remain stopped and reconcile. Never restart-loop on a used audit stream.

## Rotation and external audit

Current daemon rotation is an operator-controlled drain/restart procedure; do not
advertise zero downtime. Keep the same claim namespace, create a new audit stream,
replace private credentials safely, reissue tenant tokens and revoke old provider
credentials. Verify old tokens fail and new tokens succeed. KeyRing grace tests
do not prove multi-daemon hot rotation. During migration retain emergency revocation
and never grant both unrelated tenants a shared broad provider credential.

FileCheckpointSink remains a pilot snapshot. Independently anchor checkpoints
before ledger capacity is exhausted; rotate by explicit drain/new-stream with a
recorded link to the previous trusted anchor. Production external sink integration
must implement CheckpointSink, authenticate its operator, retain append-only or
immutable history, and pass failure/restart tests. No remote vendor is assumed.

## Telemetry and capacity

Export only bounded numeric metrics, decisions and opaque identifiers. Explicitly
exclude credentials, provider headers, title/body and raw user input. Separate
liveness (process running) from readiness (package, store, audit and capacity).
Use authenticated local health, not a public unauthenticated diagnostics endpoint.
Track p99, slots, denied count, oldest uncertainty and audit headroom externally.
The ledger is bounded (1024 entries) and Redis capacity is configured (max 4096);
neither is a disposable cache. Alert BEFORE exhaustion; never evict claims.
