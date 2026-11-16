# Product and assurance contract — 0.3.0 candidate

Nexus Ephemera gives agents policy-bounded operations instead of provider keys.
The supported production path is TenantClient.execute_payload → authenticated
local IPC → server-side enterprise admission → durable claim → audit → provider.
Framework wrappers must not perform a second provider dispatch.

## Guarantees and exclusions

* Provider credentials are not returned through the agent SDK. This requires an
  agent sandbox that cannot read broker files, inspect its process, or bypass
  the broker through unrestricted egress. Same UID alone is not isolation.
  UID/PID namespace compatibility is required by the current positive-peer-PID
  checks. A generic separate-container layout is not automatically supported.
* Wiping and lock guarantees cover managed regions. Python strings, caller
  buffers, HTTP/TLS/kernel copies, registers, privileged readers, abort/kill,
  cold boot and DMA do not have universal zero-residue guarantees.
* Same tenant/key/fingerprint uses one durable admission. Different keys do not
  provide semantic deduplication. Redis loss, namespace replacement and provider
  behavior affect guarantees; arbitrary external exactly-once is not promised.
* Pending/Inconclusive are not retry permissions. Recorded is diagnostic and
  does not imply a complete seal. Missing does not prove no external operation.
* Pre-dispatch audit failure blocks dispatch. Post-dispatch failure cannot undo
  a side effect and must remain visible as incomplete/uncertain.
* Hash/Merkle evidence is tamper-evident relative to a trusted checkpoint, not
  intrinsically immutable. FileCheckpointSink is a bounded single-writer pilot
  snapshot, not WORM storage. External anchoring is a deployment requirement.
* The 32-operation gate is an upper bound, not measured daemon parallelism;
  current connection serving is serial. Quarantine is per instance (3 policy
  denials, 30 seconds, monotonic clock), not distributed account-wide RBAC state.

## Product maturity

Linux x86_64 is the first reference pilot deployment. Windows x86_64 and macOS
ARM64 have CI paths; this does not establish identical security controls or
contractual support. See platform_support.md. No independent certification,
24/7 response, zero downtime, zero loss, crash-free or compliance guarantee is
implied by test counts. A release candidate is not a sealed customer release.

## Capabilities requiring deployment evidence

Daemon-wide hot rotation/grace, autonomous idle key expiry, external authenticated
WORM audit, Redis Sentinel/Cluster failover semantics, service-manager behavior,
cross-version recovery and customer sandbox isolation require their own tests.
KeyRing is a library primitive, not a deployed rotation control plane. Do not
advertise these capabilities as complete merely because a primitive exists.

Claims must link to exact-commit evidence, platform, topology and test scope.
