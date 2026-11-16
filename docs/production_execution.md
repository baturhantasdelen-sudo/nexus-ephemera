# Production execution contract — 0.3.0-rc.1

This is a remediation candidate, not a certification or a new sealed tag.
Historical v0.2.0 reports do not certify this working tree.

## Mandatory path

Production agents use `TenantClient.execute_payload`. Start `nexus-daemon`
with `--enterprise-config` and a private configuration directory. The daemon
enforces peer UID/SID, bounded framing, tenant HMAC/policy, role/parameter and
exact endpoint checks, bounded worker admission, a durable Redis claim,
pre-dispatch audit anchoring, provider execution, and durable completion.
Client filters are additional checks, never the authority.

Same-UID/SID IPC authentication is not an isolation boundary against arbitrary
code running with that user's full filesystem/process rights. Such code can
read a credential file owned by that same identity. Agents must run in a
separate sandbox/mount namespace that exposes only the IPC endpoint, not the
broker credential/configuration mounts, with no host PID namespace or ptrace
capability. Validate that deployment boundary in the actual customer
environment. The library alone cannot certify it.

An explicit `--reference-mode` is required for hash-only local simulation.
It must not be deployed as a provider gateway. Package execution requires
enterprise configuration. The Rust `reference-pilots` feature and Python
`ReferenceGithubIssueTransport` are scripted demonstrations only. Their
in-memory caches do not provide cross-instance or restart idempotency.

The daemon currently serves one connection at a time. The 32-operation gate
is an upper bound on shared admission, not evidence of 32 concurrent provider
calls per daemon. Use separate daemon instances sharing the same Redis
namespace when testing multiple instances; do not advertise a 32-way daemon
throughput guarantee. Each instance needs its own audit stream path.

## Native GitHub edge

Add these optional fields together to the enterprise configuration:

```json
{
  "github_policy": "/private/nexus/pilot_support_agent.json",
  "github_token_file": "/private/nexus/github.token"
}
```

Both files must have the service user's private permissions. Token file
contents are the token bytes, with no newline or `Bearer ` prefix. Neither
token belongs in agent environment variables, tool parameters, argv or logs.
Grant role `support_agent` the exact policy issue endpoint and parameters
`title` and `body`. The request is:

```json
{"tool":"support_agent","params":{"title":"Printer jam","body":"Queue is stuck"}}
```

The current enterprise parameter limit is 256 bytes per string; the native
edge does not silently relax that bound. It constructs a POST body only from
these authorized fields. TLS and hostname verification remain mandatory;
redirects, environment proxies and automatic HTTP retries are disabled.
Only HTTP 201 with positive issue `id` and `number` is accepted. The receipt
reports transport acceptance; it is not a provider-side rollback capability.

A timeout, dropped reply, invalid response or non-201 result is uncertain.
No search result, including “missing”, authorizes another POST. A durable
Pending/Inconclusive entry blocks re-execution. Reconcile with provider-side
evidence and a documented operator procedure. Do not erase uncertainty or
generate a new key merely to force a retry. Redis data loss or namespace
rotation can invalidate these guarantees; they do not create exactly-once
semantics at an arbitrary external provider.

## Lifecycle and memory scope

Native HTTP edges hold an operation permit through their bounded I/O. New
operations are rejected after apoptosis is engaged; Complete cannot precede
outstanding native HTTP work. An already accepted external side effect cannot
be undone by local memory wiping. A custom transport remains responsible for
its own cancellation/deadline behavior; the broker retains uncertainty when
an external callback outlives its wait budget.

KeyRing, tenant keys, native provider tokens and audit keys use registered
locked buffers. Input ownership guards wipe constructor error paths. Retired
rotation keys are wiped on subsequent expiry checks or global cleanup/drop;
there is no autonomous idle-time key-expiry scheduler. `sign_request` now
returns Result, including terminal lifecycle rejection.

Managed regions are the guarantee boundary. Caller-owned strings, Python
immutable objects, HTTP/TLS/header buffers, kernel/network copies, registers,
privileged inspection, DMA, cold boot, hibernation and physical DRAM are not
covered by a universal zero-residue assertion. No test proves all-machine
forensic erasure. Do not log exception locals or transport bodies.

## Files and audit recovery

Unix package directories require service ownership and 0700; files require
0600 and one hard link. Windows uses a current-user-only DACL. New secret
files are created private, not written and chmodded afterwards. Reads bound
the bytes and validate the same opened handle; leaf symlinks/reparse points
are rejected. Keep the full parent hierarchy under trusted administration.
`--seal` requires all existing package files to be private before it creates
or replaces anything. It does not repair permissions. An authorized operator
must correct ownership/permissions explicitly, then retry sealing. This also
applies to an existing `hmac.key` or `policy.hmac`; rejection preserves them.
The Python package checker is a POSIX convenience validator; Windows fails
closed and uses the Rust `--check` command for authoritative DACL validation.

The file checkpoint sink is a single-writer snapshot stream, not an append-
only/WORM journal. A persistent create-new writer marker prevents another
instance from claiming the stream. Before each replacement it verifies
committed bytes against its in-memory checkpoint and hashes, rejecting
rewrite/truncation rather than repairing them. File data is synchronized;
Unix also synchronizes the parent directory. A crash between the two renames
can leave inconsistent files: fail closed, preserve evidence and start a new
unique stream after independent verification. Never delete the writer marker
and reuse a stream as an automatic recovery action. Store trusted checkpoints
outside the log's administrative failure domain for durable tamper evidence.
There is no claim of instantaneous filesystem monitoring or Windows power-
loss directory durability.

Tenant quarantine uses verified identity, bounded state, a monotonic server
clock, three consecutive policy denials and a 30-second interval. Accepted
policy checks reset the local counter. Quarantine counters are per instance,
not a distributed anti-abuse service; Redis claims remain authoritative across
instances. Capacity rejection is a typed RateLimited IPC error, with numeric
503 metadata; IPC is not an HTTP server.

## Release gate

Run formatting, default and all-feature Clippy with warnings denied, release
tests including reference-pilot regressions, Python pytest/strict mypy and
real Redis tests. The Linux CI Redis job must execute `redis_*` tests and the
seed → actual Redis restart → verify protocol. That protocol includes Done,
Pending and Partial receipts. No ignored Redis test counts as a local pass.
Require the same source identity to pass Windows, Linux and macOS CI before
tagging a sealed release. A real customer pilot requires its own authorized
service account, operational ownership, provider reconciliation and rollback
plan; a TLS fixture is not a customer deployment.
