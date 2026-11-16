# Design Partner Pilot Kit

Entry point: product_contract.md. Release candidate; not a production certificate.

## Scope and ownership

Start with one design partner, one tenant, one agent, one private sandbox GitHub
repository and issue creation only. No payments or production destructive writes.
Name the customer owner, operator, security reviewer and rollback decision maker.
Agree the provider token's least privileges, allowed repo, data classification,
retention and deletion process before provisioning. Never put real title/body,
tokens, Redis passwords or plaintext hashes into the evidence bundle.

## Architecture and installation

1. Verify source tag, commit, archive provenance and digest. Install versioned
   binaries using distribution.md; never pipe an unauthenticated download to a shell.
2. Provision a private service account/directory (0700 directory, 0600 secrets;
   native protected Windows DACL). Use the native --init-package/--seal/--check.
3. Deploy the agent in a sandbox: expose IPC only, no broker secret/config mounts,
   no ptrace capability, and controlled provider egress. Same-user IPC requires
   deliberate sandbox design; different UID is not accepted by the current protocol.
   Both sides must also have compatible PID/user namespaces: a peer outside a
   Linux PID namespace may appear as PID 0 and is deliberately rejected. Do not
   weaken peer checks to make a generic container deployment work. Options to
   validate are a host broker with a mount/LSM/seccomp-isolated agent in a compatible
   PID namespace, or two filesystem-isolated processes sharing one PRIVATE (not
   host) PID/user namespace. Deny process-memory and /proc/root escape paths.
   Use a separate private socket directory, not the package/secret directory, as
   the shared mount. Neither pattern is customer-certified by these templates.
4. Configure production enterprise admission and GitHubTransport per
   production_execution.md. Use a sandbox-only scoped provider token. Keep the
   current parameter length limits; do not silently enlarge production requests.
5. Explicitly provision a new durable Redis namespace ONCE; share it across
   replicas. Use a distinct audit stream per daemon. Never bootstrap after loss.
6. Issue short-lived tenant authorization to the agent, not the provider key.
   Execute through TenantClient.execute_payload, never hash-only reference mode.

## Acceptance evidence

Copy pilot/acceptance.template.json into a PRIVATE evidence directory. Set the
full source commit. Gates start pending. For each gate retain a sanitized review
artifact with exact source/binary identity, platform, topology, timestamp,
reviewer, workload, expected result and observed result. Set reviewed_pass only
after review and enter its SHA-256. Run:

Failed/pending gates may retain hashed failure evidence; they still block acceptance.


    python scripts/pilot_gate.py /private/evidence/acceptance.json --expected-commit FULL_SHA

Exit 0 means attachments and decisions are complete, NOT that the tool has
performed an audit or authenticated a reviewer. Exit 1 means pending/failed;
exit 2 means invalid/missing/modified evidence. Customer acceptance and independent
review may not be replaced with CI logs. No automatic production promotion exists.

## Required drills

* Negative route/method/repo/body/tenant/token tests: denied, provider count zero.
* Concurrent same-key requests, accepted-but-response-lost, daemon crash and restart:
  no automatic second dispatch. Preserve the same Redis generation and fences.
* Redis unavailability, AOF restart, chosen real failover topology, network partition
  and backup restore. Record data-loss assumptions; AOF alone is not HA consensus.
* Audit failure before and after dispatch, full ledger/disk, rewrite/truncation,
  independent checkpoint verification and safe stream rollover across restart.
* Actual credential revocation and rotation, token expiry, agent secret-file and
  process-read denial; collect sanitized evidence without dumping real secrets.
* SIGTERM shutdown, provider deadline, capacity shedding and operator reconciliation.
* Upgrade and rollback without changing claim namespace or erasing uncertainty.

## Measurements and business decision

Agree workload and acceptance thresholds before testing: p50/p95/p99 latency,
throughput, concurrency, CPU/RSS/locked bytes, capacity denials, uncertainty age,
reconciliation time, audit anchoring delay, installation and recovery time.
Compare with the same unbrokered baseline. Include integration/operations and
infrastructure cost. Do not infer ROI from test counts or modelled incidents.

Progression: scope/security agreement → clean install → controlled sandbox calls
→ failure/load drills → operator-led recovery → customer review → limited rollout.
Budget 4–6 weeks as a planning estimate, not a delivery guarantee. Production
promotion requires customer sign-off and completion of every acceptance gate.
