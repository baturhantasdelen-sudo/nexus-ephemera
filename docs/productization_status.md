# Productization acceptance ledger

This ledger distinguishes implemented mechanisms from deployment acceptance. It
does not certify a customer rollout. Source version remains 0.3.0-rc.1.

## Implemented in this change

* Assurance/commercial boundaries and design-partner scope tied to production path.
* Read-only operator inspection with private bounded files; no retry/delete API.
* Unix SIGTERM graceful drain registered before ready; regression in pilot tests.
* Audit-aware readiness, bounded local numeric probe and capacity rejection checks.
* Verified prebuilt installer (same-byte digest/parser, strict members/architecture,
  no overwrite), installed-archive positive and tamper-negative smoke tests.
* Source/tag/SDK version gate, RC prerelease, wheel/sdist checks, license/inventory,
  secret-free downloadable pilot kit, pinned provenance action and single publisher.
* Linux release runner fixed to 24.04, glibc <=2.39 symbol gate. Cross-platform
  CI imports the installed wheel outside checkout and runs default-feature binaries.
* Reference systemd unit with private stdin, bounded resources and explicit restart.
* Evidence integrity checker: missing, pending, failed or modified evidence blocks.

## Remain blocked until actual evidence exists

* Updated same-commit three-platform CI, real Redis and tag-only release/provenance.
* Real systemd/Windows service/macOS launchd deployment and platform signing/notarization.
* Customer agent filesystem/process/egress isolation and least-privilege provider access.
* External authenticated audit sink/independent anchors, rollover and recovery in
  the chosen customer storage. No remote immutable sink is implemented by this change.
* Customer Redis HA/failover/partition/backup topology; AOF tests are not consensus proof.
* Daemon hot-rotation control plane and idle expiry scheduling: not implemented;
  current supported procedure is deliberate drain/restart/reissue/revoke.
* Measured workload SLOs and per-tenant fairness. Serial serving and per-instance
  quarantine remain explicit bounds; no distributed quarantine is added here.
* Independent external review and customer approval. No person/tool may mark these
  passed without the actual reviewer/customer evidence.
* Staffed SLA/on-call, signed commercial terms and operational liability allocation.

Each item maps to design_partner_pilot.md / pilot/acceptance.template.json. The
template starts pending and cannot truthfully be promoted by synthetic fixture tests.
