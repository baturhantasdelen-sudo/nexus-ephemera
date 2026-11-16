# Distribution, provenance and supported deployment

Current source version: 0.3.0-rc.1. No test run alone creates a sealed release.

## Release path

The existing tag pipeline is the only publisher: validate (three operating systems
and real Redis) Ã¢â€ â€™ build architecture-checked binaries and SDK Ã¢â€ â€™ execute installed
archives, reject package tampering and import an installed wheel Ã¢â€ â€™ one publisher.
Tag, Cargo and SDK source versions must agree. RC tags are prereleases. Existing
releases are not overwritten; failed drafts require operator reconciliation.

Assets: three target archives (daemon, CLI, operator and license), SDK wheel/sdist, Cargo
CycloneDX inventory, MIT LICENSE, a secret-free pilot kit ZIP and one SHA-256 manifest. Cargo inventory includes
dev/build dependencies and is not a runtime reachability or vulnerability report.
Run dependency advisories/license review before promotion; inventory is not proof
that dependencies have no vulnerabilities. Python currently has no runtime deps;
build tools are directly pinned, not a fully hash-locked transitive environment.

Provenance is generated for assets/checksums by pinned actions/attest in the
release workflow. Verify source tag and signer identity, not just a matching hash:

    gh attestation verify ARCHIVE --repo baturhantasdelen-sudo/nexus-ephemera --signer-workflow baturhantasdelen-sudo/nexus-ephemera/.github/workflows/release.yml --source-ref refs/tags/TAG

Retain verification output and derive the trusted digest only after that succeeds.
Offline installations require an independently authenticated digest/provenance
bundle from the release owner; a downloaded checksum alone is insufficient.

    python scripts/install_prebuilt.py --archive ARCHIVE --trusted-sha256 TRUSTED_SHA256 --target TARGET --destination /opt/nexus/releases/VERSION

The destination must not exist and its parent must be operator-controlled, never
a shared writable directory. The installer verifies the same archive bytes it
parses, rejects extra/duplicate/traversal/link members and wrong architecture,
and never overwrites an installation. On Windows use an operator-managed private
installation parent; secret package DACLs are enforced by the native daemon.
No secrets, services or provider calls are provisioned by this installer.

Existing install_daemon.sh/.ps1 are SOURCE bootstrap tools requiring Rust; they
are not network binary installers. Native package provisioning:

    nexus-daemon --listen PRIVATE_SOCKET_OR_PIPE --package PRIVATE_DIR --init-package
    nexus-daemon --package PRIVATE_DIR --check

--seal never repairs unsafe permissions silently. Existing files must already be
private. Production requires --enterprise-config, not --reference-mode.

## SDK and platform compatibility

    python -m pip install /verified/nexus_ephemera_py-VERSION-py3-none-any.whl

Distribution name: nexus-ephemera-py; import: nexus_ephemera. Public PyPI publication
is a separate controlled action, not implied by GitHub assets. Never put a secret
in pip URLs/command lines. Keep daemon/SDK candidate versions aligned; test frame,
token, binding, Redis schema and audit compatibility before mixed-version rollout.

Linux x86_64 GNU is the initial reference pilot target; it is NOT a static binary
guarantee. Release builds use ubuntu-24.04 with an enforced maximum glibc symbol requirement
of 2.39. Older glibc systems are outside this candidate support floor; verify on
the actual customer base image before approval. macOS ARM64 and Windows x86_64 have separate
runtime tests and limits. Intel macOS/ARM Linux are not shipped target archives.
Code signing/notarization remain explicit distribution acceptance gates where customer deployment requires them.

## Service integration

deploy/systemd/nexus-daemon.service is a Linux REFERENCE unit, not an automatically
installed service. Create the service account and trusted directories first.
Review identity, paths, network egress and resource limits in staging. StandardInput
reads a protected broker.secret file (no argv/env key). Automatic restart is OFF:
FileCheckpointSink requires a new stream after restart. TimeoutStopSec exceeds the
maximum provider/cleanup budget. Verify actual systemd behavior in the pilot.
Windows service hosting and macOS launchd packaging require platform-specific
deployment evidence; a generic subprocess is not advertised as a native service.
The unit does not sandbox an agent. Agent integration must separately validate
filesystem/process/egress isolation AND the UID/PID-namespace compatibility in
design_partner_pilot.md. Never share the broker's secret directory to expose its socket.

## Local observability adapter

After installing the SDK, scripts/probe_daemon.py --listen PRIVATE_IPC --mode readiness
prints only nexus_ready 0/1 and exits nonzero on missing/degraded/reference health.
--mode metrics emits five fixed numeric samples with no labels or secret fields.
Never expose this local adapter as an unauthenticated network service. Health is
a point-in-time observation, not a reserved dispatch slot or future availability.
Readiness also rejects closed/full audit admission; it does not attest external
checkpoint durability. Customer dashboards and alert routes remain deployment work.
