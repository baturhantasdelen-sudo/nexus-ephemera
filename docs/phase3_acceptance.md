# Phase 3 acceptance protocol

The pilot is a reproducible integration gate, not a claim of universal certification.

- `tests/pilot_daemon_smoke.rs` uses Cargo's exact binary path. Its subprocess exits through explicit agent sealing, global apoptosis completion and a zero exit status. Forced kill remains only a test-failure safety net.
- `--max-connections N` optionally stops after N connection attempts have completed, including per-connection rejections and empty requests. Zero is invalid. The default is unlimited. Ctrl-C also requests cleanup; unfinished provider work fails shutdown rather than being reported complete. This does not forcibly cancel external side effects.
- `BrokerDaemon::shutdown(self)` consumes the listener, verifies explicit agent cleanup and rejects an unresolved provider. `SecureTransactionAgent::close` permanently seals its context and returns its real seal outcome.
- Strict service targets forbid query, fragment, percent encoding, credentials, whitespace/control/non-ASCII bytes and dot segments. Targets still require exact configured allowlist membership; no URL normalization or redirect permission is implied.
- `clients/python/tests/test_pilot_python_sdk.py` is collected by ordinary pytest. CI additionally sets `NEXUS_DAEMON_EXE` to its just-built release binary and explicitly runs that file. The live test must execute there; a missing configured binary is a failure. Without this environment variable only the live test skips locally.
- The live test uses Python framing and actual peer checks to call the daemon, obtains a cached receipt, rejects a modified target, then verifies clean daemon exit and a secret-free completion marker. The short Unix socket path lives in a private temporary directory.
- On Linux, the live Python step separately provisions and records the documented 64 MiB memlock ceiling. GitHub Actions steps do not inherit a previous step's raised process limits. Python and daemon still run as the runner user, not root; production fail-closed lock admission remains unchanged. Startup failures surface the daemon exit status and redacted stderr.
- A cached broker receipt is success replay, not HTTP 409. The loopback receiver independently returns 409 on duplicate HTTP submission. Its body hash, route and signature checks are reference-provider responsibilities.
- CI keeps raw Rust/Python/mypy/Clippy output, Python JUnit reports, source commit/worktree state and daemon SHA-256 as a per-platform artifact. Retain the workflow run URL with this artifact. Failed steps fail the pipeline; artifact presence alone is not acceptance.

Run Windows, Linux and macOS jobs on the exact candidate commit. Same-user IPC is an account boundary, not isolation from every process of that user. Negative cross-user and deployment integrity-level tests require provisioned identities; elevated/kernel attackers are outside this guarantee. This pilot does not replace customer TLS/provider validation, long-duration resource observation or restart-safe durable idempotency.

In a new deployment also record: foreign UID/SID rejection, normal/elevated service-account behavior, slow/disconnected client recovery, idle resource baseline and post-load thread/handle/RSS counts, successful/failed provider restart reconciliation, and clock synchronization. No test count alone establishes these field properties.
