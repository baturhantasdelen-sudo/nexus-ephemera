# Release v0.2.0-sealed

This release represents the production-ready, security-hardened milestone for `nexus-ephemera`, fulfilling strict independent auditor requirements and achieving an 85/85 passing test suite across Windows and Linux environments.

## Key Security and Architecture Highlights

1. **Secure Memory Core (`Zeroizing` and `mlock`):**
   - Enforces strict memory locking (`mlock`), core dump exclusion (`MADV_DONTDUMP`, `MADV_DONTFORK`), and automated cryptographic zeroization on drop to reduce heap leakage risk.

2. **Isolated IPC Transport (Windows and Linux):**
   - **Windows:** Named pipes secured with dynamic process-token user SIDs, explicit owner and group SIDs, and `MapGenericMask` ACE rights (`FILE_GENERIC_READ | FILE_GENERIC_WRITE | SYNCHRONIZE | FILE_CREATE_PIPE_INSTANCE`). Same-user client checks apply; this is not mTLS and does not block a privileged local administrator.
   - **Linux:** Unix domain sockets protected by exclusive file locking (`flock`) and strict inode/PID validation to reduce TOCTOU race risk.

3. **Deterministic Stdin Daemon Guardrails:**
   - Synchronized stdin reader with cooperative `AtomicBool` shutdown, bounded handshake channel (`sync_channel(1)`), `CancelSynchronousIo` on Windows, and safe late-result discarding to reduce thread leak and deadlock risk.

4. **Quality Gates and Verification:**
   - **85/85** test suite passing in `release` mode.
   - Zero compilation warnings (`clippy -D warnings`).
   - Strict formatting enforcement (`cargo fmt`).
