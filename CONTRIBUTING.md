# Contributing

`nexus-ephemera` is a sensitive-memory lifecycle library. The guarantee is verified wiping and bounded retention of managed buffers. Changes must not widen that claim into a zero-footprint or hardware-isolation promise.

The main crate forbids `unsafe`. Unsafe code belongs only in `crates/memlock`. Production lock and `setrlimit` failures stay fail-closed. Test-only fallbacks must not compile into production binaries. Do not add a public reset for apoptosis after it has engaged.

## Pull requests that touch the security boundary

A pull request that changes any of the following must include the four explanations below in the description:

- the sensitive data flow (where plaintext is copied, borrowed, or wiped)
- the `EphemeralContext` operation permit (`acquire_operation_permit` and anything that reads or seals a managed buffer)
- `Zeroizing` or other zeroize rules, including error and panic paths

Required explanation:

1. **Data copies.** Name every new heap or stack copy of secret bytes. Say which copies are wiped, and which outputs are allowed to retain redacted or non-secret data. Prefer a borrow of locked memory over an intermediate secret `String` or `Vec<u8>`.
2. **Permit scope.** State the first and last operation covered by the permit. The permit is acquired before the buffer mutex. It must still be held across any external call that must not race with apoptosis, including broker `dispatch` and the seal that follows it.
3. **Cleanup on error.** Describe the `Drop` or `Result` path when a later step fails or panics. An early return must not drop a secret-bearing buffer through ordinary `String::drop`. A seal result of `Partial` or `Failed` must be returned to the caller.
4. **Platform impact.** Say what changes on Linux, Windows, and macOS. Call out `mlock` / `VirtualLock`, `MADV_DONTDUMP`, `MADV_DONTFORK`, `mincore`, `RLIMIT_MEMLOCK`, and process hardening. If a control exists on only one operating system, say so. Do not describe an untested platform as fully supported.

Reviews should not merge a security-boundary change that omits this section.

## Tests and style

Before opening a pull request, run:

```text
cargo fmt --all -- --check
CARGO_INCREMENTAL=0 cargo clippy --workspace --all-targets -- -D warnings
RUSTFLAGS="-D warnings" cargo test --workspace --release
```

On Linux, the fork and memlock probes need a memlock ceiling the process is allowed to set. The CI job raises it with `prlimit` in the same shell as `cargo test`. A Windows run does not execute the Linux `MADV_DONTFORK` probe.

Keep new tests deterministic. Apoptosis tests that share a process must take the existing serial test lock and reset coordinator state only through the `cfg(test)` helpers. Do not reintroduce a public harness reset.
