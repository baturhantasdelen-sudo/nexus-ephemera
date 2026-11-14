# Production acceptance and delivery contract

This document records the closure scope; it does not claim zero hardware residue or independent cryptographic certification.

## Cryptographic lifecycle

- The wire v1 HKDF/HMAC-SHA256 format is preserved and checked against an independent Python standard-library vector and RFC 4231.
- Signing uses Orion 0.18.1 with its explicit zeroize feature. Its key/tag storage and SHA-256 states have scrubbing destructors; pad storage is explicitly wiped. This backend was source-reviewed here; no third-party audit is claimed.
- Ordinary SHA-256 uses RustCrypto sha2 0.11 with zeroize enabled, including key-dependent local binding digests.
- Canonical fields stream into HMAC without a reallocating canonical Vec. PRK and derived keys are kept in guarded backend Secret types and dropped after use.
- Compiler-generated copies, CPU registers/caches, process abort/kill and hardware attacks remain outside verified managed-region wiping. These temporary cryptographic guards are not a claim that every stack page is mlock'ed.
- Rust 1.95 or newer is declared: existing atomic try_update already needs 1.95. New dependencies and release builds use Cargo.lock.

## Windows asynchronous ownership

- Cancellation requests CancelIoEx and returns to the event loop without join().
- Workers retain buffers, views and OVERLAPPED until terminal GetOverlappedResult completion; only the worker wipes active payloads.
- Close marks the connection closed. If I/O is active, handles/events remain open until _end runs after collecting completion. No idle timeout causes premature destruction.
- Pipe opening also runs off the event loop. An opening owner closes late-created handles if its coroutine was cancelled before claiming them.
- A process-wide cap of 32 native workers rejects new work if a driver never completes cancellation. Such daemon workers deliberately retain ownership; they are not unsafely killed. This is a bounded fail-closed availability cost.
- Normal asyncio shutdown must cancel outstanding tasks. Arbitrary process termination cannot guarantee cleanup.

## Reference HTTP policy

The single /charge endpoint accepts origin-form only and no query, fragment, percent-encoded path or backslash. Body length and SHA-256 must match. Wrong body returns 400; unsupported request targets return 403; invalid signatures return 401; receiver duplicates return 409. This is a loopback reference, not a production TLS/HTTP server.

## Release pipeline

- validate covers Rust, Python strict typing/tests and release packaging tests on Ubuntu, Windows and macOS.
- build jobs produce only explicitly named daemon/CLI binaries with --locked and an explicit target. Packaging checks PE/ELF/Mach-O architecture and excludes .d and other loose files.
- Each build uploads one target-named archive. A single release job waits for all validation/build jobs and requires all three target archives before generating one checksums.txt.
- One publisher stages a draft, uploads all assets, then publishes. It refuses to overwrite an existing release. Failed drafts require deliberate operator reconciliation; old sealed tags must not be moved.
- Action refs are pinned to verified commit SHAs. Checksums provide content integrity, not independent signer identity or full reproducible-build proof.

## Deployment acceptance gates

Local Windows tests and cross-target compilation do not constitute Linux/macOS runtime evidence. Before a production rollout, run this exact commit's remote three-platform validate/build workflow and retain its run URL, binary hashes and release identity. Also validate ordinary/elevated Windows service-account policy for the deployment: a high-integrity service is not relabeled low to accept a lower-integrity client.

Persistent idempotency, external authenticated audit and hard cancellation via a separate provider process remain separate product capabilities. They are not silently promised by this remediation.
