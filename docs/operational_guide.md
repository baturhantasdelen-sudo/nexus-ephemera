# Operational guide

This is the pilot guide for `nexus-ephemera` 0.2.0. It covers installing `nexus-daemon`, the 64 MiB lock quota, `CleanupIncomplete` retries, and integer metrics. It does not add a guarantee against privileged `ptrace`, cold boot, DMA, or a physical DRAM read.

## Install

Build the daemon from a checkout of tag `0.2.0`:

```text
cargo build --release --bin nexus-daemon
```

The binary is `target/release/nexus-daemon` on Unix and `target/release/nexus-daemon.exe` on Windows. Copy that file to the service host. Do not copy `target/` itself. The key is not compiled into the binary.

The daemon listens on a Unix socket or a Windows named pipe. Pass `--listen`. A pilot should use a path the service account owns, not a shared world-writable directory. The defaults are `/var/run/nexus-ephemera.sock` and `\\.\pipe\nexus-ephemera`. `/var/run` is often not writable; pass an explicit socket path instead of relying on the default.

```text
nexus-daemon --listen /run/nexus-ephemera/nexus-ephemera.sock --allow https://provider.example/charge --timeout-ms 5000 --idempotency-ttl-ms 900000
```

Repeat `--allow` for each exact endpoint. Matching is not a prefix match. `--max-payload` defaults to 65536 and cannot be raised above that. `--single-use` seals the broker after one call. Leave it off when the same daemon must serve retries.

The process prints `ready` on stdout after the key is admitted and before it accepts a client. `peer_ok pid=N` on stderr is the accepted caller's PID. Those lines do not contain the key, the payload, or the binding digest.

### The key

The process hardens memory before it reads stdin. Write the raw key bytes to the daemon's stdin and then close stdin. The bytes are the key. A trailing newline is part of the key. The read uses a fixed 4097-byte buffer on a joined reader thread. The main thread waits for a rendezvous from that thread before the secret timeout starts. An empty key, a key longer than 4096 bytes, or stdin left open past `--timeout-ms` makes the process exit before `ready`. On that stop the reader is cancelled or reaches its deadline, the buffer is wiped, and the thread is joined before the process continues. Data that arrives after the deadline is drained and rejected; the daemon never admits a late key. The overflow path stops at 4097 bytes and does not keep reading. Do not pass the key as an argument: argv is visible to other users on the same host.

```text
nexus-daemon --listen "$XDG_RUNTIME_DIR/nexus-ephemera.sock" --allow https://provider.example/charge < /run/nexus-ephemera/key
```

The daemon zeroizes its own copy after admission. The file you redirected stays on disk. That file is outside this crate's wipe. Mode `0600`, owned by the service account, is the operator's control. Do not log the redirect.

On Linux the socket is created mode `0600`. The daemon holds `<socket>.lock` for its lifetime and records its PID there. Shutdown releases the flock only; the lock file stays on disk so another process cannot lose its lock during teardown. An existing socket is removed only when that lock is free and connect is refused. Drop deletes the socket only when its device and inode are still the ones this process bound. A connect that succeeds means a live listener: the file is left in place and the new process exits. The probe sends no frame. The client checks the server UID, a non-zero server PID, and mode `0600` before it writes.

On Windows the pipe rejects remote clients. Before the first accept, the pipe DACL is replaced with one allow ACE for the current user. That ACE is `GENERIC_READ | GENERIC_WRITE` mapped to the pipe's specific rights, plus the right to create the next duplex instance. The user is the owner. Later instances are opened without `WRITE_DAC` and are created before the previous handle is closed. The client checks the server process SID before it writes. A privileged administrator is outside this check. This is not mTLS.

## Lock quota

`prepare` asks for the lock before a secret buffer becomes active. If the operating system refuses, admission fails closed. No active secret buffer is published, and the library does not retry the lock by skipping it. `nexus-daemon` exits before it prints `ready`. Stderr contains `memlock fail-closed: PrepareFailed` when the quota request itself is refused, or `memlock fail-closed: LockFailed` when the page lock is refused. Neither line contains the key.

### Linux

`prepare` requests an `RLIMIT_MEMLOCK` soft and hard limit of 64 MiB (`67108864` bytes, `64 * 1024 * 1024`). A broker admission then locks two page-rounded spans: the secret and the sanitizer copy. A short secret still consumes whole pages. One pilot key fits inside 64 MiB. A deployment that locks more than 64 MiB of pages at once needs a higher ceiling, because a later `mlock` still fails when the working set exceeds the effective limit.

Set the ceiling before the process starts. A service account that cannot raise its own hard limit cannot recover inside `admit`.

systemd unit:

```text
[Service]
LimitMEMLOCK=67108864
ExecStart=/usr/local/bin/nexus-daemon --listen /run/nexus-ephemera/nexus-ephemera.sock --allow https://provider.example/charge
StandardInput=file:/run/nexus-ephemera/key
```

A shell that starts the daemon for a smoke test can set the same ceiling for that shell only:

```text
prlimit --pid $$ --memlock=67108864:67108864
```

The Ubuntu CI job uses `unlimited` because the test process locks more than one admission. That is a CI convenience, not the pilot ceiling. Production does not treat `EPERM` as success. The test-only `EPERM` simulation is not compiled into `nexus-daemon`.

Check the live ceiling after start:

```text
prlimit --pid <daemon-pid> --memlock
```

`Max locked memory` in `/proc/<pid>/limits` shows the same soft and hard values. If admission already failed, the daemon has exited and this check must be run against the shell or unit that will start it.

### Windows

`prepare` calls `SetProcessWorkingSetSize` with a minimum of 8 MiB and a maximum of 64 MiB, then `VirtualLock`. If the working set cannot be raised or the lock fails, admission fails closed. `SetErrorMode` only suppresses the process error dialogs selected by this crate. It is not `MADV_DONTDUMP` and it is not `RLIMIT_CORE=0`. There is no `RLIMIT_MEMLOCK` on Windows. The 64 MiB figure is the working-set maximum this crate requests.

## Daemon timeout

`--timeout-ms` bounds each IPC read and each IPC write on one accepted connection. The default is 5000 ms. The allowed range is 1 ms through 120 s. A peer that connects and sends nothing is dropped with a timeout. A frame longer than `--max-payload` (hard cap 64 KiB) is rejected before the body is allocated.

The daemon serves one connection at a time. `SecureTransport::dispatch` runs on that same thread and is synchronous. The IPC timeout does not cancel a dispatch that has already started. The built-in transport returns a local status and does not open a provider socket. A deployment that calls a provider must enforce its own deadline inside `dispatch`. If that call blocks, the daemon accepts no later IPC client until `dispatch` returns. Those clients wait on connect, or their own read timeout fires. That is fail-closed on the next caller. It is not an abort of the provider call already in progress.

After `dispatch` returns, the outcome is stored under the idempotency key. A client that retries because its own timeout fired is served from that cache when the first attempt has finished. The retry does not call `dispatch` again.

## Idempotency

Every call frame carries an `idempotency_key`. The daemon accepts an opaque ASCII string of 1 to 128 graphic characters. A UUID v4 fits. An empty key, a space, or a longer key is a malformed frame and is not dispatched.

| Request | Result |
| --- | --- |
| New key | `dispatch` runs once. A receipt, `CleanupIncomplete`, or a transport error is cached until the TTL. |
| Same key, same endpoint, same payload hash | The cached outcome is returned. `dispatch` is not called. |
| Same key, different endpoint or payload hash | Conflict. `dispatch` is not called. |
| Key older than `--idempotency-ttl-ms` | The entry is gone. The next request is a new call. Default TTL is 15 minutes. The range is 1 ms through 24 h. |
| Cache already holds 256 live keys | A new key is refused before `dispatch`. Live keys are not evicted to make room. |

The cache is process memory. It is not written to disk and it does not survive a restart. A restart can dispatch a key that the previous process already sent. The key is not mixed into the binding digest, and it is not proof of who the caller is. Caller identity remains the Unix UID and PID, or the Windows user SID.

`CleanupIncomplete` is cached because the provider call already happened and the seal did not finish cleanly. Replaying it as `Ok` would hide that. A transport error is cached for the same at-most-once reason: the daemon cannot know whether the provider accepted the attempt.

### What the integrator does on CleanupIncomplete

Generate the idempotency key in the client, before the first attempt. A UUID v4 is the expected shape. Persist that key with the endpoint and the payload hash in the caller's own store. The daemon does not choose the key and does not persist it.

1. Send `NexusClient::execute(endpoint, payload_hash, idempotency_key)`.
2. If the result is `Ok`, the attempt is done. Keep the key until the TTL only if you may need to recognize a duplicate.
3. If the result is `CleanupIncomplete`, do not generate a new key. Do not change the endpoint or the payload hash. Do not treat the transport status as success. `Partial` and `Failed` seals stay errors on the retry.
4. Retry with the same three values. The daemon returns the cached `CleanupIncomplete` and does not call the provider again.
5. A different payload hash or endpoint under that same key is a conflict. The provider is still not called. Fix the caller so the retry matches the original attempt.
6. After the TTL, or after the daemon process exits, the cache is empty. The same key can be dispatched again. That is a new provider attempt. Reconcile it outside this crate before retrying across a restart.

The binding digest on the receipt is not the idempotency key and not a MAC. Do not log the digest next to the key if your policy forbids that pairing. The key itself is not a secret, but it is also not an authenticator. Caller identity remains the Unix UID and PID, or the Windows user SID.

## Counters

Collect metrics from the same socket or pipe the client already uses. `NexusClient::metrics` sends one authenticated frame. The peer check runs before that frame is read. There is no second port and no unauthenticated scrape endpoint.

Read the five integers on an interval from a process running as the daemon user. Store them as numbers. Do not attach the endpoint, the payload hash, the idempotency key, the binding digest, or the secret as a label, a log field, or a span attribute. The rendered snapshot is only the names below and their integers. If a scraper rejects a sample that contains anything else, that scraper is matching this contract.

| Field | Meaning |
| --- | --- |
| `wipe_success_count` | Apoptosis runs that finished `Complete`. A partial wipe is not counted. |
| `quarantine_trigger_total` | Transitions into the quarantined lifecycle state. |
| `cleanup_incomplete_rate` | Incomplete cleanups per one thousand finished dispatches. Zero when no dispatch has finished. This is not a 0.0–1.0 fraction. Replays are not new samples. Alert on a sustained non-zero rate; then follow the `CleanupIncomplete` steps above with the original key. |
| `ipc_auth_failure_total` | Connections dropped because the peer UID, PID, or Windows user SID was missing or did not match. |
| `p95_dispatch_latency_us` | Nearest-rank p95 of the last 128 finished dispatches, in microseconds. Replays are not samples. Zero when no dispatch has finished. A stuck provider shows up here only after `dispatch` returns. The IPC timeout does not cancel that call. |

The response has no endpoint, payload, idempotency key, binding digest, or secret. Do not add a label that copies any of those into a log line or a scraper.
