# Platform support

This matrix describes `nexus-ephemera` 0.2.0 as implemented. "Supported" means the controls below are compiled in and exercised by CI. It is not a claim that those controls stop privileged `ptrace`, cold boot, DMA, or a physical DRAM read.

The library locks the full page span of a secret, not the raw payload length. The broker also charges a second locked span for the log-sanitizer copy. A short secret still consumes at least one page, and a broker admission consumes two.

| Platform | Status | What this release actually does |
| --- | --- | --- |
| Linux x86_64 and Linux ARM64 | Supported on the code path. CI runs Ubuntu x86_64 only. | `mlock`, `MADV_DONTDUMP`, `MADV_DONTFORK`, `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`. The fork probe uses `mincore` to check that the locked span is unmapped in the child. It does not read those bytes. |
| Windows x86_64 | Partial. Covered by Windows CI. | `VirtualLock` / `VirtualUnlock` and `SetProcessWorkingSetSize`. Process hardening is `SetErrorMode` only. There is no `MADV_DONTDUMP` or `MADV_DONTFORK` path. The fork probe returns success without forking. |
| macOS (Apple Silicon and Intel) | Experimental. Not in CI. | The Unix path builds: `mlock`, `munlock`, and `setrlimit` for `RLIMIT_MEMLOCK` and `RLIMIT_CORE`. Linux advice flags are not applied. The fork probe does not run, so a local success does not prove fork isolation. |

Other targets fail closed with `UnsupportedPlatform`.

## Broker IPC

`nexus-daemon` is a same-user process boundary. The client does not receive the key. The binding digest is still the in-process SHA-256 described in the broker contract. It is not mTLS.

| Platform | What the daemon enforces |
| --- | --- |
| Linux and macOS | Unix domain socket, mode `0600`, with a `<socket>.lock` PID file held for the process lifetime (`flock` exclusive; the lock path is not unlinked on daemon exit). The peer UID must match the daemon UID. The peer PID must be present and non-zero (`SO_PEERCRED` on Linux, `LOCAL_PEEREID` on macOS). The client checks that same peer identity, and that the socket is mode `0600` and owned by its UID, before it writes. A socket file is removed only when the lock is free and connect is refused. Drop deletes the socket only if its inode is still the one this process created. A live listener is left in place and bind fails. A non-socket file at the listen path is refused. |
| Windows | Named pipe with `PIPE_REJECT_REMOTE_CLIENTS`. Before the first accept, the DACL is replaced with one allow ACE for the current user and that user is set as owner. Later instances keep that descriptor and are created before the previous handle is closed. After connect, and before the payload is read, the client PID and user SID must match the daemon user. The client checks the server process SID before it writes. A privileged administrator is outside this check. This is not mTLS. |

## Lock quota

Production builds do not ignore a refused lock. A test build may treat `EPERM` as a simulated lock. That fallback is not in the production binary. If `prepare` or `lock` fails, the caller receives `PrepareFailed` or `LockFailed` and no active secret buffer is published.

### Linux and other Unix, including macOS

`prepare` asks the kernel for an `RLIMIT_MEMLOCK` soft and hard limit of 64 MiB (`64 * 1024 * 1024` bytes). The process must be allowed to set that hard limit. If `setrlimit` fails, startup fails closed.

Diagnosis of a refused lock, and the daemon timeout and idempotency behavior, are in `docs/operational_guide.md`. Raise the ceiling before the process starts when the service account cannot raise it itself. The CI Linux job uses:

```text
sudo prlimit --pid=$$ --memlock=unlimited:unlimited
```

That command has to run in the same shell as `cargo test`. A 64 MiB ceiling is the library's own request. Deployments that lock more than 64 MiB of pages at once need a higher ceiling than this request, because a later `mlock` still fails when the working set exceeds the effective limit.

`RLIMIT_CORE` is set to 0 during process hardening. On Linux, hardening also sets `PR_SET_DUMPABLE` to 0. Hardening is required at `EphemeralContext::open` and at broker admission. A failure there fails closed.

### Windows

`prepare` calls `SetProcessWorkingSetSize` with a minimum of 8 MiB and a maximum of 64 MiB, then locks pages with `VirtualLock`. If the working set cannot be raised or the lock fails, the buffer does not become active. `SetErrorMode` suppresses the process error dialogs listed in the Windows API flags used by this crate. It is not equivalent to Linux `MADV_DONTDUMP` or `RLIMIT_CORE=0`.

## Runtime expectations

- Locked pages are page-aligned. Budget checks use the rounded span.
- A failed unlock quarantines the allocation and triggers apoptosis. The context does not return to `Active`.
- Release builds use unwind panics so wipe guards run if a transport or callback panics.
- Audit flags for `mlock` and the Linux advice bits are reported only after hardening succeeded and at least one buffer was locked. An empty seal reports those flags as false.
- The Linux fork proof is the `linux_fork_probe` binary. Windows and macOS runs of that binary are skips, not evidence that a child process cannot see the pages.
