# Security policy

`nexus-ephemera` 0.2.0 provides **Sensitive-Memory Lifecycle Protection**: verified wiping of managed buffers and bounded retention of those buffers. It does not claim a zero footprint, and it does not claim that secret bytes are gone from hardware.

## Guarantee boundary

| In scope | Out of scope |
| --- | --- |
| Core dumps of managed pages, unencrypted swap and pagefile residue, Linux `fork` inheritance of locked ranges, log disclosure of registered secrets, and same-process reads of managed buffers | Cold boot, DMA, physical DRAM reads, privileged `ptrace`, kernel memory reads, and other hardware attacks |

In-scope controls are operating-system hints plus library lifecycle rules. They apply only to memory this crate allocates and locks.

- **Swap and pagefile.** A buffer does not become active until `mlock` (Unix) or `VirtualLock` (Windows) succeeds. If the lock cannot be taken, the operation fails closed.
- **Core dumps.** Linux sets `PR_SET_DUMPABLE` to 0, `RLIMIT_CORE` to 0, and `MADV_DONTDUMP` on locked ranges. Windows sets a process error mode. These calls reduce dump exposure. They are not a guarantee that every dump tool on every configuration skips the pages.
- **Fork.** On Linux, `MADV_DONTFORK` removes the locked range from the child address space. The child does not receive a zero-filled copy of that range. The Linux probe checks the gap with `mincore` and does not read the bytes. Other operating systems do not run that proof.
- **Same-process reads and `ptrace`.** Callers need an operation permit and an active context before they can read a managed buffer. After apoptosis is engaged, new reads are denied. On Linux, `PR_SET_DUMPABLE=0` shrinks the non-privileged attach and dump surface. `mlock`, `MADV_DONTDUMP`, and `PR_SET_DUMPABLE` do not stop a privileged tracer (`CAP_SYS_PTRACE` or an equivalent administrator). Privileged `ptrace` stays outside this guarantee.
- **Logs.** `LogSanitizer` redacts registered secrets at UTF-8 character boundaries. The redaction pass borrows locked bytes. A denied permit returns before a line copy is allocated. Unregistered text is not redacted.
- **Daemon IPC.** `nexus-daemon` keeps the key in its own process. `NexusClient` sends only an endpoint, a payload hash, and an idempotency key. Unix sockets are mode `0600`. The daemon and the client both require a matching UID and a non-zero peer PID. A socket file is removed only when connect is refused. Windows named pipes reject remote clients. Before the first accept, the pipe owner is the current user. The DACL grants only that user and, when the daemon runs inside an AppContainer, its exact package SID. AppContainer access requires both identity checks; ALL APPLICATION PACKAGES and Everyone are not granted access. The pipe mandatory label matches the daemon process integrity level. Later instances keep that descriptor. The client checks the server process SID before it writes. This is not mTLS and it is not a barrier against a privileged local administrator.

A failed unlock quarantines the buffer and does not report success. `Partial` and `Failed` seal results are failures even when a transport call returned success.

## Reporting a vulnerability

Report suspected vulnerabilities in private. Do not open a public issue, pull request, or discussion that contains exploit detail, proof-of-concept code, or secret material.

Use the repository host's private security advisory form (GitHub: **Security → Report a vulnerability**). That form is the supported private channel. Do not send the report to a public issue tracker. A monitored email address is not published in this tree; maintainers who add one should list it here and keep the public-issue ban.

Include the affected version, operating system and architecture, whether the issue is inside a managed buffer, and the smallest description that lets a maintainer reproduce it. Do not send live credentials.

We aim to acknowledge a report within 3 business days and to send a status update within 10 business days. Fixes ship on the supported version line below. Please give the maintainers time to publish a fix before any public write-up.

## Supported versions

| Version | Security fixes |
| --- | --- |
| 0.2.x | Supported. 0.2.0 is the sealed release. |
| Older than 0.2.0 | Not supported. |

Only the 0.2 line receives security fixes. A report against an unsupported version may still be useful, and it will not receive a backport.
