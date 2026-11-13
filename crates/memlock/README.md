# nexus-ephemera-memlock

Fail-closed page locks for `nexus-ephemera` 0.2.0.

Unix builds call `mlock` / `munlock`. Linux also applies `MADV_DONTDUMP` and `MADV_DONTFORK`. Windows builds call `VirtualLock` / `VirtualUnlock` after raising the working set. If the lock or the quota request fails, the buffer does not become active. A production build does not treat `EPERM` as success.

These calls do not stop a privileged tracer, cold boot, DMA, or a physical DRAM read. The Linux fork check lives in `probe/linux_fork_probe.rs` and is a no-op on other operating systems.

See the workspace [operational guide](../../docs/operational_guide.md) for the 64 MiB `RLIMIT_MEMLOCK` ceiling. That guide is part of the workspace tree; it is not a file inside this crate's package.
