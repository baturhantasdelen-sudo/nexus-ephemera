# nexus-ephemera

Sensitive-memory lifecycle protection for an offline scout, an AEAD mesh, and brokered agent calls. Version 0.2.0.

The library verifies wipe and bounds how long a managed buffer is retained. It does not claim a zero footprint. `mlock`, `VirtualLock`, `MADV_DONTDUMP`, and `PR_SET_DUMPABLE` do not stop a privileged tracer, cold boot, DMA, or a physical DRAM read.

| Crate | Role |
| --- | --- |
| `nexus-ephemera` | Contexts, broker, IPC client, and `nexus-daemon` |
| `nexus-ephemera-memlock` | Fail-closed page locks |
| `nexus-ephemera-ipc-os` | Peer UID, PID, and Windows user SID checks |

Pilot install, the 64 MiB `RLIMIT_MEMLOCK` ceiling, `CleanupIncomplete` retries, and integer metrics are in [docs/operational_guide.md](docs/operational_guide.md). MCP, LangChain, Portkey, CrewAI, Composio, and Activepieces adapters are in [docs/phase4_ecosystem.md](docs/phase4_ecosystem.md). Those adapters call the local broker and do not receive its secret. Enterprise audit, tenant, and shared-claim procedures are in [docs/enterprise_runbooks.md](docs/enterprise_runbooks.md). Platform behavior is in [docs/platform_support.md](docs/platform_support.md). Vulnerability reports use the private advisory form described in [SECURITY.md](SECURITY.md).

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --release
```

On Linux, the test shell must be able to raise `RLIMIT_MEMLOCK` before `cargo test`. The daemon reads its key from stdin, not from argv.

Remediation lifecycle guarantees and release/deployment acceptance gates are documented in [docs/production_acceptance.md](docs/production_acceptance.md). Rust 1.95+ is required.

Enterprise mode is explicit: `--enterprise-config` enables mandatory server-side tenant/action/payload validation, durable Redis claims and verified HTTPS forwarding. The default CLI remains a local reference provider. Framework helpers execute the remote operation themselves; they are not permission slips for a second local dispatch. See the enterprise runbook for token-policy and audit-v2 API migration, mandatory real-backend CI, and independently retained checkpoint requirements. `Reference*` stores are models and are not distributed/HA evidence.
