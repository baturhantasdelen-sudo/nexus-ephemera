"""Same-user local probe; emits fixed numeric telemetry, never raw wire objects."""
import argparse
import asyncio

METRICS = ("wipe_success_count", "quarantine_trigger_total", "cleanup_incomplete_rate",
           "ipc_auth_failure_total", "p95_dispatch_latency_us")


def readiness(health: dict[str, object]) -> bool:
    occupied = health.get("worker_occupied")
    capacity = health.get("worker_capacity")
    return (health.get("kind") == "health" and health.get("status") == "healthy"
            and health.get("ipc_listening") is True and health.get("policy_intact") is True
            and health.get("hmac_ready") is True and health.get("idempotency") == "ready"
            and type(occupied) is int and type(capacity) is int
            and 0 <= occupied < capacity == 32)


def numeric_metrics(values: dict[str, object]) -> str:
    if set(values) != set(METRICS) or any(type(values[k]) is not int or not 0 <= values[k] <= (1 << 64) - 1 for k in METRICS):
        raise ValueError("invalid metrics")
    return "\n".join(f"nexus_{k} {values[k]}" for k in METRICS)


async def probe(listen: str, timeout: float, mode: str) -> bool:
    from nexus_ephemera import NexusClient
    client = NexusClient(listen, timeout=timeout)
    if mode == "metrics":
        print(numeric_metrics(await client.metrics()))
        return True
    ready = readiness(await client.health())
    print(f"nexus_ready {int(ready)}")
    return ready


def main() -> None:
    p = argparse.ArgumentParser(__doc__)
    p.add_argument("--listen", required=True)
    p.add_argument("--timeout", type=float, default=3)
    p.add_argument("--mode", choices=("readiness", "metrics"), default="readiness")
    a = p.parse_args()
    try:
        success = asyncio.run(probe(a.listen, a.timeout, a.mode))
    except Exception:
        # Avoid exception chaining/wire fields in log collectors.
        print("nexus_probe_error 1")
        success = False
    raise SystemExit(0 if success else 1)


if __name__ == "__main__":
    main()
