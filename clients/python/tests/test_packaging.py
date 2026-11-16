"""Install schema, policy HMAC, health rollup, and a private package."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from nexus_ephemera.errors import Malformed, ProtocolError
from nexus_ephemera.framing import parse_health
from nexus_ephemera.packaging import load_package, policy_tag, rollup_health, vector_matches

POLICY = (Path(__file__).resolve().parents[3] / "policies" / "pilot_support_agent.json").read_bytes()
LISTEN = r"\\.\pipe\nexus-ephemera-pkg" if os.name == "nt" else "/tmp/nexus-ephemera/broker.sock"


def test_package_schema_health_and_hmac(tmp_path: Path) -> None:
    assert vector_matches()
    _write(tmp_path, POLICY)
    if os.name == "posix":
        for name in ("config.toml", ".env", "pilot_support_agent.json", "hmac.key", "policy.hmac"):
            os.chmod(tmp_path / name, stat.S_IWUSR | stat.S_IRGRP)
        with pytest.raises(ProtocolError):
            load_package(tmp_path)
        for name in ("config.toml", ".env", "pilot_support_agent.json", "hmac.key", "policy.hmac"):
            os.chmod(tmp_path / name, stat.S_IRUSR | stat.S_IWUSR)
    loaded = load_package(tmp_path)
    assert loaded.allow == "https://api.github.com/repos/pilot-org/support-queue/issues"
    assert "hmac.key" not in repr(loaded)
    (tmp_path / "policy.hmac").write_text("00" + (tmp_path / "policy.hmac").read_text(encoding="ascii")[2:], encoding="ascii")
    with pytest.raises(ProtocolError):
        load_package(tmp_path)
    healthy = rollup_health(
        ipc_listening=True,
        worker_occupied=0,
        policy_intact=True,
        hmac_ready=True,
        idempotency="local",
    )
    assert healthy.status == "healthy"
    assert healthy.worker_capacity == 32
    degraded = rollup_health(
        ipc_listening=True,
        worker_occupied=32,
        policy_intact=True,
        hmac_ready=True,
        idempotency="degraded",
    )
    assert degraded.status == "degraded"
    assert rollup_health(
        ipc_listening=True,
        worker_occupied=0,
        policy_intact=False,
        hmac_ready=True,
        idempotency="ready",
    ).status == "unhealthy"
    frame = parse_health(
        {
            "kind": "health",
            "status": "healthy",
            "ipc_listening": True,
            "worker_occupied": 0,
            "worker_capacity": 32,
            "policy_intact": True,
            "hmac_ready": True,
            "idempotency": "local",
        }
    )
    assert frame["status"] == "healthy"
    with pytest.raises(Malformed):
        parse_health({"kind": "health", "status": "healthy", "token": "ghp_install_token"})


def _write(directory: Path, policy: bytes) -> None:
    key = bytes(range(32))
    (directory / "config.toml").write_text(
        "\n".join(
            [
                f'listen = "{LISTEN}"',
                "timeout_ms = 5000",
                'policy = "pilot_support_agent.json"',
                'allow = "https://api.github.com/repos/pilot-org/support-queue/issues"',
                'redis = ""',
                "",
            ]
        ),
        encoding="ascii",
    )
    (directory / ".env").write_text(
        f"NEXUS_LISTEN={LISTEN}\nNEXUS_POLICY=pilot_support_agent.json\nNEXUS_TIMEOUT_MS=5000\nNEXUS_REDIS_URL=\n",
        encoding="ascii",
    )
    (directory / "pilot_support_agent.json").write_bytes(policy)
    (directory / "hmac.key").write_bytes(key)
    (directory / "policy.hmac").write_text(policy_tag(key, policy), encoding="ascii")
