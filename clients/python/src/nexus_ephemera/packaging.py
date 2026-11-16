"""Package schema, policy HMAC, and health rollup for the support-agent install."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from pathlib import Path

from .adapters.github import GithubIssuePolicy
from .enterprise import WORKER_CAP
from .errors import Malformed, ProtocolError

_DOMAIN = b"nexus-package-policy-v1\0"
_FILES = ("config.toml", ".env", "pilot_support_agent.json", "hmac.key", "policy.hmac")
_VECTOR = "dd3cfdce70b2eb93e34e8719d9f2a217edff4535a75195882c1d924b971630c6"


@dataclass(frozen=True)
class LoadedPackage:
    listen: str
    allow: str
    timeout_ms: int
    redis_url: str

    def __repr__(self) -> str:
        return f"LoadedPackage(listen={self.listen!r}, allow={self.allow!r})"


@dataclass(frozen=True)
class HealthReport:
    status: str
    ipc_listening: bool
    worker_occupied: int
    worker_capacity: int
    policy_intact: bool
    hmac_ready: bool
    idempotency: str


def policy_tag(key: bytes, policy: bytes) -> str:
    if len(key) != 32 or not policy or len(policy) > 65536:
        raise Malformed()
    return hmac.new(key, _DOMAIN + policy, hashlib.sha256).hexdigest()


def load_package(directory: Path) -> LoadedPackage:
    if not directory.is_dir():
        raise ProtocolError("package directory is missing")
    for name in _FILES:
        _private(directory / name)
    config = _parse_config((directory / "config.toml").read_bytes())
    env = _parse_env((directory / ".env").read_bytes())
    if (
        env["listen"] != config["listen"]
        or env["policy"] != config["policy"]
        or env["timeout_ms"] != config["timeout_ms"]
        or env["redis"] != config["redis"]
    ):
        raise ProtocolError("package env does not match config.toml")
    if config["policy"] != "pilot_support_agent.json":
        raise ProtocolError("package policy path is not the pilot file")
    policy_bytes = (directory / "pilot_support_agent.json").read_bytes()
    policy = GithubIssuePolicy.load(policy_bytes)
    if config["allow"] != policy.endpoint:
        raise ProtocolError("package allowlist does not match the policy")
    key = (directory / "hmac.key").read_bytes()
    signature = (directory / "policy.hmac").read_text(encoding="ascii").strip()
    expected = policy_tag(key, policy_bytes)
    if len(expected) != len(signature) or not hmac.compare_digest(expected, signature):
        raise ProtocolError("package policy hmac does not match")
    return LoadedPackage(config["listen"], config["allow"], int(config["timeout_ms"]), config["redis"])


def rollup_health(
    *,
    ipc_listening: bool,
    worker_occupied: int,
    policy_intact: bool,
    hmac_ready: bool,
    idempotency: str,
) -> HealthReport:
    known = idempotency in {"local", "ready", "degraded", "unhealthy"}
    if (
        not ipc_listening
        or not policy_intact
        or not hmac_ready
        or not known
        or idempotency == "unhealthy"
        or worker_occupied > WORKER_CAP
    ):
        status = "unhealthy"
    elif idempotency == "degraded" or worker_occupied == WORKER_CAP:
        status = "degraded"
    else:
        status = "healthy"
    return HealthReport(
        status,
        ipc_listening,
        worker_occupied,
        WORKER_CAP,
        policy_intact,
        hmac_ready,
        idempotency,
    )


def _private(path: Path) -> None:
    if not path.is_file() or path.is_symlink():
        raise ProtocolError("package file must be a regular file")
    if os.name == "posix":
        if path.stat().st_mode & 0o777 != 0o600:
            raise ProtocolError("package file must be mode 0600")


def _parse_config(raw: bytes) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in raw.decode("utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ProtocolError("package config has a malformed line")
        key, value = (part.strip() for part in line.split("=", 1))
        if key in fields:
            raise ProtocolError("package config repeats a field")
        if key == "timeout_ms":
            if not value.isdigit() or not 1 <= int(value) <= 120_000:
                raise ProtocolError("package timeout is invalid")
            fields[key] = value
            continue
        if key not in {"listen", "policy", "allow", "redis"}:
            raise ProtocolError("package config has an unknown field")
        if len(value) < 2 or value[0] != '"' or value[-1] != '"':
            raise ProtocolError("package config value must be a quoted string")
        fields[key] = value[1:-1]
    for name in ("listen", "timeout_ms", "policy", "allow", "redis"):
        if name not in fields:
            raise ProtocolError("package config is missing a required field")
    return fields


def _parse_env(raw: bytes) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in raw.decode("utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ProtocolError("package env has a malformed line")
        key, value = line.split("=", 1)
        if key in fields:
            raise ProtocolError("package env repeats a field")
        if any(ord(char) < 32 for char in value):
            raise Malformed()
        if key not in {"NEXUS_LISTEN", "NEXUS_POLICY", "NEXUS_TIMEOUT_MS", "NEXUS_REDIS_URL"}:
            raise ProtocolError("package env has an unknown field")
        fields[key] = value
    if "NEXUS_LISTEN" not in fields or "NEXUS_POLICY" not in fields or "NEXUS_TIMEOUT_MS" not in fields:
        raise ProtocolError("package env is missing a required field")
    timeout = fields["NEXUS_TIMEOUT_MS"]
    if not timeout.isdigit():
        raise ProtocolError("package timeout is invalid")
    return {
        "listen": fields["NEXUS_LISTEN"],
        "policy": fields["NEXUS_POLICY"],
        "timeout_ms": timeout,
        "redis": fields.get("NEXUS_REDIS_URL", ""),
    }


def vector_matches() -> bool:
    return policy_tag(bytes(range(32)), b"{}") == _VECTOR
