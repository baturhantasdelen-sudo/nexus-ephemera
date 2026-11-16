"""Build a local candidate archive and execute its installation acceptance tests."""
import platform
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
from package_release import package


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    targets = {("Linux", "x86_64"): "x86_64-unknown-linux-gnu",
               ("Windows", "AMD64"): "x86_64-pc-windows-msvc",
               ("Darwin", "arm64"): "aarch64-apple-darwin"}
    target = targets.get((platform.system(), platform.machine()))
    if target is None:
        raise RuntimeError("unsupported release test host")
    tag = "v" + tomllib.loads((root / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    with tempfile.TemporaryDirectory(prefix="nx-artifact-") as tmp:
        archive = package(tag, target, root / "target/release", Path(tmp))
        subprocess.run([sys.executable, str(root / "scripts/smoke_prebuilt.py"), "--archive", str(archive), "--target", target], check=True, timeout=90)


if __name__ == "__main__":
    main()
