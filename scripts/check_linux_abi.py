"""Reject release binaries requiring glibc newer than the declared 2.39 floor."""
import argparse
from pathlib import Path
import re
import subprocess
from package_release import BINARIES, require_architecture


def check_versions(output: str) -> None:
    versions = [(int(a), int(b)) for a, b in re.findall(r"\bGLIBC_(\d+)\.(\d+)\b", output)]
    if not versions or max(versions) > (2, 39):
        raise ValueError("missing or unsupported glibc requirements")


def main() -> None:
    p = argparse.ArgumentParser(__doc__)
    p.add_argument("binary_dir", type=Path)
    a = p.parse_args()
    for name in BINARIES:
        binary = a.binary_dir / name
        require_architecture(binary, "x86_64-unknown-linux-gnu")
        output = subprocess.run(["readelf", "--version-info", str(binary)], check=True, capture_output=True, text=True)
        check_versions(output.stdout)
    print("all Linux release binaries meet glibc <= 2.39")


if __name__ == "__main__":
    main()
