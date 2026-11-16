"""Build-time check: import the installed wheel from outside the source checkout."""
from __future__ import annotations
import argparse
from pathlib import Path
import subprocess
import tempfile
import venv
import tomllib
import zipfile
from email.parser import BytesParser
from packaging.version import Version


def main() -> None:
    p = argparse.ArgumentParser(__doc__)
    p.add_argument("wheel", type=Path)
    a = p.parse_args()
    wheel = a.wheel.resolve(strict=True)
    source = Path(__file__).resolve().parents[1] / "clients/python/pyproject.toml"
    source_version = Version(tomllib.loads(source.read_text())["project"]["version"])
    with zipfile.ZipFile(wheel) as z:
        if not any(n.endswith("/licenses/LICENSE") for n in z.namelist()):
            raise ValueError("wheel must carry its MIT license")
        metadata_files = [n for n in z.namelist() if n.endswith(".dist-info/METADATA")]
        if len(metadata_files) != 1:
            raise ValueError("ambiguous wheel metadata")
        metadata = BytesParser().parsebytes(z.read(metadata_files[0]))
        versions = metadata.get_all("Version", [])
        if len(versions) != 1 or Version(versions[0]) != source_version:
            raise ValueError("wheel/source version mismatch")
        # PEP 440-equivalent versions need not have identical spelling: Hatch
        # retains 0.3.0-rc.1 in METADATA while filenames normalize to 0.3.0rc1.
        expected_version = versions[0]
    with tempfile.TemporaryDirectory(prefix="nexus-wheel-") as tmp:
        root = Path(tmp)
        environment = root / "environment"
        venv.EnvBuilder(with_pip=True).create(environment)
        python = environment / ("Scripts/python.exe" if __import__("os").name == "nt" else "bin/python")
        subprocess.run([str(python), "-m", "pip", "install", "--no-deps", "--no-index", str(wheel)], check=True, timeout=120)
        subprocess.run([str(python), "-I", "-c", "from nexus_ephemera import TenantClient; import importlib.metadata as m; import sys; assert m.version('nexus-ephemera-py') == sys.argv[1]; assert not hasattr(TenantClient, 'get_secret')", expected_version], cwd=root, check=True, timeout=30)
    print("isolated installed wheel import passed")


if __name__ == "__main__":
    main()
