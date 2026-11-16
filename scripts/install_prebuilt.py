"""Install a local prebuilt archive using an independently authenticated SHA-256.

Obtain the expected digest through a trusted channel AFTER verifying release
provenance. A checksum downloaded beside an untrusted archive is insufficient.
No downloads, privilege elevation, service start or secret provisioning occur.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import re
import shutil
import tarfile
import tempfile
import zipfile

spec = importlib.util.spec_from_file_location("release", Path(__file__).with_name("package_release.py"))
assert spec and spec.loader
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)
MAX_ARCHIVE = 128 * 1024 * 1024
MAX_BINARY = 64 * 1024 * 1024

def install(archive: Path, expected: str, target: str, destination: Path) -> None:
    if target not in release.TARGETS or not re.fullmatch("[0-9a-f]{64}", expected):
        raise ValueError("invalid target or trusted digest")
    if archive.is_symlink() or not archive.is_file() or archive.stat().st_size > MAX_ARCHIVE:
        raise ValueError("invalid archive")
    # Hash and parse the SAME bounded bytes; never reopen a mutable input path.
    with archive.open("rb") as stream:
        data = stream.read(MAX_ARCHIVE + 1)
    if len(data) > MAX_ARCHIVE or hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("archive integrity mismatch")
    destination = destination.absolute()
    if destination.exists() or destination.is_symlink():
        raise ValueError("destination already exists; upgrades require explicit drain")
    # The parent chain is operator-trusted. Reject symlink/reparse components.
    for parent in (destination.parent, *destination.parent.parents):
        if parent.is_symlink() or getattr(parent, "is_junction", lambda: False)():
            raise ValueError("indirect installation parent")
    if not destination.parent.is_dir():
        raise ValueError("installation parent must exist")
    suffix = ".exe" if "windows" in target else ""
    binary_names = {name + suffix for name in release.BINARIES}
    expected_names = binary_names | {"LICENSE"}
    temporary = Path(tempfile.mkdtemp(prefix=".nexus-install-", dir=destination.parent))
    try:
        if suffix:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                infos = z.infolist()
                if len(infos) != len(expected_names) or {i.filename for i in infos} != expected_names:
                    raise ValueError("unexpected or duplicate archive member")
                for i in infos:
                    if i.file_size > MAX_BINARY or i.is_dir() or ((i.external_attr >> 16) & 0o170000) == 0o120000:
                        raise ValueError("invalid binary member")
                    (temporary / i.filename).write_bytes(z.read(i))
        else:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
                infos = t.getmembers()
                if len(infos) != len(expected_names) or {i.name for i in infos} != expected_names:
                    raise ValueError("unexpected or duplicate archive member")
                for i in infos:
                    if not i.isfile() or i.size > MAX_BINARY or i.sparse is not None:
                        raise ValueError("invalid binary member")
                    stream = t.extractfile(i)
                    if stream is None:
                        raise ValueError("missing binary")
                    with stream:
                        (temporary / i.name).write_bytes(stream.read(MAX_BINARY + 1))
        for name in binary_names:
            file = temporary / name
            release.require_architecture(file, target)
            if os.name != "nt":
                file.chmod(0o700)
        # Refuse replacement even on POSIX, where rename can replace an empty
        # directory. Operator controls parent; do not run against shared /tmp.
        destination.mkdir(mode=0o700, exist_ok=False)
        try:
            for name in expected_names:
                os.replace(temporary / name, destination / name)
        except BaseException:
            shutil.rmtree(destination)
            raise
    finally:
        shutil.rmtree(temporary)

def main() -> None:
    p = argparse.ArgumentParser(__doc__)
    p.add_argument("--archive", required=True, type=Path)
    p.add_argument("--trusted-sha256", required=True)
    p.add_argument("--target", required=True, choices=release.TARGETS)
    p.add_argument("--destination", required=True, type=Path)
    a = p.parse_args()
    try:
        install(a.archive, a.trusted_sha256, a.target, a.destination)
    except (ValueError, OSError, tarfile.TarError, zipfile.BadZipFile):
        p.exit(1, "installation refused; verify provenance, archive and private destination\n")
    print("binaries-installed; provision a private package separately")

if __name__ == "__main__":
    main()
