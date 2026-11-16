"""Package only named release binaries; verify architecture and aggregate hashes."""
from __future__ import annotations
import argparse
import hashlib
import re
import json
import tomllib
import subprocess
import sys
import struct
import tarfile
import zipfile
from pathlib import Path

TARGETS = ("x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc", "aarch64-apple-darwin")
BINARIES = ("nexus-daemon", "nexus-ephemera", "nexus-operator")

def validate_version(tag: str, root: Path) -> None:
    rust = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]["package"]["version"]
    sdk = tomllib.loads((root / "clients/python/pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    if tag != "v" + rust or sdk != rust:
        raise ValueError("tag, Rust and Python source versions must match exactly")

def sbom(root: Path, output: Path) -> None:
    # Resolved Cargo inventory, including dev/build dependencies, not a runtime
    # reachability assertion. No environment, secrets or private source paths.
    result = subprocess.run(["cargo", "metadata", "--locked", "--format-version", "1"], cwd=root,
                            check=True, capture_output=True, text=True)
    packages = json.loads(result.stdout)["packages"]
    components = []
    for p in sorted(packages, key=lambda p: (p["name"], p["version"])):
        component = {"type": "library", "name": p["name"], "version": p["version"],
                     "purl": f"pkg:cargo/{p['name']}@{p['version']}"}
        if p.get("license"):
            component["licenses"] = [{"expression": p["license"]}]
        components.append(component)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                                 "components": components}, indent=2) + "\n", encoding="utf-8")

def kit(root: Path, dist: Path) -> Path:
    # Explicit allowlist: never include config, .env, tokens or pilot evidence.
    files = ["LICENSE", "SECURITY.md", "docs/product_contract.md", "docs/design_partner_pilot.md",
             "docs/operator_recovery.md", "docs/distribution.md", "docs/commercial_model.md", "docs/productization_status.md",
             "docs/production_execution.md", "docs/enterprise_runbooks.md", "docs/platform_support.md",
             "pilot/acceptance.template.json", "deploy/systemd/nexus-daemon.service",
             "scripts/install_prebuilt.py", "scripts/package_release.py", "scripts/pilot_gate.py",
             "scripts/probe_daemon.py"]
    dist.mkdir(parents=True, exist_ok=True)
    archive = dist / "nexus-pilot-kit.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for name in files:
            file = root / name
            if file.is_symlink() or not file.is_file():
                raise ValueError("missing pilot kit source")
            z.write(file, name)
    return archive

def archive_name(tag: str, target: str) -> str:
    if not re.fullmatch(r"v[0-9A-Za-z][0-9A-Za-z._+-]{0,127}", tag) or target not in TARGETS:
        raise ValueError("invalid release tag or target")
    suffix = ".zip" if "windows" in target else ".tar.gz"
    return f"nexus-ephemera-{tag}-{target}{suffix}"

def require_architecture(path: Path, target: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"not a regular binary: {path.name}")
    with path.open("rb") as f:
        head = f.read(64)
        if target == "x86_64-pc-windows-msvc":
            if len(head) < 64 or head[:2] != b"MZ":
                raise ValueError("expected PE binary")
            f.seek(struct.unpack_from("<I", head, 60)[0])
            pe = f.read(6)
            valid = len(pe) == 6 and pe[:4] == b"PE\0\0" and struct.unpack_from("<H", pe, 4)[0] == 0x8664
        elif target == "x86_64-unknown-linux-gnu":
            valid = len(head) >= 20 and head[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", head, 18)[0] == 62
        elif target == "aarch64-apple-darwin":
            valid = len(head) >= 8 and head[:4] == b"\xcf\xfa\xed\xfe" and struct.unpack_from("<I", head, 4)[0] == 0x100000C
        else:
            raise ValueError("unsupported target")
    if not valid:
        raise ValueError(f"binary architecture does not match {target}: {path.name}")

def package(tag: str, target: str, binary_dir: Path, dist: Path) -> Path:
    name = archive_name(tag, target)
    suffix = ".exe" if "windows" in target else ""
    files = [binary_dir / (name + suffix) for name in BINARIES]
    for file in files:
        require_architecture(file, target)
    license_file = Path(__file__).resolve().parents[1] / "LICENSE"
    if license_file.is_symlink() or not license_file.is_file():
        raise ValueError("missing distribution license")
    files.append(license_file)
    dist.mkdir(parents=True, exist_ok=True)
    archive = dist / name
    if suffix:
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as z:
            for file in files:
                z.write(file, file.name)
    else:
        with tarfile.open(archive, "w:gz") as t:
            for file in files:
                t.add(file, arcname=file.name, recursive=False)
    return archive

def checksums(tag: str, dist: Path) -> Path:
    expected = {archive_name(tag, target) for target in TARGETS}
    version = tag.removeprefix("v").replace("-rc.", "rc")
    expected |= {f"nexus_ephemera_py-{version}-py3-none-any.whl", f"nexus_ephemera_py-{version}.tar.gz", "cargo-sbom.cdx.json", "LICENSE", "nexus-pilot-kit.zip"}
    actual = {p.name for p in dist.iterdir() if p.name != "checksums.txt"}
    if actual != expected:
        raise ValueError("release requires exactly one archive for every target")
    lines = []
    for name in sorted(expected):
        file = dist / name
        if file.is_symlink() or not file.is_file():
            raise ValueError("invalid release archive")
        with file.open("rb") as f:
            digest = hashlib.file_digest(f, "sha256").hexdigest()
        lines.append(f"{digest}  {name}\n")
    manifest = dist / "checksums.txt"
    manifest.write_text("".join(lines), encoding="ascii")
    return manifest

def main() -> None:
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("command", choices=("package", "checksums", "validate-version", "sbom", "kit"))
    parser.add_argument("--tag", required=True)
    parser.add_argument("--target", choices=TARGETS)
    parser.add_argument("--binary-dir", type=Path)
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    args = parser.parse_args()
    if args.command == "validate-version":
        validate_version(args.tag, Path(__file__).resolve().parents[1])
    elif args.command == "kit":
        print(kit(Path(__file__).resolve().parents[1], args.dist))
    elif args.command == "sbom":
        sbom(Path(__file__).resolve().parents[1], args.dist / "cargo-sbom.cdx.json")
    elif args.command == "package":
        if not args.target:
            parser.error("--target is required for package")
        directory = args.binary_dir or Path("target") / args.target / "release"
        print(package(args.tag, args.target, directory, args.dist))
    else:
        print(checksums(args.tag, args.dist))

if __name__ == "__main__":
    main()
