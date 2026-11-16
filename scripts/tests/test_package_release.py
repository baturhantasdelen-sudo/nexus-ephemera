import hashlib
import importlib.util
import struct
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

spec = importlib.util.spec_from_file_location("package_release", Path(__file__).resolve().parents[1] / "package_release.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class ReleasePackagingTests(unittest.TestCase):
    def headers(self, target):
        header = bytearray(128)
        if "windows" in target:
            header[:2] = b"MZ"
            struct.pack_into("<I", header, 60, 64)
            header[64:68] = b"PE\0\0"
            struct.pack_into("<H", header, 68, 0x8664)
        elif "linux" in target:
            header[:6] = b"\x7fELF\x02\x01"
            struct.pack_into("<H", header, 18, 62)
        else:
            header[:4] = b"\xcf\xfa\xed\xfe"
            struct.pack_into("<I", header, 4, 0x100000C)
        return header

    def binaries(self, root, target):
        directory = root / target
        directory.mkdir()
        for name in m.BINARIES:
            suffix = ".exe" if "windows" in target else ""
            (directory / (name + suffix)).write_bytes(self.headers(target))
        (directory / "nexus-daemon.d").write_text("must not ship")
        return directory

    def test_archive_contents_targets_and_single_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dist = root / "dist"
            for target in m.TARGETS:
                archive = m.package("v0.2.1", target, self.binaries(root, target), dist)
                if "windows" in target:
                    with zipfile.ZipFile(archive) as z:
                        self.assertEqual(set(z.namelist()), {n + ".exe" for n in m.BINARIES} | {"LICENSE"})
                else:
                    with tarfile.open(archive) as t:
                        self.assertEqual(set(t.getnames()), set(m.BINARIES) | {"LICENSE"})
            (dist / "nexus_ephemera_py-0.2.1-py3-none-any.whl").write_bytes(b"wheel fixture")
            (dist / "nexus_ephemera_py-0.2.1.tar.gz").write_bytes(b"sdist fixture")
            (dist / "cargo-sbom.cdx.json").write_text("{}")
            (dist / "LICENSE").write_text("MIT")
            m.kit(Path(__file__).resolve().parents[2], dist)
            manifest = m.checksums("v0.2.1", dist)
            lines = manifest.read_text().splitlines()
            self.assertEqual(len(lines), 8)
            for line in lines:
                digest, name = line.split("  ")
                self.assertEqual(digest, hashlib.sha256((dist / name).read_bytes()).hexdigest())
            (dist / "nexus-daemon").write_bytes(b"collision")
            with self.assertRaises(ValueError):
                m.checksums("v0.2.1", dist)

    def test_wrong_architecture_and_incomplete_release_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = m.TARGETS[1]
            directory = self.binaries(root, target)
            bad = bytearray((directory / "nexus-daemon.exe").read_bytes())
            struct.pack_into("<H", bad, 68, 0x14C)
            (directory / "nexus-daemon.exe").write_bytes(bad)
            with self.assertRaises(ValueError):
                m.package("v0.2.1", target, directory, root / "dist")
            (root / "empty").mkdir()
            with self.assertRaises(ValueError):
                m.checksums("v0.2.1", root / "empty")
            with self.assertRaises(ValueError):
                m.archive_name("v1/../../escape", target)

    def test_version_mismatch_cannot_publish(self):
        root=Path(__file__).resolve().parents[2]
        with self.assertRaises(ValueError):
            m.validate_version("v999.0.0",root)

    def test_pilot_kit_contains_no_runtime_secrets_or_live_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive=m.kit(Path(__file__).resolve().parents[2],Path(tmp))
            with zipfile.ZipFile(archive) as z:
                names=z.namelist()
                self.assertIn("docs/operator_recovery.md",names)
                self.assertIn("scripts/install_prebuilt.py",names)
                self.assertFalse(any(n.endswith((".env",".key",".secret")) or n.startswith("outputs/") for n in names))
