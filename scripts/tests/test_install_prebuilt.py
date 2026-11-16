import hashlib
import importlib.util
import io
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import install_prebuilt as m

class PrebuiltTests(unittest.TestCase):
    def test_user_supplied_indirect_parent_is_still_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve(strict=True)
            archive,digest=self.archive(root)
            indirect=root/"indirect"
            indirect.mkdir()
            with mock.patch.object(Path,"is_symlink",autospec=True,side_effect=lambda path: path==indirect):
                with self.assertRaisesRegex(ValueError,"indirect installation parent"):
                    m.install(archive,digest,m.release.TARGETS[0],indirect/"bin")
            self.assertFalse((indirect/"bin").exists())

    def archive(self,root,malicious=False):
        path=root/"release.tar.gz"
        header=bytearray(128)
        header[:6]=b"\x7fELF\x02\x01"
        struct.pack_into("<H",header,18,62)
        with tarfile.open(path,"w:gz") as t:
            for n in (*m.release.BINARIES,"LICENSE"):
                i=tarfile.TarInfo(n)
                i.size=len(header)
                t.addfile(i,io.BytesIO(header))
            if malicious:
                i=tarfile.TarInfo("../escape"); i.size=1
                t.addfile(i,io.BytesIO(b"x"))
        return path,hashlib.sha256(path.read_bytes()).hexdigest()

    def test_verified_install_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d).resolve(strict=True); a,h=self.archive(r)
            m.install(a,h,m.release.TARGETS[0],r/"bin")
            self.assertEqual({p.name for p in (r/"bin").iterdir()},set(m.release.BINARIES) | {"LICENSE"})
            with self.assertRaises(ValueError):
                m.install(a,h,m.release.TARGETS[0],r/"bin")

    def test_tamper_traversal_and_wrong_architecture_leave_no_install(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d).resolve(strict=True); a,h=self.archive(r)
            with self.assertRaises(ValueError):
                m.install(a,"0"*64,m.release.TARGETS[0],r/"bin")
            with self.assertRaises(ValueError):
                m.install(a,h,m.release.TARGETS[2],r/"bin")
            a,h=self.archive(r,True)
            with self.assertRaises(ValueError):
                m.install(a,h,m.release.TARGETS[0],r/"bin")
            self.assertFalse((r/"bin").exists())
            self.assertFalse((r.parent/"escape").exists())
