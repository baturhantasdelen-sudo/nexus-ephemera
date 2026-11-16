import contextlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import smoke_prebuilt as m


class SmokePathTests(unittest.TestCase):
    def test_owned_temporary_root_is_canonical_before_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(strict=True)
            nested = root / "nested"
            nested.mkdir()
            # A non-canonical platform-generated name, without needing symlink
            # privileges on Windows. macOS also supplies /var and /tmp aliases.
            generated = nested / ".."
            archive = root / "archive.zip"
            archive.write_bytes(b"public archive fixture")

            def installed(_archive, _digest, _target, destination):
                self.assertEqual(destination, root / "bin")

            def execute(command, **kwargs):
                package = Path(command[command.index("--package") + 1])
                self.assertEqual(package, root / "p")
                if "--init-package" in command:
                    package.mkdir()
                    (package / "pilot_support_agent.json").write_bytes(b"original")
                    return subprocess.CompletedProcess(command, 0)
                code = int((package / "pilot_support_agent.json").read_bytes() != b"original")
                return subprocess.CompletedProcess(command, code)

            with mock.patch.object(m.tempfile, "TemporaryDirectory", return_value=contextlib.nullcontext(str(generated))), \
                 mock.patch.object(m, "install", side_effect=installed), \
                 mock.patch.object(m.subprocess, "run", side_effect=execute), \
                 mock.patch.object(sys, "argv", ["smoke_prebuilt.py", "--archive", str(archive), "--target", "x86_64-pc-windows-msvc"]):
                m.main()
