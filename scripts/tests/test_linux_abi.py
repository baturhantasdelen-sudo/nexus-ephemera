from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from check_linux_abi import check_versions


class AbiTests(unittest.TestCase):
    def test_future_or_missing_abi_fails_closed(self):
        check_versions("GLIBC_2.17 GLIBC_2.39 GLIBCXX_3.4.30")
        for text in ("GLIBC_2.40", "GLIBC_3.0", "no version data"):
            with self.assertRaises(ValueError):
                check_versions(text)
