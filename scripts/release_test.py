"""Fast release contract checks; native package/API smoke is a separate command."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("stackd_release", Path(__file__).with_name("release.py"))
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class VersionTests(unittest.TestCase):
    def test_stable_and_prerelease(self):
        for value in ("v0.0.0", "v1.2.3", "v12.34.56+build.001"):
            with self.subTest(value=value):
                self.assertFalse(release.version(value))
        for value in ("v1.2.3-rc.1", "v0.0.0-dev", "v1.2.3-0+build.2"):
            with self.subTest(value=value):
                self.assertTrue(release.version(value))

    def test_invalid_tags_are_rejected(self):
        for value in ("1.2.3", "v01.2.3", "v1.02.3", "v1.2.03", "v1.2", "v1.2.3-01",
                      "v1.2.3-rc.01", "v1.2.3-", "v1.2.3+", "v1.2.3-rc..1", "v1.2.3\n",
                      "v1.2.3/branch", "v1.2.3-$(id)"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                release.version(value)


class HelperContractTests(unittest.TestCase):
    def header(self, architecture, interpreter=False):
        header = bytearray(64)
        header[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", header, 18, {"amd64": 62, "arm64": 183}[architecture])
        struct.pack_into("<Q", header, 32, 64)
        struct.pack_into("<HH", header, 54, 56, 1)
        return bytes(header) + struct.pack("<I", 3 if interpreter else 1) + bytes(52)

    def test_linux_architecture_and_static_loader_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "helper"
            for architecture in ("amd64", "arm64"):
                path.write_bytes(self.header(architecture))
                release.elf_helper(path, architecture)
                with self.assertRaises(RuntimeError):
                    release.elf_helper(path, "arm64" if architecture == "amd64" else "amd64")
                path.write_bytes(self.header(architecture, interpreter=True))
                with self.assertRaises(RuntimeError):
                    release.elf_helper(path, architecture)


if __name__ == "__main__":
    unittest.main()
