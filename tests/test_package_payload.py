"""Inspect a real unsigned package without installing or executing its scripts."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "scripts"))
import release


class PackagePayloadTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "darwin", "Apple packaging tools require macOS")
    def test_real_package_layout_ownership_and_nonactivation(self):
        build = PROJECT / "build"
        build.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="package-inspection-", dir=build) as temporary:
            directory = Path(temporary)
            binaries = directory / "binaries" / "arm64"
            binaries.mkdir(parents=True)
            for name in ("pam_watchid.so", "pam_watchid-helper"):
                (binaries / name).write_bytes(b"non-executable package inspection fixture\n")
            root, _, scripts = release.stage_payload(
                directory / "work", binaries.parent, "arm64",
            )
            package = directory / "inspection.pkg"
            subprocess.run([
                "/usr/bin/pkgbuild", "--root", str(root), "--scripts", str(scripts),
                "--identifier", release.RECEIPT, "--version", "0.0.0",
                "--install-location", "/", "--ownership", "recommended", str(package),
            ], check=True, capture_output=True, text=True)
            expanded = directory / "expanded"
            subprocess.run([
                "/usr/sbin/pkgutil", "--expand-full", str(package), str(expanded),
            ], check=True, capture_output=True, text=True)
            metadata = ET.parse(expanded / "PackageInfo").getroot()
            self.assertEqual(metadata.attrib["identifier"], release.RECEIPT)
            self.assertEqual(metadata.attrib["install-location"], "/")
            self.assertEqual(metadata.attrib["version"], "0.0.0")
            payload = expanded / "Payload"
            files = {
                str(path.relative_to(payload))
                for path in payload.rglob("*") if path.is_file()
            }
            base = release.INSTALL_PATH.lstrip("/")
            self.assertEqual(files, {
                f"{base}/pam_watchid.so", f"{base}/libexec/pam_watchid-helper",
                f"{base}/LICENSE", f"{base}/uninstall.sh",
            })
            self.assertFalse((payload / "etc").exists())
            self.assertEqual(
                (expanded / "Scripts" / "preinstall").read_bytes(),
                (scripts / "preinstall").read_bytes(),
            )
            self.assertFalse((expanded / "Scripts" / "postinstall").exists())
            bom = subprocess.run([
                "/usr/bin/lsbom", "-p", "fug", str(expanded / "Bom"),
            ], check=True, capture_output=True, text=True).stdout
            for line in bom.splitlines():
                fields = line.split("\t")
                self.assertEqual(fields[-2:], ["0", "0"], line)


if __name__ == "__main__":
    unittest.main()
