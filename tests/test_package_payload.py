"""Inspect a real unsigned package without installing or executing its scripts."""

from pathlib import Path
import hashlib
import shutil
import subprocess
import sys
import unittest
import uuid
import xml.etree.ElementTree as ET

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "scripts"))
import release


class PackagePayloadTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "darwin", "Apple packaging tools require macOS")
    def test_real_package_layout_ownership_and_activation_hooks(self):
        build = PROJECT / "build"
        build.mkdir(exist_ok=True)
        directory = build / f"package-inspection-{uuid.uuid4().hex}"
        directory.mkdir()
        self.addCleanup(shutil.rmtree, directory)
        binaries = directory / "binaries" / "arm64"
        binaries.mkdir(parents=True)
        fixtures = {}
        for name in ("pam_watchid.so", "pam_watchid-helper"):
            fixtures[name] = f"non-executable {name} package inspection fixture\n".encode()
            (binaries / name).write_bytes(fixtures[name])
        root, _, scripts = release.stage_payload(
            directory / "work", binaries.parent, "arm64", version="0.0.0",
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
        self.assertFalse((payload / "private").exists())
        hooks = {element.tag for element in metadata.findall("./scripts/*")}
        self.assertEqual(hooks, {"preinstall", "postinstall"})
        for name in ("preinstall", "postinstall"):
            rendered = (expanded / "Scripts" / name).read_bytes()
            self.assertEqual(rendered, (scripts / name).read_bytes())
            self.assertIn(b"/private/etc/pam.d", rendered)
            self.assertIn(b"/private/var/db/pam_watchid", rendered)
            self.assertNotRegex(rendered.decode(), r"@[A-Z][A-Z0-9_]*@")
            subprocess.run(
                ["/bin/sh", "-n", str(expanded / "Scripts" / name)],
                check=True, capture_output=True,
            )
        postinstall = (expanded / "Scripts" / "postinstall").read_text()
        for name, content in fixtures.items():
            self.assertIn(hashlib.sha256(content).hexdigest(), postinstall)
            installed = payload / base / (
                "libexec/pam_watchid-helper" if name == "pam_watchid-helper" else name
            )
            self.assertEqual(installed.read_bytes(), content)
        uninstaller = (payload / base / "uninstall.sh").read_text()
        self.assertIn("/private/etc/pam.d", uninstaller)
        self.assertIn("/private/var/db/pam_watchid", uninstaller)
        self.assertNotRegex(uninstaller, r"@[A-Z][A-Z0-9_]*@")
        bom = subprocess.run([
            "/usr/bin/lsbom", "-p", "fug", str(expanded / "Bom"),
        ], check=True, capture_output=True, text=True).stdout
        for line in bom.splitlines():
            fields = line.split("\t")
            self.assertEqual(fields[-2:], ["0", "0"], line)


if __name__ == "__main__":
    unittest.main()
