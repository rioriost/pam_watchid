"""Exercise rendered package guards only in project-local synthetic filesystems."""

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import unittest
import uuid


PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "scripts"))
import release


STUB = r"""
import json
import os
from pathlib import Path
import stat
import sys

name = Path(sys.argv[0]).name
if name == "id":
    print(os.environ.get("TEST_EFFECTIVE_UID", "0"))
elif name == "stat":
    mode = stat.S_IMODE(os.lstat(sys.argv[-1]).st_mode)
    print(os.environ.get("TEST_OWNER", "0") + ":" + oct(mode)[2:])
elif name == "ls":
    if sys.argv[1] == "-A":
        for entry in Path(sys.argv[-1]).iterdir():
            print(entry.name)
    else:
        print("root-owned test fixture")
        if os.environ.get("TEST_ACL"):
            print(" 0: group:everyone allow " + os.environ["TEST_ACL"])
elif name == "sysctl":
    assert sys.argv[1:] == ["-in", "sysctl.proc_translated"]
    if os.environ.get("TEST_SYSCTL_FAILURE"):
        sys.exit(1)
    print(os.environ.get("TEST_TRANSLATED", ""))
elif name == "uname":
    assert sys.argv[1:] == ["-m"]
    if os.environ.get("TEST_UNAME_FAILURE"):
        sys.exit(1)
    default = "arm64" if os.environ.get("TEST_PHYSICAL_ARM64", "1") == "1" else "x86_64"
    print(os.environ.get("TEST_PROCESS_ARCH", default))
elif name == "sw_vers":
    print(os.environ.get("TEST_OS_VERSION", "26.1"))
elif name == "pkgutil":
    with open(os.environ["TEST_RECEIPT_LOG"], "a") as stream:
        stream.write(json.dumps(sys.argv[1:]) + "\n")
    if "--pkgs" in sys.argv:
        if os.environ.get("TEST_RECEIPT_QUERY_FAILURE"):
            sys.exit(1)
        if not os.environ.get("TEST_NO_RECEIPT"):
            print("io.github.rioriost.pam-watchid")
    if "--forget" in sys.argv and os.environ.get("TEST_FORGET_FAILURE"):
        sys.exit(1)
else:
    raise AssertionError(name)
"""


class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.root = PROJECT / "build" / f"packaging-test-{uuid.uuid4().hex}"
        self.root.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.root)
        self.library = self.root / "Library"
        self.security = self.library / "Security"
        self.base = self.security / "pam_watchid"
        (self.base / "libexec").mkdir(parents=True)
        self.pam = self.root / "pam.d"
        self.pam.mkdir()
        for directory in [self.root, self.library, self.security,
                          self.base, self.base / "libexec", self.pam]:
            directory.chmod(0o755)
        for name in ["pam_watchid.so", "libexec/pam_watchid-helper", "LICENSE", "uninstall.sh"]:
            (self.base / name).write_text("test payload, not installable\n")
            (self.base / name).chmod(0o644)
        self.configuration = self.pam / "sudo_local"
        self.configuration.write_text("# no pam_watchid activation\n")
        self.bin = self.root / "fake-tools"
        self.bin.mkdir()
        for name in ["id", "stat", "ls", "sysctl", "sw_vers", "pkgutil", "uname"]:
            executable = self.bin / name
            executable.write_text(f"#!{sys.executable}\n" + STUB)
            executable.chmod(0o755)
        self.receipt_log = self.root / "receipt.jsonl"

    def render(self, text, name):
        # These substitutions exist only in tests, never as production overrides.
        text = text.replace("base=/Library/Security/pam_watchid", f"base={shlex.quote(str(self.base))}")
        text = text.replace("pam_dir=/etc/pam.d", f"pam_dir={shlex.quote(str(self.pam))}")
        text = text.replace(
            "for directory in / /Library /Library/Security",
            "for directory in " + " ".join(shlex.quote(str(path)) for path in
                                           [self.root, self.library, self.security]),
        )
        for absolute in [
            "/usr/bin/id", "/usr/bin/stat", "/bin/ls",
            "/usr/sbin/sysctl", "/usr/bin/sw_vers", "/usr/sbin/pkgutil", "/usr/bin/uname",
        ]:
            text = text.replace(absolute, shlex.quote(str(self.bin / Path(absolute).name)))
        path = self.root / name
        path.write_text(text)
        subprocess.run(["/bin/sh", "-n", str(path)], check=True, capture_output=True)
        return path

    def run_script(self, path, arguments=(), **environment):
        env = os.environ.copy()
        env.update({"TEST_RECEIPT_LOG": str(self.receipt_log), **environment})
        return subprocess.run(
            ["/bin/sh", str(path), *arguments], text=True, capture_output=True, env=env,
        )

    def uninstall(self):
        return self.render((PROJECT / "packaging/uninstall.sh").read_text(), "uninstall-test.sh")

    def preinstall(self, architecture="arm64"):
        return self.render(release.render_preinstall(architecture), f"preinstall-{architecture}")

    def assert_payload_intact(self):
        for name in ["pam_watchid.so", "libexec/pam_watchid-helper", "LICENSE", "uninstall.sh"]:
            self.assertTrue((self.base / name).exists(), name)
        self.assertFalse(self.receipt_log.exists())

    def test_active_module_anywhere_refuses_upgrade_and_uninstall(self):
        cases = [
            "auth sufficient /Library/Security/pam_watchid/pam_watchid.so\n",
            "\tauth sufficient pam_watchid.so # active\n",
            "auth required pam_watchid\n",
            'auth sufficient "/Library/Security/pam_watchid/pam_watchid.so"\n',
            "auth sufficient 'pam_watchid.so'\n",
            "auth sufficient /Library/Security/pam_watchid/pam_watch\\\nid.so\n",
            "# comment\nauth sufficient /Library/Security/pam_watchid/pam_watchid.so\n",
        ]
        for text in cases:
            self.configuration.write_text(text)
            for path in [self.uninstall(), self.preinstall()]:
                with self.subTest(text=text, script=path.name):
                    response = self.run_script(path)
                    self.assertNotEqual(response.returncode, 0, response.stdout)
                    self.assertIn("manually before upgrading/removing", response.stderr)
                    self.assertEqual(self.configuration.read_text(), text)
                    self.assert_payload_intact()

    def test_hidden_or_different_pam_service_cannot_bypass_guard(self):
        (self.pam / ".other-service").write_text("auth sufficient pam_watchid.so\n")
        response = self.run_script(self.uninstall())
        self.assertNotEqual(response.returncode, 0)
        self.assert_payload_intact()

    def test_comment_only_and_inline_comment_are_not_activation(self):
        text = (
            " # auth sufficient /Library/Security/pam_watchid/pam_watchid.so\n"
            "auth required pam_opendirectory.so # pam_watchid.so\n"
        )
        self.configuration.write_text(text)
        response = self.run_script(self.uninstall(), ["--check"])
        self.assertEqual(response.returncode, 0, response.stderr)
        self.assertEqual(self.configuration.read_text(), text)
        self.assert_payload_intact()

    def test_unsafe_pam_entry_fails_closed(self):
        self.configuration.unlink()
        self.configuration.symlink_to(self.root / "absent")
        response = self.run_script(self.uninstall())
        self.assertNotEqual(response.returncode, 0)
        self.assertIn("Cannot safely inspect", response.stderr)
        self.assert_payload_intact()

    def test_payload_and_directory_symlinks_are_rejected(self):
        module = self.base / "pam_watchid.so"
        module.unlink()
        module.symlink_to(self.root / "outside")
        response = self.run_script(self.preinstall())
        self.assertNotEqual(response.returncode, 0)
        self.assertIn("symbolic link", response.stderr)
        module.unlink()
        module.write_text("fixture")
        old = self.security / "old-payload"
        self.base.rename(old)
        self.base.symlink_to(old, target_is_directory=True)
        response = self.run_script(self.uninstall())
        self.assertNotEqual(response.returncode, 0)
        self.assertIn("symbolic link", response.stderr)
        self.assertTrue((old / "pam_watchid.so").exists())
        self.assertFalse(self.receipt_log.exists())

    def test_non_root_owner_writable_mode_acl_and_nonroot_caller_are_rejected(self):
        path = self.uninstall()
        for environment in [
            {"TEST_OWNER": "501"}, {"TEST_ACL": "write,delete"},
            {"TEST_EFFECTIVE_UID": "501"},
        ]:
            with self.subTest(environment=environment):
                response = self.run_script(path, **environment)
                self.assertNotEqual(response.returncode, 0)
                self.assert_payload_intact()
        self.base.chmod(0o775)
        response = self.run_script(path)
        self.assertNotEqual(response.returncode, 0)
        self.assertIn("group/world writable", response.stderr)
        self.assert_payload_intact()
        self.base.chmod(0o755)
        (self.base / "libexec/pam_watchid-helper").chmod(0o4755)
        response = self.run_script(path)
        self.assertNotEqual(response.returncode, 0)
        self.assertIn("set-ID", response.stderr)
        self.assert_payload_intact()

    def test_preinstall_supported_physical_architecture_os_matrix(self):
        for architecture in release.ARCHITECTURES:
            path = self.preinstall(architecture)
            for physical_arm in ("0", "1"):
                for major in (14, 15, 16, 25, 26, 27, 28):
                    expected = (
                        architecture == ("arm64" if physical_arm == "1" else "x86_64")
                        and (major in (15, 26) or (major == 27 and physical_arm == "1"))
                    )
                    with self.subTest(package=architecture, arm=physical_arm, major=major):
                        response = self.run_script(
                            path, TEST_PHYSICAL_ARM64=physical_arm,
                            TEST_OS_VERSION=f"{major}.1",
                        )
                        self.assertEqual(response.returncode == 0, expected, response.stderr)
                        self.assert_payload_intact()

    def test_preinstall_rejects_unknown_hardware_and_other_target_volume(self):
        path = self.preinstall()
        for environment in [
            {"TEST_PROCESS_ARCH": ""},
            {"TEST_PROCESS_ARCH": "unknown"},
            {"TEST_PROCESS_ARCH": "x86_64", "TEST_TRANSLATED": "2"},
            {"TEST_PROCESS_ARCH": "x86_64", "TEST_TRANSLATED": "unknown"},
            {"TEST_PROCESS_ARCH": "x86_64", "TEST_SYSCTL_FAILURE": "1"},
            {"TEST_UNAME_FAILURE": "1"},
        ]:
            response = self.run_script(path, **environment)
            self.assertNotEqual(response.returncode, 0)
        response = self.run_script(path, ["/fake.pkg", "/", "/Volumes/Other"])
        self.assertNotEqual(response.returncode, 0)
        self.assert_payload_intact()

    def test_native_and_translated_architectures_without_optional_arm64_key(self):
        for process_arch, translated, physical_arch in [
            ("x86_64", "", "x86_64"),
            ("x86_64", "0", "x86_64"),
            ("x86_64", "1", "arm64"),
            ("arm64", "", "arm64"),
            ("arm64", "0", "arm64"),
            ("arm64", "1", "arm64"),
            ("x86_64", "unknown", None),
            ("unknown", "", None),
        ]:
            for package_arch in release.ARCHITECTURES:
                with self.subTest(process=process_arch, translated=translated,
                                  package=package_arch):
                    response = self.run_script(
                        self.preinstall(package_arch), TEST_PHYSICAL_ARM64="",
                        TEST_PROCESS_ARCH=process_arch, TEST_TRANSLATED=translated,
                    )
                    self.assertEqual(
                        response.returncode == 0, package_arch == physical_arch, response.stderr,
                    )
                    self.assert_payload_intact()

    def test_fresh_install_with_missing_payload_is_allowed_without_creation(self):
        shutil.rmtree(self.base)
        response = self.run_script(self.preinstall())
        self.assertEqual(response.returncode, 0, response.stderr)
        self.assertFalse(self.base.exists())
        self.assertFalse(self.receipt_log.exists())

    def test_uninstall_removes_only_owned_files_and_forgets_exact_receipt(self):
        extra = self.base / "user-note"
        extra.write_text("must survive")
        sibling = self.security / "another-module.so"
        sibling.write_text("must survive")
        before = self.configuration.read_bytes()
        response = self.run_script(self.uninstall())
        self.assertEqual(response.returncode, 0, response.stderr)
        self.assertEqual(self.configuration.read_bytes(), before)
        self.assertEqual(extra.read_text(), "must survive")
        self.assertEqual(sibling.read_text(), "must survive")
        for name in ["pam_watchid.so", "libexec/pam_watchid-helper", "LICENSE", "uninstall.sh"]:
            self.assertFalse((self.base / name).exists())
        self.assertFalse((self.base / "libexec").exists())
        self.assertEqual(
            [json.loads(line) for line in self.receipt_log.read_text().splitlines()],
            [["--pkgs"], ["--forget", release.RECEIPT]],
        )

    def test_forget_failure_keeps_payload_and_no_receipt_still_allows_removal(self):
        response = self.run_script(self.uninstall(), TEST_FORGET_FAILURE="1")
        self.assertNotEqual(response.returncode, 0)
        self.assertTrue((self.base / "pam_watchid.so").exists())
        self.receipt_log.unlink()
        response = self.run_script(self.uninstall(), TEST_NO_RECEIPT="1")
        self.assertEqual(response.returncode, 0, response.stderr)
        self.assertFalse(self.base.exists())
        self.assertEqual(len(self.receipt_log.read_text().splitlines()), 1)

    def test_directory_removal_failure_is_not_silently_ignored(self):
        fail_rmdir = self.bin / "fail-rmdir"
        fail_rmdir.write_text("#!/bin/sh\nexit 1\n")
        fail_rmdir.chmod(0o755)
        source = (PROJECT / "packaging/uninstall.sh").read_text()
        source = source.replace("/bin/rmdir", shlex.quote(str(fail_rmdir)))
        response = self.run_script(self.render(source, "failed-removal.sh"))
        self.assertNotEqual(response.returncode, 0)
        self.assertIn("Cannot remove empty directory", response.stderr)
        self.assertNotIn("payload removed", response.stdout)

    def test_receipt_query_failure_never_removes_payload(self):
        response = self.run_script(self.uninstall(), TEST_RECEIPT_QUERY_FAILURE="1")
        self.assertNotEqual(response.returncode, 0)
        self.assertIn("Cannot inspect package receipts", response.stderr)
        self.assertTrue((self.base / "pam_watchid.so").exists())


if __name__ == "__main__":
    unittest.main()
