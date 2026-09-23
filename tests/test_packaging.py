"""Run real rendered package hooks in project-local synthetic filesystems."""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import unittest
import uuid


PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "scripts"))
import release


TOOLS = {
    "id": "/usr/bin/id", "stat": "/usr/bin/stat", "ls": "/bin/ls",
    "sysctl": "/usr/sbin/sysctl", "sw_vers": "/usr/bin/sw_vers",
    "pkgutil": "/usr/sbin/pkgutil", "uname": "/usr/bin/uname",
    "codesign": "/usr/bin/codesign", "chown": "/usr/sbin/chown",
    "cp": "/bin/cp", "mv": "/bin/mv", "rm": "/bin/rm",
    "rmdir": "/bin/rmdir", "mkdir": "/bin/mkdir",
    "shasum": "/usr/bin/shasum", "xattr": "/usr/bin/xattr",
}

FAST_TOOLS = {"id", "stat", "ls", "xattr", "sysctl", "uname", "sw_vers"}
FAST_STUB = r"""#!/bin/sh
name=${0##*/}
if [ "${TEST_FAIL_TOOL:-}" = "$name" ]; then
    case "$*" in *"${TEST_FAIL_MATCH:-}"*) echo "injected $name failure" >&2; exit 1 ;; esac
fi
case "$name" in
    id) printf '%s\n' "${TEST_EFFECTIVE_UID:-0}" ;;
    stat)
        [ "$#" = 3 ] && [ "$1" = -f ] || exit 1
        format=$2
        owner=${TEST_OWNER:-0}
        if [ -n "${TEST_UNSAFE_PATH:-}" ] && [ "$TEST_UNSAFE_PATH" != "$3" ]; then owner=0; fi
        format=${format//%u/$owner}
        format=${format//%g/0}
        if [ -n "${TEST_FLAGS:-}" ]; then format=${format//%f/$TEST_FLAGS}; fi
        exec /usr/bin/stat -f "$format" "$3"
        ;;
    ls)
        /bin/ls "$@" || exit
        if [ -n "${TEST_ACL:-}" ]; then
            case "$1" in *e*) printf ' 0: group:everyone allow %s\n' "$TEST_ACL" ;; esac
        fi
        ;;
    xattr)
        if [ "${TEST_EMULATE_XATTRS:-}" = 1 ]; then
            exec "$TEST_PYTHON" "$TEST_XATTR_SHIM" "$@"
        fi
        exec /usr/bin/xattr "$@"
        ;;
    sysctl)
        [ "$*" = "-in sysctl.proc_translated" ] || exit 1
        printf '%s\n' "${TEST_TRANSLATED-}"
        ;;
    uname)
        [ "$*" = "-m" ] || exit 1
        printf '%s\n' "${TEST_PROCESS_ARCH-arm64}"
        ;;
    sw_vers) printf '%s\n' "${TEST_OS_VERSION:-26.1}" ;;
    *) exit 1 ;;
esac
"""

# Only ownership, privilege and signing are simulated. Files, hashes, modes,
# links, inode information, copies and renames otherwise use the real tools.
STUB = r"""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys

name = Path(sys.argv[0]).name
if name == "xattr-model":
    name = "xattr"
args = sys.argv[1:]
config = Path(os.environ["TEST_CONFIGURATION"])
state = Path(os.environ["TEST_STATE"])
base = Path(os.environ["TEST_BASE"])
log = Path(os.environ["TEST_EVENT_LOG"])
xattr_file = Path(os.environ["TEST_XATTR_FILE"])
xattrs = json.loads(xattr_file.read_text()) if xattr_file.exists() else {}
content = config.read_bytes() if config.is_file() and not config.is_symlink() else None
locks = {
    str(path.relative_to(state.parent)): path.stat().st_ino
    for path in state.parent.rglob("*")
    if path.is_dir() and "lock" in path.name
} if state.parent.exists() else {}
with log.open("a") as stream:
    stream.write(json.dumps({
        "tool": name, "args": args,
        "configuration": base64.b64encode(content).decode() if content is not None else None,
        "locks": locks,
    }) + "\n")

failure = os.environ.get("TEST_FAIL_TOOL")
match = os.environ.get("TEST_FAIL_MATCH", "")
if name == failure and (not match or any(match in argument for argument in args)):
    print("injected " + name + " failure", file=sys.stderr)
    sys.exit(1)

if name == "xattr":
    path = args[-1]
    native = subprocess.run(["/usr/bin/xattr", path], capture_output=True, text=True)
    if native.returncode:
        print(native.stderr, end="", file=sys.stderr)
        sys.exit(native.returncode)
    exact = os.environ.get("TEST_XATTR_EXACT") == "1"
    if exact and Path(path).name.startswith(".pam_watchid.") and path not in xattrs:
        xattrs[path] = {"com.apple.provenance": os.environ["TEST_COPY_PROVENANCE"]}
        xattr_file.write_text(json.dumps(xattrs, sort_keys=True))
    names = set() if exact else set(native.stdout.splitlines())
    names.update(xattrs.get(path, {}))
    if len(args) == 1:
        print("\n".join(sorted(names)), end="\n" if names else "")
    else:
        assert all(arg.startswith("-") for arg in args[:-2]), args
        assert "p" in "".join(args[:-2]) and "x" in "".join(args[:-2]), args
        attribute = args[-2]
        if attribute in xattrs.get(path, {}):
            print(xattrs[path][attribute])
        elif exact:
            print("fixture attribute is absent: " + attribute, file=sys.stderr)
            sys.exit(1)
        else:
            sys.exit(subprocess.run(["/usr/bin/xattr", *args]).returncode)
elif name == "pkgutil":
    if "--pkgs" in args:
        if not os.environ.get("TEST_NO_RECEIPT"):
            print("io.github.rioriost.pam-watchid")
    elif "--pkg-info" in args:
        print("package-id: io.github.rioriost.pam-watchid")
        print("version: " + os.environ.get("TEST_RECEIPT_VERSION", "0.1.1"))
    elif "--forget" not in args:
        raise AssertionError(args)
elif name == "codesign":
    assert "--verify" in args, args
    assert Path(args[-1]).is_file(), args
elif name == "chown":
    assert any("root" in arg or "0" in arg for arg in args[:-1]), args
    assert Path(args[-1]).exists(), args
else:
    actual = {
        "cp": "/bin/cp", "mv": "/bin/mv", "rm": "/bin/rm",
        "rmdir": "/bin/rmdir", "mkdir": "/bin/mkdir",
        "shasum": "/usr/bin/shasum",
    }[name]
    result = subprocess.run([actual, *args])
    if result.returncode == 0:
        if xattr_file.exists() and name in ("cp", "mv", "rm"):
            if name in ("cp", "mv"):
                source, destination = args[-2:]
                copied = {
                    destination + key[len(source):]: dict(value)
                    for key, value in xattrs.items()
                    if key == source or key.startswith(source + "/")
                }
                generated = os.environ.get("TEST_COPY_PROVENANCE")
                if name == "cp" and generated and Path(destination).is_file():
                    copied.setdefault(destination, {}).setdefault("com.apple.provenance", generated)
                    if Path(destination).name.startswith(".pam_watchid.") and os.environ.get("TEST_CANDIDATE_XATTRS"):
                        copied[destination] = json.loads(os.environ["TEST_CANDIDATE_XATTRS"])
                for key in list(xattrs):
                    if key == destination or key.startswith(destination + "/") or (
                        name == "mv" and (key == source or key.startswith(source + "/"))
                    ):
                        del xattrs[key]
                xattrs.update(copied)
            else:
                for removed in (arg for arg in args if not arg.startswith("-")):
                    for key in list(xattrs):
                        if key == removed or key.startswith(removed + "/"):
                            del xattrs[key]
            if name == "cp" and str(config) in args[:-1] and os.environ.get("TEST_EXTERNAL_XATTR_AFTER_BACKUP"):
                xattrs[str(config)]["com.apple.macl"] = os.environ["TEST_EXTERNAL_XATTR_AFTER_BACKUP"]
            xattr_file.write_text(json.dumps(xattrs, sort_keys=True))
        if name == "cp" and os.environ.get("TEST_EXTERNAL_EDIT_AFTER_BACKUP") and str(config) in args[:-1]:
            config.write_bytes(base64.b64decode(os.environ["TEST_EXTERNAL_BYTES"]))
    sys.exit(result.returncode)
"""


class PackagingTests(unittest.TestCase):
    VERSION = "0.2.0"
    MODULE = b"fixture pam_watchid module, not executable\n"
    HELPER = b"fixture matching helper, not executable\n"
    GENERATED_PROVENANCE = "1020304050607080"
    ORIGINAL = b"# existing local policy\nauth sufficient pam_tid.so\n"
    MAIN = (
        b"# sudo includes local authentication before password fallback\n"
        b"auth include sudo_local\n"
        b"auth sufficient pam_smartcard.so\n"
        b"auth required pam_opendirectory.so\n"
        b"account required pam_permit.so\n"
    )

    def setUp(self):
        self.root = PROJECT / "build" / f"packaging-test-{uuid.uuid4().hex}"
        self.root.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.root)
        self.reset_fixture()

    def reset_fixture(self):
        for path in self.root.iterdir():
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            else:
                path.unlink()
        self.library = self.root / "Library"
        self.security = self.library / "Security"
        self.base = self.security / "pam_watchid"
        self.private = self.root / "private"
        self.pam = self.private / "etc" / "pam.d"
        self.state = self.private / "var" / "db" / "pam_watchid"
        self.pam.mkdir(parents=True)
        self.state.parent.mkdir(parents=True)
        self.configuration = self.pam / "sudo_local"
        self.configuration.write_bytes(self.ORIGINAL)
        self.main = self.pam / "sudo"
        self.main.write_bytes(self.MAIN)
        self.write_payload()
        self.bin = self.root / "fake-tools"
        self.bin.mkdir()
        for name in TOOLS:
            executable = self.bin / name
            executable.write_text(
                FAST_STUB if name in FAST_TOOLS else f"#!{sys.executable}\n" + STUB
            )
            executable.chmod(0o755)
        xattr_model = self.bin / "xattr-model"
        xattr_model.write_text(f"#!{sys.executable}\n" + STUB)
        xattr_model.chmod(0o755)
        for path in self.root.rglob("*"):
            if path.is_dir():
                path.chmod(0o755)
        self.event_log = self.root / "events.jsonl"
        self.xattr_file = self.root / "xattrs.json"
        self.exact_xattrs = False

    def write_payload(self, module=None, helper=None):
        (self.base / "libexec").mkdir(parents=True, exist_ok=True)
        contents = {
            "pam_watchid.so": self.MODULE if module is None else module,
            "libexec/pam_watchid-helper": self.HELPER if helper is None else helper,
            "LICENSE": b"fixture license\n", "uninstall.sh": b"fixture uninstaller\n",
        }
        for name, content in contents.items():
            path = self.base / name
            path.write_bytes(content)
            path.chmod(0o644 if name in ("pam_watchid.so", "LICENSE") else 0o755)

    def render(self, text, name):
        # No runtime path overrides are supported or exercised by production.
        replacements = {
            "/Library/Security/pam_watchid": str(self.base),
            "/Library/Security": str(self.security), "/Library": str(self.library),
            "/private/etc/pam.d": str(self.pam),
            "/private/var/db/pam_watchid": str(self.state),
            "/private/var/db": str(self.state.parent),
            "/private/var": str(self.private / "var"),
            "/private/etc": str(self.private / "etc"), "/private": str(self.private),
            **{absolute: str(self.bin / name) for name, absolute in TOOLS.items()},
        }
        expression = "|".join(re.escape(key) for key in sorted(replacements, key=len, reverse=True))
        text = re.sub(expression, lambda match: replacements[match.group()], text)
        self.assertNotRegex(text, r"@[A-Z][A-Z0-9_]*@")
        path = self.root / name
        path.write_text(text)
        subprocess.run(["/bin/sh", "-n", str(path)], check=True, capture_output=True)
        return path

    def run_script(self, path, arguments=(), *, stdin=None, **environment):
        env = os.environ.copy()
        env.update({
            "TEST_EVENT_LOG": str(self.event_log), "TEST_CONFIGURATION": str(self.configuration),
            "TEST_STATE": str(self.state), "TEST_BASE": str(self.base),
            "TEST_XATTR_FILE": str(self.xattr_file), "TEST_XATTR_SHIM": str(self.bin / "xattr-model"),
            "TEST_PYTHON": sys.executable,
            "TEST_EMULATE_XATTRS": "1" if self.xattr_file.exists() else "",
            "TEST_XATTR_EXACT": "1" if self.exact_xattrs else "",
            "TEST_COPY_PROVENANCE": self.GENERATED_PROVENANCE if self.exact_xattrs else "",
            **environment,
        })
        return subprocess.run(
            ["/bin/sh", str(path), *arguments], text=True, capture_output=True, env=env,
            stdin=stdin, timeout=120,
        )

    def uninstall(self):
        return self.render(release.render_uninstall(), "uninstall-test.sh")

    def preinstall(self, architecture="arm64", version=None):
        return self.render(
            release.render_preinstall(architecture, version=version or self.VERSION),
            f"preinstall-{architecture}",
        )

    def postinstall(self, module=None, helper=None, version=None):
        return self.render(release.render_postinstall(
            "arm64", version or self.VERSION,
            hashlib.sha256(self.MODULE if module is None else module).hexdigest(),
            hashlib.sha256(self.HELPER if helper is None else helper).hexdigest(),
        ), "postinstall")

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def assert_failure(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def activate(self, original=None):
        if original is not None:
            self.configuration.write_bytes(original)
        self.assert_success(self.run_script(self.preinstall()))
        self.assert_success(self.run_script(self.postinstall()))
        return self.configuration.read_bytes()

    @property
    def auth_line(self):
        return f"auth sufficient {self.base}/pam_watchid.so\n".encode()

    @property
    def managed_block(self):
        return b"# pam_watchid: begin managed\n" + self.auth_line + b"# pam_watchid: end managed\n"

    def events(self, tool=None):
        result = [
            json.loads(line) for line in self.event_log.read_text().splitlines()
        ] if self.event_log.exists() else []
        return [event for event in result if event["tool"] == tool] if tool else result

    def backups(self):
        return {
            str(path.relative_to(self.state)): path.read_bytes()
            for path in self.state.rglob("*")
            if path.is_file() and ("backup" in str(path.relative_to(self.state)))
        } if self.state.exists() else {}

    def assert_backups_preserved(self, saved):
        current = self.backups()
        for name, content in saved.items():
            self.assertIn(name, current)
            self.assertEqual(current[name], content)

    def backup_metadata(self):
        return {
            name: ((self.state / name).stat().st_ino, (self.state / name).stat().st_mtime_ns)
            for name in self.backups()
        }

    def set_trusted_xattrs(self, attributes):
        recorded = json.loads(self.xattr_file.read_text()) if self.xattr_file.exists() else {}
        recorded[str(self.configuration)] = dict(attributes)
        self.xattr_file.write_text(json.dumps(recorded, sort_keys=True))

    def emulate_generated_provenance(self):
        # Explicitly model attr-free sources; ordinary fixtures expose native xattrs.
        self.exact_xattrs = True
        self.xattr_file.write_text("{}")

    def trusted_xattrs(self, path):
        return json.loads(self.xattr_file.read_text()).get(str(path), {})

    def assert_payload_intact(self):
        for name in ["pam_watchid.so", "libexec/pam_watchid-helper", "LICENSE", "uninstall.sh"]:
            self.assertTrue((self.base / name).exists(), name)

    def assert_no_forget(self):
        self.assertFalse(any("--forget" in event["args"] for event in self.events("pkgutil")))

    def assert_refusal_without_mutation(self, script, **environment):
        before = self.configuration.read_bytes() if self.configuration.is_file() else None
        saved = self.backups()
        response = self.run_script(script, **environment)
        self.assert_failure(response)
        after = self.configuration.read_bytes() if self.configuration.is_file() else None
        self.assertEqual(after, before)
        self.assertEqual(self.backups(), saved)
        self.assert_payload_intact()
        self.assert_no_forget()
        return response

    def test_fresh_install_waits_for_both_verified_payloads_before_prepend(self):
        shutil.rmtree(self.base)
        before = self.configuration.read_bytes()
        main = self.main.read_bytes()
        self.assert_success(self.run_script(self.preinstall()))
        self.assertFalse(self.base.exists())
        self.assertEqual(self.configuration.read_bytes(), before)
        self.assertTrue(self.state.exists())
        prepared_backups = self.backups()
        prepared_metadata = self.backup_metadata()
        self.write_payload()
        self.assert_success(self.run_script(self.postinstall()))
        installed = self.configuration.read_bytes()
        self.assertTrue(installed.endswith(before))
        prefix = installed[:-len(before)]
        self.assertEqual(prefix, self.managed_block)
        self.assertEqual(installed.count(self.auth_line), 1)
        self.assertEqual(self.main.read_bytes(), main)
        self.assert_backups_preserved(prepared_backups)
        self.assertGreaterEqual(list(self.backups().values()).count(before), 1)
        for name, identity in prepared_metadata.items():
            self.assertEqual(self.backup_metadata()[name], identity)
        for name in self.backups():
            self.assertEqual((self.state / name).stat().st_mode & 0o077, 0)
        signatures = self.events("codesign")
        self.assertEqual(
            {event["args"][-1] for event in signatures},
            {str(self.base / "pam_watchid.so"), str(self.base / "libexec/pam_watchid-helper")},
        )
        for event in signatures:
            self.assertEqual(base64.b64decode(event["configuration"]), before)

    def test_missing_corrupt_mismatched_payload_and_signature_never_activate(self):
        for failure in ("module-missing", "helper-missing", "module-corrupt", "helper-corrupt",
                        "wrong-pair", "signature", "hash"):
            with self.subTest(failure=failure):
                self.reset_fixture()
                self.assert_success(self.run_script(self.preinstall()))
                saved = self.backups()
                environment = {}
                if failure.endswith("-missing"):
                    name = "pam_watchid.so" if failure.startswith("module") else "libexec/pam_watchid-helper"
                    (self.base / name).unlink()
                elif failure.endswith("-corrupt"):
                    name = "pam_watchid.so" if failure.startswith("module") else "libexec/pam_watchid-helper"
                    (self.base / name).write_bytes(b"corrupt or other-version binary\n")
                elif failure == "wrong-pair":
                    self.write_payload(helper=b"valid-looking helper from another release\n")
                else:
                    environment["TEST_FAIL_TOOL"] = "codesign" if failure == "signature" else "shasum"
                self.assert_failure(self.run_script(self.postinstall(), **environment))
                self.assertEqual(self.configuration.read_bytes(), self.ORIGINAL)
                self.assertEqual(self.backups(), saved)
                self.assert_no_forget()
                self.assertTrue((self.state / "pending").is_dir())
                payload = {
                    str(path.relative_to(self.base)): path.read_bytes()
                    for path in self.base.rglob("*") if path.is_file()
                }
                self.assert_failure(self.run_script(self.uninstall()))
                self.assertEqual({
                    str(path.relative_to(self.base)): path.read_bytes()
                    for path in self.base.rglob("*") if path.is_file()
                }, payload)
                self.write_payload()
                self.assert_success(self.run_script(self.postinstall()))
                self.assertEqual(self.configuration.read_bytes().count(self.auth_line), 1)

    def test_postinstall_without_preinstall_cannot_activate(self):
        self.assert_refusal_without_mutation(self.postinstall())

    def test_postinstall_rejects_nonexecutable_helper_without_pam_changes(self):
        self.assert_success(self.run_script(self.preinstall()))
        (self.base / "libexec/pam_watchid-helper").chmod(0o600)
        self.assert_refusal_without_mutation(self.postinstall())
        self.assertTrue((self.state / "pending").is_dir())

    def test_existing_touch_id_comments_and_binary_bytes_are_preserved(self):
        original = (
            b"# keep this comment \xff\n"
            b"auth sufficient pam_tid.so # keep inline comment\n"
            b"\n# trailing comments\n\n"
        )
        active = self.activate(original)
        self.assertTrue(active.endswith(original))
        self.assertIn(original, self.backups().values())
        self.assert_success(self.run_script(self.uninstall()))
        self.assertEqual(self.configuration.read_bytes(), original)

    def test_absent_empty_and_newline_variants_round_trip_on_uninstall(self):
        for original in (None, b"", b"# no final newline", b"# one newline\n", b"# many\n\n\n"):
            with self.subTest(original=original):
                self.reset_fixture()
                if original is None:
                    self.configuration.unlink()
                else:
                    self.configuration.write_bytes(original)
                self.activate()
                saved = self.backups()
                self.assert_success(self.run_script(self.uninstall()))
                self.assertEqual(self.configuration.exists(), original is not None)
                if original is not None:
                    self.assertEqual(self.configuration.read_bytes(), original)
                self.assert_backups_preserved(saved)

    def test_repeated_activation_does_not_duplicate_prefix_or_overwrite_backups(self):
        active = self.activate()
        saved = self.backups()
        metadata = self.backup_metadata()
        self.assert_failure(self.run_script(self.postinstall()))
        self.assertEqual(self.configuration.read_bytes(), active)
        self.assertEqual(self.backups(), saved)
        self.assertEqual(self.backup_metadata(), metadata)
        self.assert_success(self.run_script(self.preinstall()))
        self.assert_success(self.run_script(self.postinstall()))
        self.assertEqual(self.configuration.read_bytes(), active)
        self.assert_backups_preserved(saved)
        for name, identity in metadata.items():
            self.assertEqual(self.backup_metadata()[name], identity)

    def test_managed_upgrade_disables_before_replacement_and_readds_once(self):
        self.activate()
        saved = self.backups()
        metadata = self.backup_metadata()
        self.assert_success(self.run_script(self.preinstall(version="0.2.1")))
        self.assertEqual(self.configuration.read_bytes(), self.ORIGINAL)
        next_module, next_helper = b"next signed module\n", b"next signed helper\n"
        self.write_payload(next_module, next_helper)
        self.assert_success(self.run_script(self.postinstall(
            next_module, next_helper, version="0.2.1",
        )))
        self.assertEqual(self.configuration.read_bytes().count(self.auth_line), 1)
        self.assertTrue(self.configuration.read_bytes().endswith(self.ORIGINAL))
        current = self.backups()
        for name, content in saved.items():
            self.assertEqual(current[name], content)
            self.assertEqual(self.backup_metadata()[name], metadata[name])
        self.assertGreater(len(current), len(saved))
        self.assert_success(self.run_script(self.uninstall()))
        self.assertEqual(self.configuration.read_bytes(), self.ORIGINAL)

    def test_interrupted_preinstall_requires_explicit_cancel_before_retry(self):
        preinstall = self.preinstall()
        self.assert_success(self.run_script(preinstall))
        saved = self.backups()
        self.assert_refusal_without_mutation(preinstall)
        self.assertEqual(self.configuration.read_bytes(), self.ORIGINAL)
        self.assertEqual(self.backups(), saved)
        self.assert_refusal_without_mutation(self.preinstall(version="0.2.1"))
        self.assert_refusal_without_mutation(self.postinstall(version="0.2.1"))
        self.assert_success(self.run_script(self.uninstall(), ["--cancel-install"]))
        self.assertFalse((self.state / "pending").exists())
        self.assertEqual(self.configuration.read_bytes(), self.ORIGINAL)
        self.assert_payload_intact()
        self.assert_success(self.run_script(self.preinstall(version="0.2.1")))
        self.assert_success(self.run_script(self.postinstall(version="0.2.1")))

    def test_cancel_install_refuses_to_adopt_administrator_edits(self):
        self.assert_success(self.run_script(self.preinstall()))
        saved = self.backups()
        edited = self.ORIGINAL + b"# changed while installation was pending\n"
        self.configuration.write_bytes(edited)
        self.assert_failure(self.run_script(self.uninstall(), ["--cancel-install"]))
        self.assertEqual(self.configuration.read_bytes(), edited)
        self.assertTrue((self.state / "pending").is_dir())
        self.assertEqual(self.backups(), saved)
        self.assert_payload_intact()
        self.assert_no_forget()

    def test_interrupted_postinstall_finishes_only_matching_verified_activation(self):
        self.assert_success(self.run_script(self.preinstall()))
        self.assert_failure(self.run_script(
            self.postinstall(), TEST_FAIL_TOOL="rm",
            TEST_FAIL_MATCH=str(self.state / "pending" / "token"),
        ))
        active = self.configuration.read_bytes()
        self.assertEqual(active, self.managed_block + self.ORIGINAL)
        self.assertTrue((self.state / "pending" / "token").is_file())
        self.assert_failure(self.run_script(self.uninstall()))
        self.assert_failure(self.run_script(self.uninstall(), ["--cancel-install"]))
        self.assert_payload_intact()
        saved = self.backups()
        self.assert_refusal_without_mutation(self.postinstall(version="0.2.1"))
        signatures_before = len(self.events("codesign"))
        self.assert_success(self.run_script(self.postinstall()))
        self.assertGreaterEqual(len(self.events("codesign")) - signatures_before, 2)
        self.assertEqual(self.configuration.read_bytes(), active)
        self.assertFalse((self.state / "pending").exists())
        self.assert_backups_preserved(saved)

    def test_inactive_legacy_install_activates_but_manual_legacy_requires_removal(self):
        self.assert_success(self.run_script(self.preinstall(), TEST_RECEIPT_VERSION="0.1.1"))
        self.assert_success(self.run_script(self.postinstall()))
        self.assertEqual(self.configuration.read_bytes().count(self.auth_line), 1)
        self.reset_fixture()
        self.configuration.write_bytes(self.auth_line + self.ORIGINAL)
        for script in (self.preinstall(), self.uninstall()):
            self.assert_refusal_without_mutation(script, TEST_RECEIPT_VERSION="0.1.1")

    def test_local_mandatory_authentication_gate_refuses_sufficient_prepend(self):
        for control in (b"required", b"requisite"):
            with self.subTest(control=control):
                self.reset_fixture()
                self.configuration.write_bytes(
                    b"# mandatory gate must not be bypassed\n"
                    b"auth " + control + b" pam_smartcard.so\n" + self.ORIGINAL
                )
                self.assert_refusal_without_mutation(self.preinstall())

    def test_postinstall_rechecks_policy_changed_after_preinstall(self):
        for change in ("mandatory", "main", "foreign-reference"):
            with self.subTest(change=change):
                self.reset_fixture()
                self.assert_success(self.run_script(self.preinstall()))
                if change == "mandatory":
                    self.configuration.write_bytes(b"auth required pam_smartcard.so\n" + self.ORIGINAL)
                elif change == "main":
                    self.main.write_bytes(b"# auth include sudo_local\n")
                else:
                    (self.pam / ".foreign").write_bytes(b"auth sufficient pam_watchid.so\n")
                self.assert_refusal_without_mutation(self.postinstall())

    def test_main_sudo_requires_active_auth_include_and_password_fallback(self):
        invalid = (
            None, b"", b"# auth include sudo_local\nauth required pam_opendirectory.so\n",
            b"account include sudo_local\nauth required pam_opendirectory.so\n",
            b"auth include other_local\nauth required pam_opendirectory.so\n",
            b"auth include sudo_local\n# auth required pam_opendirectory.so\n",
            b"auth include sudo_local\naccount required pam_opendirectory.so\n",
            b"auth include sudo_local\nauth required pam_custom_mfa.so\n"
            b"auth required pam_opendirectory.so\n",
        )
        for content in invalid:
            with self.subTest(content=content):
                self.reset_fixture()
                if content is None:
                    self.main.unlink()
                else:
                    self.main.write_bytes(content)
                self.assert_refusal_without_mutation(self.preinstall())

    def test_manual_quoted_continued_and_mixed_references_refuse(self):
        references = (
            b"auth sufficient pam_watchid.so\n",
            b"\tauth sufficient pam_watchid # active\n",
            b'auth sufficient "/Library/Security/pam_watchid/pam_watchid.so"\n',
            b"auth sufficient 'pam_watchid.so'\n",
            b"auth sufficient /Library/Security/pam_watchid/pam_watch\\\nid.so\n",
            b"auth sufficient pam_watchid\x00.so\n",
            b"# comment with a continuation\\\nauth sufficient pam_watchid.so\n",
        )
        for content in references:
            with self.subTest(reference=content):
                self.reset_fixture()
                self.configuration.write_bytes(content + self.ORIGINAL)
                for script in (self.preinstall(), self.uninstall()):
                    self.assert_refusal_without_mutation(script)
        self.reset_fixture()
        active = self.activate()
        self.configuration.write_bytes(active + b"auth sufficient pam_watchid.so\n")
        for script in (self.preinstall(), self.uninstall()):
            self.assert_refusal_without_mutation(script)

    def test_other_services_including_hidden_files_refuse_before_mutation(self):
        for service, managed in (
            ("other-service", False), (".hidden-service", False),
            ("..hidden", False), (".hidden-service", True),
        ):
            with self.subTest(service=service, managed=managed):
                self.reset_fixture()
                if managed:
                    self.activate()
                (self.pam / service).write_bytes(b"auth sufficient pam_watchid.so\n")
                for script in (self.preinstall(), self.uninstall()):
                    self.assert_refusal_without_mutation(script)

    def test_comment_only_and_inline_comment_are_not_activation(self):
        original = (
            b" # auth sufficient /Library/Security/pam_watchid/pam_watchid.so\n"
            b"auth sufficient pam_tid.so # pam_watchid.so\n"
        )
        active = self.activate(original)
        self.assertTrue(active.endswith(original))
        self.assert_success(self.run_script(self.uninstall()))
        self.assertEqual(self.configuration.read_bytes(), original)

    def test_edits_outside_managed_prefix_are_preserved(self):
        active = self.activate()
        edits = b"# added by administrator\nauth required pam_smartcard.so\n\n"
        self.configuration.write_bytes(active + edits)
        self.assert_success(self.run_script(self.uninstall()))
        self.assertEqual(self.configuration.read_bytes(), self.ORIGINAL + edits)

    def test_absent_original_does_not_delete_later_administrator_edits(self):
        self.configuration.unlink()
        active = self.activate()
        edits = b"# new local policy\nauth sufficient pam_tid.so\n"
        self.configuration.write_bytes(active + edits)
        self.assert_success(self.run_script(self.uninstall()))
        self.assertEqual(self.configuration.read_bytes(), edits)

    def test_damaged_duplicate_or_moved_managed_prefix_refuses(self):
        for damage in ("marker", "line", "duplicate", "moved"):
            with self.subTest(damage=damage):
                self.reset_fixture()
                active = self.activate()
                prefix = active[:-len(self.ORIGINAL)]
                if damage == "marker":
                    changed = active.replace(b"#", b"##", 1)
                elif damage == "line":
                    changed = active.replace(self.auth_line, self.auth_line.replace(b"sufficient", b"required"))
                elif damage == "duplicate":
                    changed = prefix + active
                else:
                    changed = b"# moved prefix\n" + active
                self.configuration.write_bytes(changed)
                for script in (self.preinstall(), self.uninstall()):
                    self.assert_refusal_without_mutation(script)

    def test_missing_provenance_cannot_claim_existing_managed_prefix(self):
        self.activate()
        shutil.rmtree(self.state)
        for script in (self.preinstall(), self.uninstall()):
            self.assert_refusal_without_mutation(script)

    def test_unsafe_pam_symlinks_hardlinks_and_modes_refuse(self):
        for entry in ("sudo_local", "sudo", ".other-service"):
            for unsafe in ("symlink", "hardlink", "mode"):
                with self.subTest(entry=entry, unsafe=unsafe):
                    self.reset_fixture()
                    path = self.pam / entry
                    if not path.exists():
                        path.write_bytes(b"# unrelated service\n")
                    external = self.root / "outside"
                    if unsafe == "symlink":
                        path.rename(external)
                        path.symlink_to(external)
                    elif unsafe == "hardlink":
                        os.link(path, external)
                    else:
                        path.chmod(0o666)
                    self.assert_failure(self.run_script(self.preinstall()))
                    self.assert_payload_intact()
                    self.assert_no_forget()
                    self.assertFalse(self.backups())

    def test_payload_and_directory_symlinks_are_rejected(self):
        module = self.base / "pam_watchid.so"
        module.unlink()
        module.symlink_to(self.root / "outside")
        self.assert_failure(self.run_script(self.preinstall()))
        module.unlink()
        self.write_payload()
        old = self.security / "old-payload"
        self.base.rename(old)
        self.base.symlink_to(old, target_is_directory=True)
        self.assert_failure(self.run_script(self.uninstall()))
        self.assertTrue((old / "pam_watchid.so").exists())
        self.assert_no_forget()

    def test_payload_hardlinks_are_rejected_before_activation(self):
        for name in ("pam_watchid.so", "libexec/pam_watchid-helper"):
            with self.subTest(name=name):
                self.reset_fixture()
                os.link(self.base / name, self.root / "linked-payload")
                self.assert_refusal_without_mutation(self.preinstall())

    def test_state_and_pam_directories_cannot_be_symlinks_or_writable(self):
        for target in ("pam", "state", "state-parent"):
            for unsafe in ("symlink", "mode"):
                with self.subTest(target=target, unsafe=unsafe):
                    self.reset_fixture()
                    self.state.mkdir(mode=0o700)
                    path = {"pam": self.pam, "state": self.state, "state-parent": self.state.parent}[target]
                    if unsafe == "symlink":
                        external = self.root / "outside-directory"
                        path.rename(external)
                        path.symlink_to(external, target_is_directory=True)
                    else:
                        path.chmod(0o777)
                    self.assert_refusal_without_mutation(self.preinstall())
                    self.assert_refusal_without_mutation(self.uninstall())

    def test_nonroot_owner_writable_acl_flags_and_nonroot_caller_refuse(self):
        for environment in (
            {"TEST_OWNER": "501"}, {"TEST_ACL": "write,delete"},
            {"TEST_FLAGS": "2"}, {"TEST_EFFECTIVE_UID": "501"},
        ):
            with self.subTest(environment=environment):
                self.assert_refusal_without_mutation(self.preinstall(), **environment)
                self.assert_refusal_without_mutation(self.uninstall(), **environment)
        for path, mode in ((self.base, 0o775), (self.base / "libexec/pam_watchid-helper", 0o4755)):
            with self.subTest(path=path, mode=oct(mode)):
                previous = path.stat().st_mode & 0o7777
                path.chmod(mode)
                self.assert_refusal_without_mutation(self.preinstall())
                self.assert_refusal_without_mutation(self.uninstall())
                path.chmod(previous)

    def test_nonstandard_extended_attributes_are_not_silently_dropped(self):
        subprocess.run([
            "/usr/bin/xattr", "-w", "org.pam_watchid.fixture", "preserve",
            str(self.configuration),
        ], check=True, capture_output=True)
        self.assert_refusal_without_mutation(self.preinstall())
        self.assert_refusal_without_mutation(self.uninstall())

    def test_os_generated_xattrs_are_preserved_through_activation_and_uninstall(self):
        attributes = {
            "com.apple.macl": "00112233445566778899aabbccddeeff",
            "com.apple.provenance": "0102030405060708",
        }
        self.set_trusted_xattrs(attributes)
        active = self.activate()
        self.assertEqual(active, self.managed_block + self.ORIGINAL)
        self.assertEqual(self.trusted_xattrs(self.configuration), attributes)
        saved = self.backups()
        originals = [
            self.state / name for name, content in saved.items() if content == self.ORIGINAL
        ]
        self.assertTrue(originals)
        for path in originals:
            self.assertEqual(self.trusted_xattrs(path), attributes)
        self.assert_success(self.run_script(self.uninstall()))
        self.assertEqual(self.configuration.read_bytes(), self.ORIGINAL)
        self.assertEqual(self.trusted_xattrs(self.configuration), attributes)
        self.assert_backups_preserved(saved)
        for path in originals:
            self.assertEqual(self.trusted_xattrs(path), attributes)

    def test_copy_generated_provenance_allows_attr_free_policy_snapshots(self):
        for original in (self.ORIGINAL, None):
            with self.subTest(original_present=original is not None):
                self.reset_fixture()
                self.emulate_generated_provenance()
                if original is None:
                    self.configuration.unlink()
                self.assert_success(self.run_script(self.preinstall()))
                self.assertEqual(self.main.read_bytes(), self.MAIN)
                self.assertEqual(self.trusted_xattrs(self.main), {})
                self.assertEqual(self.configuration.exists(), original is not None)
                if original is not None:
                    self.assertEqual(self.configuration.read_bytes(), original)
                    self.assertEqual(self.trusted_xattrs(self.configuration), {})
                    self.assertEqual(
                        self.trusted_xattrs(self.state / "pending" / "sudo_local"),
                        {"com.apple.provenance": self.GENERATED_PROVENANCE},
                    )
                prepared = self.backups()
                main_snapshots = [
                    self.state / name for name, content in prepared.items()
                    if content == self.MAIN
                ]
                self.assertTrue(main_snapshots)
                for path in main_snapshots:
                    self.assertEqual(
                        self.trusted_xattrs(path),
                        {"com.apple.provenance": self.GENERATED_PROVENANCE},
                    )
                self.assert_success(self.run_script(self.postinstall()))
                self.assertEqual(self.configuration.read_bytes(), self.managed_block + (original or b""))
                self.assertEqual(
                    self.trusted_xattrs(self.configuration),
                    {"com.apple.provenance": self.GENERATED_PROVENANCE},
                )
                self.assert_backups_preserved(prepared)
                self.assert_success(self.run_script(self.uninstall()))
                self.assertEqual(self.configuration.exists(), original is not None)
                if original is not None:
                    self.assertEqual(self.configuration.read_bytes(), original)
                self.assertEqual(self.main.read_bytes(), self.MAIN)
                self.assertEqual(self.trusted_xattrs(self.main), {})
                self.assert_backups_preserved(prepared)

    def test_generated_provenance_is_pinned_for_interrupted_activation_retry(self):
        for original in (self.ORIGINAL, None):
            with self.subTest(original_present=original is not None):
                self.reset_fixture()
                self.emulate_generated_provenance()
                if original is None:
                    self.configuration.unlink()
                self.assert_success(self.run_script(self.preinstall()))
                self.assert_failure(self.run_script(
                    self.postinstall(), TEST_FAIL_TOOL="rm",
                    TEST_FAIL_MATCH=str(self.state / "pending" / "token"),
                ))
                active = self.managed_block + (original or b"")
                self.assertEqual(self.configuration.read_bytes(), active)
                recorded = self.state / "pending" / "activated-attributes"
                recorded_bytes = recorded.read_bytes()
                self.assertIn(
                    f"com.apple.provenance={self.GENERATED_PROVENANCE}\n".encode(),
                    recorded_bytes,
                )
                recorded.unlink()
                self.assert_failure(self.run_script(self.postinstall()))
                self.assertEqual(self.configuration.read_bytes(), active)
                recorded.write_bytes(recorded_bytes)
                recorded.chmod(0o600)
                for changed in ({"com.apple.provenance": "ffeeddccbbaa9988"}, {}):
                    with self.subTest(changed=changed):
                        self.set_trusted_xattrs(changed)
                        self.assert_failure(self.run_script(self.postinstall()))
                        self.assertEqual(self.configuration.read_bytes(), active)
                        self.assertEqual(self.trusted_xattrs(self.configuration), changed)
                        self.assertTrue((self.state / "pending" / "token").exists())
                        self.assert_payload_intact()
                self.set_trusted_xattrs({"com.apple.provenance": self.GENERATED_PROVENANCE})
                self.assert_success(self.run_script(self.postinstall()))
                self.assertEqual(self.configuration.read_bytes(), active)
                self.assertFalse((self.state / "pending").exists())

    def test_candidate_copy_rejects_lost_changed_and_unexpected_attributes(self):
        source = {"com.apple.macl": "00112233", "com.apple.provenance": "01020304"}
        groups = (
            (source, (
                {"com.apple.provenance": source["com.apple.provenance"]},
                {"com.apple.macl": source["com.apple.macl"]},
                {**source, "com.apple.provenance": "ffffffff"},
                {**source, "com.apple.macl": "ffffffff"},
            )),
            ({}, (
                {"com.apple.provenance": self.GENERATED_PROVENANCE, "com.apple.macl": "00112233"},
                {"com.apple.provenance": self.GENERATED_PROVENANCE, "org.pam_watchid.unknown": "00112233"},
            )),
        )
        for original, changes in groups:
            self.reset_fixture()
            self.emulate_generated_provenance()
            self.set_trusted_xattrs(original)
            self.assert_success(self.run_script(self.preinstall()))
            for changed in changes:
                with self.subTest(original=original, candidate=changed):
                    self.assert_failure(self.run_script(
                        self.postinstall(), TEST_CANDIDATE_XATTRS=json.dumps(changed),
                    ))
                    self.assertEqual(self.configuration.read_bytes(), self.ORIGINAL)
                    self.assertEqual(self.trusted_xattrs(self.configuration), original)
                    self.assertTrue((self.state / "pending").is_dir())
                    self.assert_payload_intact()
                    self.assert_no_forget()

    def test_xattr_only_external_changes_are_detected_before_activation(self):
        attributes = {
            "com.apple.macl": "00112233445566778899aabbccddeeff",
            "com.apple.provenance": "0102030405060708",
        }
        changed = {**attributes, "com.apple.macl": "ffeeddccbbaa99887766554433221100"}
        for timing in ("before-postinstall", "during-backup"):
            with self.subTest(timing=timing):
                self.reset_fixture()
                self.set_trusted_xattrs(attributes)
                self.assert_success(self.run_script(self.preinstall()))
                environment = {}
                if timing == "before-postinstall":
                    self.set_trusted_xattrs(changed)
                else:
                    environment["TEST_EXTERNAL_XATTR_AFTER_BACKUP"] = changed["com.apple.macl"]
                self.assert_failure(self.run_script(self.postinstall(), **environment))
                self.assertEqual(self.configuration.read_bytes(), self.ORIGINAL)
                self.assertEqual(self.trusted_xattrs(self.configuration), changed)
                self.assertTrue((self.state / "pending").is_dir())
                self.assert_payload_intact()
                self.assert_no_forget()

    def test_uninstall_does_not_wait_for_an_open_stdin_pipe(self):
        self.activate()
        read_fd, write_fd = os.pipe()
        try:
            result = self.run_script(self.uninstall(), stdin=read_fd)
        finally:
            os.close(write_fd)
            os.close(read_fd)
        self.assert_success(result)
        self.assertEqual(self.configuration.read_bytes(), self.ORIGINAL)
        self.assertFalse(self.base.exists())

    def test_uninstall_removes_only_owned_payload_and_keeps_backups(self):
        self.activate()
        extra = self.base / "user-note"
        extra.write_text("must survive")
        sibling = self.security / "another-module.so"
        sibling.write_text("must survive")
        saved = self.backups()
        first_event = len(self.events())
        self.assert_success(self.run_script(self.uninstall()))
        self.assertEqual(self.configuration.read_bytes(), self.ORIGINAL)
        self.assertEqual(extra.read_text(), "must survive")
        self.assertEqual(sibling.read_text(), "must survive")
        self.assert_backups_preserved(saved)
        for name in ("pam_watchid.so", "libexec/pam_watchid-helper", "LICENSE", "uninstall.sh"):
            self.assertFalse((self.base / name).exists())
        events = self.events()[first_event:]
        forgets = [
            event for event in events if event["tool"] == "pkgutil" and "--forget" in event["args"]
        ]
        self.assertEqual([event["args"] for event in forgets], [["--forget", release.RECEIPT]])
        deletes = [
            event for event in events if event["tool"] == "rm"
            and any(str(self.base) in argument for argument in event["args"])
        ]
        self.assertTrue(deletes)
        config_renames = [
            event for event in events if event["tool"] == "mv"
            and event["args"][-1] == str(self.configuration)
        ]
        self.assertTrue(config_renames)
        held_lock = config_renames[0]["locks"]
        self.assertTrue(held_lock)
        for event in [*forgets, *deletes]:
            self.assertEqual(event["locks"], held_lock, event)
            self.assertEqual(base64.b64decode(event["configuration"]), self.ORIGINAL)

    def test_foreign_and_stale_lock_refuse_without_removing_owner_lock(self):
        self.activate()
        observed = {
            value for event in self.events() for value in event["locks"]
        }
        self.assertTrue(observed, "Transactions must hold a filesystem lock")
        lock_relative = min(observed, key=lambda value: len(Path(value).parts))
        for owner in ("foreign live owner\n", "stale owner pid 99999999\n"):
            with self.subTest(owner=owner):
                lock = self.state.parent / lock_relative
                lock.mkdir(parents=True)
                sentinel = lock / "foreign-owner"
                sentinel.write_text(owner)
                for script in (self.preinstall(), self.postinstall(), self.uninstall()):
                    self.assert_refusal_without_mutation(script)
                    self.assertTrue(lock.is_dir())
                    self.assertEqual(sentinel.read_text(), owner)
                shutil.rmtree(lock)

    def test_check_only_uninstall_keeps_managed_configuration_payload_and_receipt(self):
        active = self.activate()
        saved = self.backups()
        self.assert_success(self.run_script(self.uninstall(), ["--check"]))
        self.assertEqual(self.configuration.read_bytes(), active)
        self.assertEqual(self.backups(), saved)
        self.assert_payload_intact()
        self.assert_no_forget()

    def test_receipt_failure_is_not_success_and_preserves_usable_policy(self):
        for argument in ("--pkgs", "--forget"):
            with self.subTest(argument=argument):
                self.reset_fixture()
                self.activate()
                saved = self.backups()
                result = self.run_script(
                    self.uninstall(), TEST_FAIL_TOOL="pkgutil", TEST_FAIL_MATCH=argument,
                )
                self.assert_failure(result)
                if argument == "--pkgs":
                    self.assert_payload_intact()
                else:
                    self.assertEqual(self.configuration.read_bytes(), self.ORIGINAL)
                self.assertTrue(self.configuration.read_bytes().endswith(self.ORIGINAL))
                self.assertLessEqual(self.configuration.read_bytes().count(self.auth_line), 1)
                for name, content in saved.items():
                    self.assertEqual(self.backups()[name], content)

    def test_missing_receipt_still_allows_safe_uninstall(self):
        self.activate()
        self.assert_success(self.run_script(self.uninstall(), TEST_NO_RECEIPT="1"))
        self.assertEqual(self.configuration.read_bytes(), self.ORIGINAL)
        self.assertFalse(self.base.exists())
        self.assert_no_forget()

    def test_directory_removal_failure_is_not_reported_as_success(self):
        self.activate()
        result = self.run_script(
            self.uninstall(), TEST_FAIL_TOOL="rmdir", TEST_FAIL_MATCH=str(self.base / "libexec"),
        )
        self.assert_failure(result)
        self.assertEqual(self.configuration.read_bytes(), self.ORIGINAL)
        self.assertNotIn("payload removed", result.stdout)

    def test_payload_deletion_failure_leaves_sudo_usable_and_reports_failure(self):
        self.activate()
        result = self.run_script(
            self.uninstall(), TEST_FAIL_TOOL="rm", TEST_FAIL_MATCH=str(self.base / "pam_watchid.so"),
        )
        self.assert_failure(result)
        self.assertEqual(self.configuration.read_bytes(), self.ORIGINAL)
        self.assertTrue((self.base / "pam_watchid.so").exists())
        self.assertNotIn("payload removed", result.stdout)

    def test_config_rename_failure_keeps_original_and_requires_safe_cancel(self):
        self.assert_success(self.run_script(self.preinstall()))
        result = self.run_script(
            self.postinstall(), TEST_FAIL_TOOL="mv", TEST_FAIL_MATCH=str(self.configuration),
        )
        self.assert_failure(result)
        self.assertEqual(self.configuration.read_bytes(), self.ORIGINAL)
        self.assert_payload_intact()
        self.assertTrue((self.state / "pending").is_dir())
        self.assert_refusal_without_mutation(self.preinstall())
        self.assert_failure(self.run_script(self.uninstall()))
        self.assert_success(self.run_script(self.uninstall(), ["--cancel-install"]))
        self.assertEqual(self.configuration.read_bytes(), self.ORIGINAL)
        self.assertFalse((self.state / "pending").exists())
        self.assert_success(self.run_script(self.preinstall()))
        self.assert_success(self.run_script(self.postinstall()))
        self.assertEqual(self.configuration.read_bytes().count(self.auth_line), 1)

    def test_backup_copy_failure_never_mutates_configuration(self):
        self.assert_success(self.run_script(self.preinstall()))
        result = self.run_script(
            self.postinstall(), TEST_FAIL_TOOL="cp", TEST_FAIL_MATCH=str(self.configuration),
        )
        self.assert_failure(result)
        self.assertEqual(self.configuration.read_bytes(), self.ORIGINAL)
        self.assert_payload_intact()
        self.assert_success(self.run_script(self.postinstall()))

    def test_controlled_external_edit_before_rename_is_detected(self):
        self.assert_success(self.run_script(self.preinstall()))
        external = self.ORIGINAL + b"# concurrent administrator change\n"
        result = self.run_script(
            self.postinstall(), TEST_EXTERNAL_EDIT_AFTER_BACKUP="1",
            TEST_EXTERNAL_BYTES=base64.b64encode(external).decode(),
        )
        self.assert_failure(result)
        self.assertEqual(self.configuration.read_bytes(), external)
        self.assertNotIn(self.auth_line, self.configuration.read_bytes())
        self.assert_payload_intact()

    def test_preinstall_supported_physical_architecture_os_matrix(self):
        for architecture in release.ARCHITECTURES:
            for physical in release.ARCHITECTURES:
                for major in (14, 15, 16, 25, 26, 27, 28):
                    with self.subTest(package=architecture, physical=physical, major=major):
                        self.reset_fixture()
                        expected = architecture == physical and (
                            major in (15, 26) or (major == 27 and physical == "arm64")
                        )
                        response = self.run_script(
                            self.preinstall(architecture), TEST_PROCESS_ARCH=physical,
                            TEST_OS_VERSION=f"{major}.1",
                        )
                        self.assertEqual(response.returncode == 0, expected, response.stderr)
                        self.assertEqual(self.configuration.read_bytes(), self.ORIGINAL)
                        self.assert_payload_intact()

    def test_preinstall_unknown_hardware_and_other_target_volume_refuse(self):
        for environment in (
            {"TEST_PROCESS_ARCH": ""}, {"TEST_PROCESS_ARCH": "unknown"},
            {"TEST_PROCESS_ARCH": "x86_64", "TEST_TRANSLATED": "2"},
            {"TEST_PROCESS_ARCH": "x86_64", "TEST_TRANSLATED": "unknown"},
            {"TEST_PROCESS_ARCH": "x86_64", "TEST_FAIL_TOOL": "sysctl"},
            {"TEST_FAIL_TOOL": "uname"},
        ):
            self.assert_refusal_without_mutation(self.preinstall(), **environment)
        response = self.run_script(self.preinstall(), ["/fake.pkg", "/", "/Volumes/Other"])
        self.assert_failure(response)
        self.assertEqual(self.configuration.read_bytes(), self.ORIGINAL)
        self.assert_payload_intact()

    def test_native_and_translated_architectures_without_optional_arm64_key(self):
        for process_arch, translated, physical_arch in (
            ("x86_64", "", "x86_64"), ("x86_64", "0", "x86_64"),
            ("x86_64", "1", "arm64"), ("arm64", "", "arm64"),
            ("arm64", "0", "arm64"), ("arm64", "1", "arm64"),
            ("x86_64", "unknown", None), ("unknown", "", None),
        ):
            for package_arch in release.ARCHITECTURES:
                with self.subTest(process=process_arch, translated=translated, package=package_arch):
                    self.reset_fixture()
                    response = self.run_script(
                        self.preinstall(package_arch), TEST_PROCESS_ARCH=process_arch,
                        TEST_TRANSLATED=translated,
                    )
                    self.assertEqual(response.returncode == 0, package_arch == physical_arch, response.stderr)
                    self.assertEqual(self.configuration.read_bytes(), self.ORIGINAL)
                    self.assert_payload_intact()


if __name__ == "__main__":
    unittest.main()
