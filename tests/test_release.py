"""Release tests never access signing identities, credentials, or Apple's services."""

import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest import mock
import uuid


PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "scripts"))
import release
import generate_cask


TEAM = "ABCDE12345"
OTHER_TEAM = "ZZZZZ67890"
APPLICATION = release.Identity(
    "A" * 40, f"Developer ID Application: Example ({TEAM})", "Application", TEAM,
)
INSTALLER = release.Identity(
    "B" * 40, f"Developer ID Installer: Example ({TEAM})", "Installer", TEAM,
)
SUBMISSION = "00000000-0000-4000-8000-000000000001"


def result(code=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], code, stdout, stderr)


def signature(team=TEAM):
    return (
        'Package "fixture.pkg":\n'
        "   Status: signed by a developer certificate issued by Apple for distribution\n"
        f"   Certificate Chain:\n    1. Developer ID Installer: Example ({team})\n"
    )


class FakeRunner:
    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.calls = []

    def __call__(self, args, *, capture=True):
        self.calls.append(([str(arg) for arg in args], capture))
        if not self.responses:
            raise AssertionError(f"Unexpected subprocess: {args}")
        return self.responses.pop(0)


class ProjectFixture(unittest.TestCase):
    def setUp(self):
        self.root = PROJECT / "build" / f"release-test-{uuid.uuid4().hex}"
        self.root.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.root)

    def keychain(self):
        path = self.root / "example keychain-db"
        path.write_text("FAKE KEYCHAIN — no credentials", encoding="utf-8")
        return path


class IdentityTests(unittest.TestCase):
    def test_parse_only_complete_valid_developer_id_lines(self):
        identities = release.parse_identities(
            f'  1) {"a" * 40} "{APPLICATION.name}"\n'
            f'  2) {"B" * 40} "{INSTALLER.name}"\n'
            f'  3) {"C" * 40} "{APPLICATION.name}" (CSSMERR_TP_CERT_EXPIRED)\n'
            f'  4) {"D" * 40} "Apple Development: Example ({TEAM})"\n'
            f'  5) {"a" * 40} "{APPLICATION.name}"\n'
            "  4 valid identities found\n"
        )
        self.assertEqual(identities, [APPLICATION, INSTALLER])

    def test_unique_matching_team_not_first_unpaired_identity(self):
        extra = release.Identity("C" * 40, "Unpaired", "Application", OTHER_TEAM)
        self.assertEqual(
            release.select_identities([extra, APPLICATION, INSTALLER]),
            (APPLICATION, INSTALLER),
        )

    def test_multiple_teams_require_explicit_selection(self):
        second = [
            release.Identity("C" * 40, "Second app", "Application", OTHER_TEAM),
            release.Identity("D" * 40, "Second installer", "Installer", OTHER_TEAM),
        ]
        with self.assertRaisesRegex(release.ReleaseError, "Multiple signing teams"):
            release.select_identities([APPLICATION, INSTALLER, *second])
        self.assertEqual(
            release.select_identities([APPLICATION, INSTALLER, *second], TEAM),
            (APPLICATION, INSTALLER),
        )

    def test_same_team_duplicate_names_require_fingerprint(self):
        duplicate = release.Identity("C" * 40, APPLICATION.name, "Application", TEAM)
        identities = [APPLICATION, INSTALLER, duplicate]
        for selector in ("", APPLICATION.name):
            with self.assertRaisesRegex(release.ReleaseError, "Multiple identities"):
                release.select_identities(identities, TEAM, selector)
        self.assertEqual(
            release.select_identities(identities, TEAM, "c" * 40),
            (duplicate, INSTALLER),
        )

    def test_same_team_duplicate_installer_requires_fingerprint(self):
        duplicate = release.Identity("D" * 40, INSTALLER.name, "Installer", TEAM)
        with self.assertRaisesRegex(release.ReleaseError, "Multiple identities"):
            release.select_identities([APPLICATION, INSTALLER, duplicate], TEAM)
        self.assertEqual(
            release.select_identities(
                [APPLICATION, INSTALLER, duplicate], TEAM, installer="D" * 40,
            ),
            (APPLICATION, duplicate),
        )

    def test_mismatched_team_or_identity_and_malformed_team_fail(self):
        for options in [
            {"team": OTHER_TEAM}, {"application": "C" * 40}, {"installer": "C" * 40},
            {"team": "BAD=INJECTION"},
        ]:
            with self.assertRaises(release.ReleaseError):
                release.select_identities([APPLICATION, INSTALLER], **options)


class KeychainTests(ProjectFixture):
    def test_default_user_keychain_is_explicit_and_preflighted(self):
        keychain = self.keychain()
        runner = FakeRunner([result(stdout=f'    "{keychain}"\n')])
        reader = mock.Mock(return_value=7)
        self.assertEqual(release.choose_keychain(runner, status_reader=reader), keychain)
        reader.assert_called_once_with(keychain)
        self.assertEqual(runner.calls[0][0], [
            "/usr/bin/security", "default-keychain", "-d", "user",
        ])

    def test_explicit_keychain_does_not_search_or_unlock(self):
        runner = FakeRunner()
        keychain = self.keychain()
        self.assertEqual(
            release.choose_keychain(runner, str(keychain), status_reader=lambda _: 3),
            keychain,
        )
        self.assertEqual(runner.calls, [])

    def test_absent_locked_denied_and_status_errors(self):
        keychain = self.keychain()
        cases = [(self.root / "absent", 7, "absent"), (keychain, 2, "locked"),
                 (keychain, 1, "denied")]
        for path, flags, diagnostic in cases:
            with self.subTest(diagnostic=diagnostic):
                with self.assertRaisesRegex(release.ReleaseError, diagnostic):
                    release.preflight_keychain(path, lambda _: flags)
        with mock.patch.object(release.os, "access", return_value=False):
            with self.assertRaisesRegex(release.ReleaseError, "not readable"):
                release.preflight_keychain(keychain, lambda _: 7)
        with self.assertRaisesRegex(release.ReleaseError, "Security status -25293"):
            release.preflight_keychain(
                keychain, mock.Mock(side_effect=release.ReleaseError("Security status -25293")),
            )

    def test_ambiguous_or_malformed_default_is_not_guessed(self):
        for output in ["", '"/a" "/b"', '"unterminated', "relative"]:
            with self.subTest(output=output):
                with self.assertRaises(release.ReleaseError):
                    release.choose_keychain(FakeRunner([result(stdout=output)]))


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.keychain = Path("/fake/selected.keychain-db")
        self.profile = f"pam_watchid.notary.{TEAM}"
        self.preflight = mock.Mock()
        self.reader = mock.Mock(return_value="developer@example.invalid")

    def ensure(self, runner, interactive=False):
        return release.ensure_profile(
            runner, self.keychain, TEAM, interactive=interactive,
            read_apple_id=self.reader, preflight=self.preflight,
        )

    def missing(self):
        return result(69, stderr=release.missing_profile_diagnostic(self.profile) + "\n")

    def test_existing_valid_profile_never_prompts(self):
        runner = FakeRunner([result(stdout='{"history": []}')])
        self.assertEqual(self.ensure(runner, interactive=True), self.profile)
        self.reader.assert_not_called()
        self.assertEqual(len(runner.calls), 1)

    def test_only_exact_name_and_diagnostic_are_missing(self):
        for diagnostic in [
            "Keychain is locked", "User interaction is not allowed.",
            "HTTP status code 401. Invalid credentials.",
            "The Internet connection appears to be offline.",
            "Unknown error", "No Keychain password item found",
            release.missing_profile_diagnostic(self.profile + ".other"),
            release.missing_profile_diagnostic(self.profile) + "\nAccess denied",
        ]:
            with self.subTest(diagnostic=diagnostic):
                runner = FakeRunner([result(1, stderr=diagnostic)])
                with self.assertRaisesRegex(release.ReleaseError, "will not be overwritten"):
                    self.ensure(runner, interactive=True)
                self.assertEqual(len(runner.calls), 1)
        self.reader.assert_not_called()

    def test_missing_profile_accepts_only_observed_one_or_two_newline_separators(self):
        actual = (
            f"Error: No Keychain password item found for profile: {self.profile}\n\n"
            "Run 'notarytool store-credentials' to create another credential profile.\n"
        )
        self.assertTrue(release.profile_is_missing(result(69, stderr=actual), self.profile))
        self.assertTrue(release.profile_is_missing(
            result(69, stderr=actual.replace("\n\n", "\n")), self.profile,
        ))
        self.assertFalse(release.profile_is_missing(
            result(69, stderr=actual.replace("\n\n", "\n\n\n")), self.profile,
        ))
        self.assertFalse(release.profile_is_missing(
            result(69, stderr=actual + "Access denied.\n"), self.profile,
        ))

    def test_missing_noninteractive_profile_is_actionable(self):
        runner = FakeRunner([self.missing()])
        with self.assertRaisesRegex(release.ReleaseError, "make notary-profile"):
            self.ensure(runner)
        self.reader.assert_not_called()

    def test_native_secure_password_prompt_has_no_password_argument_or_capture(self):
        runner = FakeRunner([self.missing(), result(), result(stdout='{"history": []}')])
        self.assertEqual(self.ensure(runner, interactive=True), self.profile)
        args, capture = runner.calls[1]
        self.assertEqual(args, [
            "/usr/bin/xcrun", "notarytool", "store-credentials", self.profile,
            "--apple-id", "developer@example.invalid", "--team-id", TEAM,
            "--keychain", str(self.keychain), "--validate",
        ])
        self.assertFalse(capture)
        self.assertFalse(any("password" in arg for arg in args))
        self.assertEqual(self.preflight.call_count, 3)
        self.assertEqual(runner.calls[0], runner.calls[2])

    def test_store_failure_does_not_retry_or_print_captured_password(self):
        runner = FakeRunner([self.missing(), result(1, stderr="not captured")])
        with self.assertRaisesRegex(release.ReleaseError, r"xcrun failed \(1\)"):
            self.ensure(runner, interactive=True)
        self.assertEqual(len(runner.calls), 2)

    def test_ci_never_prompts_even_with_tty(self):
        with mock.patch.dict(os.environ, {"CI": "true"}), \
                mock.patch.object(sys.stdin, "isatty", return_value=True), \
                mock.patch.object(sys.stdout, "isatty", return_value=True), \
                mock.patch.object(sys.stderr, "isatty", return_value=True):
            self.assertFalse(release.interactive_terminal())
            runner = FakeRunner([self.missing()])
            with self.assertRaisesRegex(release.ReleaseError, "make notary-profile"):
                self.ensure(runner, interactive=None)
        self.reader.assert_not_called()

    def test_keychain_preflight_failure_precedes_lookup(self):
        self.preflight.side_effect = release.ReleaseError("locked")
        runner = FakeRunner()
        with self.assertRaisesRegex(release.ReleaseError, "locked"):
            self.ensure(runner, interactive=True)
        self.assertEqual(runner.calls, [])
        self.reader.assert_not_called()


class NotarizationTests(ProjectFixture):
    def test_rejected_pending_or_failed_submission_never_staples(self):
        package = self.root / "fixture.pkg"
        package.write_bytes(b"not an installable package")
        for index, (status, code) in enumerate(
                [("Invalid", 0), ("Rejected", 0), ("In Progress", 0), ("Accepted", 1)]):
            output = self.root / str(index)
            output.mkdir()
            runner = FakeRunner([
                result(code, json.dumps({"id": SUBMISSION, "status": status})),
                result(stdout=json.dumps({"jobId": SUBMISSION, "status": status})),
            ])
            with self.assertRaisesRegex(release.ReleaseError, "not Accepted"):
                release.notarize_package(
                    runner, package, output, "arm64", "fake-profile", self.root / "fake-keychain",
                )
            self.assertEqual(len(runner.calls), 2)
            self.assertTrue((output / "arm64-submission.json").is_file())
            self.assertTrue((output / "arm64-notary-log.json").is_file())

    def test_accepted_requires_matching_log_and_stapler_validation(self):
        (self.root / "fixture.pkg").write_bytes(b"fake package")
        for index, log in enumerate([
            {"jobId": SUBMISSION, "status": "Invalid"},
            {"jobId": str(uuid.uuid4()), "status": "Accepted"},
        ]):
            output = self.root / str(index)
            output.mkdir()
            runner = FakeRunner([
                result(stdout=json.dumps({"id": SUBMISSION, "status": "Accepted"})),
                result(stdout=json.dumps(log)),
            ])
            with self.assertRaisesRegex(release.ReleaseError, "log does not confirm"):
                release.notarize_package(
                    runner, self.root / "fixture.pkg", output, "arm64", "fake", self.root / "keychain",
                )
            self.assertEqual(len(runner.calls), 2)

    def test_invalid_submit_json_or_id_is_fatal(self):
        (self.root / "fixture.pkg").write_bytes(b"fake package")
        for output in ["network error", "[]", '{"status": "Accepted"}']:
            with self.subTest(output=output):
                runner = FakeRunner([result(stdout=output)])
                with self.assertRaises(release.ReleaseError):
                    release.notarize_package(
                        runner, self.root / "fixture.pkg", self.root, "arm64", "fake",
                        self.root / "keychain",
                    )

    def test_package_signer_and_trust_are_checked(self):
        for text in ["Status: no signature", signature(OTHER_TEAM)]:
            with self.assertRaises(release.ReleaseError):
                release.verify_package(FakeRunner([result(stdout=text)]), Path("fake.pkg"), TEAM)


class FakeBuildRunner:
    """Emulate only the release subprocess contract; never sign, upload, or install."""

    def __init__(self):
        self.calls = []
        self.submitted_package = None

    def __call__(self, args, *, capture=True):
        args = [str(arg) for arg in args]
        self.calls.append((args, capture))
        tool = Path(args[0]).name
        if tool == "make":
            build_root = Path(next(arg.split("=", 1)[1] for arg in args if arg.startswith("BUILD_ROOT=")))
            for architecture in release.ARCHITECTURES:
                directory = build_root / architecture
                directory.mkdir(parents=True)
                for name in ("pam_watchid.so", "pam_watchid-helper"):
                    (directory / name).write_bytes(b"fake native code")
        elif tool == "lipo":
            return result(stdout=next(arch for arch in release.ARCHITECTURES if arch in Path(args[-1]).parts))
        elif tool == "chmod":
            assert args[1] == "-RN"
            return result()
        elif tool == "codesign" and "--verbose=4" in args:
            kind = "helper" if args[-1].endswith("pam_watchid-helper") else "module"
            return result(stderr=(
                f"Identifier={release.RECEIPT}.{kind}\n"
                f"TeamIdentifier={TEAM}\nAuthority={APPLICATION.name}\n"
                "CodeDirectory v=20500 flags=0x10000(runtime)\n"
            ))
        elif tool == "codesign":
            return result()
        elif tool == "pkgbuild":
            Path(args[-1]).write_bytes(b"fake signed package BEFORE stapling")
        elif tool == "pkgutil":
            return result(stdout=signature())
        elif args[1:3] == ["notarytool", "submit"]:
            self.submitted_package = Path(args[3])
            return result(stdout=json.dumps({"id": SUBMISSION, "status": "Accepted"}))
        elif args[1:3] == ["notarytool", "log"]:
            return result(stdout=json.dumps({
                "jobId": SUBMISSION, "status": "Accepted",
                "archiveFilename": self.submitted_package.name,
                "sha256": release.sha256(self.submitted_package),
            }))
        elif args[1:3] == ["stapler", "staple"]:
            with Path(args[-1]).open("ab") as stream:
                stream.write(b" FAKE STAPLED TICKET")
        elif args[1:3] == ["stapler", "validate"]:
            return result()
        else:
            raise AssertionError(f"Unexpected command: {args}")
        return result()


class ReleaseFlowTests(ProjectFixture):
    def test_default_release_layout_is_dist_version(self):
        args = release.parser().parse_args(["release", "--version", "1.2.3"])
        self.assertEqual(args.output_root, PROJECT / "dist")
        self.assertEqual(args.output_root / args.version / "manifest.json",
                         PROJECT / "dist/1.2.3/manifest.json")

    def test_both_architectures_are_rebuilt_signed_and_hashed_after_stapling(self):
        runner = FakeBuildRunner()
        output = self.root / "1.2.3"
        output.mkdir()
        with contextlib.redirect_stdout(io.StringIO()):
            manifest = release.release(
                argparse.Namespace(version="1.2.3"), runner, APPLICATION, INSTALLER,
                self.root / "fake.keychain-db", "fake-profile", output,
            )
        self.assertEqual(len(manifest["artifacts"]), 2)
        build = runner.calls[0][0]
        self.assertEqual(build[:3], ["/usr/bin/make", "build-all", "check-artifacts"])
        self.assertIn(f"BUILD_ROOT={output}/work/build", build)
        self.assertIn(f"TEAM_ID={TEAM}", build)
        for artifact in manifest["artifacts"]:
            package = output / artifact["filename"]
            self.assertTrue(package.read_bytes().endswith(b" FAKE STAPLED TICKET"))
            self.assertEqual(artifact["sha256"], release.sha256(package))
            self.assertTrue(artifact["stapled"])
            self.assertEqual(artifact["notarization"]["status"], "Accepted")
            self.assertFalse((output / "work" / artifact["architecture"] / "scripts/postinstall").exists())
            root = output / "work" / artifact["architecture"] / "root"
            for directory in [root, *[path for path in root.rglob("*") if path.is_dir()]]:
                self.assertEqual(directory.stat().st_mode & 0o7777, 0o755)
            self.assertIn((["/bin/chmod", "-RN", str(root)], True), runner.calls)
        signing = [args for args, _ in runner.calls if "--sign" in args]
        self.assertEqual(len(signing), 6)
        for args in signing:
            self.assertIn("--timestamp", args)
            self.assertIn("--keychain", args)
            self.assertNotIn("--entitlements", args)
            if args[0].endswith("pkgbuild"):
                self.assertIn(INSTALLER.fingerprint, args)
                self.assertIn("recommended", args)
            else:
                self.assertIn(APPLICATION.fingerprint, args)
                self.assertEqual("--options" in args, args[-1].endswith("pam_watchid-helper"))
        self.assertEqual(
            json.loads((output / "manifest.json").read_text(encoding="utf-8")), manifest,
        )

    def test_existing_version_fails_before_keychain_or_credentials(self):
        (self.root / "1.2.3").mkdir()
        with mock.patch.object(sys, "platform", "darwin"), \
                mock.patch.object(release, "choose_keychain") as choose, \
                contextlib.redirect_stderr(io.StringIO()) as errors:
            code = release.main([
                "release", "--version", "1.2.3", "--output-root", str(self.root),
            ])
        self.assertEqual(code, 1)
        choose.assert_not_called()
        self.assertIn("already exists", errors.getvalue())

    def test_profile_is_validated_once_before_building(self):
        keychain = self.keychain()
        identities = (
            f'1) {APPLICATION.fingerprint} "{APPLICATION.name}"\n'
            f'2) {INSTALLER.fingerprint} "{INSTALLER.name}"\n'
        )
        runner = FakeRunner([result(stdout=identities)])
        calls = []
        with mock.patch.object(sys, "platform", "darwin"), \
                mock.patch.object(release, "Runner", return_value=runner), \
                mock.patch.object(release, "choose_keychain", return_value=keychain), \
                mock.patch.object(release, "ensure_profile",
                                  side_effect=lambda *_: calls.append("profile") or "profile"), \
                mock.patch.object(release, "release",
                                  side_effect=lambda *_: calls.append("build")):
            code = release.main([
                "release", "--version", "1.2.3", "--output-root", str(self.root),
            ])
        self.assertEqual(code, 0)
        self.assertEqual(calls, ["profile", "build"])

    def test_missing_failed_or_cancelled_credentials_do_not_reserve_version(self):
        identities = (
            f'1) {APPLICATION.fingerprint} "{APPLICATION.name}"\n'
            f'2) {INSTALLER.fingerprint} "{INSTALLER.name}"\n'
        )
        for error in [
            release.ReleaseError("Missing profile. Run make notary-profile."),
            release.ReleaseError("Credential validation failed."),
            EOFError(), KeyboardInterrupt(),
        ]:
            with self.subTest(error=type(error).__name__):
                runner = FakeRunner([result(stdout=identities)])
                with mock.patch.object(sys, "platform", "darwin"), \
                        mock.patch.object(release, "Runner", return_value=runner), \
                        mock.patch.object(release, "choose_keychain", return_value=self.root / "fake"), \
                        mock.patch.object(release, "ensure_profile", side_effect=error), \
                        mock.patch.object(release, "release") as build, \
                        contextlib.redirect_stderr(io.StringIO()):
                    code = release.main([
                        "release", "--version", "1.2.3", "--output-root", str(self.root),
                    ])
                self.assertEqual(code, 1)
                self.assertFalse((self.root / "1.2.3").exists())
                build.assert_not_called()

    def test_racing_version_creation_is_rejected_after_profile_validation(self):
        identities = (
            f'1) {APPLICATION.fingerprint} "{APPLICATION.name}"\n'
            f'2) {INSTALLER.fingerprint} "{INSTALLER.name}"\n'
        )

        def racing_profile(*_):
            (self.root / "1.2.3").mkdir()
            return "profile"

        with mock.patch.object(sys, "platform", "darwin"), \
                mock.patch.object(release, "Runner",
                                  return_value=FakeRunner([result(stdout=identities)])), \
                mock.patch.object(release, "choose_keychain", return_value=self.root / "fake"), \
                mock.patch.object(release, "ensure_profile", side_effect=racing_profile), \
                mock.patch.object(release, "release") as build, \
                contextlib.redirect_stderr(io.StringIO()) as errors:
            code = release.main([
                "release", "--version", "1.2.3", "--output-root", str(self.root),
            ])
        self.assertEqual(code, 1)
        self.assertIn("already exists", errors.getvalue())
        build.assert_not_called()

    def test_invalid_versions_cannot_escape_output_directory(self):
        for version in ["", "../1.0", "v1.0", "1.0;echo", "1.0\n", "1.0-beta", "1"]:
            with self.subTest(version=version):
                with self.assertRaises(release.ReleaseError):
                    release.validate_version(version)

    def test_helper_entitlements_are_rejected(self):
        details = (
            f"Identifier={release.RECEIPT}.helper\nTeamIdentifier={TEAM}\n"
            f"Authority={APPLICATION.name}\nflags=0x10000(runtime)\n"
        )
        import plistlib
        for entitlements in [{"com.apple.security.get-task-allow": True}, {}]:
            with self.subTest(entitlements=entitlements):
                runner = FakeRunner([
                    result(), result(), result(stderr=details),
                    result(stdout=plistlib.dumps(entitlements).decode()),
                ])
                with self.assertRaisesRegex(release.ReleaseError, "must not contain entitlements"):
                    release.sign_binary(runner, Path("fake-helper"), APPLICATION, Path("fake"), "helper")


class CaskTests(ProjectFixture):
    def manifest(self):
        output = self.root / "1.2.3"
        output.mkdir()
        with contextlib.redirect_stdout(io.StringIO()):
            release.release(
                argparse.Namespace(version="1.2.3"), FakeBuildRunner(), APPLICATION,
                INSTALLER, self.root / "fake.keychain-db", "fake-profile", output,
            )
        return output / "manifest.json"

    def verification_runner(self):
        return FakeRunner([result(), result(stdout=signature()),
                           result(), result(stdout=signature())])

    def test_cask_hashes_urls_native_architecture_and_script_only_uninstall(self):
        manifest = self.manifest()
        output = self.root / "pam-watchid.rb"
        runner = self.verification_runner()
        text = generate_cask.generate(manifest, output, runner)
        self.assertEqual(len(runner.calls), 4)
        self.assertIn("Hardware::CPU.physical_cpu_arm64?", text)
        self.assertNotIn("Hardware::CPU.arm?", text)
        self.assertIn('version "1.2.3"', text)
        self.assertIn("/releases/download/v#{version}/pam-watchid-#{version}-#{native_arch}.pkg", text)
        self.assertNotIn("pkgutil:", text)
        self.assertNotIn("delete:", text)
        self.assertIn("must_succeed: true", text)
        self.assertIn("supported_macos = [:sequoia, :tahoe]", text)
        self.assertIn("depends_on macos: supported_macos", text)
        self.assertNotIn("preflight do", text)
        for artifact in json.loads(manifest.read_text())["artifacts"]:
            self.assertIn(artifact["sha256"], text)
        ruby = shutil.which("ruby")
        if ruby:
            subprocess.run([ruby, "-c", str(output)], check=True, capture_output=True)

    def test_ruby_cask_selects_physical_cpu_and_enforces_the_exact_os_matrix(self):
        ruby = shutil.which("ruby")
        if not ruby:
            self.skipTest("Ruby is not available for the cask behavioral test.")
        manifest = self.manifest()
        output = self.root / "pam-watchid.rb"
        generate_cask.generate(manifest, output, self.verification_runner())
        harness = self.root / "cask-fixture.rb"
        harness.write_text(r'''
require "json"
module Hardware
  module CPU
    def self.physical_cpu_arm64?
      ENV.fetch("FIXTURE_PHYSICAL_ARM") == "1"
    end
  end
end
module MacOS
  def self.version
    ENV.fetch("FIXTURE_MACOS")
  end
end
class FixtureCask
  attr_reader :values
  def initialize
    @values = {}
  end
  def method_missing(name, *arguments)
    return @values[name] if arguments.empty?
    @values[name] = arguments.first
  end
  def validate
    versions = { sequoia: 15, tahoe: 26, golden_gate: 27 }
    supported = @values.fetch(:depends_on).fetch(:macos).map { |name| versions.fetch(name) }
    raise "Unsupported macOS" unless supported.include?(MacOS.version.to_i)
  end
end
def cask(_name, &block)
  fixture = FixtureCask.new
  fixture.instance_eval(&block)
  fixture.validate
  puts JSON.generate(fixture.values)
end
load ARGV.fetch(0)
''')
        data = json.loads(manifest.read_text())
        hashes = {item["architecture"]: item["sha256"] for item in data["artifacts"]}
        for physical_arm in ("0", "1"):
            for major in (14, 15, 16, 26, 27, 28):
                expected = major in (15, 26) or (major == 27 and physical_arm == "1")
                with self.subTest(arm=physical_arm, major=major):
                    env = dict(os.environ, FIXTURE_PHYSICAL_ARM=physical_arm,
                               FIXTURE_MACOS=f"{major}.0")
                    process = subprocess.run(
                        [ruby, str(harness), str(output)], env=env, text=True,
                        capture_output=True,
                    )
                    self.assertEqual(process.returncode == 0, expected, process.stderr)
                    if expected:
                        values = json.loads(process.stdout)
                        architecture = "arm64" if physical_arm == "1" else "x86_64"
                        self.assertEqual(values["sha256"], hashes[architecture])
                        self.assertTrue(values["url"].endswith(f"-{architecture}.pkg"))
                        self.assertTrue(values["uninstall"]["script"]["must_succeed"])

    def test_manifest_mutation_or_placeholder_prevents_output(self):
        path = self.manifest()
        original = json.loads(path.read_text())
        mutations = [
            ("sha256", "0" * 64), ("sha256", ":no_check"),
            ("stapled", False), ("signature_verified", False),
            ("filename", "../outside.pkg"), ("architecture", "other"),
            ("notarization", {"status": "Invalid"}),
        ]
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                data = json.loads(json.dumps(original))
                data["artifacts"][0][key] = value
                path.write_text(json.dumps(data))
                output = self.root / "must-not-exist.rb"
                with self.assertRaises(release.ReleaseError):
                    generate_cask.generate(path, output, self.verification_runner())
                self.assertFalse(output.exists())

    def test_cask_requires_stapler_and_signature_verification_not_just_manifest_flags(self):
        path = self.manifest()
        for runner in [
            FakeRunner([result(1, stderr="Ticket missing")]),
            FakeRunner([result(), result(stdout=signature(OTHER_TEAM))]),
        ]:
            with self.assertRaises(release.ReleaseError):
                generate_cask.generate(path, self.root / "must-not-exist.rb", runner)
        self.assertFalse((self.root / "must-not-exist.rb").exists())

    def test_tampered_metadata_and_duplicate_architectures_are_rejected(self):
        path = self.manifest()
        data = json.loads(path.read_text())
        log = path.parent / data["artifacts"][0]["notarization"]["log"]
        log.write_text(json.dumps({"jobId": SUBMISSION, "status": "Invalid"}))
        with self.assertRaises(release.ReleaseError):
            generate_cask.validate_manifest(path, FakeRunner())
        data["artifacts"] = [data["artifacts"][1], data["artifacts"][1]]
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(release.ReleaseError, "Duplicate"):
            generate_cask.validate_manifest(
                path, FakeRunner([result(), result(stdout=signature())]),
            )

    def test_generator_cannot_overwrite_immutable_release_files(self):
        path = self.manifest()
        before = path.read_bytes()
        with self.assertRaisesRegex(release.ReleaseError, "immutable release"):
            generate_cask.generate(path, path, FakeRunner())
        self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
