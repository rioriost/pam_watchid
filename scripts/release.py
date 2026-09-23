#!/usr/bin/env python3
"""Build immutable, signed and notarized release packages using Apple's tools."""

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
import uuid


PROJECT = Path(__file__).resolve().parents[1]
ARCHITECTURES = ("arm64", "x86_64")
INSTALL_PATH = "/Library/Security/pam_watchid"
RECEIPT = "io.github.rioriost.pam-watchid"
VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}")
TEAM_RE = re.compile(r"[A-Z0-9]{10}")
IDENTITY_RE = re.compile(
    r'^\s*\d+\)\s+([0-9A-Fa-f]{40})\s+"'
    r'(Developer ID (Application|Installer): .+ \(([A-Z0-9]{10})\))"\s*$'
)


class ReleaseError(RuntimeError):
    pass


class Runner:
    def __call__(self, args, *, capture=True):
        return subprocess.run(
            [str(arg) for arg in args],
            cwd=PROJECT,
            text=True,
            capture_output=capture,
            check=False,
        )


def checked(runner, args, *, capture=True):
    result = runner(args, capture=capture)
    if result.returncode:
        detail = (result.stderr or result.stdout or "").strip() if capture else ""
        raise ReleaseError(
            f"{Path(str(args[0])).name} failed ({result.returncode})"
            + (f": {detail}" if detail else "")
        )
    return result


def validate_version(version):
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise ReleaseError("Version must have 2–4 numeric components, for example 1.2.0.")
    return version


def validate_team(team):
    if not isinstance(team, str) or not TEAM_RE.fullmatch(team):
        raise ReleaseError("Team ID must contain exactly 10 uppercase letters or digits.")
    return team


@dataclass(frozen=True)
class Identity:
    fingerprint: str
    name: str
    kind: str
    team: str


def parse_identities(output):
    identities = set()
    for line in output.splitlines():
        match = IDENTITY_RE.fullmatch(line)
        if match:
            fingerprint, name, kind, team = match.groups()
            identities.add(Identity(fingerprint.upper(), name, kind, team))
    return sorted(identities, key=lambda item: (item.team, item.kind, item.fingerprint))


def select_identities(identities, team="", application="", installer=""):
    if team:
        validate_team(team)

    def candidates(kind, selector):
        result = [item for item in identities if item.kind == kind and
                  (not team or item.team == team)]
        if selector:
            result = [item for item in result if item.name == selector or
                      item.fingerprint == selector.upper()]
        return result

    apps = candidates("Application", application)
    installers = candidates("Installer", installer)
    teams = {item.team for item in apps} & {item.team for item in installers}
    if not teams:
        raise ReleaseError("No matching Developer ID Application/Installer pair in this Keychain.")
    if len(teams) != 1:
        raise ReleaseError("Multiple signing teams match; set TEAM_ID explicitly.")
    selected_team = teams.pop()
    apps = [item for item in apps if item.team == selected_team]
    installers = [item for item in installers if item.team == selected_team]
    if len(apps) != 1 or len(installers) != 1:
        raise ReleaseError(
            "Multiple identities match this team; set APPLICATION_IDENTITY and "
            "INSTALLER_IDENTITY to the required certificate SHA-1 fingerprints."
        )
    return apps[0], installers[0]


def keychain_status(path):
    """Read public Security.framework status without reading credentials or unlock UI."""
    security = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
    core = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    security.SecKeychainSetUserInteractionAllowed.argtypes = [ctypes.c_ubyte]
    security.SecKeychainSetUserInteractionAllowed.restype = ctypes.c_int32
    security.SecKeychainGetUserInteractionAllowed.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
    security.SecKeychainGetUserInteractionAllowed.restype = ctypes.c_int32
    security.SecKeychainOpen.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
    security.SecKeychainOpen.restype = ctypes.c_int32
    security.SecKeychainGetStatus.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    security.SecKeychainGetStatus.restype = ctypes.c_int32
    core.CFRelease.argtypes = [ctypes.c_void_p]
    core.CFRelease.restype = None
    previous = ctypes.c_ubyte()
    if security.SecKeychainGetUserInteractionAllowed(ctypes.byref(previous)):
        raise ReleaseError("Cannot query Keychain interaction policy.")
    if security.SecKeychainSetUserInteractionAllowed(False):
        raise ReleaseError("Cannot disable Keychain interaction for preflight.")
    reference = ctypes.c_void_p()
    try:
        status = security.SecKeychainOpen(os.fsencode(path), ctypes.byref(reference))
        if status:
            raise ReleaseError(f"Cannot open selected Keychain (Security status {status}).")
        flags = ctypes.c_uint32()
        status = security.SecKeychainGetStatus(reference, ctypes.byref(flags))
        if status:
            raise ReleaseError(f"Cannot read Keychain status (Security status {status}).")
        return flags.value
    finally:
        if reference:
            core.CFRelease(reference)
        security.SecKeychainSetUserInteractionAllowed(previous.value)


def preflight_keychain(path, status_reader=keychain_status):
    if not path.is_file() or not os.access(path, os.R_OK):
        raise ReleaseError("Selected Keychain is absent or not readable.")
    flags = status_reader(path)
    if not flags & 1:  # kSecUnlockStateStatus
        raise ReleaseError("Selected Keychain is locked; unlock it locally, then retry.")
    if not flags & 2:  # kSecReadPermStatus
        raise ReleaseError("Selected Keychain access is denied.")


def choose_keychain(runner, requested="", status_reader=keychain_status):
    if requested:
        path = Path(requested).expanduser().absolute()
    else:
        result = checked(runner, ["/usr/bin/security", "default-keychain", "-d", "user"])
        try:
            paths = shlex.split(result.stdout.strip())
        except ValueError as error:
            raise ReleaseError("Cannot parse the user default Keychain.") from error
        if len(paths) != 1 or not Path(paths[0]).is_absolute():
            raise ReleaseError("No unique explicit user default Keychain; set KEYCHAIN.")
        path = Path(paths[0])
    preflight_keychain(path, status_reader)
    return path


def missing_profile_diagnostic(profile):
    return (
        f"Error: No Keychain password item found for profile: {profile}\n\n"
        "Run 'notarytool store-credentials' to create another credential profile."
    )


def profile_is_missing(result, profile):
    diagnostic = "\n".join(
        value.strip() for value in (result.stdout, result.stderr) if value and value.strip()
    )
    expected = missing_profile_diagnostic(profile)
    supported = {expected, expected.replace("\n\n", "\n")}
    return result.returncode != 0 and diagnostic in supported


def interactive_terminal():
    return (
        not os.environ.get("CI")
        and sys.stdin.isatty()
        and sys.stdout.isatty()
        and sys.stderr.isatty()
    )


def ensure_profile(runner, keychain, team, *, interactive=None, read_apple_id=input,
                   preflight=preflight_keychain):
    profile = f"pam_watchid.notary.{validate_team(team)}"
    history = [
        "/usr/bin/xcrun", "notarytool", "history", "--keychain-profile", profile,
        "--keychain", str(keychain), "--output-format", "json",
    ]
    preflight(keychain)
    result = runner(history)
    if result.returncode == 0:
        return profile
    if not profile_is_missing(result, profile):
        raise ReleaseError(
            "Notarization profile validation failed; existing credentials will not be "
            "overwritten. Resolve Keychain, credentials, network, or notarytool errors: "
            + (result.stderr or result.stdout or "unknown error").strip()
        )
    if interactive is None:
        interactive = interactive_terminal()
    if not interactive:
        raise ReleaseError(
            f"Missing profile {profile}. Run make notary-profile locally in a terminal "
            "with the same TEAM_ID and KEYCHAIN, then retry."
        )
    preflight(keychain)
    apple_id = read_apple_id("Apple ID for notarization: ").strip()
    if not apple_id or any(character.isspace() or ord(character) < 32 for character in apple_id):
        raise ReleaseError("A nonempty Apple ID without whitespace is required.")
    # Apple's native prompt owns the password; never capture it or supply --password.
    checked(runner, [
        "/usr/bin/xcrun", "notarytool", "store-credentials", profile,
        "--apple-id", apple_id, "--team-id", team, "--keychain", str(keychain),
        "--validate",
    ], capture=False)
    preflight(keychain)
    checked(runner, history)
    return profile


def write_json(path, data):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2, sort_keys=True)
        stream.write("\n")


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_json_object(text, description):
    try:
        value = json.loads(text)
    except (ValueError, TypeError) as error:
        raise ReleaseError(f"{description} did not return valid JSON.") from error
    if not isinstance(value, dict):
        raise ReleaseError(f"{description} did not return a JSON object.")
    return value


def submission_id(value):
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError
    except (ValueError, TypeError, AttributeError) as error:
        raise ReleaseError("Notarization response has no canonical submission UUID.") from error
    return value


def render_preinstall(architecture, project=PROJECT):
    if architecture not in ARCHITECTURES:
        raise ReleaseError("Unsupported package architecture.")
    template = (project / "packaging/preinstall.in").read_text(encoding="utf-8")
    guard = (project / "packaging/uninstall.sh").read_text(encoding="utf-8")
    return template.replace("@ARCH@", architecture).replace("@UNINSTALL_SCRIPT@", guard)


def stage_payload(work, build_root, architecture, project=PROJECT):
    root = work / "root"
    payload = root / INSTALL_PATH.lstrip("/")
    (payload / "libexec").mkdir(parents=True)
    files = [
        (build_root / architecture / "pam_watchid.so", payload / "pam_watchid.so", 0o755),
        (build_root / architecture / "pam_watchid-helper",
         payload / "libexec/pam_watchid-helper", 0o755),
        (project / "LICENSE", payload / "LICENSE", 0o644),
        (project / "packaging/uninstall.sh", payload / "uninstall.sh", 0o755),
    ]
    for source, destination, mode in files:
        if source.is_symlink() or not source.is_file():
            raise ReleaseError(f"Missing or unsafe payload source: {source}")
        shutil.copyfile(source, destination)
        destination.chmod(mode)
    for directory in [root, *[item for item in root.rglob("*") if item.is_dir()]]:
        directory.chmod(0o755)
    scripts = work / "scripts"
    scripts.mkdir()
    preinstall = scripts / "preinstall"
    preinstall.write_text(render_preinstall(architecture, project), encoding="utf-8")
    preinstall.chmod(0o755)
    return root, payload, scripts


def sign_binary(runner, path, identity, keychain, kind):
    identifier = f"{RECEIPT}.{kind}"
    command = [
        "/usr/bin/codesign", "--force", "--sign", identity.fingerprint,
        "--keychain", str(keychain), "--timestamp", "--identifier", identifier,
    ]
    if kind == "helper":
        command.extend(["--options", "runtime"])
    checked(runner, [*command, str(path)])
    checked(runner, ["/usr/bin/codesign", "--verify", "--strict", str(path)])
    result = checked(runner, ["/usr/bin/codesign", "--display", "--verbose=4", str(path)])
    details = (result.stdout or "") + (result.stderr or "")
    for field in [f"Identifier={identifier}", f"TeamIdentifier={identity.team}",
                  f"Authority={identity.name}"]:
        if field not in details.splitlines():
            raise ReleaseError(f"Signed {kind} has unexpected signing metadata: {field}")
    if kind == "helper" and not re.search(r"^.*flags=.*\bruntime\b", details, re.MULTILINE):
        raise ReleaseError("Helper signature does not enable Hardened Runtime.")
    entitlements = checked(runner, [
        "/usr/bin/codesign", "--display", "--entitlements", "-", str(path),
    ]).stdout.strip()
    if entitlements:
        raise ReleaseError("Release binaries must not contain entitlements, even an empty plist.")


def verify_package(runner, package, team, installer_name=None):
    result = checked(runner, ["/usr/sbin/pkgutil", "--check-signature", str(package)])
    text = result.stdout + result.stderr
    if "Status: signed by a developer certificate issued by Apple for distribution" not in text:
        raise ReleaseError("Package is not signed with a trusted Apple distribution certificate.")
    names = re.findall(r"^\s*1\.\s+(Developer ID Installer: .+ \(([A-Z0-9]{10})\))\s*$",
                       text, re.MULTILINE)
    if len(names) != 1 or names[0][1] != team or (
        installer_name and names[0][0] != installer_name
    ):
        raise ReleaseError("Package has the wrong Developer ID Installer signing team/identity.")
    return text


def notarize_package(runner, package, output, architecture, profile, keychain):
    auth = ["--keychain-profile", profile, "--keychain", str(keychain)]
    submitted_sha256 = sha256(package)
    result = runner([
        "/usr/bin/xcrun", "notarytool", "submit", str(package), *auth,
        "--wait", "--output-format", "json",
    ])
    data = parse_json_object(result.stdout, "notarytool submit")
    identifier = submission_id(data.get("id"))
    metadata = {"id": identifier, "status": data.get("status"),
                "returncode": result.returncode, "filename": package.name,
                "submitted_sha256": submitted_sha256}
    metadata_path = output / f"{architecture}-submission.json"
    write_json(metadata_path, metadata)
    log_result = checked(runner, [
        "/usr/bin/xcrun", "notarytool", "log", identifier, *auth,
    ])
    log = parse_json_object(log_result.stdout, "notarytool log")
    log_path = output / f"{architecture}-notary-log.json"
    write_json(log_path, log)
    if result.returncode or data.get("status") != "Accepted":
        raise ReleaseError(f"Notarization was not Accepted; inspect {metadata_path} and {log_path}.")
    if (log.get("jobId") != identifier or log.get("status") != "Accepted"
            or log.get("archiveFilename") != package.name
            or log.get("sha256") != submitted_sha256):
        raise ReleaseError("Notarization log does not confirm the Accepted submission.")
    checked(runner, ["/usr/bin/xcrun", "stapler", "staple", str(package)])
    checked(runner, ["/usr/bin/xcrun", "stapler", "validate", str(package)])
    return {"id": identifier, "status": "Accepted", "submitted_sha256": submitted_sha256,
            "submission": metadata_path.name, "log": log_path.name}


def release(args, runner, application, installer, keychain, profile, output):
    work = output / "work"
    work.mkdir()
    build_root = work / "build"
    checked(runner, [
        "/usr/bin/make", "build-all", "check-artifacts", f"BUILD_ROOT={build_root}",
        f"TEAM_ID={application.team}",
    ])
    artifacts = []
    for architecture in ARCHITECTURES:
        architecture_work = work / architecture
        root, payload, scripts = stage_payload(architecture_work, build_root, architecture)
        # Drop inherited ACLs from our private staging tree, not from source or installed files.
        checked(runner, ["/bin/chmod", "-RN", str(root)])
        for filename, kind in [
            ("pam_watchid.so", "module"), ("libexec/pam_watchid-helper", "helper"),
        ]:
            binary = payload / filename
            result = checked(runner, ["/usr/bin/lipo", "-archs", str(binary)])
            if result.stdout.strip() != architecture:
                raise ReleaseError(f"Unexpected architecture for {binary}.")
            sign_binary(runner, binary, application, keychain, kind)
        package = output / f"pam-watchid-{args.version}-{architecture}.pkg"
        checked(runner, [
            "/usr/bin/pkgbuild", "--root", str(root), "--scripts", str(scripts),
            "--identifier", RECEIPT, "--version", args.version,
            "--install-location", "/", "--ownership", "recommended",
            "--sign", installer.fingerprint, "--keychain", str(keychain),
            "--timestamp", str(package),
        ])
        verify_package(runner, package, application.team, installer.name)
        notary = notarize_package(
            runner, package, output, architecture, profile, keychain,
        )
        signature = verify_package(runner, package, application.team, installer.name)
        signature_path = output / f"{architecture}-package-signature.txt"
        with signature_path.open("x", encoding="utf-8") as stream:
            stream.write(signature)
        artifacts.append({
            "architecture": architecture, "filename": package.name,
            "sha256": sha256(package), "notarization": notary,
            "stapled": True, "signature_verified": True,
            "signature_log": signature_path.name,
        })
    manifest = {
        "schema_version": 1, "version": args.version, "team_id": application.team,
        "receipt": RECEIPT, "install_path": INSTALL_PATH,
        "application_identity": application.fingerprint,
        "installer_identity": installer.fingerprint,
        "artifacts": artifacts,
    }
    write_json(output / "manifest.json", manifest)
    print(f"Verified local release: {output / 'manifest.json'}")
    print("No assets were published. Upload only after all manual release gates pass.")
    return manifest


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    for command in ("release", "notary-profile"):
        subparser = commands.add_parser(command)
        for option in ("team-id", "keychain", "application-identity", "installer-identity"):
            subparser.add_argument("--" + option, default="")
        if command == "release":
            subparser.add_argument("--version", required=True)
            subparser.add_argument("--output-root", type=Path, default=PROJECT / "dist")
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if sys.platform != "darwin":
            raise ReleaseError("Release and Keychain tooling require macOS.")
        output = None
        if args.command == "release":
            validate_version(args.version)
            output = args.output_root.absolute() / args.version
            output_exists_message = (
                f"Release path already exists: {output}. Never overwrite release artifacts; "
                "inspect/archive an incomplete attempt or choose a new version."
            )
            if os.path.lexists(output):
                raise ReleaseError(output_exists_message)
        runner = Runner()
        keychain = choose_keychain(runner, args.keychain)
        result = checked(runner, [
            "/usr/bin/security", "find-identity", "-v", "-p", "basic", str(keychain),
        ])
        application, installer = select_identities(
            parse_identities(result.stdout), args.team_id,
            args.application_identity, args.installer_identity,
        )
        profile = ensure_profile(runner, keychain, application.team)
        if args.command == "notary-profile":
            print(f"Validated profile {profile} in the selected Keychain.")
        else:
            output.parent.mkdir(parents=True, exist_ok=True)
            try:
                output.mkdir()
            except FileExistsError as error:
                raise ReleaseError(output_exists_message) from error
            release(args, runner, application, installer, keychain, profile, output)
        return 0
    except (ReleaseError, OSError, EOFError, KeyboardInterrupt) as error:
        print(f"release: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
