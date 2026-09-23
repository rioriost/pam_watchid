#!/usr/bin/env python3
"""Generate the existing rioriost/homebrew-cask cask from verified local assets."""

import argparse
from pathlib import Path
import re
import sys

from release import (
    ARCHITECTURES, INSTALL_PATH, PROJECT, RECEIPT, ReleaseError, Runner, checked,
    parse_json_object, sha256, submission_id, validate_team, validate_version,
    verify_package,
)


def local_file(directory, filename):
    if not isinstance(filename, str) or Path(filename).name != filename:
        raise ReleaseError("Manifest paths must be plain filenames beside the manifest.")
    path = directory / filename
    if path.is_symlink() or not path.is_file():
        raise ReleaseError(f"Missing or unsafe release artifact: {filename}")
    return path


def validate_manifest(path, runner):
    manifest = parse_json_object(path.read_text(encoding="utf-8"), "Manifest")
    if manifest.get("schema_version") != 1:
        raise ReleaseError("Unsupported release manifest schema.")
    version = validate_version(manifest.get("version"))
    team = validate_team(manifest.get("team_id"))
    if manifest.get("receipt") != RECEIPT or manifest.get("install_path") != INSTALL_PATH:
        raise ReleaseError("Manifest is not for the fixed pam_watchid installation.")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != 2:
        raise ReleaseError("Manifest must contain exactly two native package artifacts.")
    hashes = {}
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise ReleaseError("Invalid artifact entry.")
        architecture = artifact.get("architecture")
        if architecture not in ARCHITECTURES or architecture in hashes:
            raise ReleaseError("Duplicate or unsupported package architecture.")
        if artifact.get("filename") != f"pam-watchid-{version}-{architecture}.pkg":
            raise ReleaseError("Unexpected versioned package filename.")
        package = local_file(path.parent, artifact["filename"])
        digest = artifact.get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ReleaseError("Manifest contains an invalid SHA-256 checksum.")
        if sha256(package) != digest:
            raise ReleaseError("Final package bytes do not match the release checksum.")
        if artifact.get("stapled") is not True or artifact.get("signature_verified") is not True:
            raise ReleaseError("Manifest does not confirm stapling and signature verification.")
        notary = artifact.get("notarization")
        if not isinstance(notary, dict) or notary.get("status") != "Accepted":
            raise ReleaseError("Manifest does not contain Accepted notarization.")
        identifier = submission_id(notary.get("id"))
        submitted_sha256 = notary.get("submitted_sha256")
        if not isinstance(submitted_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", submitted_sha256):
            raise ReleaseError("Missing checksum of the submitted, pre-stapling package.")
        submission = parse_json_object(
            local_file(path.parent, notary.get("submission")).read_text(encoding="utf-8"),
            "Submission metadata",
        )
        log = parse_json_object(
            local_file(path.parent, notary.get("log")).read_text(encoding="utf-8"), "Notary log",
        )
        if (submission.get("id") != identifier or submission.get("status") != "Accepted"
                or submission.get("returncode") != 0 or log.get("jobId") != identifier
                or log.get("status") != "Accepted"
                or submission.get("filename") != package.name
                or log.get("archiveFilename") != package.name
                or submission.get("submitted_sha256") != submitted_sha256
                or log.get("sha256") != submitted_sha256):
            raise ReleaseError("Submission metadata/log do not confirm the Accepted submission.")
        checked(runner, ["/usr/bin/xcrun", "stapler", "validate", str(package)])
        verify_package(runner, package, team)
        hashes[architecture] = digest
    return version, hashes


def generate(manifest_path, output, runner):
    if output.resolve().is_relative_to(manifest_path.resolve().parent):
        raise ReleaseError("Cask output must be outside the immutable release directory.")
    version, hashes = validate_manifest(manifest_path, runner)
    text = (PROJECT / "packaging/pam-watchid.rb.in").read_text(encoding="utf-8")
    for key, value in {
        "@VERSION@": version, "@ARM64_SHA256@": hashes["arm64"],
        "@X86_64_SHA256@": hashes["x86_64"],
    }.items():
        text = text.replace(key, value)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.is_symlink():
        raise ReleaseError("Refusing to overwrite a cask output symlink.")
    output.write_text(text, encoding="utf-8")
    return text


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", type=Path, default=PROJECT / "build/pam-watchid.rb")
    args = parser.parse_args(argv)
    try:
        generate(args.manifest, args.output, Runner())
    except (ReleaseError, OSError, ValueError) as error:
        print(f"generate_cask: {error}", file=sys.stderr)
        return 1
    print(f"Generated {args.output}; no GitHub release or Homebrew cask was published.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
