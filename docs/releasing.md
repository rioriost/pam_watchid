# Building and releasing

The [English](../README.md) and [Japanese](../README.ja.md) READMEs cover end-user
installation. This document is for maintainers. Do not install a development
build into a live PAM configuration.

## Local checks

Use a Mac with an Xcode toolchain containing the macOS 15 SDK or later, Python 3,
and Apple's signing, packaging, and notarization tools.

```sh
make build
make build-all
make check
```

`build` detects the physical CPU, including when invoked from a Rosetta shell.
Override it with `ARCH=arm64` or `ARCH=x86_64` to cross-compile. `build-all`
creates separate binaries in `build/arm64/` and `build/x86_64/`.
Both have a deployment target of macOS 15. The native unit tests run only on the
current machine; cross-compiling does not validate another OS or CPU at runtime.

Checks must never install PAM files, edit `/etc/pam.d`, request real
authentication, submit notarization requests, or prompt for credentials.
Development builds use an empty signing Team ID and cannot authenticate
through a privileged installation.

## Signing identities and Keychain profile

Install a **Developer ID Application** certificate and a **Developer ID
Installer** certificate, with their private keys, in an accessible, unlocked
Keychain. Both must belong to the same Apple Developer team.

The release tooling selects a unique matching pair. If more than one team
qualifies, specify `TEAM_ID`. If a team has multiple eligible certificates of
the same kind, specify the desired SHA-1 certificate fingerprints using
`APPLICATION_IDENTITY` and `INSTALLER_IDENTITY`. These are certificate
identifiers, not credentials. Ambiguity is an error, not a reason to pick the
first result.

The default notarization profile is:

```text
pam_watchid.notary.<TEAM_ID>
```

The same selected Keychain is used for profile lookup, storage, and notarization.
Set `KEYCHAIN=/absolute/path/to/keychain-db` to select a different existing
Keychain. Unlock it yourself before starting; the scripts do not unlock it.

To prepare or verify the profile:

```sh
make notary-profile
```

This step also happens automatically at the start of `make release`.
Only a confirmed **missing profile** triggers interactive setup:

1. The script asks for your Apple ID on the local terminal.
2. Apple's `notarytool` securely prompts for the app-specific password that you
   created on the Apple Account website.
3. Apple validates the credentials and stores them in Keychain.

The password is not passed in a command argument or environment variable and
must not be added to a Makefile, `.env` file, GitHub issue, or chat. Existing
invalid credentials, a locked Keychain, access denial, and network errors stop
the process instead of overwriting the profile. Noninteractive builds with a
missing profile stop with instructions to run `make notary-profile` locally.

## Build a release

Choose an unused version with two to four numeric components (normally
`major.minor.patch`, without a `v` prefix) and work from a reviewed, committed tree:

```sh
make check
make release VERSION=0.2.0
```

When necessary:

```sh
make release VERSION=0.2.0 TEAM_ID=ABCDEFGHIJ \
  APPLICATION_IDENTITY=APPLICATION_CERTIFICATE_SHA1 \
  INSTALLER_IDENTITY=INSTALLER_CERTIFICATE_SHA1
```

Release builds rebuild both architectures with the selected Team ID embedded
in the module. The helper has its own exact signing identifier, Hardened
Runtime, and no entitlements. The pipeline signs the binaries and flat
installer packages, submits each package, requires notarization acceptance,
staples and validates the tickets, verifies package signatures, then records
the final SHA-256 hashes and submission metadata.

After codesigning the payload, the pipeline embeds the final module and helper
hashes in the package's postinstall script. Postinstall verifies the installed
pair before changing PAM. Do not render those hashes before codesigning.
Preinstall, postinstall, and the installed uninstaller embed the same
`packaging/pam-config.sh` implementation; the package never ships a replacement
`sudo` or `sudo_local` as payload.

Never upload a pre-stapling package or derive a checksum before stapling.
Do not reuse an already published version or replace assets under an existing
release tag. Inspect any failed release output before cleaning only that
specific version's generated files.

Outputs are reserved under `dist/<version>/` after credential validation.
A completed release
contains `manifest.json`, both native packages, notarization submission/log
files, package-signature reports, and a `work/` directory with build and staging
files. A failed build remains available for inspection; rerunning the same
version refuses to overwrite it. Failed or cancelled credential setup does not
reserve the version, so it can be retried without removing generated files.

## Automatic PAM configuration and interrupted installation

Preinstall verifies the supported PAM stack and records a pending transaction
under `/private/var/db/pam_watchid/`. It removes an existing installer-managed
entry before package payload replacement. Postinstall verifies the final
signed payload hashes, writes a byte-preserving backup in a unique
`backup.<UUID>/` directory, and atomically prepends the managed block:

```text
# pam_watchid: begin managed
auth sufficient /Library/Security/pam_watchid/pam_watchid.so
# pam_watchid: end managed
```

The `activation` state records whether `sudo_local` originally existed.
`pending/` records the version/architecture token and the prepared state.
`lock/` serializes complete operations, including uninstall through payload
and receipt removal. Each actual configuration change retains its own backup;
neither update nor uninstall deletes previous backups.

Removal strips only the exact prefix and preserves the remaining bytes,
including a missing final newline. The manager preserves macOS-generated
`com.apple.macl` and `com.apple.provenance` extended attributes and checks for
concurrent changes to their values; files edited with the system sudo editor
can legitimately carry these attributes. Other extended attributes and
extended ACLs on files that must be replaced are refused rather than lost.
If the installer created `sudo_local` and no other contents remain, removal
restores absence; an originally empty file remains a file. Unsupported metadata,
customized mandatory authentication gates, unowned references, moved/edited
markers, or concurrent changes are errors, not reasons to overwrite settings.

After a failed installation, **first make sure the installer is no longer
running**. If the pending prepared configuration is unchanged and contains no
module references, the new installed uninstaller can cancel that transaction:

```sh
sudo /Library/Security/pam_watchid/uninstall.sh --cancel-install
```

Then rerun the package installation. This command deliberately refuses an
active or modified pending configuration. If the failure occurred before the
new uninstaller was installed, use only a trusted rendered uninstaller from
the same signed release, not a legacy 0.1.1 script or an ad-hoc replacement.
A matching postinstall can finalize an interruption after activation if the
configuration and payload still exactly match its recorded transaction.

The `--disable` option removes an intact managed block without deleting payload
or backups. It refuses pending installations. A stale `lock/` after an abrupt
process kill requires administrator inspection; scripts do not guess from a
PID or silently delete another operation's lock. Do not blindly restore a
backup over newer settings or re-enable a reference to missing files.

## Hardware release gates

Automated checks do not establish that a privileged sudo process and a
credential-dropped helper are correctly bound to the intended graphical
session on every target OS. Before a stable release, explicitly approve and
perform runtime verification on the supported hardware/OS combinations:

- Touch ID with no available Watch; Watch with no available Touch ID.
- Denial, cancellation, unavailable devices, timeouts, and password fallback.
- Incorrect PAM user, fast user switching, locked desktop, SSH, askpass,
  `sudo -n`, detached terminal sessions, concurrent requests, and parent death.
- Native and Rosetta-running Homebrew installation; native sudo loading.
- Automatic activation and backup, managed upgrade and removal, interrupted
  installation recovery, and preservation of later administrator edits.

Use disposable test installations or a recovery-capable test Mac. Do not
disable Gatekeeper, SIP, signature validation, or helper trust checks.
macOS 27 has no supported Intel hardware. Translated sudo is outside the
native-package support contract.

Keep the release-status notices in both READMEs accurate. Do not replace
"targeted" with a verified-support claim based on compilation alone.

## Publish with Homebrew

Generate the cask from the completed release manifest, not from handwritten
checksums:

```sh
make cask MANIFEST=dist/0.2.0/manifest.json
```

The generated file is `build/pam-watchid.rb`. It chooses the native package
using Homebrew's physical CPU detection, including under Rosetta.

Publish both `pam-watchid-<version>-arm64.pkg` and
`pam-watchid-<version>-x86_64.pkg`, the manifest, and every submission,
notarization-log, and package-signature file referenced by it in an immutable
`v<version>` GitHub release in `rioriost/pam_watchid`. Upload to a draft first,
download the uploaded assets, and regenerate the cask from that downloaded
manifest before making the release public. Publish the cask only after the
public package URLs work and match the manifest.

The initial 0.1.1 release is explicitly a prerelease: basic authentication was
checked on one Apple silicon Mac running macOS 27, not the complete runtime
matrix. Keep that distinction in release notes until the outstanding gates
have been completed.

Commit the generated cask to:

```text
rioriost/homebrew-cask: Casks/pam-watchid.rb
```

Use the existing `rioriost/homebrew-cask` repository; do not create a new tap.
The owner's `rioriost/homebrew-tap` remains the formula tap. This project uses
a cask rather than a duplicate source formula so installed privileged files
are the signed, notarized release artifacts and are not left in a user-writable
Homebrew prefix.

The user-facing command is:

```sh
brew install --cask rioriost/cask/pam-watchid
```

Publish neither a placeholder cask nor a cask that references unavailable
assets. Version 0.2.0 and later automatically configure PAM on installation;
0.1.1 remains a manual-activation package. The manifest's `pam_configuration`
field controls the generated cask's caveats so old assets retain correct
instructions.
