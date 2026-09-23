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
make release VERSION=0.1.0
```

When necessary:

```sh
make release VERSION=0.1.0 TEAM_ID=ABCDEFGHIJ \
  APPLICATION_IDENTITY=APPLICATION_CERTIFICATE_SHA1 \
  INSTALLER_IDENTITY=INSTALLER_CERTIFICATE_SHA1
```

Release builds rebuild both architectures with the selected Team ID embedded
in the module. The helper has its own exact signing identifier, Hardened
Runtime, and no entitlements. The pipeline signs the binaries and flat
installer packages, submits each package, requires notarization acceptance,
staples and validates the tickets, verifies package signatures, then records
the final SHA-256 hashes and submission metadata.

Never upload a pre-stapling package or derive a checksum before stapling.
Do not reuse an already published version or replace assets under an existing
release tag. Inspect any failed release output before cleaning only that
specific version's generated files.

Outputs are reserved under `build/releases/<version>/`. A completed release
contains `manifest.json`, both native packages, notarization submission/log
files, package-signature reports, and a `work/` directory with build and staging
files. A failed attempt remains available for inspection; rerunning the same
version refuses to overwrite it.

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
- Explicit activation, deactivation, guarded upgrade, and guarded removal.

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
make cask MANIFEST=build/releases/0.1.0/manifest.json
```

The generated file is `build/pam-watchid.rb`. It chooses the native package
using Homebrew's physical CPU detection, including under Rosetta.

Publish both `pam-watchid-<version>-arm64.pkg` and
`pam-watchid-<version>-x86_64.pkg`, plus the manifest, in an immutable
`v<version>` GitHub release in `rioriost/pam_watchid`. Ensure the downloaded
assets match the manifest before publishing the cask.

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
assets. Installing or upgrading a package never activates it in PAM.
