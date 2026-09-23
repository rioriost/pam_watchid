# Implementation plan

## Status and scope

This plan was written before implementation and reviewed by an Astra xhigh
supervisor on 2026-09-23. The required amendments from that review are integrated
below. It was committed as `774bc8a` before parallel implementation by Astra
high agents. Changes are committed in coherent increments.

The project is an independently implemented, MIT-licensed PAM authentication
module for approving `sudo` with Apple Watch or Touch ID. Only the reference project's
documented external behavior has been consulted; its implementation is not a
source for this project.

The public source repository is `rioriost/pam_watchid`. Distribution will use
the owner's existing Homebrew repositories, not a newly created tap:
`rioriost/homebrew-cask` for the signed installer cask; `rioriost/homebrew-tap`
remains the existing formula tap and need not receive a duplicate formula.

## Confirmed requirements

- macOS Sequoia 15 and Tahoe 26: supported Intel and Apple silicon hardware.
- macOS Golden Gate 27: Apple silicon only, following Apple's hardware support.
- The module itself accepts Touch ID or companion authentication, but not a
  Mac password. On these macOS versions, Apple Watch is the supported companion.
- Failure, cancellation, unavailable authenticators, or timeout must not authorize sudo.
  The existing PAM authentication stack remains responsible for fallback.
- Installing the package does not activate it or alter any PAM configuration.
  Users explicitly add one `auth sufficient` line to `/etc/pam.d/sudo_local`.
- Preserve existing PAM entries. Other sufficient modules remain capable of
  authenticating independently; this does not replace the system's PAM policy.
- Deliver native arm64 and x86_64 packages and select by physical Mac hardware,
  including when Homebrew itself runs under Rosetta.
- Keep the English and Japanese READMEs user-oriented: purpose, prerequisites,
  installation, explicit activation, fallback, removal, and limitations.
- On a release build, select a unique signing team and a deterministic,
  project-specific Keychain notarization profile. If the profile is missing,
  interactively request the Apple ID and app-specific password without placing
  the password in source, logs, environment variables, or command arguments.
- Fail explicitly on ambiguous signing identities, invalid credentials, locked
  Keychains, network failures, or noninteractive missing-credential situations.

## Architecture

### PAM module

Use a small C module with the standard `pam_sm_authenticate` and
`pam_sm_setcred` entry points and the macOS OpenPAM headers. Keep Cocoa and
asynchronous LocalAuthentication callbacks out of the privileged PAM host.

Authenticate only the account resolved from `PAM_USER`, with a nonzero UID
matching the active console user. Require `SessionGetInfo` to report graphical
access without remote/root-session flags. Require the current Quartz session
to be logged in, on-console, and owned by that UID. Snapshot the security-session
ID and recheck it and the account in the helper after dropping privileges and
in the module before success. Never adopt another session or use `launchctl
asuser`; missing or inconsistent information means fallback. Respect the
Apple sudo `askpass-enabled` PAM datum when present. Do not interpret
`PAM_SILENT` as `sudo -n`, or a nonempty `PAM_RHOST` as SSH: neither inference is
correct on macOS sudo.

Launch the fixed, root-owned helper using `posix_spawn`, with a minimal,
explicit environment, closed inherited descriptors, reset signal state, and
no shell. Never derive an executable path from a PAM argument or environment.
Use a monotonic bounded wait, reap the exact child, and terminate it on timeout.
Pass a parent-lifetime pipe on FD 3: EOF cancels the helper and prevents success.
Do not add process-wide signal handlers or alarms. Treat `ECHILD`, unexpected
status, signalled termination, and all spawn/wait errors as non-success.
Only a normal, documented success exit from that child can authorize PAM.
Recheck the console identity and local session before returning success.

Validate root ownership, permissions, writable ACLs, and absence of symlinks
throughout the installation-directory chain before executing the helper.
Retrieve extended ACLs through an already-open, non-symlink descriptor:
macOS reports `ENOENT` for a valid file without an extended ACL. Accept that
specific condition, not failed path opens or other ACL-retrieval errors.
Production helpers must have the expected Developer ID Application team,
exact helper signing identifier, Hardened Runtime, and no entitlements.
Dependencies are limited to system libraries/frameworks. Privileged
administrators/installers are trusted; same-user processes are not. A
signature check followed by pathname execution is not an atomic binding.
Unsigned local builds are for development checks, not privileged deployment.

### Authentication helper

Use a separate Objective-C executable linked to Foundation and
LocalAuthentication. It initially runs with the PAM host's privileges only to
resolve the numeric target UID, initialize the target account's supplementary
groups, and permanently drop group and user privileges using checked
`initgroups`, `setgid`, then `setuid` calls. Verify the resulting credentials,
permanent loss of root, and unchanged session before constructing an `LAContext`.

The context therefore belongs to the actual console account, rather than
assuming that a root-owned context authenticates `PAM_USER`. This identity and
GUI-session binding must still be verified on actual supported systems.

Use the public `LAPolicyDeviceOwnerAuthenticationWithBiometricsOrCompanion`
policy, available since macOS 15. It replaces the deprecated biometrics-or-Watch
spelling; do not use private LA APIs or general device-owner authentication.
Use a fresh context, a fixed nonempty localized reason, and no command text.
Do not make configurable arguments that broaden the authentication policy.

Wait for the asynchronous callback with owned, synchronized state and an
explicit timeout. Use one terminal-state transition; the callback itself checks
the monotonic deadline. A timeout or parent cancellation is terminal, cancels
the context outside the state lock, and cannot be overridden by a late callback.
Retain callback-owned state until process exit. Process isolation ensures late callback code
cannot execute from an unloaded PAM module. Logs contain diagnostic categories,
not credentials or executed command text.

An independent helper-only watchdog starts before account lookup or framework
calls. It terminates the process on parent EOF or the absolute deadline, even
if those calls block; it must not depend on a state mutex or `invalidate`
returning. Process teardown also ends pending LocalAuthentication work.

### Installation and removal

Install root-owned files under `/Library/Security/pam_watchid/`, outside
user-writable Homebrew prefixes:

- `pam_watchid.so`
- `libexec/pam_watchid-helper`
- license and a fixed-purpose uninstall script

Use a signed, notarized, stapled flat `.pkg`. Do not include a postinstall
script that enables authentication. An architecture guard must reject an
incorrect package before installing payload files. Packages must not replace
the installation directory via an unsafe symlink.

Document manual activation in `/etc/pam.d/sudo_local`, keeping Apple's main
`/etc/pam.d/sudo` untouched. Removal must first ensure that the module's PAM
entry has been removed; do not silently rewrite user-maintained PAM files.
Document deactivation before upgrades as well as uninstall, because Homebrew
may run uninstall hooks during upgrade. Do not bypass the activation guard.
Keep password fallback and a separate authenticated terminal available while
changing authentication configuration.

### Builds, signing, and notarization

Use a Makefile as the public build interface, with small standard-library-only
scripts where shell parsing or credential/error handling would become brittle.

Expected targets include native `build`, both-architecture builds, `check`,
`notary-profile`, `release`, and cask generation. Both architectures target
macOS 15 at compile time; the runtime/platform matrix remains explicit.

Use Developer ID Application for the module/helper and Developer ID Installer
for packages, with timestamps and Hardened Runtime on the helper. Select the
unique matching team automatically; allow an explicit Team ID to disambiguate,
but never silently choose the first identity. Support explicit certificate
fingerprints to resolve multiple identities belonging to a single team.

The default profile name is `pam_watchid.notary.<TEAM_ID>`, uniquely determined
by the project and signing team. Use `notarytool history` to validate access;
only its specific missing-profile error should trigger setup. Credential,
network, or other Keychain failures must not be misclassified as absence.
Select one existing Keychain and use it consistently. Preflight its existence,
readability, and unlocked state without retrieving passwords or invoking unlock
UI. Classify absence by the supported tool's exact diagnostic for the exact
profile name; unknown diagnostics are fatal. Serialize setup before processing
the architecture-specific releases.

For missing profiles on a terminal, read the Apple ID interactively and invoke
`notarytool store-credentials` with that ID and the selected Team ID, leaving
the password to Apple's secure native prompt. Validate before storing.
Noninteractive builds fail with an actionable `make notary-profile` instruction.
Do not automatically overwrite an existing but invalid profile.

Build and sign both native packages; submit each with `notarytool --wait`,
require an Accepted result, preserve submission metadata/logs, staple and
validate the ticket, and verify the final package signature. Compute release
SHA-256 hashes only after stapling.

Do not perform a real notarized release until the user has supplied credentials
locally and both required signing identities are available.

### Homebrew and GitHub

Keep a cask template and a deterministic generator in this repository. Generated
casks must reference immutable versioned assets and the exact post-stapling
SHA-256 hashes; do not publish placeholder checksums or nonexistent packages.
The cask belongs in `rioriost/homebrew-cask/Casks/pam-watchid.rb`, installed with
`brew install --cask rioriost/cask/pam-watchid`.

Check Homebrew's physical-hardware architecture facility rather than selecting
solely from a translated process's `uname`. Protect both the cask and package
against incompatible CPU/OS combinations. Provide a receipt-based uninstall
and a guard that refuses removal while the PAM module is configured.
Use `Hardware::CPU.physical_cpu_arm64?` in the cask. This supports translated
Homebrew, not translated sudo: native-only modules require native-architecture
sudo.

Create the authorized public source repository and push reviewed commits.
Publishing a GitHub release or a working cask requires real, verified notarized
assets, so do not advertise an installable release before those exist.

### Shared implementation contract

- Activation: `auth sufficient /Library/Security/pam_watchid/pam_watchid.so`.
- No module options in protocol v1; unexpected options are errors.
- Shared header: `src/pam_watchid_protocol.h`.
- Helper invocation: `pam_watchid-helper --protocol 1 --uid <uid> --session <id>`.
  Reject unknown arguments, numeric overflow, UID zero, and protocol mismatch.
- FD 3 is the parent-lifetime pipe; standard descriptors use `/dev/null`.
  Use `POSIX_SPAWN_CLOEXEC_DEFAULT`, reset signals, and do not use RESETIDS.
- Helper deadline: 55 seconds from entry. Parent deadline: 60 seconds from
  launch attempt. No configurable environment/PAM timeout.
- Helper exit codes: 0 approval; 1 denial/cancellation/fallback; 2 unavailable;
  3 expiry/parent cancellation; 64 invalid arguments; 70 internal failure.
- Only verified exit 0 maps to `PAM_SUCCESS`; denial/expiry map to
  `PAM_AUTH_ERR`; infrastructure/unavailability map to `PAM_AUTHINFO_UNAVAIL`.
- Signing identifiers: `io.github.rioriost.pam-watchid.helper` and
  `io.github.rioriost.pam-watchid.module`; receipt:
  `io.github.rioriost.pam-watchid`.
- Compile-time team definition: `WATCHID_TEAM_ID`; empty development builds
  cannot authenticate through a privileged installation.
- Output: `build/<arch>/pam_watchid.so` and
  `build/<arch>/pam_watchid-helper`; `ARCH=arm64|x86_64`; deployment target 15.0.
- Release artifacts under `dist/<version>/`: `pam-watchid-<version>-<arch>.pkg`
  and a JSON manifest containing their post-stapling SHA-256 hashes and
  notarization identifiers. Reserve the output directory only after credentials
  validate, without overwriting an existing version.
- Fixed-purpose uninstall script: `packaging/uninstall.sh`, installed at
  `/Library/Security/pam_watchid/uninstall.sh`; refuse while actively configured.

## Work split

After the plan review and commit:

1. An Astra high agent implements the PAM module, helper, and focused native
   tests in `src/` and `tests/`, without modifying release tooling.
2. An Astra high agent implements signing/notarization/package scripts and
   their tests, without changing authentication sources.
3. The supervisor integrates the Makefile, packaging contract, bilingual
   READMEs, MIT license, CI, and Homebrew publishing flow; resolves interface
   questions; reviews the result; and makes incremental commits.

Keep interfaces explicit: fixed install paths, helper argument/exit protocol,
architecture names, release version, and signing-team build definition.
Agents must not modify system PAM settings, install privileged files, prompt
for secrets through chat, publish releases, or independently create commits.

## Validation and release gates

- Compile and link arm64 and x86_64 against the installed public SDK with
  warnings treated as errors and deployment target 15.
- Check exported PAM symbols, Mach-O architectures, dependencies, and absence
  of private LA symbols.
- Unit-test option/UID parsing, child-result handling, deadline behavior, and
  identity/session decisions without invoking real authentication.
- Exercise cancellation, late callbacks, unavailable policy, and positive
  results through a test seam; real Watch success remains a hardware gate.
- Test signing identity selection, exact missing-profile handling, refusal to
  prompt in CI, argument-safe password setup, notarization rejection, artifact
  hashes, and cask generation with isolated fake tool output.
- Inspect unsigned development package contents and metadata without installing
  them. Validate shell/Python syntax and generated cask Ruby syntax.
- CI runs nonprivileged checks on available macOS runners, including
  cross-compilation where hardware coverage is unavailable.
- Do not change this machine's `/etc/pam.d`, install the module, or invoke an
  actual Watch authorization without separate user approval.
- Before declaring hardware support verified, manually test Watch approval,
  Touch ID, and password fallback on supported Intel/Apple-silicon OS combinations, plus
  SSH, `sudo -n`, askpass, alternate PAM users, fast user switching, multiplexer
  sessions, concurrent requests, and install/upgrade/removal behavior.
- The first approved signed runtime prototype must establish Touch ID with
  Watch unavailable and Watch with Touch ID unavailable, cancellation, and
  fast user switching. Credential dropping alone is not runtime evidence.
- Public documentation must distinguish implementation targets, automated
  checks, and unperformed hardware authentication tests.

### Runtime validation status (2026-09-23)

Signed and notarized 0.1.1 passed isolated PAM authentication with the requested
Watch-only and Touch-ID-only user operations on an Apple silicon Mac running
macOS 27. Cancellation returned `PAM_AUTH_ERR`. Direct user-session sudo
authentication also succeeded with password input disabled.

Password fallback was subsequently verified in a separate fresh sudo session:
the module logged rejection after cancellation, the user confirmed entering
the Mac password, and sudo authentication succeeded. The original `sudo_local`
was restored and all temporary PAM test services were removed. The package
remains installed but is not enabled in sudo. Other hardware/OS combinations
and the remaining release gates above are not yet hardware-verified.

## Primary references

- [Reference external behavior](https://github.com/biscuitehh/pam-watchid#readme)
- [Apple biometrics-or-companion policy](https://developer.apple.com/documentation/localauthentication/lapolicy/deviceownerauthenticationwithbiometricsorcompanion)
- [Apple Watch approval prerequisites](https://support.apple.com/en-us/102442)
- [Apple macOS releases](https://support.apple.com/en-us/100100)
- [Apple PAM integration behavior](https://github.com/apple-oss-distributions/pam_modules/tree/main/modules/pam_tid)
- [Apple sudo local configuration](https://github.com/apple-oss-distributions/sudo/tree/main/pam.d)
- [Apple notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow)
- [Homebrew cask cookbook](https://docs.brew.sh/Cask-Cookbook)

Apple's PAM source is behavioral/API evidence only, not code to relicense.
