# pam_watchid

[English](README.md) | [日本語](README.ja.md)

Approve `sudo` on your Mac with **Apple Watch or Touch ID**. If neither is
available, you cancel, or authentication times out, sudo continues with its
existing authentication methods, normally your password.

**Release status:** [0.2.1 prerelease](https://github.com/rioriost/pam_watchid/releases/tag/v0.2.1)
includes automatic PAM setup. Apple Watch, Touch ID, cancellation, password
fallback, automatic backup/activation, managed reinstallation, and removal were
checked on one Apple silicon Mac running Golden Gate 27. Other hardware, OS
versions, and additional session conditions remain unverified.

**Homebrew distribution is temporarily paused:** the final Homebrew upgrade
check stalled in its uninstall hook on the verification Mac. This path is
under investigation; the cask is disabled until it is resolved. Existing
installed authentication and published package assets have not been removed.

## Compatibility

| macOS | Apple silicon | Intel |
| --- | --- | --- |
| Sequoia 15 | Targeted | Targeted |
| Tahoe 26 | Targeted | Targeted |
| Golden Gate 27 | Checked on one Mac | Not supported by macOS |

Use a Mac supported by the respective macOS release. Sequoia and Tahoe remain
implementation targets without hardware authentication verification. The
Golden Gate check does not cover every Mac model.
Homebrew selects a package for the Mac's physical CPU, including when Homebrew
runs under Rosetta. The `sudo` process itself must run natively.

For **Apple Watch**, first make sure you can
[unlock your Mac and approve requests with your Watch](https://support.apple.com/en-us/102442):
enable Wi-Fi and Bluetooth, use the same Apple Account with two-factor
authentication, enable Apple Watch unlocking in System Settings, and wear your
unlocked, passcode-protected Watch close to the Mac.

For **Touch ID**, enroll a fingerprint in System Settings on a compatible Mac
or keyboard. You do not need an Apple Watch to use Touch ID, or Touch ID hardware
to use Apple Watch. macOS controls which available authentication method it
presents.

## Install

```sh
brew tap rioriost/cask
brew install --cask rioriost/cask/pam-watchid
```

Run Homebrew as your normal user, not with `sudo`. The installer requests
administrator approval. Starting with 0.2.1, **no editor step is needed**:
it installs the signed, notarized files under `/Library/Security/pam_watchid/`,
verifies the installed module and helper, backs up `sudo_local`, and enables
the module automatically.

Backups are kept in root-only directories under
`/private/var/db/pam_watchid/` and are retained after uninstall. If
`/etc/pam.d/sudo_local` does not exist, the installer records that fact before
creating it. It never edits `/etc/pam.d/sudo`.

The installer adds the following entry inside an identifiable managed block,
without removing existing entries or adding duplicates on reinstall:

```text
auth sufficient /Library/Security/pam_watchid/pam_watchid.so
```

Customized PAM configurations that cannot be changed safely are rejected with
an explanation instead of being overwritten. Keep a separate administrator
terminal available during installation.

To disable automatically managed authentication without uninstalling:

```sh
sudo /Library/Security/pam_watchid/uninstall.sh --disable
```

Reinstalling enables it again after the same checks and backup procedure.

## Use sudo

After installation, try from another terminal:

```sh
sudo -k
sudo -v
```

Approve the system prompt with Touch ID or double-click the Apple Watch side
button when prompted. If authentication is unavailable or you cancel, the
existing sudo configuration takes over. Other enabled PAM modules can still
authenticate you; this module does not replace or disable them.

Sudo normally caches a successful authentication, so you will not see a prompt
for every command. `sudo -k` clears the current cached authentication.

## Update or remove

For installer-managed configuration from 0.2.1 onward:

```sh
brew upgrade --cask rioriost/cask/pam-watchid
```

The installer-managed entry is temporarily removed before replacing files and
re-added only after verifying the new installation. You do not need to edit
PAM settings for each update.

To uninstall instead:

```sh
brew uninstall --cask rioriost/cask/pam-watchid
```

Uninstall removes only the installer-managed entry before deleting the module.
It preserves other settings, later administrator edits, and backups. If the
managed block was modified, or another PAM file references the module, removal
stops rather than guessing which settings to delete.

**Upgrading from manually activated 0.1.1:** remove its old `pam_watchid.so`
entry once, preserving every unrelated entry, before running `brew upgrade`.
Use `/usr/bin/sudo -e /etc/pam.d/sudo_local`. The old uninstaller requires this;
subsequent automatically managed upgrades do not.

## Limitations and troubleshooting

- Use the active, logged-in local desktop account. SSH, headless sessions, and
  detached or mismatched terminal-multiplexer sessions are not supported;
  use your usual sudo authentication instead.
- Noninteractive automation is not supported. `sudo -n` is not a guarantee
  that no system authentication prompt appears: macOS PAM does not expose that
  flag to this module. Askpass requests fall back to the existing PAM stack.
- Allow up to about a minute before a stalled request falls back. Cancellation,
  a locked or unavailable Watch, and failed Touch ID must never count as success.
- If no biometric/Watch prompt appears, check that the activation line exists,
  your terminal belongs to the active desktop account, and native sudo is used.
  Verify that Watch approval or Touch ID works normally in macOS first.
- If you need to recover, use your separate administrator terminal to uninstall,
  or remove the complete pam_watchid managed block without changing other entries.
  Backups remain under `/private/var/db/pam_watchid/`; do not blindly restore an
  old backup over newer administrator changes. Never disable SIP or Gatekeeper.

## License

[MIT](LICENSE). This is an independent implementation inspired by the external
functionality of [pam-watchid](https://github.com/biscuitehh/pam-watchid).
