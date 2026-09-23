# pam_watchid

[English](README.md) | [日本語](README.ja.md)

Approve `sudo` on your Mac with **Apple Watch or Touch ID**. If neither is
available, you cancel, or authentication times out, sudo continues with its
existing authentication methods, normally your password.

**Release status:** the first signed, notarized release and hardware validation
are pending. The Homebrew commands below will become available after that
release is published. Do not use an unverified development build for everyday
sudo authentication.

## Compatibility

| macOS | Apple silicon | Intel |
| --- | --- | --- |
| Sequoia 15 | Targeted | Targeted |
| Tahoe 26 | Targeted | Targeted |
| Golden Gate 27 | Targeted | Not supported by macOS |

Use a Mac supported by the respective macOS release. These are implementation
targets, not a claim that every hardware/OS combination has been verified.
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

After the first release is available:

```sh
brew tap rioriost/cask
brew install --cask rioriost/cask/pam-watchid
```

The installer may request administrator approval. It installs a signed,
notarized package under `/Library/Security/pam_watchid/`, **without changing your
PAM configuration**. Run Homebrew as your normal user, not with `sudo`.

## Enable for sudo

Keep a separate administrator terminal available while editing authentication
settings. Do not remove any existing PAM entries or change `/etc/pam.d/sudo`.

Open the local sudo configuration, creating it if necessary:

```sh
sudoedit /etc/pam.d/sudo_local
```

Add this line before other `auth` entries, only once:

```text
auth sufficient /Library/Security/pam_watchid/pam_watchid.so
```

Save the file, then try from another terminal:

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

**First remove the added `pam_watchid.so` line** from
`/etc/pam.d/sudo_local`. Keep every unrelated entry.

Then update:

```sh
brew upgrade --cask rioriost/cask/pam-watchid
```

Re-add the line afterwards if you want to keep using pam_watchid. Deactivation
is required during upgrades so a configured PAM module is not removed or
replaced while still active.

To uninstall instead:

```sh
brew uninstall --cask rioriost/cask/pam-watchid
```

Removal is refused if an active reference to the module remains in
`/etc/pam.d`. The uninstaller never edits your authentication settings for you.

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
- If you need to recover, remove only the pam_watchid line using your separate
  administrator terminal. Keep the standard password authentication entries.
  Never disable SIP or Gatekeeper to make this module work.

## License

[MIT](LICENSE). This is an independent implementation inspired by the external
functionality of [pam-watchid](https://github.com/biscuitehh/pam-watchid).
