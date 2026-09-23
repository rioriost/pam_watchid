#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

fail() {
    printf '%s\n' "pam_watchid: $*" >&2
    exit 1
}

[ "$(/usr/bin/id -u)" = 0 ] || fail "Run this script as root."
case "$#" in
    0) check_only=no ;;
    1) [ "$1" = --check ] || fail "Only --check is supported."; check_only=yes ;;
    *) fail "Only --check is supported." ;;
esac

base=/Library/Security/pam_watchid
pam_dir=/etc/pam.d
receipt=io.github.rioriost.pam-watchid

safe_path() {
    path=$1
    [ ! -L "$path" ] || fail "Refusing symbolic link: $path"
    [ -e "$path" ] || return 0
    attributes=$(/usr/bin/stat -f '%u:%Lp' "$path") || fail "Cannot inspect $path"
    owner=${attributes%%:*}
    mode=${attributes#*:}
    [ "$owner" = 0 ] || fail "Path is not root-owned: $path"
    case "$mode" in ''|*[!0-7]*) fail "Invalid permissions: $path" ;; esac
    [ "$((0$mode & 06022))" = 0 ] || fail "Path is set-ID or group/world writable: $path"
    acl=$(/bin/ls -lde "$path") || fail "Cannot inspect ACL: $path"
    if printf '%s\n' "$acl" | /usr/bin/grep -Eq \
        '^[[:space:]]*[0-9]+:.* allow .*(write|add_file|add_subdirectory|delete|chown)'; then
        fail "Path has a writable ACL: $path"
    fi
}

for directory in / /Library /Library/Security "$base" "$base/libexec"; do
    safe_path "$directory"
    [ ! -e "$directory" ] || [ -d "$directory" ] || fail "Not a directory: $directory"
done

for file in "$base/pam_watchid.so" "$base/libexec/pam_watchid-helper" \
    "$base/LICENSE" "$base/uninstall.sh"; do
    safe_path "$file"
    [ ! -e "$file" ] || [ -f "$file" ] || fail "Not a regular file: $file"
done

[ -d "$pam_dir" ] && [ -r "$pam_dir" ] || fail "Cannot inspect $pam_dir"
for configuration in "$pam_dir"/* "$pam_dir"/.[!.]* "$pam_dir"/..?*; do
    [ -e "$configuration" ] || [ -L "$configuration" ] || continue
    [ ! -L "$configuration" ] && [ -f "$configuration" ] && [ -r "$configuration" ] ||
        fail "Cannot safely inspect PAM configuration: $configuration"
    if /usr/bin/awk '
        /\\$/ { sub(/\\$/, ""); continued = continued $0; next }
        {
            line = continued $0
            continued = ""
            sub(/#.*/, "", line)
            if (line ~ /(^|[[:space:]\/"\047])pam_watchid(\.so)?([[:space:]"\\\047]|$)/)
                active = 1
        }
        END {
            sub(/#.*/, "", continued)
            if (continued ~ /pam_watchid/) active = 1
            if (active) exit 42
        }
    ' "$configuration"; then
        :
    else
        status=$?
        [ "$status" != 42 ] || fail \
            "Remove the pam_watchid entry from $configuration manually before upgrading/removing."
        fail "Cannot parse PAM configuration: $configuration"
    fi
done

[ "$check_only" = no ] || exit 0

# Forget only our receipt, and only after every safety check has passed.
receipts=$(/usr/sbin/pkgutil --pkgs) || fail "Cannot inspect package receipts; no payload was removed."
if printf '%s\n' "$receipts" | /usr/bin/grep -Fxq "$receipt"; then
    /usr/sbin/pkgutil --forget "$receipt" >/dev/null ||
        fail "Cannot forget the package receipt; no payload was removed."
fi
for file in "$base/pam_watchid.so" "$base/libexec/pam_watchid-helper" \
    "$base/LICENSE" "$base/uninstall.sh"; do
    [ ! -e "$file" ] || /bin/rm -- "$file"
done
for directory in "$base/libexec" "$base"; do
    [ -d "$directory" ] || continue
    remaining=$(/bin/ls -A "$directory") || fail "Cannot inspect remaining files in $directory"
    if [ -n "$remaining" ]; then
        printf '%s\n' "pam_watchid: Preserving additional files in $directory" >&2
    else
        /bin/rmdir "$directory" || fail "Cannot remove empty directory: $directory"
    fi
done
printf '%s\n' "pam_watchid payload removed. No PAM configuration was modified."
