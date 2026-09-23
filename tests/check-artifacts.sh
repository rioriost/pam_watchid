#!/bin/sh
set -eu

build_root=${1:?usage: check-artifacts.sh BUILD_ROOT}
for arch in arm64 x86_64; do
    module="$build_root/$arch/pam_watchid.so"
    helper="$build_root/$arch/pam_watchid-helper"
    for binary in "$module" "$helper"; do
        actual=$(/usr/bin/lipo -archs "$binary")
        if [ "$actual" != "$arch" ]; then
            echo "Unexpected architecture for $binary: $actual" >&2
            exit 1
        fi
        if /usr/bin/nm -u "$binary" | /usr/bin/grep -E \
            'LAContext.*Private|kLAOption|LACreateNewContext|vproc|externalizedContext'; then
            echo "Private authentication symbol found in $binary" >&2
            exit 1
        fi
        /usr/bin/otool -L "$binary" | /usr/bin/awk '
            NR == 1 { next }
            $1 == "/Library/Security/pam_watchid/pam_watchid.so" { next }
            $1 ~ "^/System/Library/" || $1 ~ "^/usr/lib/" { next }
            { print "Non-system dependency: " $1 > "/dev/stderr"; bad = 1 }
            END { exit bad }
        '
    done
    exports=$(/usr/bin/nm -gUj "$module" | /usr/bin/sort)
    expected=$(printf '%s\n' _pam_sm_authenticate _pam_sm_setcred)
    if [ "$exports" != "$expected" ]; then
        echo "Unexpected exported PAM symbols: $exports" >&2
        exit 1
    fi
done
echo "Native artifacts match architecture, export, and dependency requirements."
