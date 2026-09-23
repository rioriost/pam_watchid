#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

@PAM_CONFIG@

pam_init
case "$#" in
    0) pam_uninstall ;;
    1)
        case "$1" in
            --check) pam_guard ;;
            --disable)
                pam_guard
                ! pam_exists "$pending" || fail "Installation is pending; use --cancel-install first."
                pam_lock
                pam_disable_locked
                printf '%s\n' "pam_watchid: Managed PAM activation disabled; payload and backups preserved."
                ;;
            --cancel-install) pam_cancel_install ;;
            *) fail "Supported options: --check, --disable, --cancel-install." ;;
        esac
        ;;
    *) fail "Supported options: --check, --disable, --cancel-install." ;;
esac
