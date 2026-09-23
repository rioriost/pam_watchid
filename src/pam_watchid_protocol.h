/* SPDX-License-Identifier: MIT */
#ifndef PAM_WATCHID_PROTOCOL_H
#define PAM_WATCHID_PROTOCOL_H

#define WATCHID_PROTOCOL_VERSION "1"
#define WATCHID_INSTALL_DIRECTORY "/Library/Security/pam_watchid"
#define WATCHID_HELPER_PATH WATCHID_INSTALL_DIRECTORY "/libexec/pam_watchid-helper"
#define WATCHID_HELPER_IDENTIFIER "io.github.rioriost.pam-watchid.helper"
#define WATCHID_MODULE_IDENTIFIER "io.github.rioriost.pam-watchid.module"
#define WATCHID_LIFETIME_FD 3
#define WATCHID_HELPER_SECONDS 55
#define WATCHID_PARENT_SECONDS 60

#ifndef WATCHID_TEAM_ID
#define WATCHID_TEAM_ID ""
#endif

enum watchid_exit {
    WATCHID_EXIT_APPROVED = 0,
    WATCHID_EXIT_DENIED = 1,
    WATCHID_EXIT_UNAVAILABLE = 2,
    WATCHID_EXIT_EXPIRED = 3,
    WATCHID_EXIT_USAGE = 64,
    WATCHID_EXIT_INTERNAL = 70
};

#endif
