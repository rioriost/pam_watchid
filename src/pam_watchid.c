/* SPDX-License-Identifier: MIT */
#include "watchid_common.h"

#include <Security/Security.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

static void
diagnostic(const char *category)
{
    syslog(LOG_AUTHPRIV | LOG_NOTICE, "pam_watchid: %s", category);
}

static bool
safe_helper_path(void)
{
    static const char *const paths[] = {
        "/", "/Library", "/Library/Security", WATCHID_INSTALL_DIRECTORY,
        WATCHID_INSTALL_DIRECTORY "/libexec", WATCHID_HELPER_PATH
    };
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
        struct stat info;
        bool executable = i == sizeof(paths) / sizeof(paths[0]) - 1;
        if (lstat(paths[i], &info) != 0 || info.st_uid != 0 ||
            (info.st_mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID)) != 0 ||
            (executable ? !S_ISREG(info.st_mode) : !S_ISDIR(info.st_mode)) ||
            (info.st_mode & S_IXUSR) == 0 || !watchid_safe_path_acl(paths[i]))
            return false;
    }
    return true;
}

static bool
valid_team_id(void)
{
    const char *team = WATCHID_TEAM_ID;
    if (strlen(team) != 10)
        return false;
    for (size_t i = 0; i < 10; ++i) {
        if (!((team[i] >= 'A' && team[i] <= 'Z') ||
              (team[i] >= '0' && team[i] <= '9')))
            return false;
    }
    return true;
}

static bool
trusted_helper(void)
{
    if (!valid_team_id())
        return false;
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL,
        (const UInt8 *)WATCHID_HELPER_PATH, strlen(WATCHID_HELPER_PATH), false);
    SecStaticCodeRef code = NULL;
    SecRequirementRef requirement = NULL;
    CFDictionaryRef information = NULL;
    CFStringRef expression = CFStringCreateWithFormat(NULL, NULL,
        CFSTR("anchor apple generic and identifier \"%s\" and "
              "certificate leaf[subject.OU] = \"%s\" and "
              "certificate 1[field.1.2.840.113635.100.6.2.6] exists and "
              "certificate leaf[field.1.2.840.113635.100.6.1.13] exists"),
        WATCHID_HELPER_IDENTIFIER, WATCHID_TEAM_ID);
    bool valid = url != NULL && expression != NULL &&
        SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code) == errSecSuccess &&
        SecRequirementCreateWithString(expression, kSecCSDefaultFlags, &requirement) ==
            errSecSuccess &&
        SecStaticCodeCheckValidity(code, kSecCSCheckAllArchitectures |
            kSecCSStrictValidate, requirement) == errSecSuccess &&
        SecCodeCopySigningInformation(code, kSecCSSigningInformation,
            &information) == errSecSuccess;
    if (valid) {
        CFTypeRef flags = CFDictionaryGetValue(information, kSecCodeInfoFlags);
        CFTypeRef identifier = CFDictionaryGetValue(information, kSecCodeInfoIdentifier);
        CFTypeRef team = CFDictionaryGetValue(information, kSecCodeInfoTeamIdentifier);
        CFTypeRef entitlements = CFDictionaryGetValue(information, kSecCodeInfoEntitlementsDict);
        CFTypeRef raw_entitlements = CFDictionaryGetValue(information, kSecCodeInfoEntitlements);
        uint32_t bits = 0;
        valid = flags != NULL && CFGetTypeID(flags) == CFNumberGetTypeID() &&
            CFNumberGetValue((CFNumberRef)flags, kCFNumberSInt32Type, &bits) &&
            (bits & kSecCodeSignatureRuntime) != 0 &&
            (bits & kSecCodeSignatureAdhoc) == 0 &&
            identifier != NULL && CFEqual(identifier, CFSTR(WATCHID_HELPER_IDENTIFIER)) &&
            team != NULL && CFEqual(team, CFSTR(WATCHID_TEAM_ID)) &&
            entitlements == NULL && raw_entitlements == NULL;
    }
    if (information != NULL) CFRelease(information);
    if (requirement != NULL) CFRelease(requirement);
    if (code != NULL) CFRelease(code);
    if (expression != NULL) CFRelease(expression);
    if (url != NULL) CFRelease(url);
    return valid;
}

static bool
lifetime_pipe(int descriptors[2])
{
    int original[2];
    if (pipe(original) != 0)
        return false;
    descriptors[0] = fcntl(original[0], F_DUPFD_CLOEXEC, WATCHID_LIFETIME_FD + 1);
    descriptors[1] = fcntl(original[1], F_DUPFD_CLOEXEC, WATCHID_LIFETIME_FD + 1);
    close(original[0]);
    close(original[1]);
    if (descriptors[0] >= 0 && descriptors[1] >= 0)
        return true;
    if (descriptors[0] >= 0) close(descriptors[0]);
    if (descriptors[1] >= 0) close(descriptors[1]);
    return false;
}

static enum watchid_result
run_helper(uid_t uid, uint32_t session_id, uint64_t *parent_deadline)
{
    uint64_t deadline = watchid_deadline(watchid_now_ns(), WATCHID_PARENT_SECONDS);
    *parent_deadline = deadline;
    int lifetime[2];
    if (deadline == 0 || !lifetime_pipe(lifetime))
        return WATCHID_UNAVAILABLE;
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;
    bool have_actions = posix_spawn_file_actions_init(&actions) == 0;
    bool have_attributes = posix_spawnattr_init(&attributes) == 0;
    bool ready = have_actions && have_attributes;
    sigset_t mask, defaults;
    sigemptyset(&mask);
    sigfillset(&defaults);
    sigdelset(&defaults, SIGKILL);
    sigdelset(&defaults, SIGSTOP);
    if (ready) {
        ready = posix_spawnattr_setflags(&attributes, POSIX_SPAWN_CLOEXEC_DEFAULT |
                    POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF) == 0 &&
            posix_spawnattr_setsigmask(&attributes, &mask) == 0 &&
            posix_spawnattr_setsigdefault(&attributes, &defaults) == 0 &&
            posix_spawn_file_actions_addopen(&actions, STDIN_FILENO,
                "/dev/null", O_RDONLY, 0) == 0 &&
            posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO,
                "/dev/null", O_WRONLY, 0) == 0 &&
            posix_spawn_file_actions_addopen(&actions, STDERR_FILENO,
                "/dev/null", O_WRONLY, 0) == 0 &&
            posix_spawn_file_actions_adddup2(&actions, lifetime[0],
                WATCHID_LIFETIME_FD) == 0 &&
            posix_spawn_file_actions_addclose(&actions, lifetime[0]) == 0;
    }
    char uid_text[16], session_text[16];
    snprintf(uid_text, sizeof(uid_text), "%" PRIu32, (uint32_t)uid);
    snprintf(session_text, sizeof(session_text), "%" PRIu32, session_id);
    char *const arguments[] = {
        WATCHID_HELPER_PATH, "--protocol", WATCHID_PROTOCOL_VERSION,
        "--uid", uid_text, "--session", session_text, NULL
    };
    char *const environment[] = {
        "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=en_US.UTF-8", NULL
    };
    pid_t child = -1;
    int error = ready ? posix_spawn(&child, WATCHID_HELPER_PATH, &actions,
        &attributes, arguments, environment) : EINVAL;
    if (have_actions) posix_spawn_file_actions_destroy(&actions);
    if (have_attributes) posix_spawnattr_destroy(&attributes);
    close(lifetime[0]);
    if (error != 0) {
        close(lifetime[1]);
        diagnostic("helper spawn failed");
        return WATCHID_UNAVAILABLE;
    }
    return watchid_wait_for_child(child, lifetime[1], deadline);
}

PAM_EXTERN __attribute__((visibility("default"))) int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)flags;
    (void)argv;
    if (!watchid_module_options_valid(argc)) {
        diagnostic("unsupported module options");
        return PAM_SERVICE_ERR;
    }
    const void *askpass = NULL;
    int data_status = pam_get_data(pamh, "askpass-enabled", &askpass);
    if (data_status != PAM_NO_MODULE_DATA) {
        diagnostic(data_status == PAM_SUCCESS ? "askpass mode" : "PAM data unavailable");
        return PAM_AUTHINFO_UNAVAIL;
    }
    const void *user_item = NULL;
    uid_t uid;
    uint32_t session_id;
    if (pam_get_item(pamh, PAM_USER, &user_item) != PAM_SUCCESS ||
        !watchid_user_uid(user_item, &uid) || geteuid() != 0 ||
        !watchid_check_session(uid, 0, &session_id)) {
        diagnostic("ineligible user or local session");
        return PAM_AUTHINFO_UNAVAIL;
    }
    if (!safe_helper_path()) {
        diagnostic("unsafe helper installation");
        return PAM_AUTHINFO_UNAVAIL;
    }
    if (!trusted_helper()) {
        diagnostic("helper signature rejected");
        return PAM_AUTHINFO_UNAVAIL;
    }
    uint64_t deadline;
    enum watchid_result result = run_helper(uid, session_id, &deadline);
    if (result == WATCHID_APPROVED) {
        const void *current_user = NULL;
        uid_t current_uid;
        if (pam_get_item(pamh, PAM_USER, &current_user) != PAM_SUCCESS ||
            !watchid_user_uid(current_user, &current_uid) || current_uid != uid ||
            !watchid_check_session(uid, session_id, NULL)) {
            diagnostic("identity or session changed");
            return PAM_AUTH_ERR;
        }
        uint64_t now = watchid_now_ns();
        if (now == 0 || now >= deadline) {
            diagnostic("parent deadline expired");
            return PAM_AUTH_ERR;
        }
        return PAM_SUCCESS;
    }
    diagnostic(result == WATCHID_DENIED ? "authentication denied or expired" :
        "authentication unavailable");
    return result == WATCHID_DENIED ? PAM_AUTH_ERR : PAM_AUTHINFO_UNAVAIL;
}

PAM_EXTERN __attribute__((visibility("default"))) int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argv;
    return watchid_module_options_valid(argc) ? PAM_SUCCESS : PAM_SERVICE_ERR;
}
