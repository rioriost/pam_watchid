/* SPDX-License-Identifier: MIT */
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>

#include "watchid_common.h"
#include "watchid_watchdog.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pthread.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

/* These objects deliberately survive until _exit, including late LA callbacks. */
static pthread_mutex_t state_lock = PTHREAD_MUTEX_INITIALIZER;
static struct watchid_state authentication;
static LAContext *context;

static void
diagnostic(const char *category)
{
    syslog(LOG_AUTHPRIV | LOG_NOTICE, "pam_watchid-helper: %s", category);
}

static bool
valid_lifetime_pipe(void)
{
    struct stat info;
    int flags = fcntl(WATCHID_LIFETIME_FD, F_GETFL);
    return flags != -1 && (flags & O_ACCMODE) == O_RDONLY &&
        fstat(WATCHID_LIFETIME_FD, &info) == 0 && S_ISFIFO(info.st_mode) &&
        watchid_parent_alive(WATCHID_LIFETIME_FD);
}

static bool
drop_privileges(const struct watchid_account *account)
{
    if (geteuid() != 0 || initgroups(account->name, account->gid) != 0 ||
        setgid(account->gid) != 0 || setuid(account->uid) != 0 ||
        getuid() != account->uid || geteuid() != account->uid ||
        getgid() != account->gid || getegid() != account->gid)
        return false;
    errno = 0;
    if (setuid(0) != -1 || errno != EPERM)
        return false;
    errno = 0;
    if (seteuid(0) != -1 || errno != EPERM)
        return false;
    return getuid() == account->uid && geteuid() == account->uid;
}

static int
finish(int result)
{
    pthread_mutex_lock(&state_lock);
    int terminal = watchid_state_finish(&authentication, result,
        watchid_now_ns(), watchid_parent_alive(WATCHID_LIFETIME_FD));
    pthread_mutex_unlock(&state_lock);
    return terminal;
}

static int
callback_result(BOOL success, NSError *error)
{
    if (success && error == nil)
        return WATCHID_EXIT_APPROVED;
    if (![error.domain isEqualToString:LAErrorDomain])
        return WATCHID_EXIT_INTERNAL;
    switch (error.code) {
    case LAErrorAuthenticationFailed:
    case LAErrorUserCancel:
    case LAErrorUserFallback:
    case LAErrorSystemCancel:
    case LAErrorAppCancel:
        return WATCHID_EXIT_DENIED;
    default:
        return WATCHID_EXIT_UNAVAILABLE;
    }
}

int
main(int argc, const char *argv[])
{
    uint64_t deadline = watchid_deadline(watchid_now_ns(), WATCHID_HELPER_SECONDS);
    struct watchid_request request;
    if (!watchid_parse_request(argc, argv, &request))
        return WATCHID_EXIT_USAGE;
    if (deadline == 0)
        return WATCHID_EXIT_INTERNAL;
    if (!valid_lifetime_pipe()) {
        diagnostic("parent lifetime unavailable");
        return WATCHID_EXIT_EXPIRED;
    }
    if (!watchid_start_watchdog(WATCHID_LIFETIME_FD, deadline)) {
        diagnostic("lifetime watchdog initialization failed");
        return WATCHID_EXIT_INTERNAL;
    }
    struct watchid_account account;
    if (!watchid_account_for_uid(request.uid, &account)) {
        diagnostic("target account unavailable");
        return WATCHID_EXIT_UNAVAILABLE;
    }
    if (!drop_privileges(&account)) {
        diagnostic("credential drop failed");
        return WATCHID_EXIT_INTERNAL;
    }
    if (!watchid_check_session(request.uid, request.session_id, NULL)) {
        diagnostic("session changed after credential drop");
        return WATCHID_EXIT_UNAVAILABLE;
    }
    watchid_state_init(&authentication, deadline);
    if (finish(WATCHID_PENDING) != WATCHID_PENDING)
        return WATCHID_EXIT_EXPIRED;
    @autoreleasepool {
        context = [[LAContext alloc] init];
        context.touchIDAuthenticationAllowableReuseDuration = 0;
        context.localizedFallbackTitle = @"";
        NSString *language = NSLocale.preferredLanguages.firstObject;
        NSString *reason = [language hasPrefix:@"ja"] ?
            @"管理者としての操作を承認します。" : @"Approve an administrator operation.";
        NSError *error = nil;
        const LAPolicy policy = LAPolicyDeviceOwnerAuthenticationWithBiometricsOrCompanion;
        if (context == nil || ![context canEvaluatePolicy:policy error:&error]) {
            diagnostic("biometrics or companion policy unavailable");
            finish(WATCHID_EXIT_UNAVAILABLE);
        } else if (finish(WATCHID_PENDING) == WATCHID_PENDING) {
            [context evaluatePolicy:policy localizedReason:reason
                reply:^(BOOL success, NSError *replyError) {
                    /* Time and parent liveness are checked under the same lock
                     * as the terminal transition, never just by the waiter. */
                    finish(callback_result(success, replyError));
                }];
        }
        while (finish(WATCHID_PENDING) == WATCHID_PENDING) {
            struct pollfd lifetime = { .fd = WATCHID_LIFETIME_FD, .events = POLLIN };
            int result = poll(&lifetime, 1, 20);
            if (result > 0 || (result < 0 && errno != EINTR))
                finish(WATCHID_EXIT_EXPIRED);
        }
        [context invalidate];
        pthread_mutex_lock(&state_lock);
        int result = watchid_state_exit(&authentication, watchid_now_ns(),
            watchid_parent_alive(WATCHID_LIFETIME_FD));
        pthread_mutex_unlock(&state_lock);
        if (result == WATCHID_EXIT_APPROVED &&
            !watchid_check_session(request.uid, request.session_id, NULL))
            result = WATCHID_EXIT_DENIED;
        uint64_t now = watchid_now_ns();
        if (result == WATCHID_EXIT_APPROVED &&
            (now == 0 || now >= deadline ||
             !watchid_parent_alive(WATCHID_LIFETIME_FD)))
            result = WATCHID_EXIT_EXPIRED;
        if (result != WATCHID_EXIT_APPROVED)
            diagnostic(result == WATCHID_EXIT_EXPIRED ? "expired or parent cancelled" :
                result == WATCHID_EXIT_DENIED ? "authentication denied or cancelled" :
                "authentication unavailable or internal failure");
        _exit(result);
    }
}
