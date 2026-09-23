/* SPDX-License-Identifier: MIT */
#include "watchid_common.h"

#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CGSession.h>
#include <Security/AuthSession.h>
#include <Security/SecBase.h>
#include <SystemConfiguration/SCDynamicStoreCopySpecific.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/acl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

bool
watchid_module_options_valid(int argc)
{
    return argc == 0;
}

bool
watchid_safe_path_acl(const char *path)
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return false;
    errno = 0;
    acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
    int error = errno;
    close(fd);
    /* On macOS, ENOENT on an open descriptor means there is no extended ACL,
     * not that the pathname is absent. Other retrieval failures remain errors. */
    if (acl == NULL)
        return error == ENOENT;
    bool safe = acl_valid(acl) == 0;
    const acl_permset_mask_t writable = ACL_WRITE_DATA | ACL_APPEND_DATA |
        ACL_DELETE | ACL_DELETE_CHILD | ACL_WRITE_ATTRIBUTES |
        ACL_WRITE_EXTATTRIBUTES | ACL_WRITE_SECURITY | ACL_CHANGE_OWNER;
    acl_entry_t entry;
    int selector = ACL_FIRST_ENTRY;
    while (safe) {
        errno = 0;
        if (acl_get_entry(acl, selector, &entry) != 0) {
            safe = errno == EINVAL;
            break;
        }
        selector = ACL_NEXT_ENTRY;
        acl_tag_t tag;
        acl_permset_mask_t permissions;
        if (acl_get_tag_type(entry, &tag) != 0 ||
            acl_get_permset_mask_np(entry, &permissions) != 0 ||
            (tag != ACL_EXTENDED_ALLOW && tag != ACL_EXTENDED_DENY) ||
            (tag == ACL_EXTENDED_ALLOW && (permissions & writable) != 0))
            safe = false;
    }
    acl_free(acl);
    return safe;
}

static bool
parse_number(const char *text, uint32_t *value)
{
    if (text == NULL || *text == '\0')
        return false;
    uint32_t number = 0;
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p < '0' || *p > '9')
            return false;
        uint32_t digit = (uint32_t)(*p - '0');
        if (number > (UINT32_MAX - 1 - digit) / 10)
            return false;
        number = number * 10 + digit;
    }
    if (number == 0)
        return false;
    *value = number;
    return true;
}

bool
watchid_parse_request(int argc, const char *const argv[],
                      struct watchid_request *request)
{
    if (argc != 7 || argv == NULL || request == NULL)
        return false;
    for (int i = 0; i < argc; ++i) {
        if (argv[i] == NULL)
            return false;
    }
    uint32_t uid, session;
    if (strcmp(argv[1], "--protocol") != 0 ||
        strcmp(argv[2], WATCHID_PROTOCOL_VERSION) != 0 ||
        strcmp(argv[3], "--uid") != 0 ||
        strcmp(argv[5], "--session") != 0 ||
        !parse_number(argv[4], &uid) || !parse_number(argv[6], &session))
        return false;
    request->uid = (uid_t)uid;
    request->session_id = session;
    return true;
}

bool
watchid_session_allows(const struct watchid_session *session, uid_t uid,
                       uint32_t expected_session)
{
    return session != NULL && uid != 0 && uid != (uid_t)-1 &&
        session->console_uid == uid && session->quartz_uid == uid &&
        session->session_id != 0 && session->session_id != UINT32_MAX &&
        (expected_session == 0 || session->session_id == expected_session) &&
        session->graphic && !session->remote && !session->root &&
        session->logged_in && session->on_console;
}

static bool
dictionary_true(CFDictionaryRef dictionary, CFStringRef key)
{
    CFTypeRef value = CFDictionaryGetValue(dictionary, key);
    return value != NULL && CFGetTypeID(value) == CFBooleanGetTypeID() &&
        CFBooleanGetValue((CFBooleanRef)value);
}

bool
watchid_read_session(struct watchid_session *session)
{
    if (session == NULL)
        return false;
    memset(session, 0, sizeof(*session));
    SecuritySessionId before, after;
    SessionAttributeBits attributes, after_attributes;
    if (SessionGetInfo(callerSecuritySession, &before, &attributes) != errSecSuccess)
        return false;
    uid_t console_uid = (uid_t)-1;
    CFStringRef console = SCDynamicStoreCopyConsoleUser(NULL, &console_uid, NULL);
    if (console == NULL)
        return false;
    CFRelease(console);
    CFDictionaryRef quartz = CGSessionCopyCurrentDictionary();
    if (quartz == NULL)
        return false;
    int64_t quartz_uid = -1;
    CFTypeRef value = CFDictionaryGetValue(quartz, kCGSessionUserIDKey);
    bool valid = value != NULL && CFGetTypeID(value) == CFNumberGetTypeID() &&
        CFNumberGetValue((CFNumberRef)value, kCFNumberSInt64Type, &quartz_uid) &&
        quartz_uid > 0 && quartz_uid < UINT32_MAX;
    session->logged_in = dictionary_true(quartz, kCGSessionLoginDoneKey);
    session->on_console = dictionary_true(quartz, kCGSessionOnConsoleKey);
    CFRelease(quartz);
    if (!valid ||
        SessionGetInfo(callerSecuritySession, &after, &after_attributes) != errSecSuccess ||
        before != after || attributes != after_attributes)
        return false;
    session->console_uid = console_uid;
    session->quartz_uid = (uid_t)quartz_uid;
    session->session_id = before;
    session->graphic = (attributes & sessionHasGraphicAccess) != 0;
    session->remote = (attributes & sessionIsRemote) != 0;
    session->root = (attributes & sessionIsRoot) != 0;
    return true;
}

bool
watchid_check_session(uid_t uid, uint32_t expected_session, uint32_t *session_id)
{
    struct watchid_session session;
    if (!watchid_read_session(&session) ||
        !watchid_session_allows(&session, uid, expected_session))
        return false;
    if (session_id != NULL)
        *session_id = session.session_id;
    return true;
}

static bool
lookup_account(const char *name, uid_t uid, struct watchid_account *account)
{
    for (size_t size = 16384; size <= 1024 * 1024; size *= 2) {
        char *buffer = malloc(size);
        if (buffer == NULL)
            return false;
        struct passwd entry, *found = NULL;
        int error = name != NULL
            ? getpwnam_r(name, &entry, buffer, size, &found)
            : getpwuid_r(uid, &entry, buffer, size, &found);
        bool valid = error == 0 && found != NULL && found->pw_uid != 0 &&
            found->pw_uid != (uid_t)-1 && found->pw_gid != (gid_t)-1 &&
            found->pw_name != NULL && found->pw_name[0] != '\0' &&
            strlen(found->pw_name) < sizeof(account->name);
        if (valid) {
            account->uid = found->pw_uid;
            account->gid = found->pw_gid;
            strcpy(account->name, found->pw_name);
        }
        free(buffer);
        if (error != ERANGE)
            return valid;
    }
    return false;
}

bool
watchid_user_uid(const char *name, uid_t *uid)
{
    struct watchid_account account;
    if (name == NULL || *name == '\0' || uid == NULL ||
        !lookup_account(name, 0, &account))
        return false;
    *uid = account.uid;
    return true;
}

bool
watchid_account_for_uid(uid_t uid, struct watchid_account *account)
{
    return uid != 0 && uid != (uid_t)-1 && account != NULL &&
        lookup_account(NULL, uid, account) && account->uid == uid;
}

enum watchid_result
watchid_child_result(bool reaped, int status)
{
    if (!reaped || !WIFEXITED(status))
        return WATCHID_UNAVAILABLE;
    switch (WEXITSTATUS(status)) {
    case WATCHID_EXIT_APPROVED:
        return WATCHID_APPROVED;
    case WATCHID_EXIT_DENIED:
    case WATCHID_EXIT_EXPIRED:
        return WATCHID_DENIED;
    default:
        return WATCHID_UNAVAILABLE;
    }
}

enum watchid_result
watchid_wait_for_child(pid_t child, int lifetime, uint64_t deadline_ns)
{
    if (child <= 0) {
        close(lifetime);
        return WATCHID_UNAVAILABLE;
    }
    int status;
    for (;;) {
        uint64_t now = watchid_now_ns();
        if (now == 0 || now >= deadline_ns)
            break;
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) {
            close(lifetime);
            now = watchid_now_ns();
            return now == 0 || now >= deadline_ns ? WATCHID_DENIED :
                watchid_child_result(true, status);
        }
        if (result == -1 && errno != EINTR) {
            /* ECHILD may mean the host reaped it; never signal that PID again. */
            close(lifetime);
            return WATCHID_UNAVAILABLE;
        }
        struct timespec pause = { .tv_sec = 0, .tv_nsec = 20000000 };
        nanosleep(&pause, NULL);
    }
    close(lifetime);
    pid_t result;
    do {
        result = waitpid(child, &status, WNOHANG);
    } while (result == -1 && errno == EINTR);
    if (result == child)
        return WATCHID_DENIED;
    if (result != 0)
        return WATCHID_UNAVAILABLE;
    if (kill(child, SIGKILL) != 0 && errno != ESRCH)
        return WATCHID_UNAVAILABLE;
    do {
        result = waitpid(child, &status, 0);
    } while (result == -1 && errno == EINTR);
    return result == child ? WATCHID_DENIED : WATCHID_UNAVAILABLE;
}

uint64_t
watchid_now_ns(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0 ||
        (uint64_t)now.tv_sec > UINT64_MAX / UINT64_C(1000000000))
        return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

uint64_t
watchid_deadline(uint64_t now_ns, unsigned seconds)
{
    uint64_t duration = (uint64_t)seconds * UINT64_C(1000000000);
    return now_ns == 0 || now_ns > UINT64_MAX - duration ? 0 : now_ns + duration;
}

void
watchid_state_init(struct watchid_state *state, uint64_t deadline_ns)
{
    state->deadline_ns = deadline_ns;
    state->terminal = WATCHID_PENDING;
}

int
watchid_state_finish(struct watchid_state *state, int result, uint64_t now_ns,
                     bool parent_alive)
{
    if (state->terminal == WATCHID_PENDING) {
        if (now_ns == 0 || now_ns >= state->deadline_ns || !parent_alive)
            state->terminal = WATCHID_EXIT_EXPIRED;
        else if (result != WATCHID_PENDING)
            state->terminal = result;
    }
    return state->terminal;
}

int
watchid_state_exit(const struct watchid_state *state, uint64_t now_ns,
                   bool parent_alive)
{
    if (state->terminal == WATCHID_PENDING)
        return WATCHID_EXIT_INTERNAL;
    if (state->terminal == WATCHID_EXIT_APPROVED &&
        (now_ns == 0 || now_ns >= state->deadline_ns || !parent_alive))
        return WATCHID_EXIT_EXPIRED;
    return state->terminal;
}

bool
watchid_parent_alive(int fd)
{
    if (fd < 0)
        return false;
    struct pollfd lifetime = { .fd = fd, .events = POLLIN };
    /* This is a one-way lifetime signal: any input, EOF, or error cancels. */
    return poll(&lifetime, 1, 0) == 0;
}
