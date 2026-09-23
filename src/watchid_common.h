/* SPDX-License-Identifier: MIT */
#ifndef WATCHID_COMMON_H
#define WATCHID_COMMON_H

#include "pam_watchid_protocol.h"

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

struct watchid_request {
    uid_t uid;
    uint32_t session_id;
};

struct watchid_session {
    uid_t console_uid;
    uid_t quartz_uid;
    uint32_t session_id;
    bool graphic;
    bool remote;
    bool root;
    bool logged_in;
    bool on_console;
};

struct watchid_account {
    uid_t uid;
    gid_t gid;
    char name[256];
};

enum watchid_result {
    WATCHID_APPROVED,
    WATCHID_DENIED,
    WATCHID_UNAVAILABLE
};

#define WATCHID_PENDING (-1)
struct watchid_state {
    uint64_t deadline_ns;
    int terminal;
};

bool watchid_module_options_valid(int argc);
bool watchid_safe_path_acl(const char *path);
bool watchid_parse_request(int argc, const char *const argv[],
                           struct watchid_request *request);
bool watchid_session_allows(const struct watchid_session *session, uid_t uid,
                            uint32_t expected_session);
bool watchid_read_session(struct watchid_session *session);
bool watchid_check_session(uid_t uid, uint32_t expected_session,
                           uint32_t *session_id);
bool watchid_user_uid(const char *name, uid_t *uid);
bool watchid_account_for_uid(uid_t uid, struct watchid_account *account);
enum watchid_result watchid_child_result(bool reaped, int status);
enum watchid_result watchid_wait_for_child(pid_t child, int lifetime,
                                          uint64_t deadline_ns);
uint64_t watchid_now_ns(void);
uint64_t watchid_deadline(uint64_t now_ns, unsigned seconds);
void watchid_state_init(struct watchid_state *state, uint64_t deadline_ns);
/* The helper holds its mutex when reading or changing this pure state. */
int watchid_state_finish(struct watchid_state *state, int result,
                         uint64_t now_ns, bool parent_alive);
int watchid_state_exit(const struct watchid_state *state, uint64_t now_ns,
                       bool parent_alive);
bool watchid_parent_alive(int fd);

#endif
