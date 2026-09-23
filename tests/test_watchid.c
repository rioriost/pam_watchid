/* SPDX-License-Identifier: MIT */
#include "watchid_common.h"
#include "watchid_watchdog.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void
test_arguments(void)
{
    struct watchid_request request;
    const char *arguments[] = {
        "pam_watchid-helper", "--protocol", "1", "--uid", "501", "--session", "123"
    };
    assert(watchid_module_options_valid(0));
    assert(!watchid_module_options_valid(1));
    assert(!watchid_module_options_valid(-1));
    assert(watchid_parse_request(7, arguments, &request));
    assert(request.uid == 501 && request.session_id == 123);
    assert(!watchid_parse_request(6, arguments, &request));
    assert(!watchid_parse_request(8, arguments, &request));
    assert(!watchid_parse_request(7, NULL, &request));
    assert(!watchid_parse_request(7, arguments, NULL));
    const char *invalid[] = {
        "", "0", "-1", "+501", " 501", "501 ", "1x", "4294967295",
        "4294967296", "18446744073709551616", "５01"
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        arguments[4] = invalid[i];
        assert(!watchid_parse_request(7, arguments, &request));
        arguments[4] = "501";
        arguments[6] = invalid[i];
        assert(!watchid_parse_request(7, arguments, &request));
        arguments[6] = "123";
    }
    arguments[4] = "4294967294";
    arguments[6] = "4294967294";
    assert(watchid_parse_request(7, arguments, &request));
    arguments[4] = "501";
    arguments[6] = "123";
    for (size_t i = 1; i < 7; ++i) {
        const char *original = arguments[i];
        arguments[i] = NULL;
        assert(!watchid_parse_request(7, arguments, &request));
        arguments[i] = original;
    }
    arguments[2] = "2";
    assert(!watchid_parse_request(7, arguments, &request));
    arguments[2] = "1";
    arguments[3] = "--user";
    assert(!watchid_parse_request(7, arguments, &request));
    arguments[3] = "--uid";
    arguments[5] = "--uid";
    assert(!watchid_parse_request(7, arguments, &request));
}

static void
test_sessions(void)
{
    struct watchid_session good = {
        .console_uid = 501, .quartz_uid = 501, .session_id = 123,
        .graphic = true, .logged_in = true, .on_console = true
    };
    assert(watchid_session_allows(&good, 501, 0));
    assert(watchid_session_allows(&good, 501, 123));
    assert(!watchid_session_allows(&good, 501, 124));
    assert(!watchid_session_allows(&good, 502, 123));
    assert(!watchid_session_allows(&good, 0, 123));
    assert(!watchid_session_allows(&good, (uid_t)-1, 123));
    assert(!watchid_session_allows(NULL, 501, 123));
    for (unsigned bits = 0; bits < 32; ++bits) {
        struct watchid_session candidate = good;
        candidate.graphic = (bits & 1) != 0;
        candidate.remote = (bits & 2) != 0;
        candidate.root = (bits & 4) != 0;
        candidate.logged_in = (bits & 8) != 0;
        candidate.on_console = (bits & 16) != 0;
        assert(watchid_session_allows(&candidate, 501, 123) == (bits == 25));
    }
    struct watchid_session bad = good;
    bad.console_uid = 502;
    assert(!watchid_session_allows(&bad, 501, 123));
    bad = good;
    bad.quartz_uid = 502;
    assert(!watchid_session_allows(&bad, 501, 123));
    bad = good;
    bad.session_id = 0;
    assert(!watchid_session_allows(&bad, 501, 0));
    bad.session_id = UINT32_MAX;
    assert(!watchid_session_allows(&bad, 501, 0));
}

static void
test_child_results(void)
{
    for (int code = 0; code <= 255; ++code) {
        enum watchid_result expected = code == WATCHID_EXIT_APPROVED ?
            WATCHID_APPROVED : (code == WATCHID_EXIT_DENIED ||
            code == WATCHID_EXIT_EXPIRED) ? WATCHID_DENIED : WATCHID_UNAVAILABLE;
        assert(watchid_child_result(true, code << 8) == expected);
        assert(watchid_child_result(false, code << 8) == WATCHID_UNAVAILABLE);
    }
    assert(watchid_child_result(true, SIGKILL) == WATCHID_UNAVAILABLE);
    assert(watchid_child_result(true, SIGTERM) == WATCHID_UNAVAILABLE);
    assert(watchid_child_result(true, (SIGSTOP << 8) | 0x7f) == WATCHID_UNAVAILABLE);
}

static void
test_terminal_state(void)
{
    struct watchid_state state;
    assert(watchid_deadline(100, 55) == UINT64_C(55000000100));
    assert(watchid_deadline(0, 55) == 0);
    assert(watchid_deadline(UINT64_MAX - 5, 1) == 0);
    watchid_state_init(&state, 100);
    assert(watchid_state_exit(&state, 99, true) == WATCHID_EXIT_INTERNAL);
    assert(watchid_state_finish(&state, WATCHID_PENDING, 99, true) == WATCHID_PENDING);
    assert(watchid_state_finish(&state, WATCHID_EXIT_APPROVED, 99, true) ==
        WATCHID_EXIT_APPROVED);
    assert(watchid_state_finish(&state, WATCHID_EXIT_DENIED, 99, true) ==
        WATCHID_EXIT_APPROVED);
    assert(watchid_state_exit(&state, 99, true) == WATCHID_EXIT_APPROVED);
    assert(watchid_state_exit(&state, 100, true) == WATCHID_EXIT_EXPIRED);
    assert(watchid_state_exit(&state, 99, false) == WATCHID_EXIT_EXPIRED);
    const int results[] = {
        WATCHID_EXIT_APPROVED, WATCHID_EXIT_DENIED, WATCHID_EXIT_UNAVAILABLE,
        WATCHID_EXIT_EXPIRED, WATCHID_EXIT_INTERNAL
    };
    for (size_t i = 0; i < sizeof(results) / sizeof(results[0]); ++i) {
        watchid_state_init(&state, 100);
        assert(watchid_state_finish(&state, results[i], 99, true) == results[i]);
        assert(watchid_state_finish(&state, WATCHID_EXIT_APPROVED, 99, true) == results[i]);
        watchid_state_init(&state, 100);
        assert(watchid_state_finish(&state, results[i], 100, true) == WATCHID_EXIT_EXPIRED);
        assert(watchid_state_finish(&state, WATCHID_EXIT_APPROVED, 101, true) ==
            WATCHID_EXIT_EXPIRED);
        watchid_state_init(&state, 100);
        assert(watchid_state_finish(&state, results[i], 99, false) == WATCHID_EXIT_EXPIRED);
        assert(watchid_state_finish(&state, WATCHID_EXIT_APPROVED, 99, true) ==
            WATCHID_EXIT_EXPIRED);
    }
    watchid_state_init(&state, 100);
    assert(watchid_state_finish(&state, WATCHID_PENDING, 0, true) == WATCHID_EXIT_EXPIRED);
    watchid_state_init(&state, 0);
    assert(watchid_state_finish(&state, WATCHID_EXIT_APPROVED, 1, true) ==
        WATCHID_EXIT_EXPIRED);
}

static void
test_lifetime(void)
{
    assert(!watchid_parent_alive(-1));
    int descriptors[2];
    assert(pipe(descriptors) == 0);
    assert(watchid_parent_alive(descriptors[0]));
    assert(write(descriptors[1], "x", 1) == 1);
    assert(!watchid_parent_alive(descriptors[0]));
    char byte;
    assert(read(descriptors[0], &byte, 1) == 1);
    assert(watchid_parent_alive(descriptors[0]));
    close(descriptors[1]);
    assert(!watchid_parent_alive(descriptors[0]));
    close(descriptors[0]);
    assert(!watchid_parent_alive(descriptors[0]));
}

static void
test_child_waiting(void)
{
    const int codes[] = { 0, 1, 2, 3, 64, 70, 255 };
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
        int descriptors[2];
        assert(pipe(descriptors) == 0);
        pid_t child = fork();
        assert(child >= 0);
        if (child == 0)
            _exit(codes[i]);
        close(descriptors[0]);
        assert(watchid_wait_for_child(child, descriptors[1],
            watchid_deadline(watchid_now_ns(), 5)) ==
            watchid_child_result(true, codes[i] << 8));
        assert(fcntl(descriptors[1], F_GETFD) == -1 && errno == EBADF);
        int status;
        assert(waitpid(child, &status, WNOHANG) == -1 && errno == ECHILD);
        assert(watchid_wait_for_child(child, -1,
            watchid_deadline(watchid_now_ns(), 5)) == WATCHID_UNAVAILABLE);
    }
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        for (;;)
            pause();
    }
    assert(watchid_wait_for_child(child, -1, 1) == WATCHID_DENIED);
    int status;
    assert(waitpid(child, &status, WNOHANG) == -1 && errno == ECHILD);
    assert(watchid_wait_for_child(-1, -1, 1) == WATCHID_UNAVAILABLE);
    assert(watchid_wait_for_child(0, -1, 1) == WATCHID_UNAVAILABLE);
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        raise(SIGKILL);
        _exit(0);
    }
    assert(watchid_wait_for_child(child, -1,
        watchid_deadline(watchid_now_ns(), 5)) == WATCHID_UNAVAILABLE);
}

static void
test_watchdog_while_main_blocks(bool parent_eof)
{
    int lifetime[2], ready[2];
    assert(pipe(lifetime) == 0);
    assert(pipe(ready) == 0);
    uint64_t started = watchid_now_ns();
    assert(started != 0);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        close(lifetime[1]);
        close(ready[0]);
        uint64_t deadline = watchid_deadline(watchid_now_ns(), parent_eof ? 30 : 1);
        if (!watchid_start_watchdog(lifetime[0], deadline))
            _exit(WATCHID_EXIT_INTERNAL);
        if (write(ready[1], "r", 1) != 1)
            _exit(WATCHID_EXIT_INTERNAL);
        close(ready[1]);
        /* Simulate an account/framework call that never returns. */
        for (;;)
            pause();
    }
    close(lifetime[0]);
    close(ready[1]);
    /* An independent bound also ensures a broken watchdog cannot hang tests. */
    uint64_t test_deadline = watchid_deadline(started, 5);
    assert(fcntl(ready[0], F_SETFL, O_NONBLOCK) == 0);
    bool announced = false, reaped = false;
    int status = 0;
    while (watchid_now_ns() < test_deadline) {
        if (!announced) {
            char byte;
            if (read(ready[0], &byte, 1) == 1) {
                announced = true;
                if (parent_eof) {
                    close(lifetime[1]);
                    lifetime[1] = -1;
                }
            }
        }
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) {
            reaped = true;
            break;
        }
        assert(result == 0 || (result == -1 && errno == EINTR));
        struct timespec pause_time = { .tv_sec = 0, .tv_nsec = 10000000 };
        nanosleep(&pause_time, NULL);
    }
    close(ready[0]);
    if (lifetime[1] != -1)
        close(lifetime[1]);
    if (!reaped) {
        assert(kill(child, SIGKILL) == 0 || errno == ESRCH);
        while (waitpid(child, &status, 0) == -1 && errno == EINTR)
            ;
    }
    assert(reaped);
    assert(!parent_eof || announced);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == WATCHID_EXIT_EXPIRED);
    if (!parent_eof)
        assert(watchid_now_ns() - started >= UINT64_C(1000000000));
}

int
main(void)
{
    test_arguments();
    test_sessions();
    test_child_results();
    test_terminal_state();
    test_lifetime();
    test_child_waiting();
    assert(!watchid_start_watchdog(-1, 1));
    assert(!watchid_start_watchdog(3, 0));
    test_watchdog_while_main_blocks(false);
    test_watchdog_while_main_blocks(true);
    puts("watchid native tests passed");
    return 0;
}
