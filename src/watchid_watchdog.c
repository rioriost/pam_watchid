/* SPDX-License-Identifier: MIT */
#include "watchid_watchdog.h"
#include "watchid_common.h"

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

struct watchdog_request {
    int lifetime_fd;
    uint64_t deadline_ns;
};

static void *
watch_lifetime(void *opaque)
{
    struct watchdog_request request = *(struct watchdog_request *)opaque;
    /* Retain the allocation until process exit; allocator locks must not
     * interfere with monitoring while another thread is in framework code. */
    for (;;) {
        uint64_t now = watchid_now_ns();
        if (now == 0 || now >= request.deadline_ns)
            break;
        uint64_t remaining = request.deadline_ns - now;
        uint64_t milliseconds = remaining / UINT64_C(1000000) +
            (remaining % UINT64_C(1000000) != 0);
        int timeout = milliseconds > INT_MAX ? INT_MAX : (int)milliseconds;
        struct pollfd lifetime = { .fd = request.lifetime_fd, .events = POLLIN };
        int result = poll(&lifetime, 1, timeout);
        if (result > 0 || (result < 0 && errno != EINTR))
            break;
    }
    /* Neither an authentication lock nor invalidate may block this bound.
     * Tearing down this dedicated process cancels LA and ends its callbacks. */
    _exit(WATCHID_EXIT_EXPIRED);
}

bool
watchid_start_watchdog(int lifetime_fd, uint64_t deadline_ns)
{
    if (lifetime_fd < 0 || deadline_ns == 0)
        return false;
    struct watchdog_request *request = malloc(sizeof(*request));
    if (request == NULL)
        return false;
    request->lifetime_fd = lifetime_fd;
    request->deadline_ns = deadline_ns;
    pthread_attr_t attributes;
    if (pthread_attr_init(&attributes) != 0) {
        free(request);
        return false;
    }
    int error = pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
    if (error == 0) {
        pthread_t thread;
        error = pthread_create(&thread, &attributes, watch_lifetime, request);
    }
    pthread_attr_destroy(&attributes);
    if (error != 0)
        free(request);
    return error == 0;
}
