/* SPDX-License-Identifier: MIT */
#ifndef WATCHID_WATCHDOG_H
#define WATCHID_WATCHDOG_H

#include <stdbool.h>
#include <stdint.h>

/* Helper-only: the detached watchdog remains active until process exit. */
bool watchid_start_watchdog(int lifetime_fd, uint64_t deadline_ns);

#endif
