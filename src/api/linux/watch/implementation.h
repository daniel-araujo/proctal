#ifndef API_LINUX_WATCH_IMPLEMENTATION_H
#define API_LINUX_WATCH_IMPLEMENTATION_H

#include "api/linux/proctal.h"

/*
 * Turns on the breakpoint.
 *
 * Returns 1 on success, 0 on failure.
 */
int proctal_linux_watch_implementation_breakpoint_enable(struct proctal_linux *pl, pid_t tid);

/*
 * Turns off the breakpoint.
 *
 * Returns 1 on success, 0 on failure.
 */
int proctal_linux_watch_implementation_breakpoint_disable(struct proctal_linux *pl, pid_t tid);

#endif /* API_LINUX_WATCH_IMPLEMENTATION_H */
