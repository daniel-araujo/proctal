#ifndef API_LINUX_PTRACE_INTERNAL_H
#define API_LINUX_PTRACE_INTERNAL_H

#include "api/linux/proctal.h"
#include "api/linux/ptrace.h"

/*
 * Checks whether ptrace reports an error through errno in run state.
 *
 * Automatically sets the appropriate error code for proctal if an error is
 * found.
 *
 * This function should only be called when either errno was set to 0 or when
 * ptrace's return value absolutely means an error occurred.
 *
 * Returns 1 if an error was found, 0 if not.
 */
int proctal_linux_ptrace_check_run_state_errno(struct proctal_linux *pl);

/*
 * Checks whether ptrace reports an error through errno in stop state.
 *
 * Automatically sets the appropriate error code for proctal if an error is
 * found.
 *
 * This function should only be called when either errno was set to 0 or when
 * ptrace's return value absolutely means an error occurred.
 *
 * Returns 1 if an error was found, 0 if not.
 */
int proctal_linux_ptrace_check_stop_state_errno(struct proctal_linux *pl);

/*
 * Checks whether waitpid reports an error when waiting for ptrace signals.
 *
 * Automatically sets the appropriate error code for proctal if an error is
 * found.
 *
 * This function should only be called when either errno was set to 0 or when
 * waitpid's return value absolutely means an error occurred.
 *
 * Returns 1 if an error was found, 0 if not.
 */
int proctal_linux_ptrace_check_waitpid_errno(struct proctal_linux *pl);

#endif /* API_LINUX_PTRACE_INTERNAL_H */
