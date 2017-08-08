/*
 * This implementation relies on an offset into the user struct to get the
 * values of the registers.
 */

#include <stddef.h>
#include <sys/user.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <darr.h>

#include "api/linux/proctal.h"
#include "api/linux/ptrace/internal.h"
#include "api/linux/ptrace/implementation.h"
#include "magic/magic.h"

/*
 * Returns an offset into the user struct.
 *
 * On failure it returns -1.
 */
int proctal_linux_ptrace_implementation_register_user_offset(int regid);

int proctal_linux_ptrace_implementation_register(struct proctal_linux *pl, pid_t tid, int regid, void *dst)
{
	int offset = proctal_linux_ptrace_implementation_register_user_offset(regid);

	if (offset == -1) {
		proctal_error_set(&pl->p, PROCTAL_ERROR_UNSUPPORTED);
		return 0;
	}

	errno = 0;

	// Assuming all registers are the size of a word.

	unsigned long long v = ptrace(PTRACE_PEEKUSER, tid, offset, 0);

	if (proctal_linux_ptrace_check_stop_state_errno(pl)) {
		return 0;
	}

	DEREF(unsigned long long, dst) = v;

	return 1;
}

int proctal_linux_ptrace_implementation_register_set(struct proctal_linux *pl, pid_t tid, int regid, void *src)
{
	int offset = proctal_linux_ptrace_implementation_register_user_offset(regid);

	if (offset == -1) {
		proctal_error_set(&pl->p, PROCTAL_ERROR_UNSUPPORTED);
		return 0;
	}

	errno = 0;

	// Assuming all registers are the size of a word.

	ptrace(PTRACE_POKEUSER, tid, offset, DEREF(unsigned long long, src));

	if (proctal_linux_ptrace_check_stop_state_errno(pl)) {
		return 0;
	}

	return 1;
}
