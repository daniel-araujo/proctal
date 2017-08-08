/*
 * Error checking.
 */

#include <errno.h>

#include "api/linux/proctal.h"
#include "api/linux/ptrace/internal.h"
#include "magic/magic.h"

int proctal_linux_ptrace_check_run_state_errno(struct proctal_linux *pl)
{
	if (errno == 0) {
		return 0;
	}

	switch (errno) {
	case EPERM:
		proctal_error_set(&pl->p, PROCTAL_ERROR_PERMISSION_DENIED);
		break;

	case ESRCH:
		proctal_error_set(&pl->p, PROCTAL_ERROR_PROGRAM_NOT_FOUND);
		break;

	default:
		proctal_error_set(&pl->p, PROCTAL_ERROR_UNKNOWN);
		break;
	}

	return 1;
}

int proctal_linux_ptrace_check_stop_state_errno(struct proctal_linux *pl)
{
	if (errno == 0) {
		return 0;
	}

	switch (errno) {
	case EACCES:
		proctal_error_set(&pl->p, PROCTAL_ERROR_PERMISSION_DENIED);
		break;

	case ESRCH:
		proctal_error_set(&pl->p, PROCTAL_ERROR_PROGRAM_UNTAMEABLE);
		break;

	default:
		proctal_error_set(&pl->p, PROCTAL_ERROR_UNKNOWN);
		break;
	}

	return 1;
}

int proctal_linux_ptrace_check_waitpid_errno(struct proctal_linux *pl)
{
	if (errno == 0) {
		return 0;
	}

	switch (errno) {
	case EPERM:
		proctal_error_set(&pl->p, PROCTAL_ERROR_PERMISSION_DENIED);
		break;

	case ESRCH:
		proctal_error_set(&pl->p, PROCTAL_ERROR_PROGRAM_NOT_FOUND);
		break;

	case EINTR:
		proctal_error_set(&pl->p, PROCTAL_ERROR_INTERRUPT);
		break;

	default:
		proctal_error_set(&pl->p, PROCTAL_ERROR_UNKNOWN);
		break;
	}

	return 1;
}
