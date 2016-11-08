#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/ptrace.h>

#include "proctal.h"
#include "internal.h"

int proctal_freeze(proctal p)
{
	if (ptrace(PTRACE_ATTACH, proctal_pid(p), 0, 0) == -1) {
		switch (errno) {
		case EPERM:
			proctal_set_error(p, PROCTAL_ERROR_PERMISSION_DENIED);
			break;

		default:
			proctal_set_error(p, PROCTAL_ERROR_UNKNOWN);
			break;
		}

		return 0;
	}

	return 1;
}

int proctal_unfreeze(proctal p)
{
	if (ptrace(PTRACE_DETACH, proctal_pid(p), 0, 0) == -1) {
		switch (errno) {
		case EACCES:
			proctal_set_error(p, PROCTAL_ERROR_PERMISSION_DENIED);
			break;

		default:
			proctal_set_error(p, PROCTAL_ERROR_UNKNOWN);
			break;
		}

		return 0;
	}

	return 1;
}
