#include <stdlib.h>
#include <stdio.h>
#include <sys/ptrace.h>

#include "proctal.h"
#include "internal.h"

int proctal_freeze(proctal p)
{
	proctal_ptrace_attach(p);

	if (ptrace(PTRACE_SINGLESTEP, proctal_pid(p), 0L, 0L) == -1) {
		proctal_set_error(p, PROCTAL_ERROR_UNKNOWN);
		return 0;
	}

	return 1;
}

int proctal_unfreeze(proctal p)
{
	ptrace(PTRACE_CONT, proctal_pid(p), 0L, 0L);

	proctal_ptrace_detach(p);

	return 1;
}
