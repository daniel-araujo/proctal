#include <stdlib.h>

#include "api/proctal.h"

static const char *a[] = {
	[0] = NULL,
	[PROCTAL_ERROR_OUT_OF_MEMORY] = "Out of memory.",
	[PROCTAL_ERROR_PERMISSION_DENIED] = "Permission denied.",
	[PROCTAL_ERROR_WRITE_FAILURE] = "Failed to write everything out.",
	[PROCTAL_ERROR_READ_FAILURE] = "Failed to read everything in.",
	[PROCTAL_ERROR_UNKNOWN] = "Unknown failure.",
	[PROCTAL_ERROR_UNIMPLEMENTED] = "Not implemented.",
	[PROCTAL_ERROR_UNSUPPORTED] = "Not supported.",
	[PROCTAL_ERROR_UNSUPPORTED_WATCH_READ] =
		"Watching only for reads is not supported yet."
		" You can watch for both reads and writes in the mean time.",
	[PROCTAL_ERROR_UNSUPPORTED_WATCH_READ_EXECUTE] =
		"Watching for reads and instruction executions at once is not supported.",
	[PROCTAL_ERROR_UNSUPPORTED_WATCH_WRITE_EXECUTE] =
		"Watching for writes and instruction executions at once is not supported.",
	[PROCTAL_ERROR_UNSUPPORTED_WATCH_READ_WRITE_EXECUTE] =
		"Watching for reads, writes and instruction executions at once is not supported.",
	[PROCTAL_ERROR_PROGRAM_NOT_FOUND] = "Program not found.",
	[PROCTAL_ERROR_PROGRAM_NOT_SET] = "Program was not set.",
	[PROCTAL_ERROR_INJECT_ADDR_NOT_FOUND] = "Could not find a suitable address in memory to inject code in.",
	[PROCTAL_ERROR_PROGRAM_SEGFAULT] = "Program hit segmentation fault.",
	[PROCTAL_ERROR_PROGRAM_EXITED] = "Program has exited.",
	[PROCTAL_ERROR_PROGRAM_STOPPED] = "Program has stopped.",
	[PROCTAL_ERROR_PROGRAM_UNTAMEABLE] = "Program is in a state that cannot be dealt with.",
	[PROCTAL_ERROR_PROGRAM_TRAPPED] = "Program got trapped.",
	[PROCTAL_ERROR_INTERRUPT] = "An interrupt occurred.",
	[PROCTAL_ERROR_PROGRAM_INTERRUPT] = "Program got interrupt.",
};

int proctal_error(proctal_t p)
{
	if (p == NULL) {
		return PROCTAL_ERROR_OUT_OF_MEMORY;
	}

	return p->error;
}

void proctal_set_error(proctal_t p, int error)
{
	p->error = error;
}

void proctal_error_ack(proctal_t p)
{
	p->error = 0;
}

const char *proctal_error_msg(proctal_t p)
{
	return a[proctal_error(p)];
}
