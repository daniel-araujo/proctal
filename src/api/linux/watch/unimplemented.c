#include "api/linux/proctal.h"
#include "api/linux/watch.h"
#include "api/linux/watch/implementation.h"

int proctal_linux_watch_implementation_breakpoint_enable(struct proctal_linux *pl, pid_t tid)
{
	proctal_error_set(&pl->p, PROCTAL_ERROR_UNSUPPORTED);
	return 0;
}

int proctal_linux_watch_implementation_breakpoint_disable(struct proctal_linux *pl, pid_t tid)
{
	proctal_error_set(&pl->p, PROCTAL_ERROR_UNSUPPORTED);
	return 0;
}
