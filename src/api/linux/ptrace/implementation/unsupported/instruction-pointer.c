#include "api/linux/proctal.h"
#include "api/linux/ptrace.h"
#include "api/linux/ptrace/internal.h"

int proctal_linux_ptrace_implementation_instruction_pointer(struct proctal_linux *pl, pid_t tid, void **address)
{
	proctal_error_set(&pl->p, PROCTAL_ERROR_UNSUPPORTED);
	return 0;
}

int proctal_linux_ptrace_implementation_instruction_pointer_set(struct proctal_linux *pl, pid_t tid, void *address)
{
	proctal_error_set(&pl->p, PROCTAL_ERROR_UNSUPPORTED);
	return 0;
}
