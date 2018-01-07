#include "api/linux/proctal.h"
#include "api/linux/ptrace.h"
#include "api/linux/ptrace/internal.h"

struct proctal_linux_ptrace_cpu_state *proctal_linux_ptrace_implementation_cpu_state_create(struct proctal_linux *pl)
{
	proctal_error_set(&pl->p, PROCTAL_ERROR_UNSUPPORTED);
	return NULL;
}

void proctal_linux_ptrace_implementation_cpu_state_destroy(struct proctal_linux *pl, struct proctal_linux_ptrace_cpu_state *state)
{
	proctal_error_set(&pl->p, PROCTAL_ERROR_UNSUPPORTED);
}

int proctal_linux_ptrace_implementation_cpu_state_save(struct proctal_linux *pl, pid_t tid, struct proctal_linux_ptrace_cpu_state *state)
{
	proctal_error_set(&pl->p, PROCTAL_ERROR_UNSUPPORTED);
	return 0;
}

int proctal_linux_ptrace_implementation_cpu_state_load(struct proctal_linux *pl, pid_t tid, struct proctal_linux_ptrace_cpu_state *state)
{
	proctal_error_set(&pl->p, PROCTAL_ERROR_UNSUPPORTED);
	return 0;
}
