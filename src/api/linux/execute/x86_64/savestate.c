#include "api/linux/proctal.h"
#include "api/linux/ptrace.h"

void *proctal_linux_execute_implementation_save_state(struct proctal_linux *pl, pid_t tid)
{
	struct proctal_linux_ptrace_cpu_state *state = proctal_linux_ptrace_cpu_state_create(pl);

	if (state == NULL) {
		return NULL;
	}

	if (!proctal_linux_ptrace_cpu_state_save(pl, tid, state)) {
		proctal_linux_ptrace_cpu_state_destroy(pl, state);
		return NULL;
	}

	return state;
}

int proctal_linux_execute_implementation_load_state(struct proctal_linux *pl, pid_t tid, void *state)
{
	if (!proctal_linux_ptrace_cpu_state_load(pl, tid, state)) {
		proctal_linux_ptrace_cpu_state_destroy(pl, state);
		return 0;
	}

	proctal_linux_ptrace_cpu_state_destroy(pl, state);
	return 1;
}
