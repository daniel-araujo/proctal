#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "api/linux/proctal.h"
#include "api/linux/watch.h"
#include "api/linux/watch/implementation.h"

/*
 * Attempts to disable breakpoints on as many tasks as possible.
 */
static inline void try_disable_breakpoints(
	struct proctal_linux *pl,
	struct proctal_linux_ptrace_task *begin,
	struct proctal_linux_ptrace_task *end)
{
	struct proctal_linux_ptrace_task *task;

	for (task = begin; task != end; ++task) {
		proctal_linux_watch_implementation_breakpoint_disable(pl, task->tid);
	}
}

void proctal_linux_watch_start(struct proctal_linux *pl)
{
	if (!proctal_linux_ptrace_attach(pl)) {
		return;
	}

	for (struct proctal_linux_ptrace_task *task = darr_begin(&pl->ptrace.tasks); task != darr_end(&pl->ptrace.tasks); ++task) {
		if (!proctal_linux_watch_implementation_breakpoint_enable(pl, task->tid)) {
			try_disable_breakpoints(pl, darr_begin(&pl->ptrace.tasks), task);
			proctal_linux_ptrace_detach(pl);
			return;
		}
	}

	if (!proctal_linux_ptrace_cont(pl, 0)) {
		try_disable_breakpoints(pl, darr_begin(&pl->ptrace.tasks), darr_end(&pl->ptrace.tasks));
		proctal_linux_ptrace_detach(pl);
		return;
	}
}

void proctal_linux_watch_stop(struct proctal_linux *pl)
{
	for (struct proctal_linux_ptrace_task *task = darr_begin(&pl->ptrace.tasks); task != darr_end(&pl->ptrace.tasks); ++task) {
		proctal_linux_ptrace_stop(pl, task->tid);
		proctal_linux_watch_implementation_breakpoint_disable(pl, task->tid);
	}

	proctal_linux_ptrace_detach(pl);
}

int proctal_linux_watch(struct proctal_linux *pl, void **addr)
{
	pid_t tid = proctal_linux_ptrace_catch_trap(pl, 0);

	if (tid == 0) {
		return 0;
	}

	proctal_linux_ptrace_instruction_pointer(pl, tid, addr);

	if (!proctal_linux_ptrace_cont(pl, tid)) {
		return 0;
	}

	return 1;
}
