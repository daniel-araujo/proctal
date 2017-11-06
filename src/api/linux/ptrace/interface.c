/*
 * This is the functionality that the rest of the code outside this module will
 * see.
 */

#include <stddef.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include "api/darr/darr.h"
#include "api/linux/proctal.h"
#include "api/linux/ptrace.h"
#include "api/linux/ptrace/internal.h"
#include "api/linux/ptrace/implementation.h"

static struct proctal_acur *choose_tasks(struct proctal_linux *pl, pid_t tid)
{
	if (tid == 0) {
		return &pl->ptrace.tasks_cursor;
	} else {
		struct proctal_linux_ptrace_task *task;

		for (task = proctal_darr_begin(&pl->ptrace.tasks); task != proctal_darr_end(&pl->ptrace.tasks); ++task) {
			if (task->tid == tid) {
				proctal_acur_init1(&pl->ptrace.task_cursor, sizeof(*task), task, 1);
				return &pl->ptrace.task_cursor;
			}
		}

		proctal_acur_init1(&pl->ptrace.task_cursor, sizeof(*task), NULL, 0);
		return &pl->ptrace.task_cursor;
	}
}

static int handle_signal_status(struct proctal_linux *pl, struct proctal_linux_ptrace_task *task, int wstatus)
{
	if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
		for (task = proctal_darr_begin(&pl->ptrace.tasks); task != proctal_darr_end(&pl->ptrace.tasks); ++task) {
			// Mark all tasks as stopped.
			task->running = 0;
		}

		proctal_error_set(&pl->p, PROCTAL_ERROR_PROGRAM_EXITED);
		return 0;
	} else if (WIFSTOPPED(wstatus)) {
		task->running = 0;

		int sig = WSTOPSIG(wstatus);

		kill(task->tid, sig);

		switch (sig) {
		case SIGSEGV:
			proctal_error_set(&pl->p, PROCTAL_ERROR_PROGRAM_SEGFAULT);
			return 0;

		case SIGTRAP:
			proctal_error_set(&pl->p, PROCTAL_ERROR_PROGRAM_TRAPPED);
			return 0;

		case SIGINT:
			proctal_error_set(&pl->p, PROCTAL_ERROR_PROGRAM_INTERRUPT);
			return 0;

		default:
			proctal_error_set(&pl->p, PROCTAL_ERROR_PROGRAM_STOPPED);
			return 0;
		}
	}

	return 1;
}

static int wait_ptrace_stop(struct proctal_linux *pl, struct proctal_linux_ptrace_task *task)
{
	int wstatus;

	for (;;) {
		waitpid(task->tid, &wstatus, WUNTRACED);

		if (WIFSTOPPED(wstatus)) {
			switch (WSTOPSIG(wstatus)) {
			case SIGTRAP:
				// We may have placed a breakpoint but were not
				// able to handle it quickly enough, so if we
				// sent SIGSTOP while the program was "trapped"
				// we are never going to receive it unless we
				// restore execution and check for the signal
				// again.
				if (ptrace(PTRACE_CONT, task->tid, 0, 0) != 0) {
					proctal_linux_ptrace_check_stop_state_errno(pl);
					return 0;
				}
				continue;

			case SIGSTOP:
				task->running = 0;
				return 1;

			default:
				break;
			}
		}

		if (!handle_signal_status(pl, task, wstatus)) {
			return 0;
		}
	}
}

static int wait_ptrace_cont(struct proctal_linux *pl, struct proctal_linux_ptrace_task *task)
{
	int wstatus;

	for (;;) {
		waitpid(task->tid, &wstatus, WCONTINUED | WUNTRACED);

		if (WIFCONTINUED(wstatus)) {
			task->running = 1;
			return 1;
		} else if (!handle_signal_status(pl, task, wstatus)) {
			return 0;
		}
	}
}

static int detach_threads(struct proctal_linux *pl)
{
	struct proctal_linux_ptrace_task *task;

	for (task = proctal_darr_begin(&pl->ptrace.tasks); task != proctal_darr_end(&pl->ptrace.tasks); ++task) {
		if (task->running) {
			continue;
		}

		if (ptrace(PTRACE_DETACH, task->tid, 0L, 0L) == -1) {
			proctal_linux_ptrace_check_stop_state_errno(pl);
			return 0;
		}
	}

	proctal_darr_resize(&pl->ptrace.tasks, 0);

	return 1;
}

static int is_thread_attached(struct proctal_linux *pl, pid_t tid)
{
	struct proctal_linux_ptrace_task *task;

	for (task = proctal_darr_begin(&pl->ptrace.tasks); task != proctal_darr_end(&pl->ptrace.tasks); ++task) {
		if (task->tid == tid) {
			return !task->running;
		}
	}

	return 0;
}

static int attach_threads(struct proctal_linux *pl)
{
	struct proctal_linux_ptrace_task *task;

	// It just so happens that the process id is also the id of the main
	// thread. So we're going to attach to it first and afterwards look up
	// the ids of the other threads.

	if (ptrace(PTRACE_ATTACH, pl->pid, 0L, 0L) == -1) {
		proctal_linux_ptrace_check_run_state_errno(pl);
		return 0;
	}

	proctal_darr_resize(&pl->ptrace.tasks, 1);
	task = proctal_darr_element(&pl->ptrace.tasks, 0);
	*task = (struct proctal_linux_ptrace_task) {
		.tid = pl->pid,
		.running = 1,
	};

	// Now look up the ids of the other threads.

	const struct proctal_darr *tids = proctal_linux_task_ids(pl->pid);

	proctal_darr_resize(&pl->ptrace.tasks, proctal_darr_size(&pl->ptrace.tasks) + proctal_darr_size(tids) - 1);

	task = proctal_darr_element(&pl->ptrace.tasks, 1); 

	for (const pid_t *tid = proctal_darr_begin_const(tids); tid != proctal_darr_end_const(tids); ++tid) {
		if (pl->pid == *tid) {
			// Skip main thread. We've already added it.
			continue;
		}

		*task++ = (struct proctal_linux_ptrace_task) {
			.tid = *tid,
			.running = 1,
		};
	}

	proctal_linux_task_ids_dispose(tids);

	// Now attach to the rest.
	for (task = proctal_darr_element(&pl->ptrace.tasks, 1); task != proctal_darr_end(&pl->ptrace.tasks); ++task) {
		if (ptrace(PTRACE_ATTACH, task->tid, 0L, 0L) == -1) {
			proctal_linux_ptrace_check_run_state_errno(pl);
			detach_threads(pl);
			return 0;
		}
	}

	// Now that we've attached to all tasks, we're going to wait for the
	// mandatory stop signal for each one.
	for (task = proctal_darr_begin(&pl->ptrace.tasks); task != proctal_darr_end(&pl->ptrace.tasks); ++task) {
		if (!wait_ptrace_stop(pl, task)) {
			detach_threads(pl);
			return 0;
		}
	}

	// Now we can create the cursor.
	proctal_acur_init1(&pl->ptrace.tasks_cursor, sizeof(struct proctal_linux_ptrace_task), proctal_darr_data(&pl->ptrace.tasks), proctal_darr_size(&pl->ptrace.tasks));

	return 1;
}

int proctal_linux_ptrace_attach(struct proctal_linux *pl)
{
	if (pl->ptrace.count == 0) {
		if (!attach_threads(pl)) {
			return 0;
		}
	}

	++pl->ptrace.count;

	return 1;
}

int proctal_linux_ptrace_detach(struct proctal_linux *pl)
{
	if (pl->ptrace.count == 1) {
		if (!detach_threads(pl)) {
			return 0;
		}
	}

	--pl->ptrace.count;

	return 1;
}

void proctal_linux_ptrace_detach_force(struct proctal_linux *pl)
{
	if (pl->ptrace.count) {
		pl->ptrace.count = 1;
		proctal_linux_ptrace_detach(pl);
	}
}

int proctal_linux_ptrace_stop(struct proctal_linux *pl, pid_t tid)
{
	struct proctal_acur *tasks = choose_tasks(pl, tid);

	for (size_t i = 0, l = proctal_acur_size(tasks); i < l; proctal_acur_next(tasks), ++i) {
		if (proctal_acur_finished(tasks)) {
			proctal_acur_rewind(tasks);
		}

		struct proctal_linux_ptrace_task *task = proctal_acur_element(tasks);

		if (!task->running) {
			// This task has already been stopped.
			continue;
		}

		kill(task->tid, SIGSTOP);

		if (!wait_ptrace_stop(pl, task)) {
			return 0;
		}
	}

	return 1;
}

int proctal_linux_ptrace_cont(struct proctal_linux *pl, pid_t tid)
{
	struct proctal_acur *tasks = choose_tasks(pl, tid);

	for (size_t i = 0, l = proctal_acur_size(tasks); i < l; proctal_acur_next(tasks), ++i) {
		if (proctal_acur_finished(tasks)) {
			proctal_acur_rewind(tasks);
		}

		struct proctal_linux_ptrace_task *task = proctal_acur_element(tasks);

		if (task->running) {
			// This task is still running.
			continue;
		}

		if (ptrace(PTRACE_CONT, task->tid, 0, 0) != 0) {
			proctal_linux_ptrace_check_stop_state_errno(pl);
			return 0;
		}

		task->running = 1;
	}

	return 1;
}

int proctal_linux_ptrace_step(struct proctal_linux *pl, pid_t tid)
{
	struct proctal_acur *tasks = choose_tasks(pl, tid);

	for (size_t i = 0, l = proctal_acur_size(tasks); i < l; proctal_acur_next(tasks), ++i) {
		if (proctal_acur_finished(tasks)) {
			proctal_acur_rewind(tasks);
		}

		struct proctal_linux_ptrace_task *task = proctal_acur_element(tasks);

		if (task->running) {
			// This task is running. Don't touch it.
			continue;
		}

		if (ptrace(PTRACE_SINGLESTEP, task->tid, 0, 0) != 0) {
			proctal_linux_ptrace_check_stop_state_errno(pl);
			return 0;
		}

		if (!proctal_linux_ptrace_wait_trap(pl, task->tid)) {
			return 0;
		}
	}

	return 1;
}

pid_t proctal_linux_ptrace_wait_trap(struct proctal_linux *pl, pid_t tid)
{
	struct proctal_acur *tasks = choose_tasks(pl, tid);

	for (;;) {
		for (size_t i = 0, l = proctal_acur_size(tasks); i < l; proctal_acur_next(tasks), ++i) {
			if (proctal_acur_finished(tasks)) {
				proctal_acur_rewind(tasks);
			}

			struct proctal_linux_ptrace_task *task = proctal_acur_element(tasks);

			int wstatus;
			int wresult = waitpid(task->tid, &wstatus, WUNTRACED);

			if (wresult == -1) {
				if (proctal_linux_ptrace_check_waitpid_errno( pl)) {
					return 0;
				}
			}

			if (wresult != task->tid) {
				continue;
			}

			if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGTRAP) {
				task->running = 0;
				return wresult;
			} else if (!handle_signal_status(pl, task, wstatus)) {
				return 0;
			}
		}
	}
}

pid_t proctal_linux_ptrace_catch_trap(struct proctal_linux *pl, pid_t tid)
{
	struct proctal_acur *tasks = choose_tasks(pl, tid);

	int wstatus;
	int wresult;
	struct proctal_linux_ptrace_task *task;

	for (size_t i = 0, l = proctal_acur_size(tasks); i < l; proctal_acur_next(tasks), ++i) {
		if (proctal_acur_finished(tasks)) {
			proctal_acur_rewind(tasks);
		}

		task = proctal_acur_element(tasks);

		wresult = waitpid(task->tid, &wstatus, WUNTRACED | WNOHANG);

		if (wresult == 0) {
			// Giving other tasks a chance to work.
			usleep(0);
			continue;
		}

		if (wresult == -1) {
			if (proctal_linux_ptrace_check_waitpid_errno(pl)) {
				return 0;
			}
		}

		break;
	}

	if (wresult == 0) {
		// No trap.
		return 0;
	}

	if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGTRAP) {
		task->running = 0;
		return wresult;
	} else {
		handle_signal_status(pl, task, wstatus);
		return 0;
	}
}

int proctal_linux_ptrace_instruction_pointer(struct proctal_linux *pl, pid_t tid, void **address)
{
	return proctal_linux_ptrace_implementation_instruction_pointer(pl, tid, address);
}

int proctal_linux_ptrace_instruction_pointer_set(struct proctal_linux *pl, pid_t tid, void *address)
{
	return proctal_linux_ptrace_implementation_instruction_pointer_set(pl, tid, address);
}

int proctal_linux_ptrace_register(struct proctal_linux *pl, pid_t tid, int regid, void *dst)
{
	return proctal_linux_ptrace_implementation_register(pl, tid, regid, dst);
}

int proctal_linux_ptrace_register_set(struct proctal_linux *pl, pid_t tid, int regid, void *src)
{
	return proctal_linux_ptrace_implementation_register_set(pl, tid, regid, src);
}
