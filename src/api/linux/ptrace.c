#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <errno.h>
#include <darr.h>

#include "api/proctal.h"
#include "api/linux/ptrace.h"

static inline int user_register_offset(int reg)
{
#define OFFSET_INTO_REGS(REG) \
	offsetof(struct user, regs) \
		+ offsetof(struct user_regs_struct, REG)

	switch (reg) {
	case PROCTAL_LINUX_PTRACE_X86_REG_DR0:
	case PROCTAL_LINUX_PTRACE_X86_REG_DR1:
	case PROCTAL_LINUX_PTRACE_X86_REG_DR2:
	case PROCTAL_LINUX_PTRACE_X86_REG_DR3:
	case PROCTAL_LINUX_PTRACE_X86_REG_DR4:
	case PROCTAL_LINUX_PTRACE_X86_REG_DR5:
	case PROCTAL_LINUX_PTRACE_X86_REG_DR6:
	case PROCTAL_LINUX_PTRACE_X86_REG_DR7:
		// Taking advantage that they're sequential numbers. That
		// allows us to subtract from the first one, giving us an index
		// into the debug registers array that is ordered with the same
		// sequence.
		reg -= PROCTAL_LINUX_PTRACE_X86_REG_DR0;

		return offsetof(struct user, u_debugreg)
			+ sizeof(((struct user *) 0)->u_debugreg[0]) * reg;

	case PROCTAL_LINUX_PTRACE_X86_REG_RAX:
		return OFFSET_INTO_REGS(rax);

	case PROCTAL_LINUX_PTRACE_X86_REG_RBX:
		return OFFSET_INTO_REGS(rbx);

	case PROCTAL_LINUX_PTRACE_X86_REG_RCX:
		return OFFSET_INTO_REGS(rcx);

	case PROCTAL_LINUX_PTRACE_X86_REG_RDX:
		return OFFSET_INTO_REGS(rdx);

	case PROCTAL_LINUX_PTRACE_X86_REG_RSI:
		return OFFSET_INTO_REGS(rsi);

	case PROCTAL_LINUX_PTRACE_X86_REG_RDI:
		return OFFSET_INTO_REGS(rdi);

	case PROCTAL_LINUX_PTRACE_X86_REG_RBP:
		return OFFSET_INTO_REGS(rbp);

	case PROCTAL_LINUX_PTRACE_X86_REG_RSP:
		return OFFSET_INTO_REGS(rsp);

	case PROCTAL_LINUX_PTRACE_X86_REG_RIP:
		return OFFSET_INTO_REGS(rip);

	case PROCTAL_LINUX_PTRACE_X86_REG_EFLAGS:
		return OFFSET_INTO_REGS(eflags);

	case PROCTAL_LINUX_PTRACE_X86_REG_R8:
		return OFFSET_INTO_REGS(r8);

	case PROCTAL_LINUX_PTRACE_X86_REG_R9:
		return OFFSET_INTO_REGS(r9);

	case PROCTAL_LINUX_PTRACE_X86_REG_R10:
		return OFFSET_INTO_REGS(r10);

	case PROCTAL_LINUX_PTRACE_X86_REG_R11:
		return OFFSET_INTO_REGS(r11);

	case PROCTAL_LINUX_PTRACE_X86_REG_R12:
		return OFFSET_INTO_REGS(r12);

	case PROCTAL_LINUX_PTRACE_X86_REG_R13:
		return OFFSET_INTO_REGS(r13);

	case PROCTAL_LINUX_PTRACE_X86_REG_R14:
		return OFFSET_INTO_REGS(r14);

	case PROCTAL_LINUX_PTRACE_X86_REG_R15:
		return OFFSET_INTO_REGS(r15);

	default:
		// Not implemented.
		return -1;
	}

#undef OFFSET_INTO_REGS
}

static int check_errno_waitpid(struct proctal *p)
{
	if (errno == 0) {
		return 0;
	}

	switch (errno) {
	case EPERM:
		proctal_error_set(p, PROCTAL_ERROR_PERMISSION_DENIED);
		break;

	case ESRCH:
		proctal_error_set(p, PROCTAL_ERROR_PROGRAM_NOT_FOUND);
		break;

	case EINTR:
		proctal_error_set(p, PROCTAL_ERROR_INTERRUPT);
		break;

	default:
		proctal_error_set(p, PROCTAL_ERROR_UNKNOWN);
		break;
	}

	return 1;
}

static int handle_signal_status(struct proctal_linux *pl, struct proctal_linux_ptrace_task *task, int wstatus)
{
	if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
		for (task = darr_begin(&pl->ptrace.tasks); task != darr_end(&pl->ptrace.tasks); ++task) {
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

static int check_errno_ptrace_run_state(struct proctal_linux *pl)
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

static int check_errno_ptrace_stop_state(struct proctal_linux *pl)
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

static int wait_ptrace_stop(struct proctal_linux *pl, struct proctal_linux_ptrace_task *task)
{
	int wstatus;

	for (;;) {
		waitpid(task->tid, &wstatus, WUNTRACED);

		if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGSTOP) {
			task->running = 0;
			return 1;
		} else if (!handle_signal_status(pl, task, wstatus)) {
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

	for (task = darr_begin(&pl->ptrace.tasks); task != darr_end(&pl->ptrace.tasks); ++task) {
		if (task->running) {
			continue;
		}

		if (ptrace(PTRACE_DETACH, task->tid, 0L, 0L) == -1) {
			check_errno_ptrace_stop_state(pl);
			return 0;
		}
	}

	darr_resize(&pl->ptrace.tasks, 0);

	return 1;
}

static int is_thread_attached(struct proctal_linux *pl, pid_t tid)
{
	struct proctal_linux_ptrace_task *task;

	for (task = darr_begin(&pl->ptrace.tasks); task != darr_end(&pl->ptrace.tasks); ++task) {
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
	// thread. So we're going to attach to it first and afterwards lookup
	// the ids of the other threads.

	if (ptrace(PTRACE_ATTACH, pl->pid, 0L, 0L) == -1) {
		check_errno_ptrace_run_state(pl);
		return 0;
	}

	darr_resize(&pl->ptrace.tasks, 1);
	task = darr_address(&pl->ptrace.tasks, 0);
	*task = (struct proctal_linux_ptrace_task) {
		.tid = pl->pid,
		.running = 1,
	};

	// Now lookup the ids of the other threads.

	struct darr *tids = proctal_linux_task_ids(pl->pid);

	darr_resize(&pl->ptrace.tasks, darr_size(&pl->ptrace.tasks) + darr_size(tids) - 1);

	task = darr_address(&pl->ptrace.tasks, 1); 

	for (pid_t *tid = darr_begin(tids); tid != darr_end(tids); ++tid) {
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
	for (task = darr_address(&pl->ptrace.tasks, 1); task != darr_end(&pl->ptrace.tasks); ++task) {
		if (ptrace(PTRACE_ATTACH, task->tid, 0L, 0L) == -1) {
			check_errno_ptrace_run_state(pl);
			detach_threads(pl);
			return 0;
		}
	}

	// Now that we've attached to all processes, we're going to wait for
	// the mandatory stop signal for each one.
	for (task = darr_begin(&pl->ptrace.tasks); task != darr_end(&pl->ptrace.tasks); ++task) {
		if (!wait_ptrace_stop(pl, task)) {
			detach_threads(pl);
			return 0;
		}
	}

	return 1;
}

struct tasks_cursor {
	struct proctal_linux_ptrace_task *tasks;
	size_t size;
};

static void make_tasks_cursor(struct proctal_linux *pl, struct tasks_cursor *tc, pid_t tid)
{
	if (tid == 0) {
		tc->tasks = darr_data(&pl->ptrace.tasks);
		tc->size = darr_size(&pl->ptrace.tasks);
	} else {
		struct proctal_linux_ptrace_task *task;

		for (task = darr_begin(&pl->ptrace.tasks); task != darr_end(&pl->ptrace.tasks); ++task) {
			if (task->tid == tid) {
				tc->tasks = task;
				tc->size = 1;
				return;
			}
		}

		tc->tasks = NULL;
		tc->size = 0;
	}
}

pid_t proctal_linux_ptrace_wait_trap(struct proctal_linux *pl, pid_t tid)
{
	struct tasks_cursor tc;
	make_tasks_cursor(pl, &tc, tid);

	for (;;) {
		for (size_t i = 0; i < tc.size; ++i) {
			struct proctal_linux_ptrace_task *task = &tc.tasks[i];

			int wstatus;
			int wresult = waitpid(task->tid, &wstatus, WUNTRACED);

			if (wresult == -1) {
				if (check_errno_waitpid(&pl->p)) {
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
	struct tasks_cursor tc;
	make_tasks_cursor(pl, &tc, tid);

	int wstatus;
	int wresult;
	struct proctal_linux_ptrace_task *task;

	for (size_t i = 0; i < tc.size; ++i) {
		task = &tc.tasks[i];

		wresult = waitpid(task->tid, &wstatus, WUNTRACED | WNOHANG);

		if (wresult == 0) {
			// Giving other tasks a chance to work.
			usleep(0);
			continue;
		}

		if (wresult == -1) {
			if (check_errno_waitpid(&pl->p)) {
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

int proctal_linux_ptrace_instruction_pointer(struct proctal_linux *pl, pid_t tid, void **addr)
{
	return proctal_linux_ptrace_x86_reg(
		pl,
		tid,
		PROCTAL_LINUX_PTRACE_X86_REG_RIP,
		(unsigned long long *) addr);
}

int proctal_linux_ptrace_instruction_pointer_set(struct proctal_linux *pl, pid_t tid, void *addr)
{
	return proctal_linux_ptrace_x86_reg_set(
		pl,
		tid,
		PROCTAL_LINUX_PTRACE_X86_REG_RIP,
		(unsigned long long) addr);
}

int proctal_linux_ptrace_x86_reg(struct proctal_linux *pl, pid_t tid, int reg, unsigned long long *v)
{
	int offset = user_register_offset(reg);

	if (offset == -1) {
		proctal_error_set(&pl->p, PROCTAL_ERROR_UNSUPPORTED);
		return 0;
	}

	errno = 0;

	*v = ptrace(PTRACE_PEEKUSER, tid, offset, 0);

	if (check_errno_ptrace_stop_state(pl)) {
		return 0;
	}

	return 1;
}

int proctal_linux_ptrace_x86_reg_set(struct proctal_linux *pl, pid_t tid, int reg, unsigned long long v)
{
	int offset = user_register_offset(reg);

	if (offset == -1) {
		proctal_error_set(&pl->p, PROCTAL_ERROR_UNSUPPORTED);
		return 0;
	}

	errno = 0;

	ptrace(PTRACE_POKEUSER, tid, offset, v);

	if (check_errno_ptrace_stop_state(pl)) {
		return 0;
	}

	return 1;
}

int proctal_linux_ptrace_stop(struct proctal_linux *pl, pid_t tid)
{
	struct tasks_cursor tc;
	make_tasks_cursor(pl, &tc, tid);

	for (size_t i = 0; i < tc.size; ++i) {
		struct proctal_linux_ptrace_task *task = &tc.tasks[i];

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
	struct tasks_cursor tc;
	make_tasks_cursor(pl, &tc, tid);

	for (size_t i = 0; i < tc.size; ++i) {
		struct proctal_linux_ptrace_task *task = &tc.tasks[i];

		if (task->running) {
			// This task is still running.
			continue;
		}

		if (ptrace(PTRACE_CONT, task->tid, 0, 0) != 0) {
			check_errno_ptrace_stop_state(pl);
			return 0;
		}

		task->running = 1;
	}

	return 1;
}

int proctal_linux_ptrace_step(struct proctal_linux *pl, pid_t tid)
{
	struct tasks_cursor tc;
	make_tasks_cursor(pl, &tc, tid);

	for (size_t i = 0; i < tc.size; ++i) {
		struct proctal_linux_ptrace_task *task = &tc.tasks[i];

		if (task->running) {
			// This task is running. Don't touch it.
			continue;
		}

		if (ptrace(PTRACE_SINGLESTEP, task->tid, 0, 0) != 0) {
			check_errno_ptrace_stop_state(pl);
			return 0;
		}

		if (!proctal_linux_ptrace_wait_trap(pl, task->tid)) {
			return 0;
		}
	}

	return 1;
}
