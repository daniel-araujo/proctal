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

static int bad_signal(struct proctal_linux *pl, int wstatus)
{
	if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
		proctal_set_error(&pl->p, PROCTAL_ERROR_PROCESS_EXITED);
		return 1;
	} else if (WIFSTOPPED(wstatus)) {
		int sig = WSTOPSIG(wstatus);

		switch (sig) {
		case SIGSEGV:
			proctal_set_error(&pl->p, PROCTAL_ERROR_PROCESS_SEGFAULT);
			return 1;

		case SIGTRAP:
			proctal_set_error(&pl->p, PROCTAL_ERROR_PROCESS_TRAPPED);
			return 1;

		default:
			proctal_set_error(&pl->p, PROCTAL_ERROR_PROCESS_STOPPED);
			return 1;
		}
	}

	return 0;
}

static int check_errno_ptrace_run_state(struct proctal_linux *pl)
{
	if (errno == 0) {
		return 0;
	}

	switch (errno) {
	case EPERM:
		proctal_set_error(&pl->p, PROCTAL_ERROR_PERMISSION_DENIED);
		break;

	case ESRCH:
		proctal_set_error(&pl->p, PROCTAL_ERROR_PROCESS_NOT_FOUND);
		break;

	default:
		proctal_set_error(&pl->p, PROCTAL_ERROR_UNKNOWN);
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
		proctal_set_error(&pl->p, PROCTAL_ERROR_PERMISSION_DENIED);
		break;

	case ESRCH:
		proctal_set_error(&pl->p, PROCTAL_ERROR_PROCESS_UNTAMEABLE);
		break;

	default:
		proctal_set_error(&pl->p, PROCTAL_ERROR_UNKNOWN);
		break;
	}

	return 1;
}

static int wait_ptrace_stop(struct proctal_linux *pl, pid_t tid)
{
	int wstatus;

	for (;;) {
		waitpid(tid, &wstatus, WUNTRACED);

		if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGSTOP) {
			break;
		} else if (bad_signal(pl, wstatus)) {
			return 0;
		}
	}

	return 1;
}

static int wait_ptrace_cont(struct proctal_linux *pl, pid_t tid)
{
	int wstatus;

	for (;;) {
		waitpid(tid, &wstatus, WCONTINUED | WUNTRACED);

		if (WIFCONTINUED(wstatus)) {
			break;
		} else if (bad_signal(pl, wstatus)) {
			return 0;
		}
	}

	return 1;
}

static int detach_threads(struct proctal_linux *pl)
{
	pid_t *e = darr_address(&pl->ptrace.tids, 0);
	for (size_t i = 0; i < darr_size(&pl->ptrace.tids); ++i) {
		if (ptrace(PTRACE_DETACH, e[i], 0L, 0L) == -1) {
			check_errno_ptrace_stop_state(pl);
			return 0;
		}
	}

	darr_resize(&pl->ptrace.tids, 0);

	return 1;
}

static int is_thread_attached(struct proctal_linux *pl, pid_t tid)
{
	pid_t *e = darr_address(&pl->ptrace.tids, 0);

	for (size_t i = 0; i < darr_size(&pl->ptrace.tids); ++i) {
		if (e[i] == tid) {
			return 1;
		}
	}

	return 0;
}

static int attach_threads(struct proctal_linux *pl)
{
	if (ptrace(PTRACE_ATTACH, pl->pid, 0L, 0L) == -1) {
		check_errno_ptrace_run_state(pl);
		return 0;
	}

	darr_resize(&pl->ptrace.tids, 1);
	pid_t *e = darr_address(&pl->ptrace.tids, 0);

	// It just so happens that the process id is also the id of the main
	// thread.
	*e = pl->pid;

	struct darr *tids = proctal_linux_task_ids(pl->pid);

	// Attach to all threads that have not been attached yet.
	for (size_t i = 0; i < darr_size(tids); ++i) {
		pid_t *t = darr_address(tids, i);

		if (is_thread_attached(pl, *t)) {
			continue;
		}

		if (ptrace(PTRACE_ATTACH, *t, 0L, 0L) == -1) {
			check_errno_ptrace_run_state(pl);
			// In case of failure, detach the ones we could.
			detach_threads(pl);
			return 0;
		}

		darr_resize(&pl->ptrace.tids, darr_size(&pl->ptrace.tids) + 1);
		e = darr_address(&pl->ptrace.tids, darr_size(&pl->ptrace.tids) - 1);
		*e = *t;
	}

	proctal_linux_task_ids_dispose(tids);

	// Now that we've attached to all processes, we're going to wait for
	// the mandatory stop signal for each one.
	e = darr_address(&pl->ptrace.tids, 0);
	for (size_t i = 0; i < darr_size(&pl->ptrace.tids); ++i) {
		if (!wait_ptrace_stop(pl, e[i])) {
			proctal_linux_ptrace_detach(pl);
			// In case of failure, detach them all.
			detach_threads(pl);
			return 0;
		}
	}

	return 1;
}

int proctal_linux_ptrace_wait_trap(struct proctal_linux *pl)
{
	int wstatus;

	for (;;) {
		waitpid(pl->pid, &wstatus, WUNTRACED);

		if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGTRAP) {
			break;
		} else if (bad_signal(pl, wstatus)) {
			return 0;
		}
	}

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

int proctal_linux_ptrace_get_instruction_address(struct proctal_linux *pl, void **addr)
{
	return proctal_linux_ptrace_get_x86_reg(
		pl,
		PROCTAL_LINUX_PTRACE_X86_REG_RIP,
		(unsigned long long *) addr);
}

int proctal_linux_ptrace_set_instruction_address(struct proctal_linux *pl, void *addr)
{
	return proctal_linux_ptrace_set_x86_reg(
		pl,
		PROCTAL_LINUX_PTRACE_X86_REG_RIP,
		(unsigned long long) addr);
}

int proctal_linux_ptrace_get_x86_reg(struct proctal_linux *pl, int reg, unsigned long long *v)
{
	int offset = user_register_offset(reg);

	if (offset == -1) {
		proctal_set_error(&pl->p, PROCTAL_ERROR_UNSUPPORTED);
		return 0;
	}

	errno = 0;

	*v = ptrace(PTRACE_PEEKUSER, pl->pid, offset, 0);

	if (check_errno_ptrace_stop_state(pl)) {
		return 0;
	}

	return 1;
}

int proctal_linux_ptrace_set_x86_reg(struct proctal_linux *pl, int reg, unsigned long long v)
{
	int offset = user_register_offset(reg);

	if (offset == -1) {
		proctal_set_error(&pl->p, PROCTAL_ERROR_UNSUPPORTED);
		return 0;
	}

	errno = 0;

	ptrace(PTRACE_POKEUSER, pl->pid, offset, v);

	if (check_errno_ptrace_stop_state(pl)) {
		return 0;
	}

	return 1;
}

int proctal_linux_ptrace_stop(struct proctal_linux *pl)
{
	kill(pl->pid, SIGSTOP);

	if (!wait_ptrace_stop(pl, pl->pid)) {
		return 0;
	}

	return 1;
}

int proctal_linux_ptrace_cont(struct proctal_linux *pl)
{
	if (ptrace(PTRACE_CONT, pl->pid, 0, 0) != 0) {
		check_errno_ptrace_stop_state(pl);
		return 0;
	}

	return 1;
}

int proctal_linux_ptrace_step(struct proctal_linux *pl)
{
	if (ptrace(PTRACE_SINGLESTEP, pl->pid, 0, 0) != 0) {
		check_errno_ptrace_stop_state(pl);
		return 0;
	}

	if (!proctal_linux_ptrace_wait_trap(pl)) {
		return 0;
	}

	return 1;
}
