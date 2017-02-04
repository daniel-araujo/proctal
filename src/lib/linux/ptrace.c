#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <errno.h>

#include "lib/proctal.h"
#include "lib/linux/ptrace.h"

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

static int proctal_linux_ptrace_wait_stop(struct proctal_linux *pl)
{
	int wstatus;

	for (;;) {
		waitpid(pl->pid, &wstatus, WUNTRACED);

		if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGSTOP) {
			break;
		} else if (bad_signal(pl, wstatus)) {
			return 0;
		}
	}

	return 1;
}

static int proctal_linux_ptrace_wait_cont(struct proctal_linux *pl)
{
	int wstatus;

	for (;;) {
		waitpid(pl->pid, &wstatus, WCONTINUED | WUNTRACED);

		if (WIFCONTINUED(wstatus)) {
			break;
		} else if (bad_signal(pl, wstatus)) {
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
	if (pl->ptrace == 0) {
		if (ptrace(PTRACE_ATTACH, pl->pid, 0L, 0L) == -1) {
			check_errno_ptrace_run_state(pl);
			return 0;
		}

		pl->ptrace = 1;

		if (!proctal_linux_ptrace_wait_stop(pl)) {
			proctal_linux_ptrace_detach(pl);
			return 0;
		}
	} else {
		++pl->ptrace;
	}

	return 1;
}

int proctal_linux_ptrace_detach(struct proctal_linux *pl)
{
	if (pl->ptrace > 1) {
		if (--pl->ptrace) {
			return 1;
		}
	}

	if (ptrace(PTRACE_DETACH, pl->pid, 0L, 0L) == -1) {
		check_errno_ptrace_stop_state(pl);
		return 0;
	}

	pl->ptrace = 0;

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

	if (!proctal_linux_ptrace_wait_stop(pl)) {
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
