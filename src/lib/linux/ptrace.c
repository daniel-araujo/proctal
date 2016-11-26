#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <errno.h>

#include <proctal.h>
#include <linux/ptrace.h>

#define PROCTAL_LINUX_PTRACE_X86_REG_RIP 0x1

#define PROCTAL_LINUX_PTRACE_X86_DBG_REG_START 0x8000
#define PROCTAL_LINUX_PTRACE_X86_DBG_REG_END 0x8007

static inline int user_register_offset(int reg)
{
	if (reg >= PROCTAL_LINUX_PTRACE_X86_DBG_REG_START
		&& reg <= PROCTAL_LINUX_PTRACE_X86_DBG_REG_END) {
		reg -= PROCTAL_LINUX_PTRACE_X86_DBG_REG_START;

		return offsetof(struct user, u_debugreg)
			+ sizeof (((struct user *) 0)->u_debugreg[0]) * reg;
	} else if (reg == PROCTAL_LINUX_PTRACE_X86_REG_RIP) {
		return offsetof(struct user, regs)
			+ offsetof(struct user_regs_struct, rip);
	} else {
		// Not implemented.
		return -1;
	}
}

static int proctal_linux_ptrace_wait_stop(struct proctal_linux *pl)
{
	int wstatus;

	for (;;) {
		waitpid(pl->pid, &wstatus, WUNTRACED);

		if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGSTOP) {
			return 1;
		}
	}

	proctal_set_error(&pl->p, PROCTAL_ERROR_UNKNOWN);
	return 0;
}

int proctal_linux_ptrace_attach(struct proctal_linux *pl)
{
	if (pl->ptrace == 0) {
		if (ptrace(PTRACE_ATTACH, pl->pid, 0L, 0L) == -1) {
			switch (errno) {
			case EPERM:
				proctal_set_error(&pl->p, PROCTAL_ERROR_PERMISSION_DENIED);
				break;

			default:
				proctal_set_error(&pl->p, PROCTAL_ERROR_UNKNOWN);
				break;
			}

			return 0;
		}

		pl->ptrace = 1;
	} else {
		++pl->ptrace;

		kill(pl->pid, SIGSTOP);
	}

	if (!proctal_linux_ptrace_wait_stop(pl)) {
		proctal_linux_ptrace_detach(pl);
		return 0;
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
		switch (errno) {
		case EACCES:
			proctal_set_error(&pl->p, PROCTAL_ERROR_PERMISSION_DENIED);
			break;

		default:
			proctal_set_error(&pl->p, PROCTAL_ERROR_UNKNOWN);
			break;
		}

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

	if (errno) {
		proctal_set_error(&pl->p, PROCTAL_ERROR_UNKNOWN);
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

	if (errno) {
		proctal_set_error(&pl->p, PROCTAL_ERROR_UNKNOWN);
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
	if (ptrace(PTRACE_CONT, pl->pid, 0, 0)) {
		proctal_set_error(&pl->p, PROCTAL_ERROR_UNKNOWN);
		return 0;
	}

	return 1;
}
