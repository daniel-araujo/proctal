#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <errno.h>

#include "proctal.h"
#include "internal.h"
#include "linux/ptrace.h"

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

static int proctal_linux_ptrace_wait_stop(proctal p)
{
	int wstatus;

	for (;;) {
		waitpid(proctal_pid(p), &wstatus, WUNTRACED);

		if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGSTOP) {
			return 1;
		}
	}

	proctal_set_error(p, PROCTAL_ERROR_UNKNOWN);
	return 0;
}

int proctal_linux_ptrace_attach(proctal p)
{
	if (p->ptrace == 0) {
		if (ptrace(PTRACE_ATTACH, proctal_pid(p), 0L, 0L) == -1) {
			switch (errno) {
			case EPERM:
				proctal_set_error(p, PROCTAL_ERROR_PERMISSION_DENIED);
				break;

			default:
				proctal_set_error(p, PROCTAL_ERROR_UNKNOWN);
				break;
			}

			return 0;
		}

		p->ptrace = 1;
	} else {
		++p->ptrace;

		kill(proctal_pid(p), SIGSTOP);
	}

	if (!proctal_linux_ptrace_wait_stop(p)) {
		proctal_linux_ptrace_detach(p);
		return 0;
	}

	return 1;
}

int proctal_linux_ptrace_detach(proctal p)
{
	if (p->ptrace > 1) {
		if (--p->ptrace) {
			return 1;
		}
	}

	if (ptrace(PTRACE_DETACH, proctal_pid(p), 0L, 0L) == -1) {
		switch (errno) {
		case EACCES:
			proctal_set_error(p, PROCTAL_ERROR_PERMISSION_DENIED);
			break;

		default:
			proctal_set_error(p, PROCTAL_ERROR_UNKNOWN);
			break;
		}

		return 0;
	}

	p->ptrace = 0;

	return 1;
}

int proctal_linux_ptrace_get_instruction_address(proctal p, void **addr)
{
	int offset = user_register_offset(PROCTAL_LINUX_PTRACE_X86_REG_RIP);

	if (offset == -1) {
		proctal_set_error(p, PROCTAL_ERROR_UNSUPPORTED);
		return 0;
	}

	errno = 0;

	*addr = (void *) ptrace(PTRACE_PEEKUSER, proctal_pid(p), offset, 0);

	if (errno) {
		proctal_set_error(p, PROCTAL_ERROR_UNKNOWN);
		return 0;
	}

	return 1;
}

int proctal_linux_ptrace_get_x86_reg(proctal p, int reg, unsigned long long *v)
{
	int offset = user_register_offset(reg);

	if (offset == -1) {
		proctal_set_error(p, PROCTAL_ERROR_UNSUPPORTED);
		return 0;
	}

	errno = 0;

	*v = ptrace(PTRACE_PEEKUSER, proctal_pid(p), offset, 0);

	if (errno) {
		proctal_set_error(p, PROCTAL_ERROR_UNKNOWN);
		return 0;
	}

	return 1;
}

int proctal_linux_ptrace_set_x86_reg(proctal p, int reg, unsigned long long v)
{
	int offset = user_register_offset(reg);

	if (offset == -1) {
		proctal_set_error(p, PROCTAL_ERROR_UNSUPPORTED);
		return 0;
	}

	errno = 0;

	ptrace(PTRACE_POKEUSER, proctal_pid(p), offset, v);

	if (errno) {
		proctal_set_error(p, PROCTAL_ERROR_UNKNOWN);
		return 0;
	}

	return 1;
}

int proctal_linux_ptrace_stop(proctal p)
{
	kill(proctal_pid(p), SIGSTOP);

	if (!proctal_linux_ptrace_wait_stop(p)) {
		return 0;
	}

	return 1;
}

int proctal_linux_ptrace_cont(proctal p)
{
	if (ptrace(PTRACE_CONT, proctal_pid(p), 0, 0)) {
		proctal_set_error(p, PROCTAL_ERROR_UNKNOWN);
		return 0;
	}

	return 1;
}
