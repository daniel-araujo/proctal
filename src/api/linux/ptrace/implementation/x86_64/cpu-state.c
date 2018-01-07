#include <errno.h>
#include <linux/elf.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>

#include "api/linux/proctal.h"
#include "api/linux/ptrace/internal.h"

struct proctal_linux_ptrace_cpu_state_x86_64 {
	struct user_regs_struct general;
	struct user_fpregs_struct fp;
};

struct proctal_linux_ptrace_cpu_state *proctal_linux_ptrace_implementation_cpu_state_create(struct proctal_linux *pl)
{
	struct proctal_linux_ptrace_cpu_state_x86_64 *state_x86_64 = proctal_malloc(&pl->p, sizeof(*state_x86_64));
	return (struct proctal_linux_ptrace_cpu_state *) state_x86_64;
}

void proctal_linux_ptrace_implementation_cpu_state_destroy(struct proctal_linux *pl, struct proctal_linux_ptrace_cpu_state *state)
{
	proctal_free(&pl->p, state);
}

int proctal_linux_ptrace_implementation_cpu_state_save(struct proctal_linux *pl, pid_t tid, struct proctal_linux_ptrace_cpu_state *state)
{
	struct proctal_linux_ptrace_cpu_state_x86_64 *state_x86_64 = (struct proctal_linux_ptrace_cpu_state_x86_64 *) state;
	struct iovec io;

#define GETREGSET(TYPE_REGISTER, STRUCT) \
	io.iov_base = &STRUCT; \
	io.iov_len = sizeof(STRUCT); \
\
	ptrace(PTRACE_GETREGSET, tid, TYPE_REGISTER, &io); \
\
	if (proctal_linux_ptrace_check_stop_state_errno(pl)) { \
		return 0; \
	}

	errno = 0;

	GETREGSET(NT_PRSTATUS, state_x86_64->general)
	GETREGSET(NT_PRFPREG, state_x86_64->fp)

#undef GETREGSET

	return 1;
}

int proctal_linux_ptrace_implementation_cpu_state_load(struct proctal_linux *pl, pid_t tid, struct proctal_linux_ptrace_cpu_state *state)
{
	struct proctal_linux_ptrace_cpu_state_x86_64 *state_x86_64 = (struct proctal_linux_ptrace_cpu_state_x86_64 *) state;
	struct iovec io;

#define SETREGSET(TYPE_REGISTER, STRUCT) \
	io.iov_base = &STRUCT; \
	io.iov_len = sizeof(STRUCT); \
\
	ptrace(PTRACE_SETREGSET, tid, TYPE_REGISTER, &io); \
\
	if (proctal_linux_ptrace_check_stop_state_errno(pl)) { \
		return 0; \
	}

	errno = 0;

	SETREGSET(NT_PRSTATUS, state_x86_64->general)
	SETREGSET(NT_PRFPREG, state_x86_64->fp)

#undef GETREGSET

	return 1;
}
