#include <stdint.h>
#include <sys/syscall.h>

#include "api/linux/execute.h"
#include "api/linux/ptrace.h"
#include "api/linux/mem.h"
#include "magic/magic.h"

struct state {
	void *ip; // Instruction pointer.

	unsigned long long rdi; // First argument.
	unsigned long long rsi; // Second argument.
	unsigned long long rdx; // Third argument.
	unsigned long long r10; // Fourth argument.
	unsigned long long r8; // Fifth argument.
	unsigned long long r9; // Sixth argument.
	unsigned long long rax; // System call number and return value.

	unsigned long long rcx; // May be modifed.
	unsigned long long r11; // May be modifed.
};

static inline int save_state(struct proctal_linux *pl, pid_t tid, struct state *s)
{
	if (!proctal_linux_ptrace_instruction_pointer(pl, tid, &s->ip)
		|| !proctal_linux_ptrace_register(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RDI, &s->rdi)
		|| !proctal_linux_ptrace_register(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RSI, &s->rsi)
		|| !proctal_linux_ptrace_register(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RDX, &s->rdx)
		|| !proctal_linux_ptrace_register(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R10, &s->r10)
		|| !proctal_linux_ptrace_register(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R8, &s->r8)
		|| !proctal_linux_ptrace_register(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R9, &s->r9)
		|| !proctal_linux_ptrace_register(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RAX, &s->rax)
		|| !proctal_linux_ptrace_register(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RCX, &s->rcx)
		|| !proctal_linux_ptrace_register(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R11, &s->r11)) {
		return 0;
	}

	return 1;
}

static inline int load_state(struct proctal_linux *pl, pid_t tid, struct state *s)
{
	if (!proctal_linux_ptrace_instruction_pointer_set(pl, tid, s->ip)
		|| !proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RDI, &s->rdi)
		|| !proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RSI, &s->rsi)
		|| !proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RDX, &s->rdx)
		|| !proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R10, &s->r10)
		|| !proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R8, &s->r8)
		|| !proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R9, &s->r9)
		|| !proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RAX, &s->rax)
		|| !proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RCX, &s->rcx)
		|| !proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R11, &s->r11)) {
		return 0;
	}

	return 1;
}

int setup(struct proctal_linux *pl, pid_t tid, unsigned long long sysnum, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5, void *arg6, void *arg7)
{
	if (!proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RAX, &sysnum)) {
		return 0;
	}

	if (arg1) {
		if (!proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RDI, arg1)) {
			return 0;
		}
	}

	if (arg2) {
		if (!proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RSI, arg2)) {
			return 0;
		}
	}

	if (arg3) {
		if (!proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RDX, arg3)) {
			return 0;
		}
	}

	if (arg4) {
		if (!proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R10, arg4)) {
			return 0;
		}
	}

	if (arg5) {
		if (!proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R8, arg5)) {
			return 0;
		}
	}

	if (arg6) {
		if (!proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R9, arg6)) {
			return 0;
		}
	}

	return 1;
}

static int execute(struct proctal_linux *pl, pid_t tid, void *ret)
{
	char code[] = { 0x0F, 0x05 };

	void *payload_location = proctal_linux_mem_find_payload_location(pl, ARRAY_SIZE(code));

	if (payload_location == NULL) {
		proctal_error_set(&pl->p, PROCTAL_ERROR_INJECTION_LOCATION_NOT_FOUND);
		return 0;
	}

	if (!proctal_linux_mem_swap(pl, payload_location, code, code, ARRAY_SIZE(code))) {
		return 0;
	}

	if (!proctal_linux_ptrace_instruction_pointer_set(pl, tid, payload_location)) {
		return 0;
	}

	if (!proctal_linux_ptrace_step(pl, tid)) {
		return 0;
	}

	if (ret) {
		if (!proctal_linux_ptrace_register(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RAX, ret)) {
			return 0;
		}
	}

	if (!proctal_linux_mem_swap(pl, payload_location, code, code, ARRAY_SIZE(code))) {
		return 0;
	}

	return 1;
}

/*
 * Executes a system call in the context of the program.
 *
 * The return value of the call is written to the given pointer. You can pass a
 * NULL pointer to dismiss it.
 *
 * Arguments are also passed as pointers. You can also pass NULL if you want to
 * omit the argument.
 *
 * This function blocks for as long as the system call is running.
 *
 * Returns 1 on success and 0 on failure.
 */
int proctal_linux_execute_implementation_syscall(struct proctal_linux *pl, int sysnum, void *ret, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5, void *arg6, void *arg7)
{
	int r = 0;

	struct state savestate;

	if (!proctal_linux_ptrace_attach(pl)) {
		goto exit0;
	}

	if (!save_state(pl, pl->pid, &savestate)) {
		goto exit1;
	}

	if (!setup(pl, pl->pid, sysnum, arg1, arg2, arg3, arg4, arg5, arg6, arg7)
		|| !execute(pl, pl->pid, ret)) {
		goto exit2;
	}

	r = 1;
exit2:
	if (!load_state(pl, pl->pid, &savestate)) {
		r = 0;
	}
exit1:
	if (!proctal_linux_ptrace_detach(pl)) {
		r = 0;
	}
exit0:
	return r;
}

// TODO: Should eventually generate these definitions with a script.

void *proctal_linux_execute_implementation_syscall_mmap(struct proctal_linux *pl, void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	unsigned long long return_register;
	unsigned long long addr_register = (uintptr_t) addr;
	unsigned long long prot_register = prot;
	unsigned long long flags_register = flags;
	unsigned long long length_register = length;
	unsigned long long fd_register = fd;
	unsigned long long offset_register = offset;

	proctal_linux_execute_implementation_syscall(pl, SYS_mmap, &return_register, &addr_register, &length_register, &prot_register, &flags_register, &fd_register, &offset_register, NULL);

	return (void *) (uintptr_t) return_register;
}

int proctal_linux_execute_implementation_syscall_munmap(struct proctal_linux *pl, void *addr, size_t length)
{
	unsigned long long return_register;
	unsigned long long addr_register = (uintptr_t) addr;
	unsigned long long length_register = length;

	proctal_linux_execute_implementation_syscall(pl, SYS_munmap, &return_register, &addr_register, &length_register, NULL, NULL, NULL, NULL, NULL);

	return return_register;
}
