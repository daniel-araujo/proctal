#include "api/linux/proctal.h"
#include "api/linux/ptrace.h"
#include "api/linux/ptrace/internal.h"

int proctal_linux_ptrace_implementation_instruction_pointer(struct proctal_linux *pl, pid_t tid, void **address)
{
	return proctal_linux_ptrace_register(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RIP, address);
}

int proctal_linux_ptrace_implementation_instruction_pointer_set(struct proctal_linux *pl, pid_t tid, void *address)
{
	return proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RIP, &address);
}
