#include "api/linux/proctal.h"
#include "api/linux/ptrace.h"

#define RED_ZONE_SIZE 128

int proctal_linux_execute_implementation_create_stack_frame(struct proctal_linux *pl, pid_t tid)
{
	unsigned long long stack_pointer;
	unsigned long long base_pointer;

	proctal_linux_ptrace_register(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RSP, &stack_pointer);

	stack_pointer -= RED_ZONE_SIZE;
	base_pointer = stack_pointer;

	if (!proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RSP, &stack_pointer)
		|| !proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RBP, &base_pointer)) {
		return 0;
	}

	return 1;
}

int proctal_linux_execute_implementation_destroy_stack_frame(struct proctal_linux *pl, pid_t tid)
{
	return 1;
}
