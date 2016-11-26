#include <linux/alloc.h>
#include <linux/proc.h>
#include <linux/ptrace.h>

void *proctal_linux_alloc(struct proctal_linux *pl, size_t size, int permissions)
{
	void *orig_addr;

	if (!proctal_linux_ptrace_attach(pl)) {
		return 0;
	}

	if (!proctal_linux_ptrace_get_instruction_address(pl, &orig_addr)) {
		proctal_linux_ptrace_detach(pl);
		return 0;
	}

	if (!proctal_linux_ptrace_detach(pl)) {
		return 0;
	}

	proctal_set_error(&pl->p, PROCTAL_ERROR_UNIMPLEMENTED);

	return 0;
}

int proctal_linux_dealloc(struct proctal_linux *pl, void *addr)
{
	proctal_set_error(&pl->p, PROCTAL_ERROR_UNIMPLEMENTED);
	return 0;
}
