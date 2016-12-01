#include <linux/execute.h>
#include <linux/alloc.h>
#include <linux/mem.h>
#include <linux/ptrace.h>

int proctal_linux_execute(struct proctal_linux *pl, const char *byte_code, size_t byte_code_length)
{
	if (!proctal_linux_ptrace_attach(pl)) {
		return 0;
	}

	void *addr = proctal_linux_alloc(
		pl,
		byte_code_length,
		PROCTAL_ALLOC_PERM_WRITE | PROCTAL_ALLOC_PERM_EXECUTE | PROCTAL_ALLOC_PERM_READ);

	if (addr == NULL) {
		proctal_linux_ptrace_detach(pl);
		return 0;
	}

	proctal_linux_mem_write(pl, addr, byte_code, byte_code_length);

	proctal_linux_ptrace_set_instruction_address(pl, addr);

	if (!proctal_linux_ptrace_detach(pl)) {
		return 0;
	}

	return 1;
}
