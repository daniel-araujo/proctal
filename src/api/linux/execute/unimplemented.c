/*
 * An implementation that defines the functions as always failing.
 */
#include <errno.h>

#include "api/linux/proctal.h"

int proctal_linux_execute_implementation(
	struct proctal_linux *pl,
	const char *bytecode,
	size_t bytecode_length)
{
	proctal_error_set(&pl->p, PROCTAL_ERROR_UNSUPPORTED);
	return 0;
}

void *proctal_linux_execute_implementation_syscall_mmap(
	struct proctal_linux *pl,
	void *addr,
	size_t length,
	int prot,
	int flags,
	int fd,
	off_t offset)
{
	proctal_error_set(&pl->p, PROCTAL_ERROR_UNSUPPORTED);
	return NULL;
}

int proctal_linux_execute_implementation_syscall_munmap(
	struct proctal_linux *pl,
	void *addr,
	size_t length)
{
	proctal_error_set(&pl->p, PROCTAL_ERROR_UNSUPPORTED);
	return 0;
}
