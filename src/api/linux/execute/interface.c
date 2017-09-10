/*
 * This is the functionality that the rest of the code outside this module will
 * see.
 */

#include "api/linux/execute.h"
#include "api/linux/execute/implementation.h"

int proctal_linux_execute(struct proctal_linux *pl, const void *bytecode, size_t bytecode_length)
{
	return proctal_linux_execute_implementation(pl, bytecode, bytecode_length);
}

void *proctal_linux_execute_syscall_mmap(struct proctal_linux *pl, void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	return proctal_linux_execute_implementation_syscall_mmap(pl, addr, length, prot, flags, fd, offset);
}

int proctal_linux_execute_syscall_munmap(struct proctal_linux *pl, void *addr, size_t length)
{
	return proctal_linux_execute_implementation_syscall_munmap(pl, addr, length);
}
