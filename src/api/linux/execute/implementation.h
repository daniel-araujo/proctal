#ifndef API_LINUX_EXECUTE_IMPLEMENTATION_H
#define API_LINUX_EXECUTE_IMPLEMENTATION_H

#include "api/linux/proctal.h"

/*
 * Executes code in the context of the program.
 *
 * This function blocks for as long as the code is running.
 *
 * The code is allowed to modify any register.
 *
 * Returns 1 on success and 0 on failure.
 */
int proctal_linux_execute_implementation(struct proctal_linux *pl, const char *bytecode, size_t bytecode_length);

/*
 * The following functions execute system calls in the context of the program.
 *
 * The signatures are identical to the wrappers defined in glibc, the only
 * difference is the addition of an extra argument to pass a proctal_linux
 * struct.
 *
 * Unlike the glibc versions, these do not extract error codes to an errno like
 * variable. The return values are untampered.
 *
 * These functions block for as long as the system call is running.
 *
 * If Proctal fails to dispatch the system call, an error code will be set.
 */

void *proctal_linux_execute_implementation_syscall_mmap(struct proctal_linux *pl, void *addr, size_t length, int prot, int flags, int fd, off_t offset);

int proctal_linux_execute_implementation_syscall_munmap(struct proctal_linux *pl, void *addr, size_t length);

#endif /* API_LINUX_EXECUTE_IMPLEMENTATION_H */
