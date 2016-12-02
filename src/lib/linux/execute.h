#ifndef LINUX_EXECUTE_H
#define LINUX_EXECUTE_H

#include <linux/proctal.h>

int proctal_linux_execute(struct proctal_linux *pl, const char *byte_code, size_t byte_code_length);

int proctal_linux_execute_syscall(
	struct proctal_linux *pl,
	int num,
	unsigned long long *ret,
	unsigned long long one,
	unsigned long long two,
	unsigned long long three,
	unsigned long long four,
	unsigned long long five,
	unsigned long long six);

#endif /* LINUX_EXECUTE_H */
