#include <stdio.h>
#include <stdlib.h>

#include "proctal.h"

#define FORWARD_NATIVE(pid, addr, val) \
	proctal_mem_write(pid, addr, (char *) &val, sizeof val);

int proctal_mem_write(pid_t pid, void *addr, char *in, size_t size)
{
	const char *path_template = "/proc/%d/mem";

	char path[sizeof(path_template) + 11];
	int e = snprintf(path, sizeof path, path_template, pid);
	path[e] = '\0';

	FILE *f = fopen(path, "w");

	if (f == NULL) {
		return -1;
	}

	fseek(f, (long) addr, SEEK_SET);

	long i = fwrite(in, size, 1, f);

	if (i != 1) {
		return -1;
	}

	return 0;
}

int proctal_mem_write_int(pid_t pid, void *addr, int in)
{
	return FORWARD_NATIVE(pid, addr, in);
}

int proctal_mem_write_uint(pid_t pid, void *addr, unsigned int in)
{
	return FORWARD_NATIVE(pid, addr, in);
}
