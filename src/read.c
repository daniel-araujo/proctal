#include <stdlib.h>
#include <stdio.h>

#include "proctal.h"

#define FORWARD_NATIVE(pid, addr, val) \
	proctal_mem_read(pid, addr, (char *) val, sizeof *val);

int proctal_mem_read(pid_t pid, void *addr, char *out, size_t size)
{
	const char *path_template = "/proc/%d/mem";

	char path[sizeof(path_template) + 11];
	int e = snprintf(path, sizeof path, path_template, pid);
	path[e] = '\0';

	FILE *f = fopen(path, "r");

	if (f == NULL) {
		return -1;
	}

	fseek(f, (long) addr, SEEK_SET);

	long i = fread(out, size, 1, f);

	if (i != 1) {
		return -1;
	}

	return 0;
}

int proctal_mem_read_int(pid_t pid, void *addr, int *out)
{
	return FORWARD_NATIVE(pid, addr, out);
}

int proctal_mem_read_uint(pid_t pid, void *addr, unsigned int *out)
{
	return FORWARD_NATIVE(pid, addr, out);
}
