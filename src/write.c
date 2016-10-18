#include <stdio.h>
#include <stdlib.h>

#include "proctal.h"

#define FORWARD_NATIVE(PID, ADDR, VAL) \
	proctal_mem_write(PID, ADDR, (char *) &VAL, sizeof VAL);

#define DEFINE_FORWARD_NATIVE(SUFFIX, TYPE) \
	int proctal_mem_write_##SUFFIX(pid_t pid, void *addr, TYPE in) \
	{ \
		return FORWARD_NATIVE(pid, addr, in); \
	}

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

	fclose(f);

	if (i != 1) {
		return -1;
	}

	return 0;
}

DEFINE_FORWARD_NATIVE(char, char)
DEFINE_FORWARD_NATIVE(schar, signed char)
DEFINE_FORWARD_NATIVE(uchar, unsigned char)
DEFINE_FORWARD_NATIVE(short, short)
DEFINE_FORWARD_NATIVE(ushort, unsigned short)
DEFINE_FORWARD_NATIVE(int, int)
DEFINE_FORWARD_NATIVE(uint, unsigned int)
DEFINE_FORWARD_NATIVE(long, long)
DEFINE_FORWARD_NATIVE(ulong, unsigned long)
DEFINE_FORWARD_NATIVE(longlong, long long)
DEFINE_FORWARD_NATIVE(ulonglong, unsigned long long)
DEFINE_FORWARD_NATIVE(float, float)
DEFINE_FORWARD_NATIVE(double, double)
DEFINE_FORWARD_NATIVE(longdouble, long double)
