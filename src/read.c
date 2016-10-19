#include <stdlib.h>
#include <stdio.h>

#include "proctal.h"
#include "linux.h"

#define FORWARD_NATIVE(PID, ADDR, VAL) \
	proctal_read(PID, ADDR, (char *) VAL, sizeof *VAL);

#define DEFINE_FORWARD_NATIVE(SUFFIX, TYPE) \
	int proctal_read_##SUFFIX(pid_t pid, void *addr, TYPE *out) \
	{ \
		return FORWARD_NATIVE(pid, addr, out); \
	}

int proctal_read(pid_t pid, void *addr, char *out, size_t size)
{
	FILE *f = fopen(proctal_linux_proc_path(pid, "mem"), "r");

	if (f == NULL) {
		return -1;
	}

	fseek(f, (long) addr, SEEK_SET);

	long i = fread(out, size, 1, f);

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
