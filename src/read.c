#include <stdlib.h>
#include <stdio.h>

#include "proctal.h"
#include "internal.h"

#define FORWARD_NATIVE(P, ADDR, VAL) \
	proctal_read(P, ADDR, (char *) VAL, sizeof *VAL);

#define DEFINE_FORWARD_NATIVE(SUFFIX, TYPE) \
	int proctal_read_##SUFFIX(proctal p, void *addr, TYPE *out) \
	{ \
		return FORWARD_NATIVE(p, addr, out); \
	}

int proctal_read(proctal p, void *addr, char *out, size_t size)
{
	FILE *f = proctal_memr(p);

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
