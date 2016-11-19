#include <stdio.h>
#include <stdlib.h>

#include "internal.h"

#define FORWARD_NATIVE(P, ADDR, VAL) \
	proctal_write(P, ADDR, (char *) &VAL, sizeof VAL)

#define FORWARD_NATIVE_ARRAY(P, ADDR, VAL, SIZE) \
	proctal_write(P, ADDR, (char *) VAL, SIZE * sizeof *VAL)

#define DEFINE_FORWARD_NATIVE(SUFFIX, TYPE) \
	size_t proctal_write_##SUFFIX(proctal p, void *addr, TYPE in) \
	{ \
		return FORWARD_NATIVE(p, addr, in) / sizeof (TYPE); \
	}

#define DEFINE_FORWARD_NATIVE_ARRAY(SUFFIX, TYPE) \
	size_t proctal_write_##SUFFIX(proctal p, void *addr, TYPE *in, size_t size) \
	{ \
		return FORWARD_NATIVE_ARRAY(p, addr, out, size) / sizeof (TYPE); \
	}

size_t proctal_write(proctal p, void *addr, char *in, size_t size)
{
	FILE *f = proctal_memw(p);

	if (f == NULL) {
		proctal_set_error(p, PROCTAL_ERROR_PERMISSION_DENIED);
		return 0;
	}

	fseek(f, (long) addr, SEEK_SET);

	long i = fwrite(in, size, 1, f);

	if (i != 1) {
		proctal_set_error(p, PROCTAL_ERROR_WRITE_FAILURE);
		return 0;
	}

	// The way this is using the C library makes it seem like either
	// everything is written or nothing is. Might want to investigate
	// this.

	return size;
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
DEFINE_FORWARD_NATIVE(address, void *)
