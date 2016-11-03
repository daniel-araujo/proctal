#include <stdlib.h>
#include <stdio.h>

#include "proctal.h"
#include "internal.h"

#define FORWARD_NATIVE(P, ADDR, VAL) \
	proctal_read(P, ADDR, (char *) VAL, sizeof *VAL)

#define FORWARD_NATIVE_ARRAY(P, ADDR, VAL, SIZE) \
	proctal_read(P, ADDR, (char *) VAL, SIZE * sizeof *VAL)

#define DEFINE_FORWARD_NATIVE(SUFFIX, TYPE) \
	size_t proctal_read_##SUFFIX(proctal p, void *addr, TYPE *out) \
	{ \
		return FORWARD_NATIVE(p, addr, out) / sizeof (TYPE); \
	} \
	DEFINE_FORWARD_NATIVE_ARRAY(SUFFIX##_array, TYPE)

#define DEFINE_FORWARD_NATIVE_ARRAY(SUFFIX, TYPE) \
	size_t proctal_read_##SUFFIX(proctal p, void *addr, TYPE *out, size_t size) \
	{ \
		return FORWARD_NATIVE_ARRAY(p, addr, out, size) / sizeof (TYPE); \
	}

size_t proctal_read(proctal p, void *addr, char *out, size_t size)
{
	FILE *f = proctal_memr(p);

	if (f == NULL) {
		proctal_set_error(p, PROCTAL_ERROR_PERMISSION_DENIED);
		return 0;
	}

	fseek(f, (long) addr, SEEK_SET);

	long i = fread(out, size, 1, f);

	if (i != 1) {
		proctal_set_error(p, PROCTAL_ERROR_READ_FAILURE);
		return 0;
	}

	// The way this is using the C library makes it seem like either
	// everything is read or nothing is. Might want to investigate
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
