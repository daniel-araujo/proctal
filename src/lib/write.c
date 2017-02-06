#include "lib/proctal.h"

#define FORWARD_NATIVE(P, ADDR, VAL) \
	proctal_write(P, ADDR, (const char *) &VAL, sizeof(VAL))

#define FORWARD_NATIVE_ARRAY(P, ADDR, VAL, SIZE) \
	proctal_write(P, ADDR, (const char *) VAL, SIZE * sizeof(*VAL))

#define DEFINE_FORWARD_NATIVE(SUFFIX, TYPE) \
	size_t proctal_write_##SUFFIX(proctal p, void *addr, TYPE in) \
	{ \
		return FORWARD_NATIVE(p, addr, in) / sizeof(TYPE); \
	} \
	DEFINE_FORWARD_NATIVE_ARRAY(SUFFIX##_array, TYPE)

#define DEFINE_FORWARD_NATIVE_ARRAY(SUFFIX, TYPE) \
	size_t proctal_write_##SUFFIX(proctal p, void *addr, const TYPE *in, size_t size) \
	{ \
		return FORWARD_NATIVE_ARRAY(p, addr, in, size) / sizeof(TYPE); \
	}

size_t proctal_write(proctal p, void *addr, const char *in, size_t size)
{
	return proctal_impl_write(p, addr, in, size);
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
