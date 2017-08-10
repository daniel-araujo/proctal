#include "api/proctal.h"
#include "api/implementation.h"

#define FORWARD_NATIVE(P, ADDR, VAL) \
	proctal_read(P, ADDR, (char *) VAL, sizeof(*VAL))

#define FORWARD_NATIVE_ARRAY(P, ADDR, VAL, SIZE) \
	proctal_read(P, ADDR, (char *) VAL, SIZE * sizeof(*VAL))

#define DEFINE_FORWARD_NATIVE(SUFFIX, TYPE) \
	size_t proctal_read_##SUFFIX(proctal_t p, void *addr, TYPE *out) \
	{ \
		return FORWARD_NATIVE(p, addr, out) / sizeof(TYPE); \
	} \
	DEFINE_FORWARD_NATIVE_ARRAY(SUFFIX##_array, TYPE)

#define DEFINE_FORWARD_NATIVE_ARRAY(SUFFIX, TYPE) \
	size_t proctal_read_##SUFFIX(proctal_t p, void *addr, TYPE *out, size_t size) \
	{ \
		return FORWARD_NATIVE_ARRAY(p, addr, out, size) / sizeof(TYPE); \
	}

size_t proctal_read(proctal_t p, void *addr, char *out, size_t size)
{
	return proctal_implementation_read(p, addr, out, size);
}

DEFINE_FORWARD_NATIVE(char, char)
DEFINE_FORWARD_NATIVE(signed_char, signed char)
DEFINE_FORWARD_NATIVE(unsigned_char, unsigned char)
DEFINE_FORWARD_NATIVE(short, short)
DEFINE_FORWARD_NATIVE(unsigned_short, unsigned short)
DEFINE_FORWARD_NATIVE(int, int)
DEFINE_FORWARD_NATIVE(unsigned_int, unsigned int)
DEFINE_FORWARD_NATIVE(long, long)
DEFINE_FORWARD_NATIVE(unsigned_long, unsigned long)
DEFINE_FORWARD_NATIVE(long_long, long long)
DEFINE_FORWARD_NATIVE(unsigned_long_long, unsigned long long)
DEFINE_FORWARD_NATIVE(float, float)
DEFINE_FORWARD_NATIVE(double, double)
DEFINE_FORWARD_NATIVE(long_double, long double)
DEFINE_FORWARD_NATIVE(address, void *)
