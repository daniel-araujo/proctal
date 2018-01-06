#include "api/proctal.h"
#include "api/implementation.h"

/*
 * Calls proctal_read with a C value.
 */
#define FORWARD_NATIVE(P, ADDRESS, VAL) \
	proctal_read(P, ADDRESS, VAL, sizeof(*VAL))

/*
 * Calls proctal_read with a C array.
 */
#define FORWARD_NATIVE_ARRAY(P, ADDRESS, VAL, SIZE) \
	proctal_read(P, ADDRESS, VAL, SIZE * sizeof(*VAL))

/*
 * Defines variants of proctal_read that take C types.
 */
#define DEFINE_FORWARD_NATIVE(SUFFIX, TYPE) \
	size_t proctal_read_##SUFFIX(struct proctal *p, void *address, TYPE *out) \
	{ \
		return FORWARD_NATIVE(p, address, out) / sizeof(TYPE); \
	} \
\
	size_t proctal_read_##SUFFIX##_array(struct proctal *p, void *address, TYPE *out, size_t size) \
	{ \
		return FORWARD_NATIVE_ARRAY(p, address, out, size) / sizeof(TYPE); \
	}

size_t proctal_read(struct proctal *p, void *address, void *out, size_t size)
{
	return proctal_implementation_read(p, address, out, size);
}

// Defining versions of proctal_read that take C types.
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
