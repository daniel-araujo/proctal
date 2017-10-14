#include <stdlib.h>
#include <stdio.h>

#include "magic/magic.h"

int main(void)
{
#define CHECK(P, T, V) \
	do { \
		T result = DEREF(T, P); \
\
		if (result != V) { \
			fprintf(stderr, "DEREF(" #T ", " #P ") did not result in " #V ".\n"); \
			return 1; \
		} \
	} while (0);

	union {
		float f;
		int i;
	} value;

	value.f = 2.0;
	CHECK(&value, int, 0x40000000);

	float *float_pointer = &value.f;
	CHECK(float_pointer, int, 0x40000000);

	return 0;

#undef CHECK
}
