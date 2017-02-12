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

	float float_value = 2.0;
	float *float_pointer = &float_value;

	// Using a pointer.
	CHECK(float_pointer, int, 0x40000000);

	// Using an address.
	CHECK(&float_value, int, 0x40000000);

	return 0;

#undef CHECK
}
