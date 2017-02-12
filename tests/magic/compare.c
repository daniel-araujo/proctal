#include <stdlib.h>
#include <stdio.h>

#include "magic/magic.h"

int main(void)
{
#define CHECK(X, Y, Z) \
	do { \
		int result = COMPARE(X, Y); \
\
		if (result != Z) { \
			fprintf(stderr, "COMPARE(" #X ", " #Y") resulted in %d but was expecting " #Z ".\n", result); \
			return 1; \
		} \
	} while (0);

	// Using plain integers.
	CHECK(1, 2, -1);
	CHECK(1, 1, 0);
	CHECK(2, 1, 1);

	// Long ints.
	CHECK(1U, 2U, -1);
	CHECK(1U, 1U, 0);
	CHECK(2U, 1U, 1);

	// Floats.
	CHECK(1.0, 2.0, -1);
	CHECK(1.0, 1.0, 0);
	CHECK(2.0, 1.0, 1);

	return 0;

#undef CHECK
}
